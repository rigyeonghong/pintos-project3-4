#include "filesys/fat.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <stdio.h>
#include <string.h>

/* Should be less than DISK_SECTOR_SIZE */
/* DISK_SEOCTOR_SIZE보다 작아야함 */
struct fat_boot {
    unsigned int magic;
    unsigned int sectors_per_cluster; /* Fixed to 1 */
    unsigned int total_sectors;
    unsigned int fat_start;
    unsigned int fat_sectors; /* 섹터의 FAT 크기 */
    unsigned int root_dir_cluster;
};

/* FAT FS */
struct fat_fs {
    struct fat_boot bs;
    unsigned int *fat;
    unsigned int fat_length; // 파일 시스템의 클러스터 수 
    disk_sector_t data_start; // 파일이 들어있는 시작 섹터를 저장
    cluster_t last_clst;
    struct lock write_lock;
};

static struct fat_fs *fat_fs;

void fat_boot_create (void);
void fat_fs_init (void);

void
fat_init (void) {
    fat_fs = calloc (1, sizeof (struct fat_fs));
    if (fat_fs == NULL)
        PANIC ("FAT init failed");

    // 디스크에서 부팅 섹터 읽기
    unsigned int *bounce = malloc (DISK_SECTOR_SIZE);
    if (bounce == NULL)
        PANIC ("FAT init failed");
    disk_read (filesys_disk, FAT_BOOT_SECTOR, bounce); // 두번째 인자(sec_no)를 첫번째 인자에서 세번째 인자로 읽음.
    memcpy (&fat_fs->bs, bounce, sizeof (fat_fs->bs));
    free (bounce);

    // FAT 정보 추출
    if (fat_fs->bs.magic != FAT_MAGIC) // FAT 디스크를 식별하는 매직 문자열이 아니면
        fat_boot_create ();
    fat_fs_init ();
}

void
fat_open (void) {
    fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
    if (fat_fs->fat == NULL)
        PANIC ("FAT load failed");

    // 디스크에서 직접 FAT 로드
    uint8_t *buffer = (uint8_t *) fat_fs->fat;
    off_t bytes_read = 0;
    off_t bytes_left = sizeof (fat_fs->fat);
    const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof (cluster_t);
    for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
        bytes_left = fat_size_in_bytes - bytes_read;
        if (bytes_left >= DISK_SECTOR_SIZE) {
            disk_read (filesys_disk, fat_fs->bs.fat_start + i,
                       buffer + bytes_read);
            bytes_read += DISK_SECTOR_SIZE;
        } else {
            uint8_t *bounce = malloc (DISK_SECTOR_SIZE);
            if (bounce == NULL)
                PANIC ("FAT load failed");
            disk_read (filesys_disk, fat_fs->bs.fat_start + i, bounce); // 두번째 인자(sec_no)를 첫번째 인자에서 세번째 인자로 읽음.
            memcpy (buffer + bytes_read, bounce, bytes_left); // 디스크에서 읽은 것을 buffer+bytes_read로 복사 (dest, source, num)
            bytes_read += bytes_left; // 읽은 만큼 추가 
            free (bounce); // bounce buffer 프리
        }
    }
}

void
fat_close (void) {
    // Write FAT boot sector
    // FAT 부팅 섹터 쓰기
    uint8_t *bounce = calloc (1, DISK_SECTOR_SIZE);
    if (bounce == NULL)
        PANIC ("FAT close failed");
    memcpy (bounce, &fat_fs->bs, sizeof (fat_fs->bs));
    disk_write (filesys_disk, FAT_BOOT_SECTOR, bounce);
    free (bounce);

    // Write FAT directly to the disk
    // 디스크에 직접 FAT 쓰기
    uint8_t *buffer = (uint8_t *) fat_fs->fat;
    off_t bytes_wrote = 0;
    off_t bytes_left = sizeof (fat_fs->fat);
    const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof (cluster_t);
    for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
        bytes_left = fat_size_in_bytes - bytes_wrote;
        if (bytes_left >= DISK_SECTOR_SIZE) {
            disk_write (filesys_disk, fat_fs->bs.fat_start + i,
                        buffer + bytes_wrote);
            bytes_wrote += DISK_SECTOR_SIZE;
        } else {
            bounce = calloc (1, DISK_SECTOR_SIZE);
            if (bounce == NULL)
                PANIC ("FAT close failed");
            memcpy (bounce, buffer + bytes_wrote, bytes_left);
            disk_write (filesys_disk, fat_fs->bs.fat_start + i, bounce);
            bytes_wrote += bytes_left;
            free (bounce);
        }
    }
}

void
fat_create (void) {
    // Create FAT boot
    fat_boot_create ();
    fat_fs_init ();

    // Create FAT table
    fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
    if (fat_fs->fat == NULL)
        PANIC ("FAT creation failed");

    // Set up ROOT_DIR_CLST
    fat_put (ROOT_DIR_CLUSTER, EOChain);

    // Fill up ROOT_DIR_CLUSTER region with 0
    // ROOT_DIR_CLUSTER 영역을 0으로 채움
    uint8_t *buf = calloc (1, DISK_SECTOR_SIZE);
    if (buf == NULL)
        PANIC ("FAT create failed due to OOM");
    disk_write (filesys_disk, cluster_to_sector (ROOT_DIR_CLUSTER), buf);
    free (buf);
}

void
fat_boot_create (void) {
    unsigned int fat_sectors =
        (disk_size (filesys_disk) - 1)
        / (DISK_SECTOR_SIZE / sizeof (cluster_t) * SECTORS_PER_CLUSTER + 1) + 1;
        // [alram-single] fat_sectors: 157
        // disk_size (filesys_disk): 20160
    fat_fs->bs = (struct fat_boot){
        .magic = FAT_MAGIC,
        .sectors_per_cluster = SECTORS_PER_CLUSTER,        
        .total_sectors = disk_size (filesys_disk),
        .fat_start = 1,
        .fat_sectors = fat_sectors,
        .root_dir_cluster = ROOT_DIR_CLUSTER,
    };
}

void
fat_fs_init (void) {
    /* FAT 파일 시스템을 초기화합니다. 
    `fat_fs`의 `fat_length`와 `data_start` 필드를 초기화해야 합니다.
    `fat_length`는 파일 시스템의 클러스터 수를 저장하고, `data_start`는 파일 저장을 시작할 수 있는 섹터를 저장합니다. 
    `fat_fs→bs`에 저장된 일부 값을 이용할 수 있습니다. 또한, 이 함수에서 다른 유용한 데이터들을 초기화할 수도 있습니다.*/
    fat_fs->fat_length = fat_fs->bs.total_sectors;
    fat_fs->data_start = fat_fs->bs.fat_start + fat_fs->bs.fat_sectors;
}

/*----------------------------------------------------------------------------*/
/* FAT handling                                                               */
/*----------------------------------------------------------------------------*/

/* Add a cluster to the chain.
 * If CLST is 0, start a new chain.
 * Returns 0 if fails to allocate a new cluster. */
/* 체인에 클러스터를 추가합니다.
* CLST가 0이면 새 체인을 시작합니다.
* 새 클러스터를 할당하지 못하면 0을 반환합니다.*/
cluster_t
fat_create_chain (cluster_t clst) {
    /* clst(클러스터 인덱싱 번호)로 특정된 클러스터의 뒤에 클러스터를 추가하여 체인을 확장합니다. 
    clst가 0이면 새 체인을 만듭니다. 
    새로 할당된 클러스터의 번호를 반환합니다. */

    for(cluster_t i= 2 ; i <= (fat_fs->bs.fat_sectors*128); i++){
        cluster_t value = fat_get(i); // fat[i] 확인 
        if(value == 0){ // 만약에 i번째 클러스터가 비어 있다면
            fat_put(i, EOChain); // 새로운 클러스터 할당
            if (clst != 0) // clst가 0이 아니면
                fat_put(clst, i); // 원래 체인에 새로 할당한 클러스터 번호를 넣어줌
            return i; 
        }
    }    
    return 0;
}

/* Remove the chain of clusters starting from CLST.
 * If PCLST is 0, assume CLST as the start of the chain. */
/* CLST에서 시작하는 클러스터 체인을 제거합니다.
* PCLST가 0이면 CLST를 체인의 시작으로 가정합니다.*/
void
fat_remove_chain (cluster_t clst, cluster_t pclst) {
    /* clst에서 시작하여, 체인에서 클러스터를 제거합니다. 
    pclst는 체인에서 clst의 바로 뒤에 있는 클러스터여야 합니다. 
    즉, 이 함수가 실행된 후에,pclst는 업데이트된 체인의 마지막 요소가 될 것입니다. 
    만약 clst가 체인의 첫 요소라면, pclst는 0이 되어야 합니다. */
    // pclst의 next가 clst인지 check
    // clst부터 돌면서 뒤 값을 다 0으로 바꿈
    cluster_t i =clst;
    cluster_t prev_i;

    while(fat_get(i) != EOChain){
        prev_i = i;
        i = fat_get(i);
        fat_put(prev_i, 0);
    }    
    fat_put(i, 0);

    if(pclst != 0)
        fat_put(pclst, EOChain);    // pclst의 값을 -1로 만듦
    //[4-1?] 검증이 필요한가? 
}


/* Update a value in the FAT table. */
/* FAT 테이블의 값 업데이트 */
void
fat_put (cluster_t clst, cluster_t val) {
    /* 클러스터 번호 clst가 가리키는 FAT 엔트리를 val로 업데이트합니다. 
    FAT의 각 엔트리가 체인의 다음 클러스터를 가리키므로, (존재하는 경우; 그렇지 않다면 EOChain) 
    이는 연결을 업데이트하는데 사용할 수 있습니다.  */
    unsigned int *fat= fat_fs->fat;
    fat[clst-1] = val;
}

/* Fetch a value in the FAT table. */
/* FAT 테이블에서 값을 가져옴 */
cluster_t
fat_get (cluster_t clst) {
    /* 주어진 클러스터 clst 가 가리키는 클러스터 번호를 반환합니다. */
    unsigned int *fat= fat_fs->fat;
    return fat[clst-1];
}

/* Covert a cluster # to a sector number. */
/* 클러스터 # 을 섹터 번호로 암호화함 */
disk_sector_t
cluster_to_sector (cluster_t clst) {
    /* 클러스터 번호 clst를 해당하는 섹터 번호로 변환하고, 반환합니다.*/
    // 157 + clst 
    return fat_fs->bs.fat_sectors + clst;
}

/* Covert a cluster # to a sector number. */
/* 클러스터 # 을 섹터 번호로 암호화함 */
cluster_t
sector_to_cluster(disk_sector_t sector)
{
	/* 클러스터 번호 clst를 해당하는 섹터 번호로 변환하고, 반환합니다.*/
	// 159 - 157 = 2
	return sector - fat_fs->bs.fat_sectors;
}