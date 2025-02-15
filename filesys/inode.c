#include "filesys/inode.h"
// #include <list.h>
// #include <debug.h>
// #include <round.h>
// #include <string.h>
// #include "filesys/filesys.h"
// #include "filesys/free-map.h"
// #include "filesys/fat.h"
// #include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* Returns the number of sectors to allocate for an inode SIZE
 * bytes long. */
static inline size_t
bytes_to_sectors(off_t size)
{
    return DIV_ROUND_UP(size, DISK_SECTOR_SIZE);
}


/* Returns the disk sector that contains byte offset POS within
 * INODE.
 * Returns -1 if INODE does not contain data for a byte at offset
 * POS. */
static disk_sector_t
byte_to_sector(const struct inode *inode, off_t pos)
{
    ASSERT(inode != NULL);

    cluster_t cur = sector_to_cluster(inode->data.start);
    // int jump = pos / (int)DISK_SECTOR_SIZE;
    // for (int i = 0; i < jump; i++)
    // {
    //     cur = fat_get(cur);
    //     if (cur == EOChain)
    //     {
    //         return -1;
    //     }
    // }
    while (pos >= DISK_SECTOR_SIZE)
    {
        if (fat_get(cur) == EOChain)
            fat_create_chain(cur);

        cur = fat_get(cur);
        pos -= DISK_SECTOR_SIZE;
    }
    return cluster_to_sector(cur);
}

/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void)
{
    list_init(&open_inodes);
}

/* 데이터의 길이 바이트로 inode를 초기화합니다.
 * 파일 시스템 디스크의 섹터에 새 inode를 씁니다.
 * 성공하면 true를 반환합니다.
 * 메모리 또는 디스크 할당에 실패하면 false를 반환합니다. */
// [DR] inode_create : is dir 변수 받도록 수정
bool inode_create(disk_sector_t sector, off_t length, uint32_t is_dir)
{
    struct inode_disk *disk_inode = NULL;
    bool success = false;
    cluster_t start_clst;

    ASSERT(length >= 0);
    ASSERT(sizeof *disk_inode == DISK_SECTOR_SIZE);

    disk_inode = calloc(1, sizeof *disk_inode);
    if (disk_inode != NULL)
    {

        size_t sectors = bytes_to_sectors(length); // 주어진 파일 길이를 위한 섹터 수를 계산
        disk_inode->length = length;
        disk_inode->magic = INODE_MAGIC;
        disk_inode->isdir = is_dir;
        disk_inode->islink = false;

        /* data cluster allocation */
        if (start_clst = fat_create_chain(0))
        {                                                      // 새로운 체인 만들고
            disk_inode->start = cluster_to_sector(start_clst); // inode.start에 새체인 시작 sector 넣고

            /* write disk_inode on disk */
            disk_write(filesys_disk, sector, disk_inode);

            if (sectors > 0)
            {
                static char zeros[DISK_SECTOR_SIZE];
                cluster_t cur = start_clst;
                disk_sector_t cur_sector;
                size_t i;

                /* make cluster chain based length and initialize zero*/
                while (sectors > 0)
                {
                    cur_sector = cluster_to_sector(cur);
                    disk_write(filesys_disk, cur_sector, zeros);

                    cur = fat_create_chain(cur); // 연결된 체인 넣기
                    sectors--;
                }
            }
            success = true;
        }
        free(disk_inode);
    }
    return success;
}


/* Reads an inode from SECTOR
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
struct inode *
inode_open(disk_sector_t sector)
{
    struct list_elem *e;
    struct inode *inode;

    /* Check whether this inode is already open. */
    for (e = list_begin(&open_inodes); e != list_end(&open_inodes);
         e = list_next(e))
    {
        inode = list_entry(e, struct inode, elem);
        if (inode->sector == sector)
        {
            inode_reopen(inode);
            return inode;
        }
    }

    /* Allocate memory. */
    inode = malloc(sizeof *inode);
    if (inode == NULL)
        return NULL;

    /* Initialize. */
    list_push_front(&open_inodes, &inode->elem);
    inode->sector = sector;
    inode->open_cnt = 1;
    inode->deny_write_cnt = 0;
    inode->removed = false;
    disk_read(filesys_disk, inode->sector, &inode->data);

    return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen(struct inode *inode)
{
    if (inode != NULL)
        inode->open_cnt++;
    return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber(const struct inode *inode)
{
    return inode->sector;
}

/* Closes INODE and writes it to disk.
 * If this was the last reference to INODE, frees its memory.
 * If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode *inode)
{
    /* Ignore null pointer. */
    if (inode == NULL)
        return;

                                                                                                                                                  
    /* Release resources if this was the last opener. */
    if (--inode->open_cnt == 0)
    {
        /* Remove from inode list and release lock. */
        list_remove(&inode->elem);
        disk_write(filesys_disk, inode->sector, &inode->data);

        /* Deallocate blocks if removed. */
        if (inode->removed)
        {
            /* remove disk_inode */
            fat_remove_chain(sector_to_cluster(inode->sector), 0);

            /* remove file data */
            fat_remove_chain(sector_to_cluster(inode->data.start), 0);
        }

        free(inode);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void inode_remove(struct inode *inode)
{
    ASSERT(inode != NULL);
    inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
/* 위치 오프셋에서 시작하여 INODE에서 버퍼로 SIZE 바이트를 읽습니다.
   실제로 읽은 바이트 수를 반환합니다.
   오류가 발생하거나 파일 끝에 도달한 경우 SIZE보다 작을 수 있습니다. */
off_t inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset)
{
    uint8_t *buffer = buffer_;
    off_t bytes_read = 0;
    uint8_t *bounce = NULL;

    // if (offset > inode_length(inode) || inode_length(inode)==0)
    //     return 0;

    // disk_sector_t sector_idx = byte_to_sector(inode, offset); // 오프셋이 있는 섹터의 인덱스
    // cluster_t cluster_idx = sector_to_cluster(sector_idx);    // 오프셋이 있는 클러스터의 인덱스

    while (size > 0)
    {
        /* Disk sector to read, starting byte offset within sector. */
        disk_sector_t sector_idx = byte_to_sector(inode, offset); // 오프셋이 있는 섹터의 인덱스
        int sector_ofs = offset % DISK_SECTOR_SIZE;

        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        off_t inode_left = inode_length(inode) - offset; //
        int sector_left = DISK_SECTOR_SIZE - sector_ofs; //
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually copy out of this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0)
            break;

        if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE)
        {
            /* Read full sector directly into caller's buffer. */
            disk_read(filesys_disk, sector_idx, buffer + bytes_read);
        }
        else
        {
            /* Read sector into bounce buffer, then partially copy
             * into caller's buffer. */
            if (bounce == NULL)
            {
                bounce = malloc(DISK_SECTOR_SIZE);
                if (bounce == NULL)
                    break;
            }
            disk_read(filesys_disk, sector_idx, bounce);
            memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_read += chunk_size;
    }
    free(bounce);

    return bytes_read;
}

/* 버퍼에서 INODE로 오프셋부터 SIZE 바이트 쓰기.
 *  실제로 쓴 바이트 수를 반환합니다. 파일 끝에 도달하거나 오류가 발생할 경우 SIZE보다 작을 수 있습니다.
 * (일반적으로 파일 끝에 쓰기는 아이노드를 확장하지만, 성장은 아직 구현되지 않았다.) */
off_t inode_write_at(struct inode *inode, const void *buffer_, off_t size,
                     off_t offset)
{
    const uint8_t *buffer = buffer_;
    off_t bytes_written = 0;
    uint8_t *bounce = NULL;
    off_t origin_offset = offset;
    if (inode->deny_write_cnt)
        return 0;
    /* if (offset+size (파일이 늘어나야 하는 길이) < length
        쓰려는 섹터 = offset+size
        if 쓰려는 섹터 > 파일이 점유하고 있는 섹터 수
            섹터를 할당해와야함 -> fat_create_chain
        디스크에 쓰기
    */
    /*
    먼저 offset이 존재하는 섹터의 인덱스를 찾습니다
    (DIY한 함수 이용 - 만약 offset이 위치한 곳보다 파일 길이가 짧으면 섹터를 할당하여 파일을 연장해줌)
    연장이 된 상태!!!
    */
    // cluster_t cluster_idx = fat_byte_to_cluster(inode, offset); // 오프셋이 있는 섹터의
    // disk_sector_t sector_idx = cluster_to_sector(cluster_idx);

    while (size > 0)
    { // 쓸 섹터, 섹터 내 시작 바이트 오프셋
        /* Sector to write, starting byte offset within sector. */
        disk_sector_t sector_idx = byte_to_sector(inode, offset);
        int sector_ofs = offset % DISK_SECTOR_SIZE; // 한섹터 안에서의 오프셋
        // 아이노드에 남은 바이트, 섹터에 남은 바이트, 둘 중 더 작은 바이트.
        // off_t inode_left = ((int)(inode_length(inode) / DISK_SECTOR_SIZE) + 1) * DISK_SECTOR_SIZE - offset; // 아이노드 (찐렝스) 에 남은 바이트
        // off_t inode_left = inode_length (inode) - offset;
        int sector_left = DISK_SECTOR_SIZE - sector_ofs;
        // int min_left = inode_left < sector_left ? inode_left : sector_left;
        int min_left = sector_left;
        // 이거는 우리가 파일 길이를 섹터의 배수로 할당했기 때문에 같을 수밖에 없을 것 같음 (inode_left = sector_left 이거나 inode_left > sector_left)

        // int chunk_size = size < sector_left ? size : sector_left;
        /* Number of bytes to actually write into this sector. */
        int chunk_size = size < min_left ? size : min_left;

        // 더이상 종이가 없는데 써야하는 데이터는 있는 경우
        // if (inode_left == 0){// 종이 내놔
        //     cluster_idx = fat_create_chain(cluster_idx); // 새로 받아온 종이 번호
        //     sector_idx = cluster_to_sector(cluster_idx);
        //     // inode->data.length += chunk_size; // 파일 길이 늘려주기
        //     // printf("[inode_write_at] data.length %d\n", inode->data.length);
        // }

        if (chunk_size <= 0)
            break;

        if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE)
        {
            disk_write(filesys_disk, sector_idx, buffer + bytes_written);
        }
        else
        {
            if (bounce == NULL)
            {
                bounce = malloc(DISK_SECTOR_SIZE);
                if (bounce == NULL)
                    break;
            }

            /* 만약 섹터가 우리가 쓰고 있는 청크의 앞이나 뒤에 데이터를 포함하고 있다면, 우리는 먼저 섹터에서 읽을 필요가 있다. 그렇지 않으면 모든 0의 섹터로 시작 */
            if (sector_ofs > 0 || chunk_size < sector_left)
                disk_read(filesys_disk, sector_idx, bounce);
            else
                memset(bounce, 0, DISK_SECTOR_SIZE);
            memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
            disk_write(filesys_disk, sector_idx, bounce);
        }

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_written += chunk_size;
        // if (fat_get(cluster_idx) != EOChain){// 현 클러스터가 체인의 끝이 아니라면
        //     cluster_idx = fat_get(cluster_idx); // 다음 클러스터로 이동
        //     sector_idx = cluster_to_sector(cluster_idx);
    }
    free(bounce);
    // }

    off_t changed_length = origin_offset + bytes_written;
    if (inode->data.length < changed_length)
        inode->data.length = changed_length;

    return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode *inode)
{
    inode->deny_write_cnt++;
    ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode *inode)
{
    ASSERT(inode->deny_write_cnt > 0);
    ASSERT(inode->deny_write_cnt <= inode->open_cnt);
    inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode *inode)
{
    return inode->data.length;
}

bool inode_is_dir(const struct inode *inode)
{
    bool result;

    struct inode_disk *on_disk_inode = calloc(1, sizeof(struct inode_disk));

    disk_read(filesys_disk, inode->sector, on_disk_inode);

    result = on_disk_inode->isdir;
    free(on_disk_inode);

    /* inode_disk 자료구조를 메모리에 할당 */
    /* in-memory inode의 on-disk inode를 읽어 inode_disk에 저장 */ /* on-disk inode의 is_dir을 result에 저장하여 반환 */
    return result;
}

// link file 만드는 함수
// bool link_inode_create (disk_sector_t sector, char* path_name) {

// 	struct inode_disk *disk_inode = NULL;
// 	bool success = false;

// 	ASSERT (strlen(path_name) >= 0);

// 	/* If this assertion fails, the inode structure is not exactly
// 	 * one sector in size, and you should fix that. */
// 	ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

// 	disk_inode = calloc (1, sizeof *disk_inode);
// 	if (disk_inode != NULL) {
// 		disk_inode->length = strlen(path_name) + 1;
// 		disk_inode->magic = INODE_MAGIC;

//         // link file 여부 추가
//         disk_inode->isdir = 0;
//         disk_inode->islink = 1;

//         strlcpy(disk_inode->link_name, path_name, strlen(path_name) + 1);

//         cluster_t cluster = fat_create_chain(0);
//         if(cluster)
//         {
//             disk_inode->start = cluster;
//             disk_write (filesys_disk, cluster_to_sector(sector), disk_inode);
//             success = true;
//         }

// 		free (disk_inode);
// 	}
// 	return success;
// }

bool inode_create_link(disk_sector_t sector, char *path_name)
{
	struct inode_disk *disk_inode = NULL;
	cluster_t start_clst;

	ASSERT(sizeof *disk_inode == DISK_SECTOR_SIZE);

	disk_inode = calloc(1, sizeof *disk_inode);
	if (disk_inode == NULL)
		return false;

	disk_inode->length = 0;
	disk_inode->isdir = 0;
	disk_inode->islink = 1;
	disk_inode->magic = INODE_MAGIC;

	strlcpy(disk_inode->link_name, path_name, strlen(path_name) + 1);

	if (start_clst = fat_create_chain(0))
		disk_inode->start = cluster_to_sector(start_clst);

	disk_write(filesys_disk, sector, disk_inode);

	free(disk_inode);

	return true;
}

bool inode_is_link(const struct inode *inode)
{
	return inode->data.islink;
}

char *inode_get_link_name(const struct inode *inode)
{
	return inode->data.link_name;
}