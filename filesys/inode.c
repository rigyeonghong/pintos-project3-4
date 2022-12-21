#include "filesys/inode.h"

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


/* 위치 오프셋에서 시작하여 INODE에서 버퍼로 SIZE 바이트를 읽습니다.
   실제로 읽은 바이트 수를 반환합니다.
   오류가 발생하거나 파일 끝에 도달한 경우 SIZE보다 작을 수 있습니다. */
off_t inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset)
{
    uint8_t *buffer = buffer_;
    off_t bytes_read = 0;
    uint8_t *bounce = NULL;

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

    while (size > 0){ 
        disk_sector_t sector_idx = byte_to_sector(inode, offset);
        int sector_ofs = offset % DISK_SECTOR_SIZE; // 한섹터 안에서의 오프셋
        int sector_left = DISK_SECTOR_SIZE - sector_ofs;

        int chunk_size = size < sector_left ? size : sector_left;

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
    }
    free(bounce);

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