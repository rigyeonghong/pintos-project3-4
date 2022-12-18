#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "filesys/fat.h"
#include "filesys/fsutil.h"

/* A directory. */
struct dir {
	struct inode *inode;                /* Backing store. */
	off_t pos;                          /* Current position. */
};

/* A single directory entry. */
struct dir_entry {
	disk_sector_t inode_sector;         /* Sector number of header. */
	char name[NAME_MAX + 1];            /* Null terminated file name. */
	bool in_use;                        /* In use or free? */
};

/* Creates a directory with space for ENTRY_CNT entries in the
 * given SECTOR.  Returns true if successful, false on failure. */
/* 지정된 섹터의 ENTERY_CNT 항목에 대한 공간이 있는 디렉터리를 만듭니다.
   성공하면 true를 반환하고 실패하면 false를 반환합니다.*/
bool
dir_create (disk_sector_t sector, size_t entry_cnt) {
	return inode_create (sector, entry_cnt * sizeof (struct dir_entry), 1);
}

/* Opens and returns the directory for the given INODE, of which
 * it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) {
	struct dir *dir = calloc (1, sizeof *dir);
	if (inode != NULL && dir != NULL) {
		dir->inode = inode;
		dir->pos = 0;
		return dir;
	} else {
		inode_close (inode);
		free (dir);
		return NULL;
	}
}

/* Opens the root directory and returns a directory for it.
 * Return true if successful, false on failure. */
/* 루트 디렉토리를 열고, 이에 해당하는 dir을 반환한다. 
   즉, 이 파일을 실행하면 dir를 가지고, 이 dir은 ROOT_DIR_SECTOR를 열 수 있다.*/
struct dir *
dir_open_root (void) {
	disk_sector_t root = cluster_to_sector(ROOT_DIR_CLUSTER);
	return dir_open (inode_open (root));
}

/* Opens and returns a new directory for the same inode as DIR.
 * Returns a null pointer on failure. */
/* DIR과 동일한 inode에 대한 새 디렉토리를 열고 반환합니다.
* 실패 시 null 포인터를 반환 */
struct dir *
dir_reopen (struct dir *dir) {
	return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
// DIR을 삭제하고 연결된 리소스를 확보
void
dir_close (struct dir *dir) {
	if (dir != NULL) {
		inode_close (dir->inode);
		free (dir);
	}
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) {
	return dir->inode;
}

/* Searches DIR for a file with the given NAME.
 * If successful, returns true, sets *EP to the directory entry
 * if EP is non-null, and sets *OFSP to the byte offset of the
 * directory entry if OFSP is non-null.
 * otherwise, returns false and ignores EP and OFSP. */
/* DIR에서 지정된 이름의 파일을 검색
   찾는 것에 성공했다면 ep를 해당 dir_entry로 지정 */
static bool
lookup (const struct dir *dir, const char *name,
		struct dir_entry *ep, off_t *ofsp) {
	struct dir_entry e;
	size_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* dir의 inode에서 inode_disk가 가리키는 곳을 읽음. 
	 (dir_entry가 차곡차곡 쌓여있을거라, 가장 밑부터 dir_entry 읽음 ) */
	for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
		// dir_entry이고, strcmp()로 dir_entry의 name과 인자 name이 같은지 비교해본다.
		if (e.in_use && !strcmp (name, e.name)) {
			// 같다면 ep는 현재 e를 가리키게 하고, ofsp가 현재 ofs를 가리키게 한다. 
			if (ep != NULL)
				*ep = e;
			if (ofsp != NULL)
				*ofsp = ofs;
			return true;
		}

	return false;
}

/* Searches DIR for a file with the given NAME
 * and returns true if one exists, false otherwise.
 * On success, sets *INODE to an inode for the file, otherwise to
 * a null pointer.  The caller must close *INODE. 
 name에 해당하는 파일을 dir에서 찾음. 성공하면 ture, 실패하면 false 반환
 성공하는 경우, *inode를 파일의 아이노드로 설정, 실패하면 null로 설정
 함수 호출자는 *inode를 반드시 닫아야 함.
 */

bool
dir_lookup (const struct dir *dir, const char *name,
		struct inode **inode) {
	struct dir_entry e;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	if (lookup (dir, name, &e, NULL))
		*inode = inode_open (e.inode_sector);
	else
		*inode = NULL;

	return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
 * file by that name.  The file's inode is in sector
 * INODE_SECTOR.
 * Returns true if successful, false on failure.
 * Fails if NAME is invalid (i.e. too long) or a disk or memory
 * error occurs. */
/* dir에 dir_entry 추가하는 함수 
   dir는 inode를 가지고 있음. 이 inode는 다시 어느 sector 가리킴 
   dir_entry는 파일 하나를 가리킴. sector에는 파일의 inode가 있는 sector */
bool
dir_add (struct dir *dir, const char *name, disk_sector_t inode_sector) {
	struct dir_entry e;
	off_t ofs;
	bool success = false;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Check NAME for validity. 이름 유효성 검사 */ 
	if (*name == '\0' || strlen (name) > NAME_MAX)
		return false;

	/* Check that NAME is not in use. 해당 이름 가진 dir_entry가 dir안에 있는지 확인 */
	if (lookup (dir, name, NULL, NULL))
		goto done;

	// 해당 이름 가진 dir_entry가 dir안에 없다면 진행
	/* Set OFS to offset of free slot.
	 * If there are no free slots, then it will be set to the
	 * current end-of-file.

	 * inode_read_at() will only return a short read at end of file.
	 * Otherwise, we'd need to verify that we didn't get a short
	 * read due to something intermittent such as low memory. */
	/* for문으로  dir에서 비어있는 dir_entry를 하나 가져와서
	   in_use를 true로 하고, name을 새겨놓는다. 
	   작성한 entry 원래 자리(disk상의)에 복사함 */
	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (!e.in_use)
			break;

	/* Write slot. */
	e.in_use = true;
	strlcpy (e.name, name, sizeof e.name);
	e.inode_sector = inode_sector;
	success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
	return success;
}

/* Removes any entry for NAME in DIR.
 * Returns true if successful, false on failure,
 * which occurs only if there is no file with the given NAME. */
/* dir에서 name 가진 file 지움 */ 
bool
dir_remove (struct dir *dir, const char *name) {
	struct dir_entry e;
	struct inode *inode = NULL;
	bool success = false;
	off_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Find directory entry. dir에 name가진 entry 있는지 봄 */
	if (!lookup (dir, name, &e, &ofs))
		goto done;

	/* Open inode. 있다면 inode 열고 entry 지움 */
	inode = inode_open (e.inode_sector);
	if (inode == NULL)
		goto done;

	/* Erase directory entry. */
	// 지우는 과정 : in_use를 false로 바꾸고, 원래대로 돌려놓음. 이게 왜 원래대로 돌려놓는 과정이지?
	e.in_use = false;
	if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
		goto done;

	/* Remove inode. inode 삭제 */
	inode_remove (inode);
	success = true;

done:
	inode_close (inode);
	return success;
}

/* Reads the next directory entry in DIR and stores the name in
 * NAME.  Returns true if successful, false if the directory
 * contains no more entries. */
/* DIR의 다음 dir_entry를 읽고 이름을 NAME에 저장합니다.
성공하면 true를 반환하고, 디렉터리에 더 이상 항목이 없으면 false를 반환 */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1]) {
	struct dir_entry e;

	while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
		dir->pos += sizeof e;
		if (e.in_use) {
			strlcpy (name, e.name, NAME_MAX + 1);
			return true;
		}
	}
	return false;
}
