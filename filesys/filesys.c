#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/fat.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format(void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void filesys_init(bool format)
{
	filesys_disk = disk_get(0, 1);
	if (filesys_disk == NULL)
		PANIC("hd0:1 (hdb) not present, file system initialization failed");

	inode_init();

#ifdef EFILESYS
	fat_init();

	if (format)
		do_format();

	fat_open();
	thread_current()->cur_dir = dir_open_root();
#else
	/* Original FS */
	free_map_init();

	if (format)
		do_format();

	free_map_open();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void filesys_done(void)
{
	/* Original FS */
#ifdef EFILESYS
	fat_close();
#else
	free_map_close();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
/* 지정된 INITIAL_SIZE를 사용하여 NAME이라는 이름의 파일을 만듭니다.
* 성공하면 true를 반환하고, 그렇지 않으면 false를 반환합니다.
* 이름이 NAME인 파일이 이미 있거나 내부 메모리 할당에 실패한 경우 실패 */
bool
filesys_create (const char *name, off_t initial_size) {
	disk_sector_t inode_sector = 0;
	char *cp_name;
	char *file_name;

	/*[DR] name의 파일경로를 cp_name에 복사, cp_name의 경로를 분석하여 파일명을 file_name에 저장 */
	strlcpy(cp_name, name, sizeof name); 
	struct dir *dir = parse_path(cp_name, file_name);

	cluster_t new_clst = fat_create_chain(0);
	inode_sector = cluster_to_sector(new_clst);
	bool inode_create_rst = inode_create(inode_sector, initial_size, 0);

	/* 추가되는 디렉터리 엔트리의 이름을 file_name으로 수정 */
	bool dir_add_rst = dir_add(dir, file_name, inode_sector);

	bool success = (dir != NULL && new_clst && inode_create_rst && dir_add_rst);

	if (!success && inode_sector != 0){
		if (new_clst != 0)
			fat_remove_chain(new_clst, 0);
	}
	dir_close(dir);

	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open(const char *name)
{
	char *cp_name;
	char *file_name;
	struct inode *inode = NULL;

	/*[DR] name의 파일경로를 cp_name에 복사, cp_name의 경로를 분석하여 파일명을 file_name에 저장 */
	strlcpy(cp_name, name, sizeof name);
	struct dir *dir = parse_path(cp_name, file_name);

	/*[DR] 디렉토리 엔트리에서 file_name을 검색하도록 수정 */
	if (dir != NULL)
		dir_lookup(dir, file_name, &inode); 

	dir_close(dir);
	// 루트 디렉토리를 닫는다

	// 받은 루트 디렉토리의 아이노드를 이용해서 파일 name을 연다
	return file_open(inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool filesys_remove(const char *name)
{
	/* 한토스 565p
	1. root 디렉터리에 파일 생성을 name 경로에 파일 생성하도록 변경
		- 생성하고자 하는 파일경로인 name을 cp_name에 복사
		- 파일 생성시 절대, 상대경로를 분석하여 디렉토리에 파일을 생성하도록 수정 
			- parse_path()를 추가하여 cp_name의 경로 분석
				- return : 파일을 생성하고자 하는 디렉터리의 위치
				- path_name : 생성하고자 하는 파일의 경로
				- file_name : 생성하고자 하는 파일의 이름 저장
	2. 디렉터리 엔트리에서 file_name의 in-memory inode가 파일/디렉터리인지 판단
		- inode가 디렉터리일 경우 디렉터리내 파일 존재 여부 검사
			: 디렉터리내 파일이 존재하지 않을 경우, 디렉터리에서 file_name의 엔트리 삭제
		- inode가 파일일 경우 디렉터리 엔트리에서 file_name 엔트리 삭제
	*/

	struct dir *dir = dir_open_root();
	bool success = dir != NULL && dir_remove(dir, name);
	dir_close(dir);

	return success;
}

/* Formats the file system. */
	static void
	do_format(void)
	{
		printf("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create();

	/* Root Directory 생성 */
	disk_sector_t root = cluster_to_sector(ROOT_DIR_CLUSTER);

	if (!dir_create(root, 16))
		PANIC("root directory creation failed");

	fat_close();
#else
	free_map_create();
	if (!dir_create(ROOT_DIR_SECTOR, 16))
		PANIC("root directory creation failed");
	free_map_close();
#endif

	printf("done.\n");
}

struct dir *parse_path(char *path_name, char *file_name)
{
	struct dir *dir;
	if (path_name == NULL || file_name == NULL)
		goto fail;
	if (strlen(path_name) == 0)
		return NULL;
	/* PATH_NAME의 절대/상대경로에 따른 디렉터리 정보 저장 (구현)*/ char *token, *nextToken, *savePtr;
	token = strtok_r(path_name, "/", &savePtr);
	nextToken = strtok_r(NULL, "/", &savePtr);

	while (token != NULL && nextToken != NULL)
	{
		/* dir에서 token이름의 파일을 검색하여 inode의 정보를 저장*/ /* inode가 파일일 경우 NULL 반환 */
		/* dir의 디렉터리 정보를 메모리에서 해지 */
		/* inode의 디렉터리 정보를 dir에 저장 */
		/* token에 검색할 경로 이름 저장 */
	}
	/* token의 파일 이름을 file_name에 저장
	/* dir 정보 반환 */

	fail:
}