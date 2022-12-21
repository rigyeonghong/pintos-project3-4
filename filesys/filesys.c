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
#include "threads/thread.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format(void);

void dir_read(struct dir *dir)
{
	struct dir_entry e;
	off_t save = dir->pos;
	dir->pos = 0;
	printf("====================\n");
	while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e)
	{
		dir->pos += sizeof e;
		if (e.in_use)
		{
			printf("%s\n", e.name);
		}
	}
	printf("====================\n");
	dir->pos = save;
}

int dir_read_count(struct dir *dir)
{
	struct dir_entry e;
	off_t save = dir->pos;
	dir->pos = 0;
	int cnt = 0;
	while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e)
	{
		dir->pos += sizeof e;
		if (e.in_use)
		{
			cnt++;
		}
	}
	dir->pos = save;

	return cnt;
}

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
	// thread_current()->cur_dir = dir_open_root();
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
bool filesys_create(const char *name, off_t initial_size)
{
	
	disk_sector_t inode_sector = 0;
	char *cp_name = malloc(strlen(name) + 1);

	char *file_name = malloc(strlen(name) + 1);

	/*name의 파일경로를 cp_name에 복사, cp_name의 경로를 분석하여 파일명을 file_name에 저장 */
	strlcpy(cp_name, name, strlen(name)+1);
	struct dir *dir = parse_path(cp_name, file_name);

	if (dir->inode->removed == true)
	{
		return false;
	}

	cluster_t new_clst;

	// /* 추가되는 디렉터리 엔트리의 이름을 file_name으로 수정 */
	new_clst = fat_create_chain(0);

	bool success =
			(dir != NULL && new_clst && inode_create(inode_sector = cluster_to_sector(new_clst), initial_size, 0) && dir_add(dir, file_name, inode_sector));

	if (!success && inode_sector != 0)
	{
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
	char *cp_name = (char *)malloc(strlen(name) + 1);
	char *file_name = (char *)malloc(strlen(name) + 1);
	struct inode *inode = NULL;
	struct dir *dir = NULL;
	char *link_path;

	/* name의 파일경로를 cp_name에 복사, cp_name의 경로를 분석하여 파일명을 file_name에 저장 */
	strlcpy(cp_name, name, strlen(name) + 1);
	dir = parse_path(cp_name, file_name);

	if (dir==NULL){
		return NULL;
	}

	if (dir->inode->removed == true){
		return NULL;
	}

	/* 디렉토리 엔트리에서 file_name을 검색하도록 수정 */
	if (dir != NULL)
		dir_lookup(dir, file_name, &inode);

	while (inode != NULL && inode_is_link(inode))
	{
		link_path = inode_get_link_name(inode);
		strlcpy(cp_name, link_path, strlen(link_path) + 1);

		dir_close(dir);
		dir = parse_path(cp_name, file_name);

		if (dir != NULL)
			dir_lookup(dir, file_name, &inode);
	}

	dir_close(dir); // 디렉토리를 닫는다
	free(cp_name);
	free(file_name);

	return file_open(inode); // 받은 디렉토리의 아이노드를 이용해서 파일을 연다
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool filesys_remove(const char *name)
{
	/* [DR] 한토스 565p
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
	char *cp_name = (char *)malloc(strlen(name) + 1);
	char *file_name = (char *)malloc(strlen(name) + 1);
	bool success;

	strlcpy(cp_name, name, strlen(name) + 1);

	struct dir * dir = parse_path(cp_name, file_name);
	struct inode *file_inode;

	dir_lookup(dir, file_name, &file_inode);

	if (inode_is_dir(file_inode))
	{
		struct dir *target_dir = dir_open(file_inode);

		if (dir_read_count(target_dir)<=2)
		{
			success = dir_remove(dir, file_name);
		}

		dir_close(target_dir);
		goto done;
	}
	else // 지우려고 하는 파일이 디렉토리가 아닌 '파일'인 경우
	{
		inode_close(file_inode);
		success = dir_remove(dir, file_name);
		goto done;
	}

done:

	dir_close(dir);

	free(cp_name);
	free(file_name);

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

	struct dir *root_dir = dir_open_root();
	dir_add(root_dir, ".", root);
	dir_add(root_dir, "..", root);
	dir_close(root_dir);

	fat_close();
#else
	free_map_create();
	if (!dir_create(ROOT_DIR_SECTOR, 16))
		PANIC("root directory creation failed");
	free_map_close();
#endif

	printf("done.\n");
}

/* parse_path : *path_name을 분석하여 작업하는 디렉터리의 포인터를 반환, 파일 또는 디렉터리의 이름을 *file_name에 저장
- path_name: ‘/’로의 시작의 여부에 따라 절대, 상대경로 구분
- strtok_r() 함수를 이용하여 path_name의 디렉터리 정보와 파일 이름 저장
- file_name에 파일 이름 저장
- dir로 오픈된 디렉터리를 포인팅
*/
struct dir *parse_path(char *path_name, char *file_name)
{
	struct dir *dir;
	struct inode *inode = NULL;

	if (path_name == NULL || file_name == NULL)
		goto fail;
	if (strlen(path_name) == 0)
		goto fail;


	/* path_name의 절대/상대경로에 따른 디렉터리 정보 저장*/
	if (path_name[0] == '/')
	{
		dir = dir_open_root();
	}
	else
	{
		dir = dir_reopen(thread_current()->cur_dir);
	}


	char *token, *nextToken, *savePtr;
	token = strtok_r(path_name, "/", &savePtr);
	nextToken = strtok_r(NULL, "/", &savePtr);

	/* "/"를 오픈하는 경우 */
	if (token == NULL)
	{
		token = (char *)malloc(2);
		strlcpy(token, ".", 2);
	}

	while (token != NULL && nextToken != NULL)
	{
		/* dir에서 token이름의 파일을 검색하여 inode의 정보를 저장*/
		if (!dir_lookup(dir, token, &inode))
		{
			dir_close(dir);
			goto fail;
		}

		if (inode_is_link(inode))
		{
			char *link_name = inode_get_link_name(inode);
			strlcpy(path_name, link_name, strlen(link_name) + 1);
			strlcat(path_name, "/", strlen(path_name) + 2);
			strlcat(path_name, nextToken, strlen(path_name) + strlen(nextToken) + 1);
			strlcat(path_name, savePtr, strlen(path_name) + strlen(savePtr) + 1);

			dir_close(dir);

			if (path_name[0] == '/')
				dir = dir_open_root();
			else
				dir = dir_reopen(thread_current()->cur_dir);

			token = strtok_r(path_name, "/", &savePtr);
			nextToken = strtok_r(NULL, "/", &savePtr);

			continue;
		}

		/* inode가 파일일 경우 NULL 반환 */
		if (!inode_is_dir(inode))
		{
			dir_close(dir);
			inode_close(inode);
			goto fail;
		}

		dir_close(dir);		   // dir의 디렉터리 정보를 메모리에서 해지
		dir = dir_open(inode); // inode에 해당하는 디렉터리 정보를 dir에 저장

		token = nextToken; // token에 검색할 다음 경로이름 저장
		nextToken = strtok_r(NULL, "/", &savePtr);
	}
	strlcpy(file_name, token, strlen(token) + 1); // token의 파일 이름을 file_name에 저장 */

	return dir; // dir 정보 반환

fail:

	return NULL;

}

// file 위치에 해당하는 dir 생성
bool filesys_create_dir(const char *name)
{
	if (!strcmp(name, ""))
		return false;

	bool success = false;
	/* name 경로 분석 */
	char *cp_name = (char *)malloc(strlen(name) + 1);
	strlcpy(cp_name, name, strlen(name) + 1);

	char *file_name = (char *)malloc(strlen(name) + 1);
	struct dir *dir = parse_path(cp_name, file_name);

	// 새로운 디렉토리의 inode sector 할당
	cluster_t new_cluster = fat_create_chain(0);
	disk_sector_t new_sector = cluster_to_sector(new_cluster);

	struct inode *sub_inode;
	struct dir *sub_dir = NULL;

	success = (dir != NULL && dir_create(new_sector, 16)															// new_sector에 해당하는 디렉토리 생성
			   && dir_add(dir, file_name, new_sector)																// 할당받은 sector에 file_name의 디렉터리 생성
			   && dir_lookup(dir, file_name, &sub_inode) 
			   && dir_add(sub_dir = dir_open(sub_inode), ".", new_sector) // '.' 디렉토리를 현재 디렉토리의 아이노드 섹터와 연결
			   && dir_add(sub_dir, "..", inode_get_inumber(dir_get_inode(dir)))										// '..' 디렉토리를 상위 디렉토리의 아이노드 섹터와 연결
	);

	if (!success && new_cluster != 0)
	{
		fat_remove_chain(new_cluster, 0);
	}

	// in-memory에 있는 dir, sub_dir 청소 (리소스 확보)
	if (sub_dir)
		dir_close(sub_dir);
	dir_close(dir);

	free(cp_name);
	free(file_name);


	return success;
}


int filesys_create_link(const char *target, const char *linkpath)
{
	struct thread *curr = thread_current();

	/* Root Directory open */
	char file_name[NAME_MAX + 1];
	struct dir *dir = parse_path(linkpath, file_name);
	if (dir == NULL)
		return -1;

	/* struct disk_inode를 저장할 새로운 cluster 할당 */
	cluster_t inode_cluster = fat_create_chain(0);
	disk_sector_t inode_sector = cluster_to_sector(inode_cluster);

	bool succ_create = inode_create_link(inode_sector, target);
	bool succ_dir_add = dir_add(dir, file_name, inode_sector);

	/* 할당 받은 cluster에 inode를 만들고 directory에 file 추가 */
	bool success = (succ_create && succ_dir_add);
	if (!success && inode_cluster != 0)
		fat_remove_chain(inode_cluster, 0);

	dir_close(dir);

	return success - 1;
}