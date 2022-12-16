#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/console.h"
#include "lib/string.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "threads/vaddr.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
struct page * check_address(void *addr);

void halt (void);
void exit (int status);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);

int open (const char *file); // 파일을 열때
int filesize (int fd); // 파일의 크기를 알려준다.
int read (int fd, void *buffer, unsigned size); // 열린 파일의 데이터를 읽음
int write (int fd, const void *buffer, unsigned size); // 열린 파일의 데이터를 기록
void seek (int fd, unsigned position); // 열린파일의 위치(offset)를 이동
unsigned tell (int fd); // 열린 파일의 위치(offset)을 알려줌
void close (int fd); // 열린 파일을 닫음

int fork (const char *thread_name, struct intr_frame *f);
int exec (const char *cmd_line);
int wait (int pid);

void *mmap(void *addr, size_t length, int writable, int fd, off_t offset);
void munmap(void *addr);

void check_valid_buffer(void* buffer, unsigned size, void* rsp, bool to_write);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

	void syscall_init(void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init (&filesys_lock);
	}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
// TODO: Your implementation goes here.

	thread_current()->rsp = f->rsp;
	
	int syscall_number = f->R.rax;
	switch (syscall_number){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_EXEC:
			if(exec(f->R.rdi) == -1) {
				exit(-1);
			}
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE: // return 값이 있는 함수들은 레지스터의 rax에서 확인
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 1);
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 0);
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;	
		case SYS_MMAP:
			f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
			break;
		case SYS_MUNMAP:
			munmap(f->R.rdi);
			break;
		default:
			exit(-1);
			break;
	}

// 시스템 콜의 함수의 리턴 값은 인터럽트 프레임의 eax에 저장
	// thread_exit ();
}

struct page *
check_address(void *addr) {
	/* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 */
	/* 잘못된 접근일 경우 프로세스 종료 */
	if((!is_user_vaddr(addr)) || (addr == NULL)){
		exit(-1);
	}
	return spt_find_page(&thread_current()->spt, addr);
}

void check_valid_buffer(void* buffer, unsigned size, void* rsp, bool to_write){
	// to_write 변수는 buffer에 내용을 쓸 수 있는지 없는지 검사하는 변수
	/* 인자로 받은 buffer부터 buffer + size까지의 크기가 한 페이지의 크기를 넘을 수도 있음 */
	if (buffer <= USER_STACK && buffer >= rsp)
		return;

	uintptr_t start_page = pg_round_down(buffer);
	uintptr_t end_page = pg_round_down(buffer + size -1);

	/* buffer 부터 buffer + size까지의 주소에 포함되는 vm_entry들에 대해 적용 */
	for (; start_page <= end_page; start_page += PGSIZE){
		/* check_address를 이용해서 주소의 유저영역 여부를 검사함과 동시에 vm_entry 구조체를 얻음 */
		struct page *p = check_address(start_page);
		if(p == NULL)
			exit(-1);

		/* writable 멤버가 true인지 검사 */
		if (p->writable == false && to_write == true)
			exit(-1);
	}

}

void
halt (void) {
	power_off();
}

void
exit (int status) {
	struct thread *cur_thread = thread_current();
	cur_thread->exit_status = status;
	printf("%s: exit(%d)\n", cur_thread->name, status);
	thread_exit();
}

bool 
create (const char *file, unsigned initial_size) {

	check_address(file);
	// lock_acquire(&filesys_lock);
	bool result = filesys_create(file, initial_size); // directory:filesys / filesys.c
	// lock_release(&filesys_lock);
	return result;
}

bool
remove (const char *file) {
	check_address(file);
	return filesys_remove(file); // directory:filesys / filesys.c
}
// Parent~child struct 구현 

int open (const char *file){
	check_address(file); // 파일 유효 주소 확인
	if(file == NULL){
		exit(-1);
	}
	lock_acquire(&filesys_lock);
	struct file *open_file = filesys_open(file); // 파일 오픈 및 파일 명 지정
	lock_release(&filesys_lock);
	if (open_file == NULL){ // 오픈 파일 명 값 확인
		return -1;
	}	
	int open_file_fd = process_add_file(open_file); // 오픈 파일 파일 디스크립터 테이블에 추가
	if (open_file_fd == -1){			//실패시
		file_close(open_file);	 // 파일 닫기
	} 
	
	return open_file_fd;	 // 성공시 fd값 리턴
	// 파일을 열 때 사용하는 시스템 콜
	// 성공 시 fd를 생성하고 반환, 실패 시 -1 반환
 	// File : 파일의 이름 및 경로 정보
};

int filesize(int fd){
	if(fd < 0 || fd >= FDCOUNT_LIMIT){
		return -1;
	}
	struct file *cur_file = process_get_file(fd); // 해당 파일 을 가져온다.
	if (cur_file == NULL){ // 파일 유효 확인
		return -1;
	}
	return file_length(cur_file);
	// return fl; //struct file -> struct inode -> struct inode_disk data -> off_t length에 정보가 담겨있다.
}

int read (int fd, void *buffer, unsigned size){

	check_address(buffer); // 버퍼 유효주소 확인
	struct file *get_file = process_get_file(fd); // 파일 가져오기
	// struct file *get_file = file_reopen(process_get_file(fd));
	int key_length = 0;

	if (get_file == NULL){
		return -1;
	}
	
	if (fd == 0){	 // STDIN 이면
		char key;
		while (key_length < size){
			key = input_getc(); // key 반환 (문자 하나)
			*(char*)buffer = key; // 버퍼에 넣어주기 (버퍼=주소 ->버퍼=문자형변환)
			if (key == '\0') {
				break;
			}
			*buffer++;
			key_length++;
		}
	}
	else if (fd == 1){ // STDOUT 이면 
		return -1; // 오류 리턴
	}
	else { 	 // 이외이면
		lock_acquire(&filesys_lock); // 읽는동안 락 
		key_length = file_read(get_file, buffer, size); // return bytes_read; //가져온 파일에서 읽고 버퍼에 넣어준다.
		lock_release(&filesys_lock); // 락 해제	
	}
	return key_length;
}

int write (int fd, const void *buffer, unsigned size){

	check_address(buffer); // 버퍼 유효주소 확인
	struct file *get_file = process_get_file(fd); // 파일 가져오기

	int key_length;
	if (get_file == NULL){
		return -1;
	}

	else if (fd == 0){
		return -1;
	}
	
	else if (fd == 1){	 
		putbuf(buffer, size);
		return size;
	}
	
	else { 	 // 이외이면
		lock_acquire(&filesys_lock); // 읽는동안 락 
		key_length = file_write(get_file, buffer, size); // return bytes_read; //가져온 파일에서 읽고 버퍼에 넣어준다.
		lock_release(&filesys_lock); // 락 해제	
	}
	return key_length;

};

void seek (int fd, unsigned position){
	if (fd < 2){
		return;
	} 
	struct file *get_file = process_get_file(fd); // 파일 가져오기
	if (get_file == NULL){
		return;
	}
	file_seek(get_file, position);
};

unsigned tell (int fd){
	if (fd < 2){
		return;
	} 
	struct file *get_file = process_get_file(fd); // 파일 가져오기
	if (get_file == NULL){
		return;
	}
	return file_tell(get_file);
};

void close (int fd){
	if (fd < 2){
		return;
	}
	struct thread *cur_thread = thread_current();
	struct file *get_file = process_get_file(fd); // 파일 가져오기
	if (get_file == NULL){
		return;
	}
	file_close(get_file);
	cur_thread->fd_table[fd] = NULL; // fd 초기화
};


int fork (const char *thread_name, struct intr_frame *f){
	return process_fork(thread_name, f);
};

int exec (const char *cmd_line){
	check_address(cmd_line);
	char* fn_copy;
	int size = strlen(cmd_line) + 1;
	fn_copy = palloc_get_page(PAL_ZERO);
    if (fn_copy == NULL)
        exit(-1);
    strlcpy (fn_copy, cmd_line, size);
	if (process_exec(fn_copy) == -1) {
		return -1;
	}
	NOT_REACHED();
	return 0;
}

int wait (int pid){
	return process_wait(pid);
}

void *mmap(void *addr, size_t length, int writable, int fd, off_t offset)
{
	/*
	1) fd로 열린 파일의 길이가 0인 경우
	2) addr이 0인 경우
	3) length가 0인 경우
	4) fd=0 or fd=1 (stdin, stdout)
	5) addr이 page-aligned 하지 않은 경우
	6) 매핑된 페이지 영역이 기존의 매핑된 페이지 집합과 겹치는 경우
	*/

	if (offset % PGSIZE != 0){
		return NULL;
	}

	if(is_kernel_vaddr((uint64_t)addr))
	{
		return NULL;
	}

	size_t file_size = filesize(fd) < length ? filesize(fd) : length;


	if ((fd != 0) && (fd != 1) && (file_size > 0) && (addr != 0) && ( (long long) length > 0) && (addr == pg_round_down(addr)) && (spt_find_page(&thread_current()->spt, addr) == NULL))
	{
		lock_acquire(&filesys_lock);
		struct file *map_file = file_reopen(process_get_file(fd));
		lock_release(&filesys_lock);
		void *mmap_addr = do_mmap(addr, file_size, writable, map_file, offset); // file size 수정
		return mmap_addr;
	}
	return NULL;
}

void munmap(void *addr)
{
	do_munmap(addr);
}
