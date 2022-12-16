#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/synch.h"
#include "userprog/syscall.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

// void argument_stack(char **token, int count, struct intr_frame *if_);

/* General process initializer for initd and other process. */
static void
process_init(void)
{
	struct thread *current = thread_current ();
}

/* FILE_NAME으로부터 load된 "initd"라는 첫번째 userland program을 시작함
   thread_creat()해서 thread생성 후 tid 반환 */
/* 프로세스(쓰레드)를 생성하는 함수를 호출하고 tid를 반환한다 */
/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;
	/* file_name 문자열을 파싱(첫번째 토큰) */
	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;

	/* 커맨드라인에서 프로세스이름 확인 */ 
	strlcpy (fn_copy, file_name, PGSIZE);
	
	char *token, *save_ptr;
	strtok_r (file_name, " ", &save_ptr);

	/* Project 2 - user program : 스레드 이름 파싱 */
	char *save_ptr, *token;
	token = strtok_r(file_name, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	// file_name: 스레드이름(문자열), PRI_DEFAULT: 스레드우선순위(31)
	// initd: 생성된 스레드가 실행할 함수를 가리키는 포인터, fn_copy: start_process 함수를 수행할 때 사용하는 인자값
	// initd : 1st argument(rdi) , fn_copy : 2nd argument(rsi)
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);

	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif
	process_init ();
	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
/* 인터럽트 프레임 : 인터럽트가 호출됐을 때 이전에 레지스터에 작업하던 context 정보를 스택에 담는 구조체 (Woony)*/
/* 즉, 유저 프로그램 실행 정보는 syscall_handler로 전달되는 intr_frame에 저장된다. 이를 __do_fork에 넘겨주는 방식. 
 * 따라서 우리가 구현해야 하는 시스템 콜 핸들러의 fork 함수에는 thread_name과 tf를 인자로 받아야 하며, 
 * 이때 전달되는 tf는 시스템 콜 핸들러로 넘어온 f에 정보가 들어있다. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	struct thread *parent_thread = thread_current();
	memcpy(&parent_thread->parent_if, if_, sizeof(struct intr_frame)); // kernel stack에 있는 intr_frame을 부모 스레드의 intr_frame에 복사

	tid_t new_tid = thread_create (name, PRI_DEFAULT, __do_fork, parent_thread); // 새로운 스레드 생성

	if (new_tid == TID_ERROR) {
		return TID_ERROR;
	}

	struct thread *child_thread = get_child_process(new_tid);
	sema_down(&child_thread->fork_sema);
	if (child_thread->exit_status == -1) {
		return TID_ERROR;
	}
	return new_tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();     
	struct thread *parent = (struct thread *) aux;  
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr(va)) {
		return true;
	}

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);
	if(parent_page == NULL) {
		return false;
	}

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if(newpage == NULL) {
		return false;
	}

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* pml4_set_page로 가상메모리와 물리메모리를 맵핑함 (writable에 대한 정보를 가지고서) */
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	return true;
}
#endif

/* 부모 프로세스의 실행 context를 자식 프로세스로 복사하는 함수(by Woony) */
/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
/* 인터럽트 프레임 : 인터럽트가 호출됐을 때 이전에 레지스터에 작업하던 context 정보를 스택에 담는 구조체(Woony)*/
static void
__do_fork (void *aux) {	//process_fork함수에서 thread_create()을 호출하면서 aux는 thread_current()를 들고옴
	struct intr_frame if_; 
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current (); 

	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = &parent->parent_if;
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);

#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt)){
		goto error;
	}

#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent)){
		goto error;
	}
#endif
	// multi -oom
	if(parent->fd == FDCOUNT_LIMIT)
		goto error;
	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	for (int i = 2; i < FDCOUNT_LIMIT; i++)
	{
		struct file *fd = parent->fd_table[i];
		if (fd == NULL) {
			continue;
		}
		current->fd_table[i] = file_duplicate(fd);
	}
	current->fd = parent->fd;
	sema_up(&current->fork_sema);
	if_.R.rax = 0;
	process_init ();

	/* Finally, switch to the newly created process. */
	if (succ) {
		// thread_current()->rsp = if_.rsp; // [3-3]
		do_iret(&if_);
	}
error:
	current->exit_status = TID_ERROR;
	sema_up(&current->fork_sema);
	exit(TID_ERROR);
}

/* (한양대 : start_process, CSAPP p.721) 프로그램을 메모리에 적재(load) 후 프로그램 시작*/
/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name; // void*로 넘겨받은 f_name을 문자열로 형 변환 
	bool success;
	int count = 0;


	/* 인자들을 띄어쓰기 기준으로 토큰화 및 토큰의 개수계산 (strtok_r() 함수이용) */
	// strtok_r() 함수를 이용해 인자들을 토큰화하여 토큰의 개수를 계산한다.

	// Setup virtual address of the program: code, data, stack (user stack) (추측)
	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */

	/* Context change가 일어날 때 thread_launch()와 do_iret() 함수에서 아래와 같은 과정이 이루어지며, 이 과정에서 interrupt frame이 활용됩니다.
	 * (1) 현재 cpu의 register 값들을 current thread(T1)의 intr_frame (tf)로 옮긴다.
	 * (2) 새롭게 실행할 thread(T2)의 intr_frame에 있는 값을 cpu register로 옮긴다.
	 * (3) iretq instruction을 활용해 T2에서 실행하던 코드를 마저 실행한다.
	 * 정리하자면, intr_frame에 들어가야 할 내용은 cpu register에 있는 값입니다. 따라서 kernel memory에 별도로 저장되어 있는 값이 아닙니다. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;
	/* We first kill the current context */
	process_cleanup ();
	supplemental_page_table_init(&thread_current()->spt);
	/* And then load the binary */

	success = load (file_name, &_if);

	/* If load failed, quit. */
	palloc_free_page (file_name);

	if (!success)
		return -1; 

	// hex_dump(_if.rsp,_if.rsp,USER_STACK-_if.rsp,true);
	
	/* Start switched process. */
	do_iret(&_if);

	NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 * 
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	struct thread *parent_thread = thread_current();
	struct thread* child_thread = get_child_process(child_tid);
	if (child_thread == NULL) {
		return -1;
	}
	sema_down(&child_thread->wait_sema); // 여기서는 parent가 잠드는 거고
	int exit_status = child_thread->exit_status;// 여기서부터는 깨어났다.
    // 깨어나면 child의 exit_status를 얻는다.
	list_remove(&child_thread->child_elem); // child를 부모 list에서 지운다.
	sema_up(&child_thread->free_sema);// 내가 받았음을 전달하는 sema
	return exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current();

	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	// list_entry(cur.)
	palloc_free_multiple(cur->fdt, FDT_PAGES);
	file_close (cur->running_file);
	sema_up(&cur->sema_wait); //fault!!

	// Postpone child termination until parents receives its exit status with 'wait'
	sema_down(&cur->sema_free);

	palloc_free_multiple(curr->fd_table, FDT_PAGES);
	
	file_close(curr->running); // load에서 file close -> process_exit할때 close file_deny_write

	sema_up(&curr->wait_sema); // 종료되었다고 기다리고 있는 부모 thread에게 signal 보냄-> sema_up에서 val을 올려줌
	process_cleanup(); // pml4를 날림(이 함수를 call 한 thread의 pml4)
	sema_down(&curr->free_sema); // 부모에게 exit_Status가 정확히 전달되었는지 확인(wait)
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* 메모리를 할당받고 사용자 프로그램을 메모리에 적재*/
/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP(프로그램 카운터:실행할 다음 인스트럭션의 메모리 주소를 가리키는 포인터)
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */

/* 리경's load */
static bool
load(const char *file_name, struct intr_frame *if_)
{
	struct thread *t = thread_current();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	char *argv[128]; // 커맨드 라인 길이 제한 128
	char *token, *save_ptr;
	int argc = 0;
	// lock_init(&file_lock);

	token = strtok_r(file_name, " ", &save_ptr);
	argv[argc] = token;

	while (token != NULL)
	{
		token = strtok_r(NULL, " ", &save_ptr);
		argc++;
		argv[argc] = token;
	}

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create();
	if (t->pml4 == NULL)
		goto done;

	process_activate(t);

	/* 락 획득 */
	lock_acquire(&filesys_lock);
	/* Open executable file. */
	file = filesys_open(file_name);
	lock_release(&filesys_lock);
	if (file == NULL)
	{
		/* 락 해제 */
		printf("load: %s: open failed\n", file_name);
		goto done;
		// exit(-1);
	}
	

	/* thread 구조체의 run_file을 현재 실행할 파일로 초기화 */
	t->running = file;
	/* file_deny_write()를 이용하여 파일에 대한 write를 거부 */
	file_deny_write(file);
	
	/* 락 해제 */
	// lock_release(&file_lock);

	/* Read and verify executable header. */
	lock_acquire(&filesys_lock);
	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 0x3E // amd64
		|| ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024)
	{
		lock_release(&filesys_lock);
		printf("load: %s: error loading executable\n", file_name);
		goto done;
	}

	lock_release(&filesys_lock);

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++)
	{
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length(file))
			goto done;
		file_seek(file, file_ofs);

		lock_acquire(&filesys_lock);
		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr){
			lock_release(&filesys_lock);
			goto done;
		}
		lock_release(&filesys_lock);
		file_ofs += sizeof phdr;
		switch (phdr.p_type)
		{
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
			/* Ignore this segment. */
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment(&phdr, file))
			{
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint64_t file_page = phdr.p_offset & ~PGMASK;
				uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint64_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0)
				{
					/* Normal segment.
					 * Read initial part from disk and zero the rest. */
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
				}
				else
				{
					/* Entirely zero.
					 * Don't read anything from disk. */
					read_bytes = 0;
					zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
				}
				if (!load_segment(file, file_page, (void *)mem_page,
								  read_bytes, zero_bytes, writable))
					goto done;
			}
			else
				goto done;
			break;
		}
	}

	/* Set up stack. */
	if (!setup_stack(if_))
		goto done;

	/* Start address. */
	// text세그먼트 시작 주소
	if_->rip = ehdr.e_entry;

	// 인자들을 스택에 삽입(인자 전달)
	/* 유저스택에 프로그램이름과 인자들을 저장하는 함수 */
	/* parse: 프로그램이름과 인자가 저장되어있는 메모리공간, count: 인자의개수, rsp: 스택포인터를가리키는주소 */
	/* argument_stack() 함수를 호출할 시 인자 값을 스택에 오른쪽에서 왼쪽 순으로 저장한다. */
	/* Return Address는 Caller(함수를 호출하는 부분)의 다음 수행 명령어 주소를 의미한다. */
	/* Callee(호출 받은 함수)의 리턴 값은 rax 레지스터에 저장된다. */

	argument_stack(arg_list,idx,if_);

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
	argument_stack(argv, argc, if_);

	success = true;
	
done:
	/* We arrive here whether the load is successful or not. */
	// file_close(file); // file 닫히면서 lock이 풀림
	
				
	return success;
}

void argument_stack(char **arg_list,int idx,struct intr_frame *if_){

	int i,j;
	int cnt=0;
	int start_addr=if_->rsp;

	for (int i=idx-1; i>-1; i--)
	{
		cnt+=strlen(arg_list[i])+1;
		for (j=strlen(arg_list[i]); j>-1 ; j--)
		{
			if_->rsp=if_->rsp-1;
			memset(if_->rsp, arg_list[i][j], sizeof(char));
		
		}
	
		if (i==0){
	
		/* word-align*/
		int align = 8 - (cnt % 8);
		for (int k=0; k < align ; k++)
		{
			if_->rsp=if_->rsp-1;
			memset(if_->rsp, 0, sizeof(char));
		}

		for (i=idx; i>-1; i--)
		{
			if_->rsp = if_->rsp-8;

			if (i==idx)
				memset(if_->rsp, 0, sizeof(char *));
			else {
				start_addr=start_addr-strlen(arg_list[i])-1;
				memcpy(if_->rsp, &start_addr, sizeof(start_addr));
			}
		}
		if_->rsp = if_->rsp-8;
		memset(if_->rsp, 0, sizeof(void *));
		if_->R.rdi=idx;
		if_->R.rsi=if_->rsp + 8; 
		}
	}
}

/* 리경's argstack */
void argument_stack(char **argv, int argc, struct intr_frame *if_)
{
	char *arg_address[128];

	/* 맨 끝 NULL 값(arg[4]) 제외하고 스택에 저장(arg[3]~arg[0]) */
	for (int i = argc - 1; i >= 0; i--)
	{
		int argv_len = strlen(argv[i]); // foo 면 3
		/* if_->rsp: 현재 user stack에서 현재 위치를 가리키는 스택 포인터.
		각 인자에서 인자 크기(argv_len)를 읽고 (이때 각 인자에 sentinel이 포함되어 있으니 +1 - strlen에서는 sentinel 빼고 읽음)
		그 크기만큼 rsp를 내려준다. 그 다음 빈 공간만큼 memcpy를 해준다. */
		if_->rsp = if_->rsp - (argv_len + 1);
		memcpy(if_->rsp, argv[i], argv_len + 1);
		arg_address[i] = if_->rsp; // arg_address 배열에 현재 문자열 시작 주소 위치를 저장한다.
	}

	/* word-align: 8의 배수 맞추기 위해 padding 삽입*/
	while (if_->rsp % 8 != 0)
	{
		if_->rsp--;				  // 주소값을 1 내리고
		*(uint8_t *)if_->rsp = 0; //데이터에 0 삽입 => 8바이트 저장
	}

	/* 이제는 주소값 자체를 삽입! 이때 센티넬 포함해서 넣기*/
	for (int i = argc; i >= 0; i--)
	{							 // 여기서는 NULL 값 포인터도 같이 넣는다.
		if_->rsp = if_->rsp - 8; // 8바이트만큼 내리고
		if (i == argc)
		{ // 가장 위에는 NULL이 아닌 0을 넣어야지
			memset(if_->rsp, 0, sizeof(char **));
		}
		else
		{														// 나머지에는 arg_address 안에 들어있는 값 가져오기
			memcpy(if_->rsp, &arg_address[i], sizeof(char **)); // char 포인터 크기: 8바이트
		}
	}
	if_->R.rdi = argc;
	if_->R.rsi = if_->rsp; // arg_address 맨 앞 가리키는 주소값

	/* fake return address */
	if_->rsp = if_->rsp - 8; // void 포인터도 8바이트 크기
	memset(if_->rsp, 0, sizeof(void *));
}

	/* Checks whether PHDR describes a valid, loadable segment in
	 * FILE and returns true if so, false otherwise. */
	static bool
	validate_segment(const struct Phdr *phdr, struct file *file)
	{
		/* p_offset and p_vaddr must have the same page offset. */
		if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
			return false;

		/* p_offset must point within FILE. */
		if (phdr->p_offset > (uint64_t)file_length(file))
			return false;

		/* p_memsz must be at least as big as p_filesz. */
		if (phdr->p_memsz < phdr->p_filesz)
			return false;

		/* The segment must not be empty. */
		if (phdr->p_memsz == 0)
			return false;

		/* The virtual memory region must both start and end within the
		   user address space range. */
		if (!is_user_vaddr((void *)phdr->p_vaddr))
			return false;
		if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
			return false;

		/* The region cannot "wrap around" across the kernel virtual
		   address space. */
		if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
			return false;

		/* Disallow mapping page 0.
		   Not only is it a bad idea to map page 0, but if we allowed
		   it then user code that passed a null pointer to system calls
		   could quite likely panic the kernel by way of null pointer
		   assertions in memcpy(), etc. */
		if (phdr->p_vaddr < PGSIZE)
			return false;

		/* It's okay. */
		return true;
	}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		//ofs += page_read_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;
	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */

	struct file_info *aux_file_info = (struct file_info *)aux;

	file_seek(aux_file_info->file, aux_file_info->offset);

	// lock_acquire(&filesys_lock);
	int result = file_read(aux_file_info->file, page->frame->kva, aux_file_info->read_bytes);
	// lock_release(&filesys_lock);

	if ( result != (int)aux_file_info->read_bytes)
	{
		palloc_free_page(page->frame->kva);
		return false;
	}

	memset(page->frame->kva + aux_file_info->read_bytes, 0, aux_file_info->zero_bytes);

	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		struct file_info *aux_file_info;
		aux_file_info = (struct file_info *)malloc(sizeof(struct file_info));
		aux_file_info->file = file;
		aux_file_info->offset = ofs;
		aux_file_info->read_bytes = page_read_bytes;
		aux_file_info->zero_bytes = page_zero_bytes;
		aux_file_info->writable = writable;

		/* file에서 불러온 세그먼트지만, VM_ANON으로 설정해둠
		이유 : VM_FILE은 swap-out될 때 변경 내용이 디스크에 기록됨
		근데, .bss는 writable =1 로 들어오기 때문에, 수정이 가능하고
		수정 내용이 디스크에 기록될 경우 실행파일 영구 손상 가능성있음. 이를 막으려고 ANON으로 설정*/

		if (!vm_alloc_page_with_initializer(VM_ANON, upage,
											writable, lazy_load_segment, (void *)aux_file_info))
		{
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += page_read_bytes;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	if (vm_alloc_page(VM_ANON, stack_bottom, 1))
	{
		if (vm_claim_page(stack_bottom))
		{
			if_->rsp = USER_STACK;
			success = true;
		}
	}

	return success;
}

bool
install_page(void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
}
#endif /* VM */

/* Project 2 - User Program */
struct thread *get_child_process(int pid){
	struct thread* cur_thread = thread_current();
	struct list *child_list = &cur_thread->childs;
	struct list_elem *find_child;

	if(!list_empty(&cur_thread->childs)) {
		for (find_child = list_begin(child_list); find_child != list_end(child_list); find_child = list_next(find_child)) {
			struct thread *child_thread = list_entry(find_child, struct thread, child_elem);
			if (pid == child_thread->tid) {
				return child_thread;
			}
		}
	}
	return NULL;
}

/* Project 2 - User Program */
int process_add_file(struct file *f){ 
	struct thread* cur_thread = thread_current(); //현재 스레드
	struct file **fd_table = cur_thread->fd_table; // 현재 스레드의 파일 디스크립터 테이블
	// int fd = cur_thread->fd; // 현재 스레드의 파일 디스크립터

	while (cur_thread->fd_table[cur_thread->fd] && cur_thread->fd <FDCOUNT_LIMIT){ // fdt에 빈 자리가 날 때까지 fd 값을 계속 1씩 올린다. 그래서 자리가 나면 해당 자리에 파일을 배치하고 해당 디스크립터 값(=fdt의 인덱스)를 반환한다.
		cur_thread->fd++;
	}

	if (cur_thread->fd >= FDCOUNT_LIMIT){  // 오류시 리턴 -1 
		return -1;
	}

	// cur_thread->fd = fd; // 새 식별자
	fd_table[cur_thread->fd] = f; // 새식별자가 파일을 가리키도록 설정
	return cur_thread->fd; // 파일 디스크립터 리턴
	/* 파일 객체를 파일 디스크립터 테이블에 추가 */
	/* 파일 디스크립터의 최대값 1 증가 */
	/* 파일 디스크립터 리턴 */
}

/* Project 2 - User Program */
struct file *process_get_file(int fd)
{	
	if (fd < 0 || fd >= FDCOUNT_LIMIT){ // 파일 디스크립터 유효 검사
		return NULL;
	}
	struct thread *cur_thread = thread_current();
	struct file **fd_table = cur_thread->fd_table;
	struct file *file = fd_table[fd]; // 파일 디스크립터 테이블에서 해당 파일 디스크립터를 찾는다.
	return file;

	/* 파일 디스크립터에 해당하는 파일 객체를 리턴 */
	/* 없을 시 NULL 리턴 */
}
