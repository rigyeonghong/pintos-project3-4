#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "filesys/directory.h"
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                     
 /* Highest priority. */

//project 2 file

#define FDT_PAGES 3
#define FDCOUNT_LIMIT FDT_PAGES *(1<<9) // limit fd

/* Project 2 */
#define FDT_PAGES 3					  		// pages to allocate for file descriptor tables (thread_create, process_exit)
#define FDCOUNT_LIMIT FDT_PAGES *(1 << 9) 	// Limit fd_idx

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int init_priority; // donation 이후 우선순위를 초기화하기 위해 초기값 저장
	int priority;                       /* Priority. */
	int64_t wakeup_tick; 					// [수정1] 깨어나야할 tick


	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */
	int64_t wakeup_tick;				/* 깨어나야할 tick 저장 */

	/* prioriry donation 관련 항목 */
	int init_priority;                  /* donation 이후 우선순위를 초기화하기 위해 초기값 저장 */
	struct lock *wait_on_lock;			/* 해당 스레드가 대기 하고 있는 lock자료구조의 주소를 저장 */
	struct list donations;				/* multiple donation 을 고려하기 위해 사용 */		 
	struct list_elem donation_elem;	    /* multiple donation 을 고려하기 위해 사용 */


	/* Project 2 open function */
	struct file **fdt;
	int fd_idx;

	/* Project 2 exit function */

	/* Project 2 fork()*/
	struct intr_frame parent_if;        /* __do_fork()실행을 위해 유저 스택의 정보를 넘겨주기 위한 인터럽트 프레임 */
	struct list_elem child_elem;	    /* 자식리스트 element */
	struct list child_list;				/* 자식리스트 */
	struct semaphore sema_fork;
	bool is_waited_flag;		 		/* ???프로세스의 종료유무 확인*/
	int process_exit_status;		 	/* ???exit 호출 시 종료 status*/
	struct semaphore sema_wait;			/* wait 세마포어*/
	struct semaphore sema_free;			/* load 세마포어*/

	/* Project 2-4 file_deny_write */
	struct file *running_file;

	/* (한양대)필요 없음 */
	bool process_load_flag;				/* ???프로세스의 프로그램 메모리 적재유무확인 */
	bool process_exit_flag;		 		/* ???프로세스의 종료유무 확인*/



	/* Project 1 - Priority Scheduling */
	struct lock *wait_on_lock; // 해당 스레드가 대기 하고 있는 lock자료구조의 주소를 저장
	struct list donations; // multiple donation 을 고려하기 위해 사용
	struct list_elem donation_elem; // multiple donation을 고려하기 위해 사용
	
	/* Project 1 - MLFQS */
	int nice;
	int recent_cpu;
	struct list_elem all_elem;

	/* Project 2 - Syscall (fork, wait) */
	struct thread *parent_thread; /* 부모 스레드 */
	struct list_elem child_elem; /* 자식 리스트 element */
	struct list childs;			 /* 자식 리스트 */
	struct semaphore wait_sema; /* wait 세마포어 */
	struct semaphore fork_sema;  /* fork 세마포어 */
	struct semaphore free_sema;  /* free 세마포어 */
	int exit_status; /* exit 호출 시 종료 status */

	/* Project 2 - Syscall (file 관련) */
	int fd;
	struct file **fd_table;
	struct intr_frame parent_if;
	struct file *running;
	
	/* Project 3 - VM */
	uintptr_t rsp;
	struct list mmap_list;

	/* Project 4 - File System */
	struct dir *cur_dir;

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;

	// user->kernel 전환 전에 rsp를 저장해둠
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

/* Project 1 - Alarm Clock */
void thread_sleep(int64_t ticks); // 실행중인 스레드를 슬립으로 만듬
void thread_awake(int64_t ticks); // 슬립큐를 순회하면서 깨워야할 스레드를 깨움
void update_next_tick_to_awake(int64_t ticks); // next_tick_to_awake를 최소값으로 업데이트
int64_t get_next_tick_to_awake(void); // thread.c의 next_tick_to_awake 반환

/* Project 1 - Priority Scheduling */
void test_max_priority(void); // 현재 수행중인 스레드와 가장 높은 우선순위의 스레드의 우선순위를 비교하여 스케줄링 */
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED); // 인자로 주어진 스레드들의 우선순위를 비교 
void donate_priority(void);
void remove_with_lock(struct lock *lock);
void refresh_priority(void);

/* Project 1 - MLFQS */
void mlfqs_priority (struct thread *t);
void mlfqs_recent_cpu (struct thread *t);
void mlfqs_load_avg (void);
void mlfqs_increment (void);
void mlfqs_recalc (void);

#endif /* threads/thread.h */

