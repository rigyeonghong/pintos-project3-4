#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"

#include "threads/fixed_point.h" // Project 1 - MLFQS
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Project 1 - MLFQS */
#define NICE_DEFAULT 0
#define RECENT_CPU_DEFAULT 0
#define LOAD_AVG_DEFAULT 0

int load_avg; // Project 1 - MLFQS

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b // 스택 오버플로우 감지

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210 // 기초 스레드 값 변경 금지

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list; // 준비 리스트

/* Project 1 - Alarm Clock */
static struct list sleep_list; // Blocked Thread의 list
static int64_t next_tick_to_awake = INT64_MAX; // sleep_list에서 대기중인 스레드들의 wakeup_tick 값 중 최소값을 저장

static struct list all_list;

// /* Project 3 - VM */
// static struct list mmap_list; 

/* Idle thread. */
// idle 스레드란 운영체제가 초기화되고 ready_list가 생성되는데 이때 ready_list에 첫번째로 추가되는 스레드입니다. 굳이 이 스레드가 필요한 이유는 CPU가 실행상태를 유지하기 위해 실행할 스레드 하나 필요해서 입니다.
//CPU가 할일이 없으면 아예 꺼져버렸다가 할일이 생기면 다시 켜는방식에서 소모되는 전력보다 무의미한 일이라도 하고 있는게 더 적은 전력을 소모하기 때문입니다.
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
// destruction_req : 제거 요청이 들어온 스레드의 리스트
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4		  /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);
static int64_t next_tick_to_awake = INT64_MAX; /* 다음에 일어나야할 tick 저장 */
void thread_sleep(int64_t ticks);			   /* 실행 중인 스레드를 슬립으로 만듦 */
void thread_awake(int64_t ticks);			   /* 슬립큐에서 깨워야 할 스레드를 깨움*/
void update_next_tick_to_awake(int64_t ticks); /* 최소 틱을 가진 스레드 저장 */
int64_t get_next_tick_to_awake(void);		   /* thread.c의 next_tick_to_awake를 반환 */

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))

// Macro
#define LIST_MIN(x, y) ((x) < (y) ? (x) : (y));

// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = {0, 0x00af9a000000ffff, 0x00cf92000000ffff};

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
	finishes. */


void thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof(gdt) - 1,
		.address = (uint64_t)gdt};
	lgdt(&gdt_ds);

	/* Init the global thread context */
	lock_init(&tid_lock);
	list_init(&ready_list);
	list_init(&sleep_list); /* sleep_list를 초기화 */
	list_init(&destruction_req);

	list_init(&all_list); // Project 1 - MLFQS 
	list_init(&sleep_list); // Project 1 - Alarm Clock

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread (); 
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();

	next_tick_to_awake = INT64_MAX; // Project 1 - Alarm Clock : next_tick_to_awake (전역변수) - sleep_list에서 대기 중인 스레드들의 wakeup_tick 값 중 최솟값
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void)
{
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started); // idle thread 생성, ready_list추가, pir=0(min), sema_up

	load_avg = LOAD_AVG_DEFAULT; // Project 1 - MLFQS

	/* Start preemptive thread scheduling. */
	intr_enable();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void)
{
	struct thread *t = thread_current();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;
		
	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return();
}

/* Prints thread statistics. */
void thread_print_stats(void)
{
	printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
		   idle_ticks, kernel_ticks, user_ticks);
}

/*Thread의 ready_list삽입시 현재 실행중인 thread와 우선순위를 비교하여, 새로생성된 thread의 우선순위가 높다면 thread_yield()를 통해CPU를 양보*/
/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */

/* Project 1 - Priority Scheduling 
Thread의 ready_list 삽입시 현재 실행중인 thread와 우선순위를 비교하여, 새로 생성된 thread의 우선순위가 높다면 thread_yield()를 통해 CPU를 양보 */
tid_t
thread_create(const char *name, int priority,
			  thread_func *function, void *aux)
{
	struct thread *t;
	tid_t tid;

	ASSERT(function != NULL);

	/* Allocate thread. */
	t = palloc_get_page(PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread(t, name, priority);
	tid = t->tid = allocate_tid();
	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t)kernel_thread; 	//PC 실행할 다음 인스트럭션의 메모리주소를 가리킴
	t->tf.R.rdi = (uint64_t)function;		//스레드가 수행할 함수
	t->tf.R.rsi = (uint64_t)aux;			//수행 할 함수의 인자
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Project 2 - Syscall : file descriptor table 초기화 */
	t->fd_table = palloc_get_multiple(PAL_ZERO, FDT_PAGES);
	if (t->fd_table == NULL){
		thread_exit();
	}
	t->fd_table[0] = 0; // standard input
	t->fd_table[1] = 1; // standard output
	t->fd = 2;
	list_push_back(&thread_current()->childs, &t->child_elem);

	/* Add to run queue. */
	struct thread *curr = thread_current();
	thread_unblock(t); // ready list에 순서에 맞게 넣어줌



	/* Project 2 -  Priority Scheduling : 생성된 스레드의 우선순위가 현재 실행중이 스레드의 우선순위 보다 높다면 CPU를 양보한다. */
	test_max_priority();

	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void)
{
	ASSERT(!intr_context());
	ASSERT(intr_get_level() == INTR_OFF);
	thread_current()->status = THREAD_BLOCKED;
	schedule();
}

/* block 상태의 스레드를 ready로 바꿔줌 */
/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
/* Project 1 - Priority Scheduling 
Thread가 unblock 될때 우선순위 순으로 정렬 되어 ready_list에 삽입되도록 수정*/
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;
	ASSERT(is_thread(t));
	old_level = intr_disable();
	ASSERT(t->status == THREAD_BLOCKED);
	/* Thread가 unblock될 때 우선순위 순으로 정렬되어 ready_list에 삽입되도록 수정 */
	list_insert_ordered(&ready_list, &t->elem, cmp_priority, NULL); //list_less_func* less는 cmp_priority함수포인터로 전달 ,aux=NULL로 전달

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	/* 스레드가 unblock 될때 우선순위 순으로 정렬 되어 ready_list에 삽입되도록 수정 */
	list_insert_ordered(&ready_list, &(t->elem), cmp_priority, NULL);
	//(수정 전) list_push_back (&ready_list, &t->elem);
	t->status = THREAD_READY;
	intr_set_level(old_level);
}

/* Returns the name of the running thread. */
	const char *
	thread_name(void)
	{
		return thread_current()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) { 
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT(is_thread(t));
	ASSERT(t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void)
{
	return thread_current()->tid;
}

/* Deschedules the current thread and destroys it.  
   Never returns to the caller. */
void thread_exit(void)
{
	ASSERT(!intr_context());

#ifdef USERPROG
	process_exit();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable();
	do_schedule(THREAD_DYING);
	NOT_REACHED();
}


/* Project 1 - Alarm Clock
현재 스레드가 idle 스레드가 아닐 경우 : 
wakeup_tick을 업데이트하고, 슬립 큐에 삽입하고, 현재 스레드를 블락상태로 바꾸며 스케줄링 한다
해당 과정 중에는 인터럽트를 받아들이지 않는다.*/
void thread_sleep(int64_t ticks) 
{	
	struct thread *cur = thread_current();
	enum intr_level old_level;
	old_level = intr_disable();
	if (cur != idle_thread){
		cur-> wakeup_tick = ticks;
		list_push_back(&sleep_list, &(cur->elem));
		update_next_tick_to_awake(ticks);
		do_schedule(THREAD_BLOCKED); 
	} 
	intr_set_level(old_level);
}


/* Project 1 - Alarm Clock
sleep_list를 순회하면서 wake_up tick이 ticks보다 작다면 리스트에서 빼고, unblock
그렇지 않다면 next_tick_to_awake를 업데이트 한다 */
void thread_awake(int64_t ticks)
{	
	struct list_elem *e;
	struct thread* e_thread;

	e = list_begin(&sleep_list);

	while(e != list_end(&sleep_list)){
		e_thread = list_entry(e, struct thread, elem);

		if (e_thread->wakeup_tick <= ticks){
			e = list_remove(e);
			thread_unblock(e_thread);
		}
		else {
			update_next_tick_to_awake(e_thread->wakeup_tick);
			e = list_next(e);
		}

	}
}

/* Project 1 - Alarm Clock 
next_tick_to_awake가 깨워야 할 스레드중 가장 작은 tick을 갖도록 업데이트한다.*/
void update_next_tick_to_awake(int64_t ticks) 
{	
	next_tick_to_awake = LIST_MIN(next_tick_to_awake,ticks);
}

/* Project 1 - Alarm Clock
next_tick_to_awake 반환 */
int64_t get_next_tick_to_awake(void) 
{
	return next_tick_to_awake;
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
/* Project 1 - Priority Scheduling
현재 thread가 CPU를 양보하여 ready_list에 삽입 될 때 우선순위 순서로 정렬되어 삽입 되도록 수정*/
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	old_level = intr_disable(); // 인터럽트를 비활성하고 이전 인터럽트 상태(old_level)를 받아온다.

	old_level = intr_disable ();
	if (curr != idle_thread)
		list_insert_ordered(&ready_list, &(curr->elem), cmp_priority, NULL); // 우선순위 순서로 정렬되어 삽입
		// (수정 전)list_push_back (&ready_list, &curr->elem);
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

/* 스레드의 우선순위가 변경되었을 때 우선순위에 따라 ready_list의 우선순위와 비교하여 스케줄링(preempted) */
/* donation을 고려하여 thread_set_priority() 함수를 수정 */
/* Sets the current thread's priority to NEW_PRIORITY. */
/* Project 1 - Priority Scheduling
스레드의 우선순위가 변경되었을때 우선순위에 따라 선점이 발생하도록 한다.*/
void
thread_set_priority (int new_priority) {

	if (!thread_mlfqs) /* mlfqs 스케줄러 일때 우선순위를 임의로 변경할수 없도록 한다. */
	{ 
		struct thread *cur_thread = thread_current();
		cur_thread->init_priority = new_priority;
		
		refresh_priority();
		donate_priority();
		test_max_priority();
	}
	/* refresh_priority() 함수를 사용하여 우선순위를 변경으로 인한 donation 관련 정보를 갱신한다. 
	donation_priority(), test_max_pariority() 함수를 사용하여 priority donation 을 수행하고 스케줄링 한다. */
	
}

/* Returns the current thread's priority. */
int thread_get_priority(void)
{
	return thread_current()->priority;
}

/* Project 1 - Priority Scheduling 
ready_list에서 Priority가 가장 높은 스레드와 현재 스레드의 Priority를 비교해서
현재 스레드의 Priority가 더 낮으면, 높은 스레드에게 양보한다*/
void test_max_priority(void)
{
	if (!intr_context()){
		if (!list_empty(&ready_list)) // ready_list 가 비어있지 않은지 확인
		{
			struct thread *high_thread = list_entry(list_begin(&ready_list), struct thread, elem);
			if (thread_get_priority() < high_thread->priority)
				thread_yield();
		}
	}
	// ready_list에서 우선순위가 가장 높은 스레드와 현재 스레드의 우선순위를 비교하여 스케줄링 한다. (ready_list 가 비어있지 않은지 확인)
}

/* Project 1 - Priority Scheduling 
a의 priority가 높으면 1을 반환, b의 priority가 높으면 0을 반환 */
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
	struct thread *thread_a = list_entry(a, struct thread, elem);
	struct thread *thread_b = list_entry(b, struct thread, elem);

	return ((thread_a->priority) > (thread_b->priority));
	// 인자로 주어진 스레드들의 우선순위를 비교
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by

   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle(void *idle_started_ UNUSED)
{
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current();
	sema_up(idle_started);

	for (;;)
	{
		/* Let someone else run. */
		intr_disable();
		thread_block();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile("sti; hlt"
					 :
					 :
					 : "memory");
	}
}


/* Function used as the basis for a kernel thread. */
static void
kernel_thread(thread_func *function, void *aux)
{

	ASSERT(function != NULL);
	intr_enable(); /* The scheduler runs with interrupts off. */
	function(aux); /* Execute the thread function. */
	thread_exit(); /* If function() returns, kill the thread. */

}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread(struct thread *t, const char *name, int priority)
{
	ASSERT(t != NULL);
	ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT(name != NULL);

	memset(t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy(t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t)t + PGSIZE - sizeof(void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;

	/* Project 1 - Priority Scheduling : init_priority, wait_on_lock, dontaion list 초기화 */
	t->init_priority = priority;
	t->wait_on_lock = NULL;
	list_init(&t->donations);

	/* Project 1 - Priority Scheduling : nice, recent_cpu 초기화, all list에 스레드 추가 */
	t->nice = NICE_DEFAULT;
	t->recent_cpu = RECENT_CPU_DEFAULT;
	list_push_back(&all_list, &t->all_elem);

	/* Project 2 - Syscall : exit_status, child list, semaphore 초기화 */
	t->exit_status = 0;
	list_init(&t->childs); // project 2 user program
	sema_init(&t->fork_sema, 0); // fork_sema : 자식 프로세스 create 될 때까지 기다림
	sema_init(&t->wait_sema, 0); // wait_sema : 자식 프로세스 종료할 때 까지 기다림
	sema_init(&t->free_sema, 0); // free_sema : 자식 프로세스 free될 때 까지 기다림

	list_init(&t->mmap_list); // Project 3 - VM
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
	static struct thread *
	next_thread_to_run(void)
	{
		if (list_empty(&ready_list))
			return idle_thread;
		else
			return list_entry(list_pop_front(&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void do_iret(struct intr_frame *tf)
{
	__asm __volatile(
		"movq %0, %%rsp\n"
		"movq 0(%%rsp),%%r15\n"
		"movq 8(%%rsp),%%r14\n"
		"movq 16(%%rsp),%%r13\n"
		"movq 24(%%rsp),%%r12\n"
		"movq 32(%%rsp),%%r11\n"
		"movq 40(%%rsp),%%r10\n"
		"movq 48(%%rsp),%%r9\n"
		"movq 56(%%rsp),%%r8\n"
		"movq 64(%%rsp),%%rsi\n"
		"movq 72(%%rsp),%%rdi\n"
		"movq 80(%%rsp),%%rbp\n"
		"movq 88(%%rsp),%%rdx\n"
		"movq 96(%%rsp),%%rcx\n"
		"movq 104(%%rsp),%%rbx\n"
		"movq 112(%%rsp),%%rax\n"
		"addq $120,%%rsp\n"
		"movw 8(%%rsp),%%ds\n"
		"movw (%%rsp),%%es\n"
		"addq $32, %%rsp\n"
		"iretq"
		:
		: "g"((uint64_t)tf)
		: "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch(struct thread *th)
{
	uint64_t tf_cur = (uint64_t)&running_thread()->tf;
	uint64_t tf = (uint64_t)&th->tf;
	ASSERT(intr_get_level() == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile(
		/* Store registers that will be used. */
		"push %%rax\n"
		"push %%rbx\n"
		"push %%rcx\n"
		/* Fetch input once */
		"movq %0, %%rax\n"
		"movq %1, %%rcx\n"
		"movq %%r15, 0(%%rax)\n"
		"movq %%r14, 8(%%rax)\n"
		"movq %%r13, 16(%%rax)\n"
		"movq %%r12, 24(%%rax)\n"
		"movq %%r11, 32(%%rax)\n"
		"movq %%r10, 40(%%rax)\n"
		"movq %%r9, 48(%%rax)\n"
		"movq %%r8, 56(%%rax)\n"
		"movq %%rsi, 64(%%rax)\n"
		"movq %%rdi, 72(%%rax)\n"
		"movq %%rbp, 80(%%rax)\n"
		"movq %%rdx, 88(%%rax)\n"
		"pop %%rbx\n" // Saved rcx
		"movq %%rbx, 96(%%rax)\n"
		"pop %%rbx\n" // Saved rbx
		"movq %%rbx, 104(%%rax)\n"
		"pop %%rbx\n" // Saved rax
		"movq %%rbx, 112(%%rax)\n"
		"addq $120, %%rax\n"
		"movw %%es, (%%rax)\n"
		"movw %%ds, 8(%%rax)\n"
		"addq $32, %%rax\n"
		"call __next\n" // read the current rip.
		"__next:\n"
		"pop %%rbx\n"
		"addq $(out_iret -  __next), %%rbx\n"
		"movq %%rbx, 0(%%rax)\n" // rip
		"movw %%cs, 8(%%rax)\n"	 // cs
		"pushfq\n"
		"popq %%rbx\n"
		"mov %%rbx, 16(%%rax)\n" // eflags
		"mov %%rsp, 24(%%rax)\n" // rsp
		"movw %%ss, 32(%%rax)\n"
		"mov %%rcx, %%rdi\n"
		"call do_iret\n"
		"out_iret:\n"
		:
		: "g"(tf_cur), "g"(tf)
		: "memory");
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		list_remove(&victim->all_elem);
		palloc_free_page(victim);
	}
	thread_current()->status = status;
	schedule(); //스케줄 함수 호출
}

/* next thread를 thread running으로 만드는 scheduling */
static void
schedule(void)
{
	struct thread *curr = running_thread();		// do_schedule에서는 status만 바꿔줌
	struct thread *next = next_thread_to_run(); // next run할 변수 설정

	ASSERT(intr_get_level() == INTR_OFF);	    // scheduling 도중에는 인터럽트가 발생하면 안 되기 때문에 INTR_OFF 상태인지 확인한다.
	ASSERT(curr->status != THREAD_RUNNING);     // CPU 소유권을 넘겨주기 전에 running 스레드는 그 상태를 running 외의 다른 상태로 바꾸어주는 작업이 되어 있어야 하고 이를 확인하는 부분이다.
	ASSERT(is_thread(next));				    // next_thread_to_run()에 의해 올바른 thread 가 return 되었는지 확인returns true if next appears to point to a valid thread
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate(next); // CPU에 running user code를 setup 하고, 모든 context switching에서 이 작업을 수행함
#endif

	if (curr != next)
	{
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used bye the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		/* 한마디로 얘기해서 PREV 함수가 죽어있으면 destruction_req list로 보내라는 것 */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread)
		{
			ASSERT(curr != next);
			list_push_back(&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch(next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid(void)
{
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire(&tid_lock);
	tid = next_tid++;
	lock_release(&tid_lock);

	return tid;
}

/* Project 1 - Priority Scheduling
현재 스레드가 기다리고 있는 lock 과 연결 된 모든 스레드들을 순회하며
현재 스레드의 우선순위를 lock 을 보유하고 있는 스레드에게 기부 (nested depth는 8로 제한)*/
void donate_priority(void)
{
	struct thread *cur_thread = thread_current();
	// struct thread *next_thread ;
	int donate_p = cur_thread->priority;
	int nested_depth;
	for (nested_depth = 0; nested_depth < 8; nested_depth++){
		if(cur_thread->wait_on_lock == NULL){
			break;
		}
		else{
			if (cur_thread->wait_on_lock->holder > 0x100 )
				cur_thread = cur_thread->wait_on_lock->holder;
			if (cur_thread->priority < donate_p){
				cur_thread->priority = donate_p;
			}
		}
	}  
}

/* Project 1 - Priority Scheduling
lock을 해지 했을 때, 현재 스레드의 donations 리스트를 확인하여
해지 할 lock 을 보유하고 있는 donation element를 삭제한다. */
void remove_with_lock(struct lock *lock)
{	
	struct thread *cur_thread = thread_current();
	struct list *d_list = &cur_thread->donations;
	struct list_elem *de;
	
	if (list_empty(d_list))
        return;

	de = list_begin(d_list);
    while (de != list_tail(d_list)){
		struct thread* d_thread = list_entry(de, struct thread, donation_elem);
        if (d_thread->wait_on_lock == lock)
            de = list_remove(&d_thread->donation_elem);
        else
            de = list_next(de);
    }
}

/* Project 1 - Priority Scheduling
스레드의 우선순위가 변경되었을 때, donation을 고려하여 우선순위를 다시 결정.
donations 리스트에서 우선순위가 가장 높은 스레드와 현재 스레드의 우선순위를 비교하여, 
높은 값을 현재 스레드의 우선순위로 설정한다. */
void refresh_priority(void)
{	
	struct thread *cur_thread = thread_current(); 
	
	cur_thread->priority = cur_thread->init_priority;

	if (!list_empty(&cur_thread->donations)){ // *********리스트가 비었는지 확인하기**********
		struct thread *begin_thread = list_entry(list_begin(&cur_thread->donations), struct thread, donation_elem);

		if ((cur_thread->priority) < (begin_thread->priority)){
			(cur_thread->priority) = (begin_thread->priority);
		}
	}	
}

/* Project 1 - MLFQS */
void mlfqs_priority (struct thread *t)
{
	int recent_cpu = t->recent_cpu;
	int nice = t->nice;
	if (t!=idle_thread){
		t->priority = fp_to_int(sub_mixed((sub_fp(int_to_fp(PRI_MAX), div_mixed(recent_cpu,4))),(nice * 2)));
		//priority = PRI_MAX – (recent_cpu / 4) – (nice * 2)
	}
	/* 해당 스레드가 idle_thread 가 아닌 검사 */
	/* priority계산식을 구현 (fixed_point.h의 계산함수 이용) */
}

/* Project 1 - MLFQS */
void mlfqs_recent_cpu (struct thread *t)
{
	
	int recent_cpu = t->recent_cpu;
	int nice = t->nice;
	if (t!=idle_thread){
		t->recent_cpu = add_mixed(mult_fp(div_fp(mult_mixed(load_avg, 2),add_mixed(mult_mixed(load_avg,2), 1)), recent_cpu), nice);
		// recent_cpu = (2 * load_avg) / (2 * load_avg + 1) * recent_cpu + nice
	}
	/* 해당 스레드가 idle_thread 가 아닌지 검사 */
	/*recent_cpu계산식을 구현 (fixed_point.h의 계산함수 이용)*/
}

/* Project 1 - MLFQS */
void mlfqs_load_avg (void){
	int ready_threads;
	if( thread_current() != idle_thread){
		ready_threads = 1+list_size(&ready_list);
	}
	else{
		ready_threads=list_size(&ready_list);
	}
	load_avg = add_fp(mult_fp(div_fp(int_to_fp(59),int_to_fp(60)),load_avg), mult_mixed(div_fp(int_to_fp(1),int_to_fp(60)), ready_threads));
	// load_avg = (59/60) * load_avg + (1/60) * ready_threads
	/* load_avg 계산식을 구현 (fixed_point.h의 계산함수 이용) */
	/* load_avg 는 0 보다 작아질 수 없다.*/
}

/* Project 1 - MLFQS */
void mlfqs_increment (void)
{
	
	struct thread *cur_thread = thread_current();
	if (cur_thread!=idle_thread){
		cur_thread->recent_cpu += F;
	}
	/* 해당 스레드가 idle_thread 가 아닌지 검사 */
	/* 현재 스레드의 recent_cpu 값을 1증가 시킨다. */
}

/* Project 1 - MLFQS */
void mlfqs_recalc (void)
{
	struct list_elem *e;

	for(e = list_begin(&all_list); e !=list_end(&all_list); e=list_next(e)){
		struct thread* circle_thread = list_entry(e, struct thread, all_elem);
		mlfqs_recent_cpu(circle_thread);
		mlfqs_priority(circle_thread);
	}
	/* 모든 thread의 recent_cpu와 priority값 재계산 한다. */
}

/* Project 1 - MLFQS */
void thread_set_nice (int nice UNUSED)
{ 

	struct thread *cur_thread = thread_current();
	enum intr_level old_level = intr_disable();

	cur_thread->nice = nice;
	mlfqs_priority(cur_thread);
	test_max_priority();
	intr_set_level(old_level);

	/* 현재 스레드의 nice값을 변경하는 함수를 구현. 해당 작업중에 인터럽트는 비활성화 해야 한다. */
	/* nice 값 변경 후에 현재 스레드의 우선순위를 재계산하고 우선순위에 의해 스케줄링 한다. */
}

/* Project 1 - MLFQS */
int thread_get_nice (void)
{	
	enum intr_level old_level = intr_disable();
	int cur_nice;
	struct thread *cur_thread = thread_current();
	cur_nice = cur_thread->nice;
	intr_set_level(old_level);
	return cur_nice;

	/* 현재 스레드의 nice 값을 반환한다. 해당 작업중에 인터럽트는 비활성되어야 한다. */
}

/* Project 1 - MLFQS */
int thread_get_load_avg (void)
{
	enum intr_level old_level = intr_disable();
	int cur_load_avg = fp_to_int_round(mult_mixed(load_avg, 100));
	intr_set_level(old_level);
	return cur_load_avg;

	/* load_avg에 100을 곱해서 반환 한다. 해당 과정중에 인터럽트는 비활성되어야 한다. */
}

/* Project 1 - MLFQS */
int thread_get_recent_cpu (void)
{
	enum intr_level old_level = intr_disable();
	struct thread *cur_thread = thread_current();
	int cur_recent_cpu = fp_to_int_round(mult_mixed(cur_thread->recent_cpu, 100));
	intr_set_level(old_level);
	return cur_recent_cpu;
	/* recent_cpu 에 100을 곱해서 반환 한다. 해당 과정중에 인터럽트는 비활성되어야 한다. */
}