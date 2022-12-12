/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "vm/uninit.h"
#include "threads/mmu.h"

#include "userprog/process.h"
#include "threads/thread.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */

	/* Project 3 - VM : lru list 초기화 */
	list_init(&lru_list);
	// printf("list_init 완료!\n");
	lock_init(&lru_list_lock);
	lru_clock = NULL;
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
									vm_initializer *init, void *aux)
{

	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;
	// printf("[vm_alloc_page_with_initializer] writable %d:\n",writable);

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL)
	{
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *new_page = (struct page *)malloc(sizeof(struct page));
		if (type == VM_ANON)
		{
			uninit_new(new_page, upage, init, type, aux, anon_initializer);
		} //[3-1?] ??
		else if (type == VM_FILE)
		{
			// printf("[vm_alloc_page_with_initializer] VM_FILE init: %p\n", init);
			uninit_new(new_page, upage, init, type, aux, file_backed_initializer);
		}
		else
		{
			// uninit_new(new_page, upage, init, type, aux, NULL);
			goto err;
		}
		new_page->writable = writable;
		/* TODO: Insert the page into the spt. */
		if (spt_insert_page(spt, new_page) == false)
		{
			goto err;
		}

	}
	return true;
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt, void *va)
{
	struct page *page = NULL;

	/* TODO: Fill this function. */
	// [3-1?] 우리가 원하는 va에 해당하는 페이지를 찾기 위해 가짜 페이지 할당
	// printf("----va: %p-----\n", va);
	struct page *temp = (struct page *)malloc(sizeof(struct page));
	temp->va = pg_round_down(va);
	// printf("----temp->va: %p-----\n", temp->va);
	// 가짜 페이지와 같은 hash를 가지는 페이지를 찾아옴
	struct hash_elem *va_hash_elem = hash_find(&spt->spt_hash, &temp->h_elem);
	// printf("----hash_elem: %p-----\n", va_hash_elem);
	// 가짜 페이지 메모리 해제
	free(temp);

	if (va_hash_elem != NULL)
	{
		// printf("----hash elem 찾음!----\n");
		page = hash_entry(va_hash_elem, struct page, h_elem);
		// printf("찾은 페이지 va : %p\n", page->va);
	}
	// printf("----page 찾음!----\n");
	return page;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt,
					 struct page *page)
{
	int succ = false;
	/* TODO: Fill this function. */
	if (hash_insert(&spt->spt_hash, &page->h_elem) == NULL)
	{
		succ = true;
	}
	return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	hash_delete(&spt->spt_hash, &page->h_elem);
	// vm_dealloc_page(page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	struct list_elem *fe;
	struct frame *f;
	/* TODO: The policy for eviction is up to you. - Clock Algorithm*/
	/* while (제거할 페이지를 못찾을때까지 = 리스트 끝까지) {
		if (현재 페이지의 accessed bit == 0)
			너가 나가
		else
			accessed bit 0으로 세팅
		clock pointer 옮기기
	}*/

	lock_acquire(&lru_list_lock);

	if (lru_clock == NULL){
		lru_clock = list_begin(&lru_list);
	}
	// printf("lru_clock: %p\n", lru_clock);

	// printf("lru_list is empty: %d\n", list_empty(&lru_list));
	/* 첫번째 for문 : lru clock부터 리스트 끝까지 돌기*/
	// 시간이 남으면 for문을 하나로 만들어보자
	for (fe = lru_clock; fe != list_tail(&lru_list); fe = list_next(fe))
	{
		f = list_entry(fe, struct frame, lru);
		// printf("fe: %p\n", fe);
		if (!pml4_is_accessed(f->thread->pml4, f->page->va)){
			// printf("찾았다!\n");
			victim = f;
			lru_clock = list_remove(fe);
			/* TBD: 원소가 하나인데 쫓아내서 리스트에서 제거했을 경우, lru_clock에 list tail이 들어가게 되는데 괜찮나...? */
			if (lru_clock == list_tail(&lru_list)){
				lru_clock = list_begin(&lru_clock);
			}
			goto done;
		}
		else {
			pml4_set_accessed(f->thread->pml4, f->page->va, 0);
			// printf("set_acccess_bit into 0\n");
		}
	}

	// printf("lru_clock: %p\n", lru_clock);

	/* 두번째 for 문 : 처음부터 lru clock까지 돌기 */
	for (fe = list_begin(&lru_list); fe != list_next(lru_clock); fe = list_next(fe))
	{
		f = list_entry(fe, struct frame, lru);
		// printf("fe: %p\n", fe);
		if (!pml4_is_accessed(f->thread->pml4, f->page->va))
		{
			victim = f;
			lru_clock = list_remove(fe);
			if (lru_clock == list_tail(&lru_list))
			{
				
				lru_clock = list_begin(&lru_clock);
			}
			goto done;
		}
		else
		{
			pml4_set_accessed(f->thread->pml4, f->page->va, 0);
		}
	}

	// printf("lru_clock: %p\n", lru_clock);

	goto done;

done:
	lock_release(&lru_list_lock);
	// printf("victim: %p\n", victim);

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	// printf("vm_evict_frame\n");
	struct frame *victim UNUSED = vm_get_victim();
	if (victim == NULL){
		return victim;
	}
	/* TODO: swap out the victim and return the evicted frame. */
	
	/* virtual page swap out */
	swap_out(victim->page);

	/* frame 구조체 초기화 */
	victim->page = NULL;
	victim->thread = NULL;

	/* frame 메모리 영역 안에 기록된 내용 0으로 초기화해주기 */
	memset(victim->kva, 0, PGSIZE);

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	// printf("vm_get_frame\n");
	void *new_kva = palloc_get_page(PAL_USER); // 유저 풀에서 새로운 물리 페이지를 가져온다
	// printf("new_kva = %p\n", new_kva);
	if (new_kva == NULL)
	{
		// printf("이제 frame이 없어유\n");
		frame = vm_evict_frame();
		if (frame ==NULL)
			PANIC("todo"); // 쫓아낼 프레임도 없으면 패닉
	}
	else
	{
		// 프레임 초기화
		frame = (struct frame *)malloc(sizeof(struct frame)); // [3-1?] 프레임 할당은 어디서 해오지????!!@!!@!!@!!@!@malloc을 하라
		frame->kva = new_kva;
		frame->page = NULL;
	}
	frame->thread = thread_current();

	lock_acquire(&lru_list_lock);
	list_push_back(&lru_list, &frame->lru);
	// [3-1?] 다른 멤버들 초기화 필요? (operations, union)
	lock_release(&lru_list_lock);

	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}


/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
	vm_alloc_page(VM_ANON, addr, 1);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
	struct frame *old_f = page->frame;	
	struct frame *new_f = vm_get_frame();

	if (new_f==NULL)
		return false;

	memcpy(new_f->kva, old_f->kva, PGSIZE);

	// printf("new kva: %p\n", new_f->kva);
	// printf("old kva: %p\n", old_f->kva);


	page->writable = 1;
	page->frame = new_f;
	page->cow = 0;
	new_f->page = page;

	// cow를 돌려놔야 하나?

	// printf("page->va: %p\n", page->va);

	// printf("pml4_get_page: %p\n", pml4_get_page(thread_current()->pml4, page->va));

	return pml4_set_page(thread_current()->pml4, page->va, new_f->kva, 1);
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
						 bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
	struct page *fault_p;

	bool doclaim_r;
	struct file_info *temp;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	// printf("=======page fault, addr: %p=======\n", addr);
	// printf("[vm_try_handle_fault] user: %d\n", user);
	// printf("[vm_try_handle_fault] write: %d\n", write);
	// printf("[vm_try_handle_fault] not_present: %d\n", not_present);
	// printf("[vm_try_handle_fault] tid: %d\n", thread_current()->tid);

	/* invalid excess fault*/
	if ((!is_user_vaddr(addr)) || (addr == NULL))
	{
		printf("찐폴트\n");
		exit(-1);
	}
 
	/* STACK GROWTH */
	void *rsp;
	if (user == 1)
		rsp = (void *)f->rsp;
	else
		rsp = (void *)thread_current()->rsp;

	if ((rsp - 8 <= addr) && (addr <= USER_STACK) && (addr >= (USER_STACK - MAXSTACK)))
	{
		// printf("스택아 자라라\n");
		vm_stack_growth(pg_round_down(addr));
		// printf("스택 자랐당\n");
	}

	fault_p = spt_find_page(&thread_current()->spt, addr);

	if (fault_p == NULL)
	{
		// printf("페이지 어딧지 \n");
		exit(-1);
	}

	// printf("write: %d\n", write);
	// printf("p->cow: %d\n", fault_p->cow);



	/* write protected page : Copy on Write */
	if (write == 1 && fault_p->cow == 1)
	{
		bool result = vm_handle_wp(fault_p);
		// printf("write_protected_page, handling complete: %d\n", result);
		// printf("=======page fault 끝, addr: %p=======\n", addr);
		return result;
	}
	// printf("=======page fault 끝, addr: %p=======\n", addr);
	return vm_claim_page(addr);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED)
{
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);
	// printf("page type: %d\n" ,page->uninit.type);
	if (page == NULL)
	{
		// printf("page==NULL\n");
		return false;
	}
	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
bool vm_do_claim_page(struct page *page)
{
	struct frame *frame = vm_get_frame();
	// printf("===========vm_do_claim_page: start=============\n");
	// printf("[vm_do_claim_page] va: %p\n", page->va);
	// printf("[vm_do_claim_page] type: %d\n", page->uninit.type);
	int result = false;
	struct thread *t = thread_current();
	// printf("[vm_do_claim_page] tid: %d\n", thread_current()->tid);
	// bool writable;

	/* Set links */
	frame->page = page;
	page->frame = frame;


	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// [3-1?] wr 세팅을 1로 하는게 맞나?

	// printf("[vm_do_claim_page] page->va: %p\n", page->va);
	// printf("[vm_do_claim_page] frame->kva: %p\n", frame->kva);
	// printf("[vm_do_claim_page] page->writable: %d\n", page->writable);
	if (!install_page(page->va, frame->kva, page->writable))
		return false;

	// printf("pte: %p\n", *( (uint64_t *) page->va));
	// printf("[vm_do_claim_page] set_page 성공 \n");

	result = swap_in(page, frame->kva);
	// printf("[vm_do_claim_page] swap in 성공 - %d \n", result);

	return result;
}


/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	hash_init(&spt->spt_hash, spt_hash_func, spt_less_func, NULL);
}

static unsigned spt_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
	const struct page *p = hash_entry(e, struct page, h_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

static bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
	const struct page *ap = hash_entry(a, struct page, h_elem);
	const struct page *bp = hash_entry(b, struct page, h_elem);

	return ap->va < bp->va;
}

/* Project 3-2 Anonymous Page */
/* src에서 dst로 spt를 복사하는 함수
자식이 부모의 execution context를 복사해야 할 때 사용됨 (i.e. fork())
src의 spt에 있는 각 페이지를 순회하면서 각 엔트리와 똑같은 복사본을 dst의 spt에 만든다.
uninit page를 할당하고 즉시 claim 해야함 */
/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED, struct supplemental_page_table *src UNUSED){
	// printf("copy 시작\n");
	hash_apply(&src->spt_hash, supplemental_copy_entry);
	// printf("copy 끝\n");
	return true;
}

void supplemental_copy_entry(struct hash_elem *e, void *aux){
	// printf("entry\n");

	struct page *p = hash_entry(e, struct page, h_elem);
	struct page *child_p;
	enum vm_type parent_type = p->operations->type;
	// bool child_cow = p->writable;

	if (parent_type== VM_UNINIT)
	{
		// printf("VM_UNINIT\n");
		// printf("[spt entry] : uninit p kva: %p\n", p->frame->kva);
		vm_alloc_page_with_initializer(p->uninit.type, p->va, p->writable, lazy_load_segment, p->uninit.aux);
	}
	else{
		struct page *child_p = (struct page *)malloc(sizeof(struct page));
		memcpy(child_p, p, sizeof(struct page));

		spt_insert_page(&thread_current()->spt, child_p);
		pml4_set_page(thread_current()->pml4, child_p->va, p->frame->kva, 0);

		child_p->writable = p->writable;
		child_p->cow = p->writable;
	}

}

/* Project 3-2 Anonymous Page */
/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	// printf("spt_kill start\n");
	hash_destroy(&spt->spt_hash, supplemental_destroy_entry);
	// printf("spt_kill end\n");
}

void supplemental_destroy_entry(struct hash_elem *e, void *aux)
{
	struct page *p = hash_entry(e, struct page, h_elem);
	if (p->operations->type == VM_FILE){
		do_munmap(p->va);
	}
	//spt_remove_page(&thread_current()->spt,p);
}