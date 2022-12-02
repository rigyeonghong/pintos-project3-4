/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	page->va = pg_round_down(va);
	struct hash_elem *va_hash_elem = hash_find(&spt->spt_hash, &page->elem);
	if (va_hash_elem == NULL)
		page = NULL;
	else
		page = hash_entry(va_hash_elem, struct page, elem);
	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	int succ = false;
	/* TODO: Fill this function. */
	if (hash_insert(&spt->spt_hash, &page->elem)==NULL){
		succ = true;
	}
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = pt_find_page(&thread_current()->spt, va);
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// [3-1?] wr 세팅을 1로 하는게 맞나?
	pml4_set_page(&thread_current()->pml4, page, frame, 1);

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->spt_hash, spt_hash_func, spt_less_func);
}

static unsigned spt_hash_func(const struct hash_elem *e, void *aux)
{
	struct page *p = hash_entry(e, struct page, elem);
	return hash_int(p->va);
}

static bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b)
{
	struct page *ap = hash_entry(a, struct page, elem);
	struct page *bp = hash_entry(b, struct page, elem);

	if (ap->va < bp->va)
		return true;
	else
		return false;
}

// struct page *spt_find_page(struct supplemental_page_table *spt, void *va){

// 	struct page *temp;
// 	temp->va = pg_round_down(va);
// 	struct hash_elem *va_hash_elem = hash_find(&spt->spt_hash, &temp->elem);
// 	if (va_hash_elem == NULL)
// 		return NULL;
// 	else
// 		return hash_entry(va_hash_elem, struct page, elem);
// }

// bool spt_insert_page(struct supplemental_page_table *spt, struct page *page){

// 	if (hash_insert(&spt->spt_hash, &page->elem)==NULL) {
// 		return true;
// 	}
// 	else {
// 		return false;
// 	}
// }

static struct frame *vm_get_frame(void){
	void *new_kva = palloc_get_page(PAL_USER); //유저 풀에서 새로운 물리 페이지를 가져온다
	if (new_kva==NULL){
		PANIC("todo"); //페이지 할당이 실패하면, 일단 패닉 -> 나중에 수정
	}
	else{
		// 프레임 초기화
		struct frame *new_frame; 
		new_frame->kva = new_kva;
		// 프레임에 매핑된 페이지 초기화
		struct page *new_page;
		new_page->frame = new_frame;
		new_page->va = new_kva;
		// [3-1?] 다른 멤버들 초기화 필요? (operations, union)
		return new_frame;
	}
}


// bool vm_do_claim_page(struct page *page){
// 	struct frame *f = vm_get_frame();

// 	// uint64_t *pte = pml4e_walk(&thread_current()->pml4, (uint64_t)page, 0);
// 	// if (pte==NULL)
// 	// 	return false;
// 	// else
// 	// [3-1?] wr 세팅을 1로 하는게 맞나?
// 	return pml4_set_page(&thread_current()->pml4, page, f, 1);
// }

// bool vm_claim_page(void *va){
// 	struct page *p = spt_find_page(&thread_current()->spt, va);
// 	return vm_do_claim_page(p);
// }

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
