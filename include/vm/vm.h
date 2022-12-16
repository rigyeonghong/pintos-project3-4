#ifndef VM_VM_H
#define VM_VM_H
#include <stdbool.h>
#include "threads/palloc.h"
#include "lib/kernel/hash.h"

enum vm_type
{
	/* page not initialized */
	VM_UNINIT = 0,
	/* page not related to the file, aka anonymous page */
	VM_ANON = 1,
	/* page that realated to the file */
	VM_FILE = 2,
	/* page that hold the page cache, for project 4 */
	VM_PAGE_CACHE = 3,

	/* Bit flags to store state */

	/* Auxillary bit flag marker for store information. You can add more
	 * markers, until the value is fit in the int. */
	VM_MARKER_0 = (1 << 3),
	VM_MARKER_1 = (1 << 4),

	/* DO NOT EXCEED THIS VALUE. */
	VM_MARKER_END = (1 << 31),
};

#include "vm/uninit.h"
#include "vm/anon.h"
#include "vm/file.h"
#ifdef EFILESYS
#include "filesys/page_cache.h"
#endif

struct page_operations;
struct thread;

#define VM_TYPE(type) ((type)&7)

/* The representation of "page".
 * This is kind of "parent class", which has four "child class"es, which are
 * uninit_page, file_page, anon_page, and page cache (project4).
 * DO NOT REMOVE/MODIFY PREDEFINED MEMBER OF THIS STRUCTURE. */
struct page
{
	const struct page_operations *operations;
	void *va;			 /* Address in terms of user space */
	struct frame *frame; /* Back reference for frame */

	/* Your implementation */
	struct hash_elem h_elem;
	struct list_elem mmap_elem;

	/* Per-type data are binded into the union.
	 * Each function automatically detects the current union */
	union
	{
		struct uninit_page uninit;
		struct anon_page anon;
		struct file_page file;
#ifdef EFILESYS
		struct page_cache page_cache;
#endif
	};
	bool writable;
	bool cow; 
};

/* The representation of "frame" */
struct frame
{
	void *kva;
	struct page *page;
	struct list_elem lru;
	struct thread *thread;
};

/* Project 3 - VM */
struct list lru_list; // 할당된 물리 프레임들을 관리하는 리스트
struct lock lru_list_lock;
struct list_elem *lru_clock;


/* The function table for page operations.
 * This is one way of implementing "interface" in C.
 * Put the table of "method" into the struct's member, and
 * call it whenever you needed. */
struct page_operations
{
	bool (*swap_in)(struct page *, void *);
	bool (*swap_out)(struct page *);
	void (*destroy)(struct page *);
	enum vm_type type;
};

#define swap_in(page, v) (page)->operations->swap_in((page), v)
#define swap_out(page) (page)->operations->swap_out(page)
#define destroy(page)                \
	if ((page)->operations->destroy) \
	(page)->operations->destroy(page)

/* Representation of current process's memory space.
 * We don't want to force you to obey any specific design for this struct.
 * All designs up to you for this. */
struct supplemental_page_table{
	struct hash spt_hash;
};

/* 매핑된 파일의 정보를 저장 */
struct mmap_file {
	void * mmap_addr; //
	struct file *file; //매핑하는 파일의 오브젝트
	struct list_elem elem; //mmap_file들의 리스트 연결을 위한 구조체, 리스트 헤드는 struct thread의 mmap_list
	struct list page_list; //mmap_file에 해당하는 모든 페이지들의 리스트
};

/* typedef struct hash supplemental_page_table; */

#include "threads/thread.h"

void supplemental_page_table_init(struct supplemental_page_table *spt);
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
								  struct supplemental_page_table *src);
void supplemental_page_table_kill(struct supplemental_page_table *spt);
struct page *spt_find_page(struct supplemental_page_table *spt,
						   void *va);
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page);
void spt_remove_page(struct supplemental_page_table *spt, struct page *page);

void vm_init(void);
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
						 bool write, bool not_present);

#define vm_alloc_page(type, upage, writable) \
	vm_alloc_page_with_initializer((type), (upage), (writable), NULL, NULL)
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
									bool writable, vm_initializer *init, void *aux);
void vm_dealloc_page(struct page *page);
bool vm_claim_page(void *va);
enum vm_type page_get_type(struct page *page);

/* Project 3-1 : Memory Management */
static struct frame *vm_get_frame(void);
static unsigned spt_hash_func(const struct hash_elem *e, void *aux UNUSED);
static bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

/* Helpers */
static struct frame *vm_get_victim(void);
bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

void supplemental_copy_entry(struct hash_elem *e, void *aux);
void supplemental_destroy_entry(struct hash_elem *e, void *aux);
#endif /* VM_VM_H */
