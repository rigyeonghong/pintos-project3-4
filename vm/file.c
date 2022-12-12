/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/file.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;
	struct file_info *temp = (struct file_info *) page->uninit.aux;
	// printf("page_read_bytes: %d\n", temp->read_bytes);
	// printf("page_zero_bytes: %d\n", temp->zero_bytes);

	struct file_page *file_page = &page->file;
	file_page->aux = temp;

	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	struct thread *page_owner = page->frame->thread;
	struct file_info *aux = (struct file_info *) page->file.aux;
	/* 내용 읽어오고 */
	// 여기 커널?
	// printf("kva: %p\n", kva);
	// printf("aux: %p\n", aux);
	// printf("aux->read_bytes: %x\n", aux->read_bytes);
	// printf("aux->zero_bytes: %x\n", aux->zero_bytes);
	// printf("aux->offset: %x\n", aux->offset);

	int result = file_read_at(aux->file, page->frame->kva, aux->read_bytes, aux->offset);
	// printf("result: %d\n", result);
	if (result != (int)aux->read_bytes)
	{
		// printf("file_backed_swap_in: false\n");
		return false;
	}
	// printf("11\n");

	memset(page->frame->kva + aux->read_bytes, 0, aux->zero_bytes);

	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	struct thread *page_owner = page->frame->thread;
	struct file_info *aux = &page->file.aux;

	if (pml4_is_dirty(page_owner->pml4, page->va)){
		file_write_at(aux->file, page->va, aux->read_bytes, aux->offset);
		pml4_set_dirty(page_owner->pml4, page->va, 0);
	}
	pml4_clear_page(page_owner->pml4, page->va);
	//spt_remove(&page_owner->spt, page);
	// swap-in할때 내쫓은 애 다시 돌아와야 하는데 어케 하지?
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;

}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {

	void *origin_addr = addr;
	uint32_t read_bytes = length;
	uint32_t zero_bytes = (length%PGSIZE == 0) ? 0 : PGSIZE - (length % PGSIZE);
	// printf("length: %d\n", length);
	// printf("read bytes: %d\n", read_bytes);
	// printf("zero bytes: %d\n", zero_bytes);

	struct mmap_file *m_file = (struct mmap_file *)malloc(sizeof(struct mmap_file));
	m_file->mmap_addr = origin_addr;
	m_file->file = file;
	list_init(&m_file->page_list);
	// struct list p_list;
	// list_init(&p_list);

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		// printf("offset: %p\n", offset);

		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		// printf("read bytes: %d\n", read_bytes);

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		struct file_info *aux_file_info;
		aux_file_info = (struct file_info *)malloc(sizeof(struct file_info));
		aux_file_info->file = file;
		aux_file_info->offset = offset;
		aux_file_info->read_bytes = page_read_bytes;
		aux_file_info->zero_bytes = page_zero_bytes;
		aux_file_info->writable = writable;

		// printf("page_read_bytes: %d\n", page_read_bytes);
		// printf("page_zero_bytes: %d\n", page_zero_bytes);
		if (!vm_alloc_page_with_initializer(VM_FILE, addr,
											writable, lazy_load_segment, (void *)aux_file_info))
		{
			// printf("alloc 실패!");
			return NULL;
		}
		// printf("alloc 성공!\n");
		struct page *p = spt_find_page(&thread_current()->spt, addr);
		list_push_back(&m_file->page_list, &p->mmap_elem);
		// printf("[mmap] pe: %p\n", &p->mmap_elem);

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}

	if (list_empty(&m_file->page_list)){
		// printf("페이지 없다\n");
		free(m_file);
	}

		// printf("mmap list : %p\n", &thread_current()->mmap_list);
		// printf("mmap_list end: %p\n", list_end(&thread_current()->mmap_list));
		// printf("mfile elem : %p\n", &m_file->elem);
	list_push_back(&thread_current()->mmap_list, &m_file->elem);
	// printf("tid: %d\n", thread_current()->tid);
	// printf("mmap list : %p\n", &thread_current()->mmap_list);

	return origin_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	// printf("addr in munmap = %p\n", addr);

	/*
	1) addr에 대한 매핑 해제 (addr은 동일 프로세스에서 mmap으로 반환된 va)
	2) 프로세스에 의해 기록된 모든 페이지가 파일에 다시 기록되며, 쓰지 않은 페이지는 기록 x
	3) 가상 페이지 목록에서 페이지 제거
	*/
	struct list_elem *e = list_begin(&thread_current()->mmap_list);
	struct mmap_file *e_file;
	struct thread *cur = thread_current();
	// printf("thread tid: %d\n",cur->tid);

	while (e != list_end(&cur->mmap_list))
	{
		e_file = list_entry(e, struct mmap_file, elem);
		// printf("[1]\n");

		if (e_file->mmap_addr == addr)
		{
			// printf("[2]\n");
			struct list *p_list = &e_file->page_list;
			struct list_elem *pe;
			struct page *p;
			// printf("[3]\n");

			for (pe = list_begin(p_list); pe != list_tail(p_list); )
			{
				// printf("[munmap] pe: %p\n", pe);
				// printf("[munmap] p_list: %p\n", &p_list);
				// printf("[munmap] list_end: %p\n", list_end(&p_list));
				// printf("[munmap] list_head %p\n", &p_list.head);
				// printf("[munmap] list_tail %p\n", &p_list.tail);
				p = list_entry(pe, struct page, mmap_elem);
				struct file_info *aux = p->file.aux;
				// printf("[4]\n");
				// list_remove(pe);
				// printf("[5]\n");

				if (pml4_is_dirty(cur->pml4, p->va))
				{
					// printf("[6]\n");
					file_write_at(e_file->file, p->va, aux->read_bytes, aux->offset);
					pml4_set_dirty(cur->pml4, p->va, 0);
				}
				// printf("[7]\n");
				pml4_clear_page(cur->pml4, p->va);
				// printf("[8]\n");
				struct page *before_p = p;
				pe = list_remove(pe);
				spt_remove_page(&cur->spt, before_p);
				// printf("[9]\n");
				
			}
			// printf("탈출!\n");

			return;
		}
	}

}