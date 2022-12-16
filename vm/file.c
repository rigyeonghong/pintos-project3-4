/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "userprog/syscall.h"

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
	// lock_acquire(&filesys_lock);
	int result = file_read_at(aux->file, page->frame->kva, aux->read_bytes, aux->offset);
	// lock_release(&filesys_lock);

	if (result != (int)aux->read_bytes)
	{
		return false;
	}

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
		// lock_acquire(&filesys_lock);
		file_write_at(aux->file, page->va, aux->read_bytes, aux->offset);
		// lock_release(&filesys_lock);
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

	struct mmap_file *m_file = (struct mmap_file *)malloc(sizeof(struct mmap_file));
	m_file->mmap_addr = origin_addr;
	m_file->file = file;
	list_init(&m_file->page_list);

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */

		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		struct file_info *aux_file_info;
		aux_file_info = (struct file_info *)malloc(sizeof(struct file_info));
		aux_file_info->file = file;
		aux_file_info->offset = offset;
		aux_file_info->read_bytes = page_read_bytes;
		aux_file_info->zero_bytes = page_zero_bytes;
		aux_file_info->writable = writable;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr,
											writable, lazy_load_segment, (void *)aux_file_info))
		{
			return NULL;
		}
		struct page *p = spt_find_page(&thread_current()->spt, addr);
		list_push_back(&m_file->page_list, &p->mmap_elem);

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}

	if (list_empty(&m_file->page_list)){
		free(m_file);
	}

	list_push_back(&thread_current()->mmap_list, &m_file->elem);

	return origin_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {

	/*
	1) addr에 대한 매핑 해제 (addr은 동일 프로세스에서 mmap으로 반환된 va)
	2) 프로세스에 의해 기록된 모든 페이지가 파일에 다시 기록되며, 쓰지 않은 페이지는 기록 x
	3) 가상 페이지 목록에서 페이지 제거
	*/
	struct list_elem *e = list_begin(&thread_current()->mmap_list);
	struct mmap_file *e_file;
	struct thread *cur = thread_current();

	while (e != list_end(&cur->mmap_list))
	{
		e_file = list_entry(e, struct mmap_file, elem);

		if (e_file->mmap_addr == addr)
		{
			struct list *p_list = &e_file->page_list;
			struct list_elem *pe;
			struct page *p;

			for (pe = list_begin(p_list); pe != list_tail(p_list); )
			{
				p = list_entry(pe, struct page, mmap_elem);
				struct file_info *aux = p->file.aux;


				if (pml4_is_dirty(cur->pml4, p->va))
				{
					// lock_acquire(&filesys_lock);
					file_write_at(e_file->file, p->va, aux->read_bytes, aux->offset);
					// lock_release(&filesys_lock);
					pml4_set_dirty(cur->pml4, p->va, 0);
				}
				pml4_clear_page(cur->pml4, p->va);
				struct page *before_p = p;
				pe = list_remove(pe);
				spt_remove_page(&cur->spt, before_p);
				
			}
			file_close(e_file->file);
			list_remove(e);
			return;
		}
		e = list_next(e);
	}
}