/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

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
	void *temp = &page->uninit.aux;

	struct file_page *file_page = &page->file;
	file_page->aux = temp;

	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
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
	uint32_t zero_bytes = (length==PGSIZE) ? 0 : PGSIZE - (length % PGSIZE);
	// printf("length: %d\n", length);
	// printf("read bytes: %d\n", read_bytes);
	// printf("zero bytes: %d\n", zero_bytes);

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
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

		if (!vm_alloc_page_with_initializer(VM_FILE, addr,
											writable, lazy_load_segment, (void *)aux_file_info))
		{
			// printf("alloc 실패!");
			return NULL;
		}
		// printf("alloc 성공!\n");
		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}
	// printf("성공\n");
	return origin_addr;
}

/* Do the munmap */
// void
// do_munmap (void *addr) {
// 	printf("addr in munmap = %p\n", addr);
// 	struct supplemental_page_table *cur_spt = &thread_current()->spt;
// 	spt_remove_page(cur_spt, spt_find_page(cur_spt, addr));

// }

// void do_munmap(void *addr)
// {
// 	while (true)
// 	{
// 		struct thread *curr = thread_current();
// 		struct page *find_page = spt_find_page(&curr->spt, addr);
// 		struct frame *find_frame = find_page->frame;
// 		printf("addr in munmap = %p\n", addr);
// 		if (find_page == NULL)
// 		{
// 			return NULL;
// 		}

// 		// // 연결 해제
// 		// find_page->frame = NULL;
// 		// find_frame->page = NULL;

// 		struct file_info *container = (struct file_info *)find_page->uninit.aux;
// 		// 페이지의 dirty bit이 1이면 true를, 0이면 false를 리턴한다.
// 		if (pml4_is_dirty(&curr->pml4, find_page->va) == true)
// 		{
// 			// 물리 프레임에 변경된 데이터를 다시 디스크 파일에 업데이트 buffer에 있는 데이터를 size만큼, file의 file_ofs부터 써준다.
// 			file_write_at(container->file, addr, container->read_bytes, container->offset);
// 			// dirty bit = 0
// 			// 인자로 받은 dirty의 값이 1이면 page의 dirty bit을 1로, 0이면 0으로 변경해준다.
// 			pml4_set_dirty(curr->pml4, find_page->va, 0);
// 		}
// 		// dirty bit = 0
// 		// 인자로 받은 dirty의 값이 1이면 page의 dirty bit을 1로, 0이면 0으로 변경해준다.

// 		// present bit = 0
// 		// 페이지의 present bit 값을 0으로 만들어주는 함수
// 		pml4_clear_page(curr->pml4, find_page->va);
// 		addr += PGSIZE;
// 	}
// }
