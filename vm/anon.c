/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "lib/kernel/bitmap.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

struct bitmap *swap_table;
struct lock swap_table_lock;

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void)
{
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);  // 1:1 - swap
	// swap disk = 4 MB, 1 swap slot = 4KB
	// swap disk = 1000 swap slot
	// SECTORS_PER_PAGE = 8 sector = 4096 (bytes) / 512 (bytes/sector)
	// lock_init(&swap_table_lock);
	disk_sector_t SECTORS_PER_PAGE = 4096 / DISK_SECTOR_SIZE;
	size_t swap_slot_num = disk_size(swap_disk) / SECTORS_PER_PAGE;

	// swap size 크기만큼 swap_table을 비트맵으로 생성
	swap_table = bitmap_create(swap_slot_num);
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva)
{
	/* Set up the handler */
	page->operations = &anon_ops;
	void *temp = &page->uninit.aux;

	struct anon_page *anon_page = &page->anon;
	anon_page->aux = temp;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in(struct page *page, void *kva)
{
	struct anon_page *anon_page = &page->anon;
	size_t sector_idx = anon_page->sector_idx;
	size_t idx = sector_idx / 8;

	for (int i = 0; i < 8; i++)
		disk_read(swap_disk, sector_idx + i, page->frame->kva + (i*512));

	// lock_acquire(&swap_table_lock);
	bitmap_set(swap_table, idx, 0);
	// lock_release(&swap_table_lock);

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out(struct page *page)
{
	struct anon_page *anon_page = &page->anon;
	struct thread *page_owner = page->frame->thread;

	// lock_acquire(&swap_table_lock);
	size_t idx = bitmap_scan(swap_table, 0, 1, 0);
	if (idx==BITMAP_ERROR){
		PANIC("스왑 디스크가 꽉 찼습니다\n");
	}
	
	disk_sector_t sector_idx = idx * 8;
	page->anon.sector_idx = sector_idx;
	for (int i = 0; i < 8; i++)
		disk_write(swap_disk, sector_idx + i, page->frame->kva + (i*512)); 
	
	pml4_clear_page(page_owner->pml4, page->va, 0);
	bitmap_set(swap_table, idx, 1);
	// lock_release(&swap_table_lock);
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy(struct page *page)
{
	struct anon_page *anon_page = &page->anon;
}