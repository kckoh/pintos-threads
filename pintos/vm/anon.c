/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "bitmap.h"
#include "devices/disk.h"
#include "threads/mmu.h"
#include "threads/thread.h"
#include "vm/vm.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
    .swap_in = anon_swap_in,
    .swap_out = anon_swap_out,
    .destroy = anon_destroy,
    .type = VM_ANON,
};

static struct bitmap *swap_table;

/* Initialize the data for anonymous pages */
void vm_anon_init(void) {
    /* TODO: Set up the swap_disk. */
    swap_disk = disk_get(1, 1);
    swap_table = bitmap_create(disk_size(swap_disk) / 8);
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &anon_ops;

    struct anon_page *anon_page = &page->anon;

    return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool anon_swap_in(struct page *page, void *kva) {
    struct anon_page *anon_page = &page->anon;

    for (int i = 0; i < 8; i++) {
        disk_read(swap_disk, anon_page->swap_slot_idx * 8 + i, kva + DISK_SECTOR_SIZE * i);
    }

    bitmap_set(swap_table, anon_page->swap_slot_idx, false);

    return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool anon_swap_out(struct page *page) {
    struct anon_page *anon_page = &page->anon;

    anon_page->swap_slot_idx = bitmap_scan_and_flip(swap_table, 0, 1, false);
    if (anon_page->swap_slot_idx == BITMAP_ERROR)
        return false;

    for (int i = 0; i < 8; i++) {
        disk_write(swap_disk, anon_page->swap_slot_idx * 8 + i,
                   page->frame->kva + DISK_SECTOR_SIZE * i);
    }

    pml4_clear_page(thread_current()->pml4, page->va);

    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void anon_destroy(struct page *page) {
    struct anon_page *anon_page = &page->anon;
}
