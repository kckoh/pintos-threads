/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/file.h"
#include "filesys/file.h"
#include "devices/disk.h"
#include "filesys/off_t.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "vm/vm.h"
#include "threads/mmu.h"
#include "list.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/uninit.h"
#include "vm/vm_type.h"
#include "userprog/process.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void) {}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva) {

    struct uninit_page *uninit = &page->uninit;
    struct lazy_load_aux *aux = uninit->aux;

    struct file *file = aux->file;
    off_t offset = aux->ofs;
    size_t read_bytes = aux->page_read_bytes;
    size_t zero_bytes = aux->page_zero_bytes;

    page->operations = &file_ops;

    struct file_page *file_page = &page->file;
    file_page->file = file;
    file_page->offset = offset;
    file_page->read_bytes = read_bytes;
    file_page->zero_bytes = zero_bytes;

    return true;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
    struct file_page *file_page = &page->file;

    off_t read_bytes = file_read_at(file_page->file, kva, file_page->read_bytes, file_page->offset);
    if (read_bytes < 0) {
        return false;
    }

    memset(kva + read_bytes, 0, PGSIZE - read_bytes);
    return true;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
    struct file_page *file_page = &page->file;
    return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {

    if (addr == 0 || pg_ofs(addr) != 0 || length == 0 || file_length(file) == 0 ||
        file_length(file) <= offset)
        goto error;

    file = file_reopen(file);
    if (file == NULL)
        goto error;

    struct mmap_info *info = malloc(sizeof(struct mmap_info));
    if (info == NULL)
        goto error;
    info->file = file;
    info->addr = addr;
    info->length = length;

    void *current_addr = addr;
    off_t current_offset = offset;
    size_t remain_length = length;

    while (remain_length > 0) {
        size_t page_read_bytes = remain_length < PGSIZE ? remain_length : PGSIZE;

        struct lazy_load_aux *aux = malloc(sizeof(struct lazy_load_aux));
        if (aux == NULL)
            goto error;
        aux->file = file;
        aux->ofs = current_offset;
        aux->page_read_bytes = page_read_bytes;
        aux->page_zero_bytes = PGSIZE - page_read_bytes;

        if (!vm_alloc_page_with_initializer(VM_FILE, current_addr, writable, lazy_load_segment, aux)) {
            for (void *i = addr; i < current_addr; i += PGSIZE) {
                struct page *cleanup_page = spt_find_page(&thread_current()->spt, i);
                if (cleanup_page)
                    spt_remove_page(&thread_current()->spt, cleanup_page);
            }
            free(aux);
            goto error;
        }

        current_offset += page_read_bytes;
        remain_length -= page_read_bytes;
        current_addr += PGSIZE;
    }

    list_push_back(&thread_current()->mmap_list, &info->elem);

    return addr;

error:

    if (file)
        file_close(file);

    if (info)
        free(info);

    return NULL;
}

/* Do the munmap */
void do_munmap(void *addr) {

    if (addr == 0 || pg_ofs(addr) != 0)
        return;

    struct mmap_info *info = NULL;
    for(struct list_elem *i = list_begin(&thread_current()->mmap_list); i != list_end(&thread_current()->mmap_list); i = list_next(i)){
        struct mmap_info *temp = list_entry(i, struct mmap_info, elem);
        if(info != NULL && info->addr == addr){
            info = temp;
            break;
        }
    }

    if(info == NULL) return;

    void *current_addr = info->addr;
    void *max_addr = current_addr + info->length;
    size_t remain_length = info->length;

    for(void *i = current_addr; i < max_addr; i += PGSIZE){
        struct page *current_page = spt_find_page(&thread_current()->spt, i);
        if(current_page == NULL) continue;
        if(VM_TYPE(current_page->operations->type) != VM_FILE) continue;

        struct file_page *current_file_page = &current_page->file;

        if(current_page->frame != NULL && pml4_is_dirty(thread_current()->pml4, i)){
            size_t page_write_bytes = remain_length < PGSIZE ? remain_length : PGSIZE;
            file_write_at(info->file, current_page->frame->kva, page_write_bytes, current_file_page->offset);
        }

        remain_length -= PGSIZE;
    }

    file_close(info->file);
    list_remove(&info->elem);
    free(info);
}
