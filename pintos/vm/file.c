/* file.c: Implementation of memory backed file object (mmaped object). */

#include "threads/palloc.h"
#include "threads/thread.h"
#include "vm/vm.h"
#include "userprog/process.h"
#include "threads/vaddr.h" // ← 추가! (PGSIZE 정의)
#include "threads/mmu.h"   // ← 추가! (pml4_is_dirty,
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
    /* Set up the handler */
    page->operations = &file_ops;

    struct lazy_load_aux *aux = page->uninit.aux; // aux 읽기
    struct file_page *file_page = &page->file;    // 여기서 union 덮어씀

    file_page->file = aux->file;
    file_page->offset = aux->ofs;
    file_page->length = aux->page_read_bytes;
    file_page->mmap_total_length = aux->mmap_total_length;
    return true;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
    struct file_page *file_page = &page->file;
    off_t read_bytes;

    if (page->frame != NULL) {
        read_bytes = file_read_at(file_page->file, kva, file_page->length, file_page->offset);
        if (read_bytes < 0)
            return false;
        memset(kva + read_bytes, 0, PGSIZE - read_bytes);
    }

    return true;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
    struct file_page *file_page = &page->file;

    if (page->frame != NULL) {
        if (pml4_is_dirty(thread_current()->pml4, page->va)) {
            file_write_at(file_page->file, page->frame->kva, file_page->length, file_page->offset);
        }
        pml4_clear_page(thread_current()->pml4, page->va);
    }

    return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
    struct file_page *file_page = &page->file;
    // ★ NULL 체크 추가!
    if (file_page->file == NULL) {
        // do_munmap에서 이미 처리됨
        if (page->frame != NULL) {
            list_remove(&page->frame->elem);
            free(page->frame);
        }
        return;
    }
    // Dirty면 파일에 write-back
    if (page->frame != NULL) { // claim된 페이지만
        struct thread *curr = thread_current();

        if (pml4_is_dirty(curr->pml4, page->va)) {
            // lock_acquire(&file_lock);
            file_write_at(file_page->file, page->frame->kva, file_page->length, file_page->offset);
            // lock_release(&file_lock);
        }

        // 페이지 테이블에서 제거
        // pml4_clear_page(curr->pml4, page->va);
    }

    // 파일 닫기
    if (file_page->file != NULL) {
        // lock_acquire(&file_lock);
        file_close(file_page->file);
        // lock_release(&file_lock);
    }

    // 프레임 해제
    if (page->frame != NULL) {
        list_remove(&page->frame->elem);
        free(page->frame);
    }
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {}

/* Do the munmap */
void do_munmap(void *addr) {

    struct thread *curr = thread_current();
    struct page *first_page = spt_find_page(&curr->spt, addr);
    if (first_page == NULL)
        return;

    // Get total length from first page
    size_t total_length;

    if (first_page->operations->type == VM_FILE) {
        total_length = first_page->file.mmap_total_length;
    } else { // VM_UNINIT
        total_length = ((struct lazy_load_aux *)first_page->uninit.aux)->mmap_total_length;
    }
    size_t num_pages = (total_length + PGSIZE - 1) / PGSIZE;

    for (size_t i = 0; i < num_pages; i++) {
        void *page_addr = addr + (i * PGSIZE);
        struct page *page = spt_find_page(&curr->spt, page_addr);
        if (page == NULL)
            continue;

        if (page->operations->type == VM_FILE && page->frame != NULL) {
            struct file_page *fp = &page->file;
            if (pml4_is_dirty(curr->pml4, page->va)) {
                file_write_at(fp->file, page->frame->kva, fp->length, fp->offset);
            }
            file_close(fp->file);
            fp->file = NULL;
        }

        spt_remove_page(&curr->spt, page);
    }
}
