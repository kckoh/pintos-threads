/* file.c: Implementation of memory backed file object (mmaped object). */

#include "stdbool.h"
#include "vm/vm.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "lib/kernel/list.h"
#include "vm/vm_type.h"
#include <stdlib.h>

extern struct lock file_lock;

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
    struct file_page *file_page = &page->file;
    struct lazy_load_aux *aux = page->uninit.aux;
    page->file.file = aux->file;
    page->file.ofs = aux->ofs;

    return true;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
    struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
    struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
    struct file_page *file_page = &page->file;

    // mmap 페이지일때 더티 페이지 확인
    if (page->operations->type & VM_MARKER_1) {
        if (page->frame && pml4_is_dirty(thread_current()->pml4, page->va)) {
            file_write_at(file_page->file, page->frame->kva, PGSIZE, file_page->ofs);
        }
    }

    // 프레임 있으면 해제
    if (page->frame) {
        palloc_free_page(page->frame->kva);
        free(page->frame);
    }
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {
    struct thread *curr_thread = thread_current();

    // 기존 페이지와 충돌 검사
    void *u_page = addr;
    void *end_page = pg_round_down(addr + length);
    while (u_page <= end_page) {
        if (spt_find_page(&curr_thread->spt, u_page) != NULL)
            return NULL;
        u_page += PGSIZE;
    }

    // file_reopen
    lock_acquire(&file_lock);
    struct file *mmap_file = file_reopen(file);
    lock_release(&file_lock);
    if (!mmap_file)
        return NULL;

    // 스레드에 mmap 정보 저장을 위한 구조체
    struct mmap_entry *mmap_entry = malloc(sizeof(struct mmap_entry));
    if (!mmap_entry)
        return NULL;
    mmap_entry->addr = addr;
    mmap_entry->length = length;
    mmap_entry->offset = offset;
    mmap_entry->file = mmap_file;
    list_push_back(&curr_thread->mmap_list, &mmap_entry->elem);

    // 페이지를 먼저 다 생성
    size_t page_count = (pg_round_up(addr + length) - pg_round_down(addr)) / PGSIZE;

    struct page **pages = malloc(sizeof(struct page *) * page_count);
    if (!pages)
        return NULL;

    void *start_page = addr;
    size_t i = 0;
    while (start_page <= end_page) {
        size_t read_bytes = length < PGSIZE ? length : PGSIZE;
        size_t zero_bytes = PGSIZE - read_bytes;

        struct page *page = malloc(sizeof(struct page));
        if (page == NULL)
            goto cleanup;

        struct lazy_load_aux *aux = malloc(sizeof(struct lazy_load_aux));
        if (!aux) {
            free(page);
            goto cleanup;
        }

        aux->file = mmap_file;
        aux->ofs = offset;
        aux->page_read_bytes = read_bytes;
        aux->page_zero_bytes = zero_bytes;

        uninit_new(page, start_page, lazy_load_segment, VM_FILE | VM_MARKER_1, aux,
                   file_backed_initializer);
        page->writable = writable;

        pages[i++] = page;

        start_page += PGSIZE;
        offset += read_bytes;
        length -= read_bytes;
    }

    // 페이지가 문제 없이 다 생성되었으면 spt에 삽입
    for (size_t j = 0; j < i; j++) {
        if (!spt_insert_page(&curr_thread->spt, pages[j])) {
            goto cleanup_inserted;
        }
    }
    free(pages);

    return addr;

cleanup_inserted:
    // spt에 삽입중 실패 할경우 spt에 들어 간 것들 다 삭제
    for (size_t j = 0; j < i; j++) {
        spt_remove_page(&curr_thread->spt, pages[j]);
    }

cleanup:
    // 생성된 페이지들 모두 삭제
    for (size_t j = 0; j < i; j++) {
        free(pages[j]->uninit.aux);
        free(pages[j]);
    }

    free(pages);

    lock_acquire(&file_lock);
    file_close(mmap_file);
    lock_release(&file_lock);

    return NULL;
}

/* Do the munmap */
void do_munmap(void *addr) {
    struct thread *curr_thread = thread_current();

    // addr의 mmap 정보 찾기
    struct list_elem *e;
    struct mmap_entry *mmap_entry;
    for (e = list_begin(&curr_thread->mmap_list); e != list_end(&curr_thread->mmap_list);
         e = list_next(e)) {
        mmap_entry = list_entry(e, struct mmap_entry, elem);
        if (mmap_entry->addr == addr) {
            break;
        }
    }

    if (e == list_end(&curr_thread->mmap_list)) {
        return;
    }

    // 페이지를 삭제
    size_t page_count = (pg_round_up(addr + mmap_entry->length) - pg_round_down(addr)) / PGSIZE;

    for (size_t i = 0; i < page_count; i++) {
        spt_remove_page(&curr_thread->spt, addr + i * PGSIZE);
    }

    // 파일 포인터 닫기
    lock_acquire(&file_lock);
    file_close(mmap_entry->file);
    lock_release(&file_lock);

    // mmap_entry 삭제
    list_remove(&mmap_entry->elem);
    free(mmap_entry);
}
