/* vm.c: Generic interface for virtual memory objects. */

#include <stdio.h>
#include "vm/vm.h"
#include <string.h>
#include "threads/synch.h"
#include "vm/anon.h"
#include "vm/file.h"
#include "vm/uninit.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "vm/inspect.h"
#include "vm/vm_type.h"

extern struct lock file_lock;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void) {
    vm_anon_init();
    vm_file_init();
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page *page) {
    int ty = VM_TYPE(page->operations->type);
    switch (ty) {
    case VM_UNINIT:
        return VM_TYPE(page->uninit.type);
    default:
        return ty;
    }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
/* 초기화 함수와 함께 대기 중인 페이지 객체를 생성. 페이지를 생성하려면
 * 직접 생성하지 말고 이 함수나 `vm_alloc_page`를 통해 생성해야 함. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux) {

    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    /* upage가 이미 사용 중인지 확인 */
    if (spt_find_page(spt, upage) == NULL) {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */
        /* TODO: 페이지를 생성하고, VM 타입에 따라 초기화 함수를 가져온 다음,
         * TODO: uninit_new를 호출하여 "uninit" 페이지 구조체를 생성.
         * TODO: uninit_new 호출 후 필드를 수정해야 함. */

        struct page *page = malloc(sizeof(struct page));
        if (page == NULL)
            goto err;

        bool (*page_initializer)(struct page *, enum vm_type, void *);
        switch (VM_TYPE(type)) {
        case VM_ANON:
            page_initializer = anon_initializer;
            break;
        case VM_FILE:
            page_initializer = file_backed_initializer;
            break;
        default:
            free(page);
            goto err;
        }

        uninit_new(page, upage, init, type, aux, page_initializer);

        page->writable = writable;

        if (!spt_insert_page(spt, page)) {
            free(page);
            goto err;
        }
    }
    return true;
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt, void *va) {
    struct page p;
    struct hash_elem *e;

    /* TODO: Fill this function. */
    p.va = pg_round_down(va);

    e = hash_find(&spt->spt, &p.elem);

    return e != NULL ? hash_entry(e, struct page, elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {

    struct hash_elem *e = hash_insert(&spt->spt, &page->elem);

    return e == NULL;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
    vm_dealloc_page(page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void) {
    struct frame *victim = NULL;
    /* TODO: The policy for eviction is up to you. */

    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void) {
    struct frame *victim UNUSED = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */

    return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *vm_get_frame(void) {
    struct frame *frame = malloc(sizeof(struct frame));
    /* TODO: Fill this function. */
    // get the page
    if (!frame) {
        PANIC("Failure to allocate");
    }

    frame->kva = palloc_get_page(PAL_USER);

    if (!frame->kva) {
        // TODO: do eviction later
        free(frame);
        PANIC("todo");
    }

    frame->page = NULL;

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}

/* Growing the stack. */
static bool vm_stack_growth(void *addr UNUSED) {
    void *page_addr = pg_round_down(addr);

    if (!vm_alloc_page(VM_ANON | VM_MARKER_0, page_addr, true))
        return false;

    if (!vm_claim_page(page_addr))
        return false;

    return true;
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write,
                         bool not_present UNUSED) {
    struct thread *curr_thread = thread_current();
    struct supplemental_page_table *spt = &curr_thread->spt;

    if (addr == NULL || !is_user_vaddr(addr))
        return false;
    /* TODO: Validate the fault */
    /* TODO: Your code goes here */
    // 접근하려는 va에 페이지가 존재 하는지 확인
    struct page *page = spt_find_page(spt, addr);
    // 페이지가 존재한다면 lazy loading  임으로 프레임 할당 후 연결
    if (page) {
        if (write && !page->writable)
            return false;

        return vm_do_claim_page(page);
    }
    // 페이지가 없다면 스택 확징이 필요한지 체크
    else {
        uintptr_t rsp = user ? f->rsp : curr_thread->user_stack_rsp;

        // 스택 확장이 가능한 주소 범위 접근이면 스택 확장
        if (addr < USER_STACK && addr >= USER_STACK - (1 << 20) &&
            addr >= (void *)((uint8_t *)rsp - 8)) {
            return vm_stack_growth(addr);
        }
        // 아니면 그냥 폴트 임으로 실패 처리
        return false;
    }
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va) {
    struct page *page = NULL;

    // Claims the page to allocate va. You will first need to get a page and then
    // calls vm_do_claim_page with the page.

    page = spt_find_page(&thread_current()->spt, va);

    if (!page)
        return false;

    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page *page) {
    struct frame *frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)) {
        // Failed to set page table entry, clean up
        return false;
    }

    return swap_in(page, frame->kva);
}

/* Hash function for supplemental page table */
static uint64_t page_hash(const struct hash_elem *e, void *aux UNUSED) {
    const struct page *p = hash_entry(e, struct page, elem);
    return hash_bytes(&p->va, sizeof(p->va));
}

/* Comparison function for supplemental page table */
static bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    const struct page *page_a = hash_entry(a, struct page, elem);
    const struct page *page_b = hash_entry(b, struct page, elem);
    return page_a->va < page_b->va;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt) {
    hash_init(&spt->spt, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src) {

    struct hash_iterator i;
    hash_first(&i, &src->spt);
    while (hash_next(&i)) {
        struct page *page = hash_entry(hash_cur(&i), struct page, elem);
        switch (page->operations->type) {
        case VM_UNINIT: {
            struct uninit_page *uninit = &page->uninit;
            void *aux = uninit->aux;

            struct lazy_load_aux *old_aux = (struct lazy_load_aux *)aux;
            struct lazy_load_aux *new_aux = malloc(sizeof(struct lazy_load_aux));
            if (new_aux == NULL)
                return false;

            memcpy(new_aux, old_aux, sizeof(struct lazy_load_aux));
            lock_acquire(&file_lock);
            new_aux->file = file_reopen(old_aux->file);
            lock_release(&file_lock);
            aux = new_aux;

            if (!vm_alloc_page_with_initializer(uninit->type, page->va, page->writable,
                                                uninit->init, aux))
                return false;
            break;
        }
        case VM_FILE:
            if (!vm_alloc_page_with_initializer(page->operations->type, page->va, page->writable,
                                                NULL, NULL))
                return false;
            break;
        case VM_ANON:
            if (!vm_alloc_page_with_initializer(page->operations->type, page->va, page->writable,
                                                NULL, NULL))
                return false;
            break;
        default:
            return false;
        }

        if (page->operations->type != VM_UNINIT) {
            if (page->frame != NULL) {
                if (!vm_claim_page(page->va))
                    return false;
                memcpy(spt_find_page(dst, page->va)->frame->kva, page->frame->kva, PGSIZE);
            }
        }
    }
    return true;
}

void page_destructor(struct hash_elem *e, void *aux) {
    struct page *page = hash_entry(e, struct page, elem);

    // 페이지의 destroy 함수 호출
    vm_dealloc_page(page);
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
    hash_destroy(&spt->spt, page_destructor);
}
