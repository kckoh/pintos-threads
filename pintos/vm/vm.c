/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"
#include "filesys/file.h"
#include "hash.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "vm/inspect.h"
#include "vm/uninit.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

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
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux) {

    ASSERT(VM_TYPE(type) != VM_UNINIT);

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL) {

        struct page *p = malloc(sizeof(struct page));
        if (p == NULL)
            goto err;

        bool (*page_initializer)(struct page *, enum vm_type, void *kva);
        switch (VM_TYPE(type)) {
        case VM_FILE:
            page_initializer = file_backed_initializer;
            break;
        case VM_ANON:
            page_initializer = anon_initializer;
            break;
        default:
            free(p);
            goto err;
        }

        uninit_new(p, upage, init, type, aux, page_initializer);

        p->writable = writable;

        if (!spt_insert_page(spt, p)) {
            free(p);
            goto err;
        }

        return true;
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
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
        PANIC("OUT OF MEMORY");
    }

    frame->page = NULL;

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr UNUSED) {}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write,
                         bool not_present) {

    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *page = NULL;

    page = spt_find_page(spt, addr);
    if (page == NULL) {
        return false;
    }

    return vm_do_claim_page(page);
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

    struct hash *p_spt_hash = &src->spt;
    struct hash_iterator parent_iterator;

    hash_first(&parent_iterator, p_spt_hash);

    while (hash_next(&parent_iterator)) {
        struct hash_elem *p_elem = hash_cur(&parent_iterator);
        struct page *p_page = hash_entry(p_elem, struct page, elem);
        enum vm_type type = page_get_type(p_page);
        vm_initializer *init;
        void *aux;

        if (type == VM_TYPE(VM_UNINIT)) {
            struct lazy_load_info *p_info = p_page->uninit.aux;
            struct lazy_load_info *c_info = malloc(sizeof(struct lazy_load_info));
            if (c_info == NULL)
                return false;

            lock_acquire(&file_lock);
            c_info->file = file_reopen(p_info->file);
            lock_release(&file_lock);
            c_info->ofs = p_info->ofs;
            c_info->read_bytes = p_info->read_bytes;
            c_info->zero_bytes = p_info->zero_bytes;

            type = p_page->uninit.type;
            init = p_page->uninit.init;
            aux = c_info;
        } else {
            init = NULL;
            aux = NULL;
        }

        if (!vm_alloc_page_with_initializer(type, p_page->va, p_page->writable, init, aux)) {
            if (type == VM_TYPE(VM_UNINIT))
                free(aux);
            return false;
        }

        if (type != VM_TYPE(VM_UNINIT)) {
            if (p_page->frame != NULL) {
                if (!vm_claim_page(p_page->va))
                    return false;
                struct page *c_page = spt_find_page(dst, p_page->va);
                if (c_page == NULL || c_page->frame == NULL)
                    return false;
                memcpy(c_page->frame->kva, p_page->frame->kva, PGSIZE);
            }
        }
    }

    return true;
}

static void hash_page_destroy(struct hash_elem *d_elem, void *aux) {
    struct page *d_page = hash_entry(d_elem, struct page, elem);
    destroy(d_page);
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt) {
    hash_destroy(&spt->spt, hash_page_destroy);
}