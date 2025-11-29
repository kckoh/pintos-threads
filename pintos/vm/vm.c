/* vm.c: Generic interface for virtual memory objects. */

#include "hash.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/vm.h"
#include <stddef.h>
#include <stdint.h>
#include "vm/inspect.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
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
enum vm_type page_get_type(struct page* page)
{
    int ty = VM_TYPE(page->operations->type);
    switch (ty)
    {
        case VM_UNINIT:
            return VM_TYPE(page->uninit.type);
        default:
            return ty;
    }
}

/* Helpers */
static struct frame* vm_get_victim(void);
static bool vm_do_claim_page(struct page* page);
static struct frame* vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void* upage, bool writable,
                                    vm_initializer* init, void* aux)
{
    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table* spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL)
    {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */

        /* TODO: Insert the page into the spt. */
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page* spt_find_page(struct supplemental_page_table* spt UNUSED, void* va UNUSED)
{
    ASSERT(spt != NULL);
    struct page page;
    page.va = pg_round_down(va);
    struct hash_elem* hash_elem = hash_find(&spt->spt, &page.hash_elem);
    return hash_elem != NULL ? hash_entry(hash_elem, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table* spt UNUSED, struct page* page UNUSED)
{
    ASSERT(spt != NULL);
    ASSERT(page != NULL);
    return hash_insert(&spt->spt, &page->hash_elem) == NULL;
}

void spt_remove_page(struct supplemental_page_table* spt, struct page* page)
{
    vm_dealloc_page(page);
    // return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame* vm_get_victim(void)
{
    struct frame* victim = NULL;
    /* TODO: The policy for eviction is up to you. */

    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame* vm_evict_frame(void)
{
    struct frame* victim UNUSED = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */

    return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame* vm_get_frame(void)
{
    struct frame* frame = malloc(sizeof(struct frame));
    if (frame == NULL)
    {
        PANIC("frame allocation failed");
    }
    frame->kva = palloc_get_page(PAL_USER);
    if (frame->kva == NULL)
    {
        // TODO: eviction 구현 (나중에)
        free(frame);
        PANIC("todo: implement eviction");
    }
    frame->page = NULL;
    return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void* addr UNUSED) {}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page* page UNUSED) {}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame* f UNUSED, void* addr UNUSED, bool user UNUSED,
                         bool write UNUSED, bool not_present UNUSED)
{
    struct supplemental_page_table* spt UNUSED = &thread_current()->spt;
    struct page* page = NULL;
    /* TODO: Validate the fault */
    /* TODO: Your code goes here */

    return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page* page)
{
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void* va UNUSED)
{
    ASSERT(pg_ofs(va) == 0);

    struct page* page = spt_find_page(&thread_current()->spt, va);
    if (page == NULL)
    {
        return false;
    }
    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page* page)
{
    ASSERT(page != NULL);
    ASSERT(page->frame == NULL);

    struct frame* frame = vm_get_frame();
    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable))
    {
        free(frame);
        return false;
    }

    return swap_in(page, frame->kva);
}

/*페이지를 넣을때 어느 버킷에 넣을지 결정하는 함수*/
static uint64_t hash_fun(const struct hash_elem* e, void* aux)
{
    struct page* page = hash_entry(e, struct page, hash_elem);
    return hash_bytes(&page->va, sizeof page->va);
}

/*버킷 안에서의 순서를 결정하기 위해 페이지들을 비교해주는 함수*/
static bool less_fun(const struct hash_elem* a, const struct hash_elem* b, void* aux)
{
    struct page* page_a = hash_entry(a, struct page, hash_elem);
    struct page* page_b = hash_entry(b, struct page, hash_elem);
    return (uintptr_t)page_a->va < (uintptr_t)page_b->va;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table* spt UNUSED)
{
    hash_init(&spt->spt, hash_fun, less_fun, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table* dst UNUSED,
                                  struct supplemental_page_table* src UNUSED)
{
    return false;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table* spt UNUSED)
{
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
}
