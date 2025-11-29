/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"

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

/* NOTE : spt_find */
struct page* spt_find_page(struct supplemental_page_table* spt UNUSED, void* va UNUSED)
{
    struct page page;
    page.va = va;

    struct hash_elem* result_elem = hash_find(&spt->hash_table, &page.hash_elem);
    if (result_elem == NULL) return NULL;

    struct page* result_page = hash_entry(result_elem, struct page, hash_elem);

    return result_page;
}

/* NOTE : spt_insert */
bool spt_insert_page(struct supplemental_page_table* spt UNUSED, struct page* page UNUSED)
{
    int succ = false;

    if (!hash_insert(&spt->hash_table, &page->hash_elem)) succ = true;

    return succ;
}

void spt_remove_page(struct supplemental_page_table* spt, struct page* page)
{
    vm_dealloc_page(page);
    return true;
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

/* palloc()을 호출하여 프레임을 가져옵니다. 가용한 페이지가 없다면,
 * 페이지를 축출(evict)하고 해당 프레임을 반환합니다.
 * 이 함수는 항상 유효한 주소를 반환해야 합니다.
 * 즉, 사용자 풀(user pool) 메모리가 가득 찼다면,
 * 이 함수는 가용 메모리 공간을 확보하기 위해 프레임을 축출합니다. */
static struct frame* vm_get_frame(void)
{
    struct frame* frame = malloc(sizeof(struct frame));
    if (frame == NULL) PANIC("todo -> swap_out");

    frame->kva = palloc_get_page(PAL_USER);
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
/* NOTE: vm_claim_page */
bool vm_claim_page(void* va UNUSED)
{
    struct thread *curr = thread_current();

    struct page *page = spt_find_page(&curr->spt, va);
    if(page == NULL) return false;

    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
/* NOTE: vm_do_claim_page */
static bool vm_do_claim_page(struct page* page)
{
    struct frame* frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)) return false;

    return swap_in(page, frame->kva);
}

/* NOTE : spt_init */
void supplemental_page_table_init(struct supplemental_page_table* spt UNUSED)
{
    if (!hash_init(&spt->hash_table, page_hash, page_less, NULL))
    {
        PANIC("Hash table initialization failed");
    }
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table* dst UNUSED,
                                  struct supplemental_page_table* src UNUSED)
{
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table* spt UNUSED)
{
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
}