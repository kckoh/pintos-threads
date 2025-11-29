#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stdbool.h"
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/malloc.h"
#ifdef VM
#include "vm/vm.h"
#endif

#include "include/threads/synch.h"
#include <list.h>

static void process_cleanup(void);
static bool load(const char** argv, int argc, struct intr_frame* if_);
static void initd(void* aux);
static void __do_fork(void*);

extern struct lock file_lock;

/* General process initializer for initd and other process. */
static void process_init(void)
{
    struct thread* curr = thread_current();
    /* 프로세스에 필요한 구조체 여기서 만들어야함.*/
    // initialize the fd_table + size
    curr->fd_table = calloc(FD_TABLE_SIZE, sizeof(struct file*));
    curr->fd_capacity = FD_TABLE_SIZE;
    if (curr->fd_table == NULL)
    {
        PANIC("Failed to allocate file descriptor table");
    }
    // initialize the STD_IN and STD_OUT
    curr->fd_table[0] = (struct file*)STDIN_FILENO;
    curr->fd_table[1] = (struct file*)STDOUT_FILENO;
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */

struct initd_arg
{
    char* fn_copy;
    struct child* c;
};

tid_t process_create_initd(const char* file_name)
{
    struct thread* parent = thread_current();
    struct child* c = calloc(1, sizeof(struct child));
    if (c == NULL) return TID_ERROR;

    struct initd_arg* initd_arg = calloc(1, sizeof(struct initd_arg));
    if (initd_arg == NULL)
    {
        free(c);
        return TID_ERROR;
    }

    char* fn_copy;
    tid_t tid;

    /* Make a copy of FILE_NAME.
     * Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
    {
        free(c);
        free(initd_arg);
        return TID_ERROR;
    }
    strlcpy(fn_copy, file_name, PGSIZE);

    // thread에 file_name만 전달하도록
    // 이 과정은 단순 이름 전달 용도임, 보존이 의미가 없음 이미 fn_copy로 보존함
    char* save_ptr;
    file_name = strtok_r((char*)file_name, " ", &save_ptr);

    /* initd 인자 전달 세팅 */
    initd_arg->fn_copy = fn_copy;
    initd_arg->c = c;

    sema_init(&c->wait_sema, 0);  // 먼저 sema_init 해야함!!

    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create(file_name, PRI_DEFAULT, initd, initd_arg);
    if (tid == TID_ERROR)
    {
        palloc_free_page(fn_copy);
        free(c);
        free(initd_arg);
        return TID_ERROR;
    }

    // 자식(initd) 구조체 필드 채우고 부모(main) list에 등록
    c->child_tid = tid;
    c->exit_status = -1;
    c->waited = false;
    list_push_back(&parent->child_list, &c->child_elem);

    return tid;
}

/* A thread function that launches first user process. */
static void initd(void* aux)
{
#ifdef VM
    supplemental_page_table_init(&thread_current()->spt);
#endif

    /* initd 스레드의 child 구조체 생성 */
    struct initd_arg* i = aux;
    struct child* child = i->c;
    char* file_name = i->fn_copy;
    free(i);  // aux로 전달된 구조체 free

    // exit시 child_info 접근(sema_up, exit_status) 하기 때문에 여기서 해야함
    thread_current()->child_info = child;

    process_init();
    if (process_exec(file_name) < 0) PANIC("Fail to launch initd\n");
    NOT_REACHED();
}

struct forkarg
{
    struct intr_frame* f;
    struct thread* t;
    struct semaphore forksema;
    struct child* c;
    bool success;
};

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char* name, struct intr_frame* if_)
{
    struct forkarg* fork = calloc(1, sizeof(struct forkarg));
    if (fork == NULL) return TID_ERROR;
    // 자식 구조체 생성
    struct child* c = calloc(1, sizeof(struct child));
    if (c == NULL)
    {
        free(fork);
        return TID_ERROR;
    }
    fork->f = if_;
    fork->t = thread_current();
    fork->c = c;
    sema_init(&fork->forksema, 0);  //__do_fork 결과 확인용
    sema_init(&c->wait_sema, 0);    // create전에 init 해야함

    /* Clone current thread to new thread.*/
    tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, fork);
    if (tid == TID_ERROR)
    {
        /* 자원 해제 */
        free(fork);
        free(c);
        return TID_ERROR;
    }

    // 자식 구조체 필드 채우고 부모 list에 등록
    c->child_tid = tid;
    c->exit_status = -1;
    c->waited = false;
    list_push_back(&thread_current()->child_list, &c->child_elem);

    // __do_fork 결과 확인용
    sema_down(&fork->forksema);

    if (fork->success)
    {
        free(fork);
        return tid;
    }
    else
    {
        free(fork);
        return TID_ERROR;
    }
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
/* 부모의 각 유저 PTE를 자식에게 복제.*/
/* 1. aux로 받은 부모 스레드의 pml4에서 va 대응 물리 페이지를 pml4_get_page로 구해온다
    (커널 페이지라면 건너 뛰기)
   2. 자식용 유저페이지를 새로 할당. 부모 페이지 내용을 복사
   3. 부모 PTE의 writable 비트에 따라 writeable 설정
   4. 자식의 pml4에 pml4_set_page(current->pml4, va, newpage, writable)
      로 매핑. 실패 시 할당 해제 등 처리.*/

/* pte : va를 가리키는 페이지테이블 엔트리 포인터(물리 페이지 주소 + 플래그가 담김) */
static bool duplicate_pte(uint64_t* pte, void* va, void* aux)
{
    struct thread* current = thread_current();
    struct thread* parent = (struct thread*)aux;
    void* parent_page;
    void* newpage;
    bool writable;

    /* 1. TODO: If the parent_page is kernel page, then return immediately. */
    if (is_kern_pte(pte)) return true;  // 커널 매핑이면 false 반환이 아니라 건너 뛰어야함.

    /* 2. Resolve VA from the parent's page map level 4. */
    /* pml4에서 va가 가리키는 물리주소와 매핑된 커널 가상주소(물리주소+KERN_BASE) 반환.*/
    parent_page = pml4_get_page(parent->pml4, va);

    /* 3. TODO: Allocate new PAL_USER page for the child and set result to
     *    TODO: NEWPAGE. */
    newpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (newpage == NULL) return false;

    /* 4. TODO: Duplicate parent's page to the new page and
     *    TODO: check whether parent's page is writable or not (set WRITABLE
     *    TODO: according to the result). */
    memcpy(newpage, parent_page, PGSIZE);

    /* 5. Add new page to child's page table at address VA with WRITABLE
     *    permission. */
    writable = is_writable(pte);
    if (!pml4_set_page(current->pml4, va, newpage, writable))
    {
        palloc_free_page(newpage);
        return false;
        /* 6. TODO: if fail to insert page, do error handling. */
    }
    return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void __do_fork(void* aux)
{
    struct forkarg* args = aux;
    struct intr_frame if_;
    struct thread* parent = (struct thread*)args->t;
    struct thread* current = thread_current();

    // current->parent = parent;
    current->child_info = args->c;

    /* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
    struct intr_frame* parent_if = args->f;
    bool succ = true;

    /* 1. Read the cpu context to local stack. */
    memcpy(&if_, parent_if, sizeof(struct intr_frame));

    /* 2. Duplicate PT */
    current->pml4 = pml4_create();
    if (current->pml4 == NULL) goto error;

    process_activate(current);
#ifdef VM
    supplemental_page_table_init(&current->spt);
    if (!supplemental_page_table_copy(&current->spt, &parent->spt)) goto error;
#else
    /*  주어진 pml4에 존재하는 모든 페이지 테이블 엔트리를 순회하며 func 호출
        func가 false를 리턴하면 멈추고 false 리턴*/
    if (!pml4_for_each(parent->pml4, duplicate_pte, parent)) goto error;
#endif

    /* TODO: Your code goes here.
     * TODO: Hint) To duplicate the file object, use `file_duplicate`
     * TODO:       in include/filesys/file.h. Note that parent should not return
     * TODO:       from the fork() until this function successfully duplicates
     * TODO:       the resources of parent.*/

    process_init();
    // 먼저 자식의 fd_table을 부모 크기로 확장
    if (parent->fd_capacity > current->fd_capacity)
    {
        struct file** new_table =
            realloc(current->fd_table, sizeof(struct file*) * parent->fd_capacity);
        if (new_table == NULL) goto error;

        // 새로 할당된 부분 초기화
        for (int i = current->fd_capacity; i < parent->fd_capacity; i++)
        {
            new_table[i] = NULL;
        }

        current->fd_table = new_table;
        current->fd_capacity = parent->fd_capacity;
    }
    /* fdt 복사, 나중에 fdt 타입 바꾸면 수정 필요 */
    // 이제 부모의 fd_capacity까지 복사
    for (int i = 0; i < parent->fd_capacity; i++)
    {
        struct file* file = parent->fd_table[i];
        if (file == NULL) continue;
        if (file == (struct file*)STDIN_FILENO || file == (struct file*)STDOUT_FILENO)
        {
            current->fd_table[i] = file;
            continue;
        }
        lock_acquire(&file_lock);
        struct file* dup = file_duplicate(file);
        lock_release(&file_lock);
        if (dup == NULL) goto error;
        current->fd_table[i] = dup;
    }

    /* Finally, switch to the newly created process. */
    if (succ)
    {
        args->success = true;
        if_.R.rax = 0;  // 자식은 0 반환
        sema_up(&args->forksema);
        do_iret(&if_);
    }
error:
    args->success = false;
    sema_up(&args->forksema);
    thread_exit();
}

/* load the arguments to the stack */
void load_arguments_to_stack(struct intr_frame* if_, char** argv, int argc)
{
    uint8_t* rsp = (uint8_t*)if_->rsp;
    char* arg_addresses[argc];  // 각 인자의 주소를 저장할 배열

    // 1. 먼저 문자열 데이터를 스택에 푸시 (역순으로)
    for (int i = argc - 1; i >= 0; i--)
    {
        int len = strlen(argv[i]) + 1;  // null terminator 포함
        rsp -= len;
        memcpy(rsp, argv[i], len);
        arg_addresses[i] = (char*)rsp;  // 이 주소를 저장
    }

    // 2. Word-align
    while ((uintptr_t)rsp % 8 != 0)
    {
        rsp--;
        *rsp = 0;  // 패딩
    }

    // 3. argv[argc] = NULL 추가
    rsp -= sizeof(char*);
    *(char**)rsp = 0;

    // 4. address stack에 추가
    for (int i = argc - 1; i >= 0; i--)
    {
        rsp -= sizeof(char*);
        *(char**)rsp = arg_addresses[i];
    }

    // 5. rsi 저장 + return address 0 으로 추가
    uint64_t rsi_value = (uint64_t)rsp;
    rsp -= sizeof(void*);
    *(char**)rsp = 0;

    // 6. rdi + rsi 저장 + rsp 업데이트
    if_->R.rdi = argc;
    if_->R.rsi = rsi_value;
    if_->rsp = (uintptr_t)rsp;
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec(void* f_name)
{
    bool success;
    // argv[0] = 프로그램 이름
    char* argv[128];
    int argc = 0;

    char *token, *save_ptr;
    for (token = strtok_r(f_name, " ", &save_ptr); token != NULL;
         token = strtok_r(NULL, " ", &save_ptr))
    {
        argv[argc++] = token;
    }

    /* We cannot use the intr_frame in the thread structure.
     * This is because when current thread rescheduled,
     * it stores the execution information to the member. */
    struct intr_frame _if;
    _if.ds = _if.es = _if.ss = SEL_UDSEG;
    _if.cs = SEL_UCSEG;
    _if.eflags = FLAG_IF | FLAG_MBS;

    /* We first kill the current context */
    process_cleanup();
    /* And then load the binary */
    success = load((const char**)argv, argc, &_if);

    /* If load failed, quit. */
    palloc_free_page(f_name);
    if (!success)
    {
        return -1;
    }

    /* Start switched process. */
    do_iret(&_if);
    NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */

/* TID인 스레드가 죽을때까지 기다리기 그리고 그 자식의 exit status를 반환
    자식이 커널에 의해 종료된 경우 -1 반환
    TID가 유효하지 않거나, 자식이 아니거나,
    주어진 TID에 대해 process_wait()가 이미 성공적으로 호출된 경우 -1을 반환*/
int process_wait(tid_t child_tid UNUSED)
{
    /* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
     * XXX:       to add infinite loop here before
     * XXX:       implementing the process_wait. */

    struct thread* curr = thread_current();
    struct child* target = NULL;

    for (struct list_elem* e = list_begin(&curr->child_list); e != list_end(&curr->child_list);
         e = list_next(e))
    {
        struct child* c = list_entry(e, struct child, child_elem);
        if (c->child_tid == child_tid)
        {
            target = c;
            break;
        }
    }

    // 자식이 아니거나, 이미 wait 호출한 자식이면
    if (target == NULL || target->waited == true) return -1;

    target->waited = true;
    sema_down(&target->wait_sema);

    int exit_status = target->exit_status;  // 커널에 의해 강제 종료된 경우는 -1이 들어있음

    /* child 구조체 free */
    list_remove(&target->child_elem);
    free(target);

    return exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void)
{
    struct thread* curr = thread_current();
    /* TODO: Your code goes here.
     * TODO: Implement process termination message (see
     * TODO: project2/process_termination.html).
     * TODO: We recommend you to implement process resource cleanup here. */

    /* fdt 초기화 */
    if (curr->fd_table != NULL)
    {
        for (int i = 2; i < curr->fd_capacity; i++)
        {
            struct file* file = curr->fd_table[i];
            if (file != NULL && file != (struct file*)STDIN_FILENO &&
                file != (struct file*)STDOUT_FILENO)
            {
                // 다른 fd가 같은 파일을 가리키는지 체크
                bool should_close = true;
                for (int j = i + 1; j < curr->fd_capacity; j++)
                {
                    if (curr->fd_table[j] == file)
                    {
                        curr->fd_table[j] = NULL;  // 중복 제거
                    }
                }

                lock_acquire(&file_lock);
                file_close(file);
                lock_release(&file_lock);
            }
            curr->fd_table[i] = NULL;
        }
        free(curr->fd_table);
    }

    process_cleanup();

    /* child_info 없으면 그냥 exit하면 됨 */
    if (curr->child_info)
    {
        printf("%s: exit(%d)\n", curr->name, curr->exit_status);
        sema_up(&curr->child_info->wait_sema);
    }

    if (curr->executable)
    {
        lock_acquire(&file_lock);
        file_allow_write(curr->executable);
        file_close(curr->executable);
        lock_release(&file_lock);
    }
}

/* Free the current process's resources. */
static void process_cleanup(void)
{
    struct thread* curr = thread_current();

#ifdef VM
    supplemental_page_table_kill(&curr->spt);
#endif

    uint64_t* pml4;
    /* Destroy the current process's page directory and switch back
     * to the kernel-only page directory. */
    pml4 = curr->pml4;
    if (pml4 != NULL)
    {
        /* Correct ordering here is crucial.  We must set
         * cur->pagedir to NULL before switching page directories,
         * so that a timer interrupt can't switch back to the
         * process page directory.  We must activate the base page
         * directory before destroying the process's page
         * directory, or our active page directory will be one
         * that's been freed (and cleared). */
        curr->pml4 = NULL;
        pml4_activate(NULL);
        pml4_destroy(pml4);
    }
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread* next)
{
    /* Activate thread's page tables. */
    pml4_activate(next->pml4);

    /* Set thread's kernel stack for use in processing interrupts. */
    tss_update(next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr
{
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct ELF64_PHDR
{
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame* if_);
static bool validate_segment(const struct Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool load(const char** argv, int argc, struct intr_frame* if_)
{
    struct thread* t = thread_current();
    struct ELF ehdr;
    struct file* file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* Allocate and activate page directory. */
    t->pml4 = pml4_create();
    if (t->pml4 == NULL) goto done;
    process_activate(thread_current());

    /* Open executable file. */
    file = filesys_open(argv[0]);

    if (file == NULL)
    {
        printf("load: %s: open failed\n", argv[0]);
        goto done;
    }

    file_deny_write(file);
    t->executable = file;

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
        memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 ||
        ehdr.e_machine != 0x3E  // amd64
        || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024)
    {
        printf("load: %s: error loading executable\n", argv[0]);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++)
    {
        struct Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file)) goto done;
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type)
        {
            case PT_NULL:
            case PT_NOTE:
            case PT_PHDR:
            case PT_STACK:
            default:
                /* Ignore this segment. */
                break;
            case PT_DYNAMIC:
            case PT_INTERP:
            case PT_SHLIB:
                goto done;
            case PT_LOAD:
                if (validate_segment(&phdr, file))
                {
                    bool writable = (phdr.p_flags & PF_W) != 0;
                    uint64_t file_page = phdr.p_offset & ~PGMASK;
                    uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
                    uint64_t page_offset = phdr.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;
                    if (phdr.p_filesz > 0)
                    {
                        /* Normal segment.
                         * Read initial part from disk and zero the rest. */
                        read_bytes = page_offset + phdr.p_filesz;
                        zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
                    }
                    else
                    {
                        /* Entirely zero.
                         * Don't read anything from disk. */
                        read_bytes = 0;
                        zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                    }
                    if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes,
                                      writable))
                        goto done;
                }
                else
                    goto done;
                break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(if_)) goto done;

    /* Start address. */
    if_->rip = ehdr.e_entry;

    /* TODO: Your code goes here.
     * TODO: Implement argument passing (see project2/argument_passing.html). */
    load_arguments_to_stack(if_, (char**)argv, argc);

    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    if (!success)
    {
        file_close(file);
        t->executable = NULL;
    }
    return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Phdr* phdr, struct file* file)
{
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (uint64_t)file_length(file)) return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz) return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0) return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr((void*)phdr->p_vaddr)) return false;
    if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz))) return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr) return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE) return false;

    /* It's okay. */
    return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */
/* 이 블록의 코드는 프로젝트 2에서만 사용됩니다.
 * 전체 프로젝트 2에 대한 함수를 구현하려면 #ifndef 매크로 외부에 구현하세요. */

/* load() helpers. */
/* load() 헬퍼 함수들. */
static bool install_page(void* upage, void* kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
/* FILE의 offset OFS부터 시작하는 세그먼트를 UPAGE 주소에 로드합니다.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리가 다음과 같이 초기화됩니다:
 *
 * - UPAGE에 READ_BYTES 바이트를 FILE의 offset OFS부터 읽어야 합니다.
 *
 * - UPAGE + READ_BYTES에 ZERO_BYTES 바이트를 0으로 채워야 합니다.
 *
 * 이 함수로 초기화된 페이지는 WRITABLE이 true면 사용자 프로세스가 수정할 수 있고,
 * 그렇지 않으면 읽기 전용입니다.
 *
 * 성공하면 true, 메모리 할당 오류나 디스크 읽기 오류 발생 시 false 반환. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable)
{
    /* 전제 조건 검사 */
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);  // 총 바이트는 페이지 크기의 배수여야 함
    ASSERT(pg_ofs(upage) == 0);                       // upage는 페이지 경계에 정렬되어야 함
    ASSERT(ofs % PGSIZE == 0);                        // offset도 페이지 경계에 정렬되어야 함

    file_seek(file, ofs);                     // 파일 포인터를 시작 위치로 이동
    while (read_bytes > 0 || zero_bytes > 0)  // 모든 바이트를 처리할 때까지 반복
    {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        /* 이 페이지를 어떻게 채울지 계산합니다.
         * FILE에서 PAGE_READ_BYTES 바이트를 읽고
         * 마지막 PAGE_ZERO_BYTES 바이트는 0으로 채웁니다. */
        size_t page_read_bytes =
            read_bytes < PGSIZE ? read_bytes : PGSIZE;  // 이번 페이지에서 읽을 바이트 수 (최대 4KB)
        size_t page_zero_bytes = PGSIZE - page_read_bytes;  // 이번 페이지에서 0으로 채울 바이트 수

        /* Get a page of memory. */
        /* 물리 메모리 페이지 할당 */
        uint8_t* kpage = palloc_get_page(PAL_USER);  // 사용자 풀에서 4KB 페이지 할당
        if (kpage == NULL) return false;             // 할당 실패 시 false 반환

        /* Load this page. */
        /* 이 페이지를 로드 */
        if (file_read(file, kpage, page_read_bytes) !=
            (int)page_read_bytes)  // 파일에서 데이터 읽기
        {
            palloc_free_page(kpage);  // 읽기 실패 시 할당한 페이지 해제
            return false;             // 실패 반환
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);  // 나머지 부분을 0으로 채움 (BSS 영역)

        /* Add the page to the process's address space. */
        /* 페이지를 프로세스의 주소 공간에 추가 */
        if (!install_page(upage, kpage, writable))  // 가상 주소(upage)를 물리 주소(kpage)에 매핑
        {
            printf("fail\n");         // 매핑 실패 메시지 출력
            palloc_free_page(kpage);  // 할당한 페이지 해제
            return false;             // 실패 반환
        }

        /* Advance. */
        /* 다음 페이지로 진행 */
        read_bytes -= page_read_bytes;  // 남은 읽을 바이트 수 감소
        zero_bytes -= page_zero_bytes;  // 남은 0으로 채울 바이트 수 감소
        upage += PGSIZE;                // 다음 페이지의 가상 주소로 이동 (4KB 증가)
    }
    return true;  // 모든 페이지 로드 성공
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
/* USER_STACK 위치에 0으로 초기화된 페이지를 매핑하여 최소한의 스택 생성 */
static bool setup_stack(struct intr_frame* if_)
{
    uint8_t* kpage;        // 커널 가상 주소 (물리 페이지)
    bool success = false;  // 성공 여부

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);  // 사용자 풀에서 0으로 초기화된 페이지 할당
    if (kpage != NULL)                             // 할당 성공 시
    {
        /* USER_STACK - PGSIZE 위치(사용자 스택의 바닥)에 페이지 설치 */
        success = install_page(((uint8_t*)USER_STACK) - PGSIZE, kpage,
                               true);  // writable=true (스택은 쓰기 가능해야 함)
        if (success)
            if_->rsp = USER_STACK;  // 성공 시 스택 포인터를 USER_STACK으로 설정
        else
            palloc_free_page(kpage);  // 실패 시 할당한 페이지 해제
    }
    return success;  // 성공 여부 반환
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
/* 사용자 가상 주소 UPAGE에서 커널 가상 주소 KPAGE로의 매핑을 페이지 테이블에 추가합니다.
 * WRITABLE이 true면 사용자 프로세스가 페이지를 수정할 수 있고,
 * 그렇지 않으면 읽기 전용입니다.
 * UPAGE는 아직 매핑되지 않아야 합니다.
 * KPAGE는 아마도 palloc_get_page()로 사용자 풀에서 얻은 페이지여야 합니다.
 * 성공 시 true, UPAGE가 이미 매핑되어 있거나 메모리 할당 실패 시 false 반환. */
static bool install_page(void* upage, void* kpage, bool writable)
{
    struct thread* t = thread_current();  // 현재 스레드 가져오기

    /* Verify that there's not already a page at that virtual
     * address, then map our page there. */
    /* 해당 가상 주소에 아직 페이지가 없는지 확인한 후, 페이지를 매핑합니다. */
    return (pml4_get_page(t->pml4, upage) == NULL &&  // 1. upage가 아직 매핑되지 않았는지 확인
            pml4_set_page(t->pml4, upage, kpage,
                          writable));  // 2. upage를 kpage에 매핑 (writable 권한 설정)
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */
/* 여기서부터는 프로젝트 3 이후에 사용될 코드입니다.
 * 프로젝트 2 전용 함수를 구현하려면 위 블록에 구현하세요. */

static bool lazy_load_segment(struct page* page, void* aux)
{
    /* TODO: Load the segment from the file */
    /* TODO: This called when the first page fault occurs on address VA. */
    /* TODO: VA is available when calling this function. */
    /* TODO: 파일에서 세그먼트를 로드합니다 */
    /* TODO: 이 함수는 주소 VA에서 첫 번째 page fault가 발생할 때 호출됩니다. */
    /* TODO: 이 함수 호출 시 VA를 사용할 수 있습니다. */

    /* 구현 가이드:
     * 1. aux에서 파일 정보 추출 (file, offset, read_bytes, zero_bytes)
     * 2. vm_get_frame()으로 물리 프레임 할당
     * 3. file_read()로 파일에서 데이터 읽어오기
     * 4. 나머지 부분 memset으로 0 채우기
     * 5. 페이지와 프레임 연결
     */
    return false;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
/* FILE의 offset OFS부터 시작하는 세그먼트를 UPAGE 주소에 로드합니다.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리가 다음과 같이 초기화됩니다:
 *
 * - UPAGE에 READ_BYTES 바이트를 FILE의 offset OFS부터 읽어야 합니다.
 *
 * - UPAGE + READ_BYTES에 ZERO_BYTES 바이트를 0으로 채워야 합니다.
 *
 * 이 함수로 초기화된 페이지는 WRITABLE이 true면 사용자 프로세스가 수정할 수 있고,
 * 그렇지 않으면 읽기 전용입니다.
 *
 * 성공하면 true, 메모리 할당 오류나 디스크 읽기 오류 발생 시 false 반환. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable)
{
    /* 전제 조건 검사 */
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);  // 총 바이트는 페이지 크기의 배수여야 함
    ASSERT(pg_ofs(upage) == 0);                       // upage는 페이지 경계에 정렬되어야 함
    ASSERT(ofs % PGSIZE == 0);                        // offset도 페이지 경계에 정렬되어야 함

    while (read_bytes > 0 || zero_bytes > 0)  // 모든 바이트를 처리할 때까지 반복
    {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        /* 이 페이지를 어떻게 채울지 계산합니다.
         * FILE에서 PAGE_READ_BYTES 바이트를 읽고
         * 마지막 PAGE_ZERO_BYTES 바이트는 0으로 채웁니다. */
        size_t page_read_bytes =
            read_bytes < PGSIZE ? read_bytes : PGSIZE;  // 이번 페이지에서 읽을 바이트 수 (최대 4KB)
        size_t page_zero_bytes = PGSIZE - page_read_bytes;  // 이번 페이지에서 0으로 채울 바이트 수

        /* TODO: Set up aux to pass information to the lazy_load_segment. */
        /* TODO: lazy_load_segment에 전달할 정보를 aux에 설정하세요. */
        /* 구현 가이드: aux 구조체를 만들어서 file, ofs, page_read_bytes, page_zero_bytes 전달 */
        void* aux = NULL;  // TODO: 파일 정보를 담은 구조체로 교체 필요

        /* SPT에 페이지 등록 (Lazy Loading - 실제 물리 메모리는 아직 할당 안 함) */
        if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, lazy_load_segment, aux))
            return false;  // SPT 등록 실패

        /* Advance. */
        /* 다음 페이지로 진행 */
        read_bytes -= page_read_bytes;  // 남은 읽을 바이트 수 감소
        zero_bytes -= page_zero_bytes;  // 남은 0으로 채울 바이트 수 감소
        upage += PGSIZE;                // 다음 페이지의 가상 주소로 이동 (4KB 증가)
    }
    return true;  // SPT에 모든 페이지 메타데이터 등록 완료 (실제 로딩은 page fault 발생 시)
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
/* USER_STACK에 스택 페이지를 생성합니다. 성공 시 true 반환. */
static bool setup_stack(struct intr_frame* if_)
{
    bool success = false;  // 성공 여부
    void* stack_bottom =
        (void*)(((uint8_t*)USER_STACK) - PGSIZE);  // 스택의 바닥 주소 (USER_STACK - 4KB)

    /* TODO: Map the stack on stack_bottom and claim the page immediately.
     * TODO: If success, set the rsp accordingly.
     * TODO: You should mark the page is stack. */
    /* TODO: stack_bottom에 스택을 매핑하고 즉시 페이지를 claim하세요.
     * TODO: 성공하면, rsp를 그에 맞게 설정하세요.
     * TODO: 페이지를 스택으로 표시해야 합니다. */
    /* TODO: Your code goes here */

    /* 구현 가이드:
     * 1. vm_alloc_page()로 stack_bottom에 VM_ANON 타입 페이지 할당
     * 2. vm_claim_page(stack_bottom)로 즉시 물리 메모리 할당 (Lazy 아님!)
     * 3. 성공 시 if_->rsp = USER_STACK 설정
     * 4. 페이지에 스택 마커 설정 (VM_MARKER_0 등 활용)
     */

    return success;  // 구현 완료 시 실제 성공 여부 반환
}
#endif /* VM */
