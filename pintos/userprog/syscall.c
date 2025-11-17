#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/synch.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "include/threads/init.h"
#include "filesys/directory.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

static struct lock syscall_lock;

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&syscall_lock);
}

void exit(int status) {
    struct thread *cur = thread_current();
    cur->exit_status = status;
    thread_exit();
}

static bool is_valid_pointer(const void *ptr) {
    // 1. NULL 포인터 체크
    if (ptr == NULL)
        return false;

    // 2. 커널 영역 포인터 체크 (0xc0000000 이상)
    if (!is_user_vaddr(ptr))
        return false;


    return true;
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// System call number is in rax
	int syscall_num = f->R.rax;

	switch (syscall_num) {
		case SYS_WRITE:
			{
				int fd = f->R.rdi;                    // First argument: file descriptor
				const void *buffer = (void *)f->R.rsi;  // Second argument: buffer
				unsigned size = f->R.rdx;             // Third argument: size

				// For now, only handle writing to stdout (fd = 1)
				if (fd == 1) {
					putbuf(buffer, size);  // Write to console
					f->R.rax = size;         // Return number of bytes written
				} else {
					f->R.rax = -1;           // Error: unsupported fd
				}
			}
			break;

		case SYS_CREATE:
            {
                char *file = f->R.rdi;
                unsigned initial_size = f->R.rsi;
                bool success = false;

                if (!is_valid_pointer(file)|| initial_size < 0) {
                    f->R.rax = success;
                    exit(-1);
                    break;
                }

                // bad pointer 처리는 page_fault에서?
                lock_acquire(&syscall_lock);
                success = filesys_create(file, initial_size);
                lock_release(&syscall_lock);

                f->R.rax = success;
            }
            break;

        case SYS_REMOVE:
           	{
                char *file = (char *)f->R.rdi;
                    if (!is_valid_pointer(file)) {
                        exit(-1);
                        break;
                    }

                    lock_acquire(&syscall_lock);
                    bool success = filesys_remove(file);
                    lock_release(&syscall_lock);

                    f->R.rax = success;
           	}
            break;



		case SYS_EXIT:
			{
				int status = f->R.rdi;  // First argument: exit status
				// thread_current()->exit_status = status;
				// thread_exit();
				exit(status);
			}
			break;

		case SYS_HALT:
            {
                power_off();
                //thread_exit(); power_off하면 끝
            }
            break;
		default:
			printf("system call! (unimplemented syscall number: %d)\n", syscall_num);
			thread_exit();
			break;
	}
}
