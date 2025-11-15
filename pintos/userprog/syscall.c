#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "include/threads/init.h"

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
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// System call number is in rax
	int syscall_num = f->R.rax;
    struct thread *curr = thread_current();
    uint64_t *pml4 = curr->pml4;

	switch (syscall_num) {
		case SYS_WRITE:
			{
				int fd = f->R.rdi;                    // First argument: file descriptor
				const void *buffer = (void *)f->R.rsi;  // Second argument: buffer
				unsigned size = f->R.rdx;             // Third argument: size

				// Write때 구현
                // // 1. NULL 체크
                // if (buffer == NULL)
                //     thread_exit();

                // // 2. User 주소 범위 체크
                // if (!is_user_vaddr(buffer) || !is_user_vaddr(buffer + size - 1))
                //      thread_exit();

                // // 3. 매핑 체크 - 시작과 끝 주소만 체크 (중간은 연속되어 있다고 가정)
                // if (!pml4_get_page(curr->pml4, buffer))
                //     thread_exit();

                // if (size > 0 && !pml4_get_page(curr->pml4, buffer + size - 1))
                //     thread_exit();

                // 중간 페이지까지 체크를 해야되나? -> maybe optional

				// For now, only handle writing to stdout (fd = 1)

				if (fd == 1) {
					putbuf(buffer, size);  // Write to console
					f->R.rax = size;         // Return number of bytes written
				} else {
					f->R.rax = -1;           // Error: unsupported fd
				}
			}
			break;

		case SYS_EXIT:
			{
				int status = f->R.rdi;  // First argument: exit status
				printf("%s: exit(%d)\n", thread_current()->name, status);
				thread_exit();
			}
			break;

		case SYS_HALT:
            {
                power_off();
                thread_exit();
            }
            break;
		default:
			printf("system call! (unimplemented syscall number: %d)\n", syscall_num);
			thread_exit();
			break;
	}
}
