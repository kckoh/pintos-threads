#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

	// SYS_HALT,                   /* 0*/
	// SYS_EXIT,                   /* Terminate this process. */
	// SYS_FORK,                   /* Clone current process. */
	// SYS_EXEC,                   /* Switch current process. */
	// SYS_WAIT,                   /* Wait for a child process to die. */
	// SYS_CREATE,                 /* Create a file. */
	// SYS_REMOVE,                 /* Delete a file. */
	// SYS_OPEN,                   /* Open a file. */
	// SYS_FILESIZE,               /* Obtain a file's size. */
	// SYS_READ,                   /* Read from a file. */
	// SYS_WRITE,                  /* Write to a file. */
	// SYS_SEEK,                   /* Change position in a file. */
	// SYS_TELL,                   /* Report current position in a file. */
	// SYS_CLOSE,   

	// 	/* Extra for Project 2 */
	// SYS_DUP2,                   /* Duplicate the file descriptor */

	// SYS_MOUNT,
	// SYS_UMOUNT,

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
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	uint64_t syscall_num = f->R.rax;
	struct thread *curr = thread_current ();
	switch (syscall_num)
	{
		case SYS_HALT:
			power_off();
			break;

		case SYS_EXIT:
			/*  - 현재 프로세스 종료
				- 부모가 wait()을 호출하면 status를 반환
					sema up down 뭔가 해야할듯..?
				- status 0 = 성공, 나머지는 실패
				- 프로세스 자원 정리 필수
				- 스레드 종료 = thread_exit() 호출 필요 */
			//printf("exit구현해!!!");
			int status = f->R.rdi;
			f->R.rax = status;
			thread_exit();
			break;

		case SYS_WRITE:
			/*  - fd 1 → console 출력 (putbuf 사용)
				- 너무 자주 putbuf 호출하지 말고 일정 크기 이상은 나눠서 처리
				- 파일 시스템은 파일 확장 기능이 없음
				→ EOF 뒤로 쓰기는 실패하거나 0만 씀*/

			int fd = f->R.rdi; //fd
			int buffer = f->R.rsi; //buffer
			int size = f->R.rdx; //size
			
			if(fd == 1){
				/* todo : 너무 자주 putbuf 호출하지 말고 일정 크기 이상은 나눠서 처리 */			
				/* console 출력 (putbuf 사용) */
				putbuf(buffer, size);
				f->R.rax = size;
			}
			else{
				/* fd에 출력? */
			}
			break;

		default:
			//thread_exit ();
			printf(" 디버깅용!!! ");
			break;
	}
}
