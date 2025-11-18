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

#include "threads/synch.h"
#include "include/filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);


static void valid_get_addr(void *addr);
static void valid_put_addr(void *addr, unsigned length);
static void check_string(const char *str);

//syscall 함수화
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove(const char *file);
static int sys_write(int fd, void *buffer, unsigned length);
static int sys_open(const char *file);
static void sys_close(int fd);
static int sys_read(int fd, void *buffer, unsigned length);
static int sys_filesize(int fd);

static void sys_exit(int status);

struct lock file_lock;

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

/* todo : 지금 주소 저장 할지 말지*/
static int64_t
get_user (const uint8_t *uaddr) {
    int64_t result;

    if (uaddr == NULL || !is_user_vaddr (uaddr))
        return -1;

    __asm __volatile (
        "movabsq $done_get, %0\n"
        "movzbq %1, %0\n"
        "done_get:\n"
        : "=&a" (result) : "m" (*uaddr));
    return result;
}

static bool
put_user (uint8_t *udst, uint8_t byte) {
    int64_t error_code;

    if (udst == NULL || !is_user_vaddr (udst))
        return false;

    __asm __volatile (
        "movabsq $done_put, %0\n"
        "movb %b2, %1\n"
        "done_put:\n"
        : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}


void
syscall_init (void) {

	lock_init(&file_lock);

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

	switch (syscall_num) {

		case SYS_HALT:
            power_off();
            break;

		case SYS_EXIT:
			sys_exit(f->R.rdi);
			break;



		case SYS_CREATE:
			f->R.rax = sys_create((const char *)f->R.rdi, f->R.rsi);
			break;

		case SYS_REMOVE:
			f->R.rax = sys_remove((const char *)f->R.rdi);
			break;

		case SYS_OPEN:
			f->R.rax = sys_open((const char *)f->R.rdi);
			break;

		case SYS_FILESIZE:
			f->R.rax = sys_filesize(f->R.rdi);
			break;

		case SYS_READ:
			f->R.rax = sys_read(f->R.rdi, (void *)f->R.rsi, f->R.rdx);
			break;

		case SYS_WRITE:
			f->R.rax = sys_write(f->R.rdi, (const void *)f->R.rsi, f->R.rdx);
			break;

		case SYS_SEEK:

			break;

		case SYS_TELL:

			break;


		case SYS_CLOSE:
			sys_close(f->R.rdi);
			break;

		default:
			printf("system call! (unimplemented syscall number: %d)\n", syscall_num);
			thread_exit();
			break;
	}
}

static void valid_get_addr(void *addr){
	if(is_kernel_vaddr(addr) || addr == NULL)
		sys_exit(-1);
	if(get_user(addr) < 0)
		sys_exit(-1);
}

static void valid_put_addr(void *addr, unsigned length){
	if(addr==NULL || !is_user_vaddr(addr))
		sys_exit(-1);

	if(length==0)
		return;

	uint8_t *end = (uint8_t *)addr + length - 1;

	if(!is_user_vaddr(end))
		sys_exit(-1);

	if(get_user((uint8_t *)addr)==-1)
		sys_exit(-1);

	if(get_user(end)==-1)
		sys_exit(-1);
}

static bool sys_create(const char *file, unsigned initial_size){
	check_string(file); 

	lock_acquire(&file_lock);
	bool success = filesys_create(file, initial_size);
	lock_release(&file_lock);
	return success;
}

static bool sys_remove(const char *file){
	check_string(file); 

	lock_acquire(&file_lock);
	bool success = filesys_remove(file);
	lock_release(&file_lock);
	return success;
}

static int sys_write(int fd, void *buffer, unsigned length){

	/* todo : buffer valid*/
	if(buffer == NULL || !is_user_vaddr(buffer))
    {
        sys_exit(-1);
    }

	if(length > 0)
    {
        uint8_t *end = (uint8_t *)buffer + length - 1;
        if(!is_user_vaddr(end))
            sys_exit(-1);
        
        if(get_user((uint8_t *)buffer) == -1)
            sys_exit(-1);
        
        if(get_user(end) == -1)
            sys_exit(-1);
    }

	// For now, only handle writing to stdout (fd = 1)
	if (fd == 1) {
		putbuf(buffer, length);  // Write to console
		return length;         // Return number of bytes written
	} else {
		return -1;           // Error: unsupported fd
	}

}

static int sys_open(const char *file)
{
	check_string(file);

	if(strlen(file)==0)
	{
		return -1;
	}

	struct thread *curr = thread_current();

	if(curr->next_fd >= 128)
	{
		return -1;
	}

	lock_acquire(&file_lock);
	struct file *opened_file = filesys_open(file);
	lock_release(&file_lock);

	if(opened_file != NULL)
	{
		int fd = curr->next_fd;
		curr->fd_table[fd] = opened_file;
		curr->next_fd++;

		return fd;
	}
	else
	{
		return -1;
	}
}

static void check_string(const char *str)
{
	if(str==NULL)
	{
		sys_exit(-1);
	}
	if(!is_user_vaddr(str))
	{
		sys_exit(-1);
	}
	const char *ptr = str;
	int count = 0;
	while (true) 
	{
		if(count++ > 512)
		{
			sys_exit(-1);
		}

		if (get_user((const uint8_t *)ptr) == -1) 
		{
			sys_exit(-1);
		}
		if (*ptr == '\0') 
		{
			break;
		}
		ptr++;
	}
}

static void sys_close(int fd)
{
	if(fd<2 || fd>=128)
	{
		return;
	}
	struct thread *curr = thread_current();

	if(curr->fd_table[fd] == NULL)
	{
		return;
	}
	lock_acquire(&file_lock);
	file_close(curr->fd_table[fd]);
	lock_release(&file_lock);

	curr->fd_table[fd]=NULL;
}

static int sys_read(int fd, void *buffer, unsigned length)
{
	if(buffer==NULL || !is_user_vaddr(buffer))
	{
		sys_exit(-1);
	}

	valid_put_addr(buffer, length);

	if(length==0)
	{
		return 0;
	}

	if(fd==0)
	{
		unsigned i;
		for (i=0; i<length; i++)
		{
			uint8_t c = input_getc();
			((uint8_t *)buffer)[i] = c;
		}
		return i;
	}
	if(fd<2 || fd>=128)
	{
		return -1;
	}

	struct thread *curr = thread_current();
	struct file *f = curr->fd_table[fd];
	if(f==NULL)
	{
		return -1;
	}
	lock_acquire(&file_lock);
	int bytes_read = file_read(f, buffer, length);
	lock_release(&file_lock);

	return bytes_read;
}

static int sys_filesize(int fd)
{	
	//fd 유효성 검사
	if(fd<2 || fd>=128)
	{
		return -1;
	}

	//현재 스레드의 fd_table에서 파일 가져오기
	struct thread *curr = thread_current();
	struct file *f = curr->fd_table[fd];

	if(f==NULL)
	{
		return -1;
	}

	lock_acquire(&file_lock);
	int size = file_length(f);
	lock_release(&file_lock);

	return size;
}

static void sys_exit(int status){
	thread_current()->exit_status = status;
	thread_exit();
}