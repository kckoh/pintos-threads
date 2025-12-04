#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stddef.h>
#include "filesys/off_t.h"
#include "lib/kernel/list.h"

void syscall_init(void);

#ifdef VM
struct mmap_entry {
    void *addr;        // 시작 주소
    size_t length;     // 길이
    off_t offset;      // 오프셋
    struct file *file; // 파일 포인터
    struct list_elem elem;
};
#endif

#endif /* userprog/syscall.h */
