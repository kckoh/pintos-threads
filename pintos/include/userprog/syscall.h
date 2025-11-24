#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

struct file;
void syscall_init (void);

void file_ref_inc(struct file *file);
bool file_ref_dec(struct file *file);

#endif /* userprog/syscall.h */
