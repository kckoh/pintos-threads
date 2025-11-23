#ifndef USERPROG_FDT_H
#define USERPROG_FDT_H

#include "threads/thread.h"

void close_fdt_entry(struct fdt_entry **table, int fd);
bool increase_fdt_size(struct thread *t, int fd);

#endif /* USERPROG_FDT_H */
