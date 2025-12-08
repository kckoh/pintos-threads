#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd(const char *file_name);
tid_t process_fork(const char *name, struct intr_frame *if_);
int process_exec(void *f_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(struct thread *next);
bool lazy_load_segment(struct page *page, void *aux);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

struct file;
struct page;

struct lazy_load_aux {
    struct file *file;      // 읽어야 되는 파일
    off_t ofs;              // 시작 위치 오프셋
    size_t page_read_bytes; // 읽을 크기
    size_t page_zero_bytes; // 나머지 크기
};

#endif /* userprog/process.h */
