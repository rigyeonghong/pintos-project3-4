#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
void argument_stack(char **arg_list,int idx,struct intr_frame *if_);
/* Project 2 file descriptor */
struct file *process_get_file(int fd);

int process_add_file(struct file *f);
struct file *process_get_file(int fd);
// void process_close_file(int fd);
struct thread *get_child_process(int pid);

void argument_stack(char **argv, int argc, struct intr_frame *if_);
bool lazy_load_segment(struct page *page, void *aux);
bool install_page(void *upage, void *kpage, bool writable);

/* Project 3 - Anonymous Page*/
struct file_info
{
    struct file *file;
    off_t offset;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    bool writable;
};
#endif /* userprog/process.h */
