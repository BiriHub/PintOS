#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include "string.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "user/syscall.h"


static void syscall_handler (struct intr_frame *);

typedef void (*handler) (struct intr_frame *);
static void syscall_exit (struct intr_frame *f);
static void syscall_write (struct intr_frame *f);
static void *user_to_kernel_vaddr (void *uaddr);

static void syscall_exec(struct intr_frame *f);
static void syscall_wait(struct intr_frame *f);

#define SYSCALL_MAX_CODE 19
static handler call[SYSCALL_MAX_CODE + 1];

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  /* Any syscall not registered here should be NULL (0) in the call array. */
  memset(call, 0, SYSCALL_MAX_CODE + 1);

  /* Check file lib/syscall-nr.h for all the syscall codes and file
   * lib/user/syscall.c for a short explanation of each system call. */
  call[SYS_EXIT]  = syscall_exit;   // Terminate this process.
  call[SYS_WRITE] = syscall_write;  // Write to a file.
    call[SYS_WAIT] = syscall_wait;
    call[SYS_EXEC] = syscall_exec;
}

static void
syscall_handler (struct intr_frame *f)
{
  int syscall_code = *((int*)f->esp);
  call[syscall_code](f);
}

static void
syscall_exit (struct intr_frame *f)
{
  int *stack = f->esp;
  struct thread* t = thread_current ();
  t->exit_status = *(stack+1);
  thread_exit ();
}

static void
syscall_write (struct intr_frame *f)
{
  int *stack = f->esp;
  ASSERT (*(stack+1) == 1); // fd 1
  char * buffer = *(stack+2);
  int    length = *(stack+3);
  putbuf (buffer, length);
  f->eax = length;
}

static void syscall_exec(struct intr_frame *f) {
    const char *file = *(int*) user_to_kernel_vaddr(f->esp + 4);
    char *fn_copy = palloc_get_page (0);
    if (fn_copy == NULL)
        f->eax = TID_ERROR;
    strlcpy (fn_copy, file, PGSIZE);

    tid_t child_tid = process_execute (fn_copy);
    if (child_tid == TID_ERROR)
        f->eax = TID_ERROR;

    struct child_thread_elem *child = thread_get_child (child_tid);
    if (child->loading_status == -1)
        f->eax = -1;

    f->eax = child_tid;
}

static void syscall_wait(struct intr_frame *f){
    pid_t pid = *(int*) user_to_kernel_vaddr(f->esp + 4);
    f->eax = process_wait(pid);
}

static void *
user_to_kernel_vaddr (void *uaddr)
{
    struct thread *t = thread_current ();
    void *kaddr = NULL;
    if(is_user_vaddr(uaddr))
        kaddr = pagedir_get_page (t->pagedir, uaddr);
    if (kaddr == NULL)
        if (t->child_elem != NULL)
            t->child_elem->exit_status = -1;
        thread_exit();
    return kaddr;
}