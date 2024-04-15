#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <lib/stdio.h>
#include <kernel/stdio.h>
#include <lib/syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void
syscall_handler (struct intr_frame *f UNUSED) {
    int n_sc = *(int *) f->esp;

    switch (n_sc) {
        case SYS_EXIT:
        {
            int *esp = f->esp;
            struct thread* curr = thread_current();
            curr->exit_status = *(esp+1);
            thread_exit ();
            break;
        }
        case SYS_WRITE:
        {
            int *esp = f->esp;
            ASSERT (*(esp+1) == STDOUT_FILENO);
            char * buf = *(esp+2);
            int len = *(esp+3);
            putbuf (buf, len);
            f->eax = len;
            break;
        }
        default:
        {
            printf("Other sys_call: %d\n", n_sc);
            break;
        }
    }
}