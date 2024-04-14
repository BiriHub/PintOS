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

bool
is_valid_ptr(const void *ptr)
{
    if (ptr == NULL || !is_user_vaddr(ptr) || pagedir_get_page
                                                      (thread_current()->pagedir, ptr) == NULL) {
        return false;
    }
    return true;
}

bool has_valid_args(void *ptr, int args){
    int i;
    args *= 4; // size of an arg in 32-bit sys
    for(i = 0; i < args; i++)
    {
        if(is_valid_ptr(ptr+i))
            return false;
    }
    return true;
}

//void exit(int status)
//{
//    struct thread *cur = thread_current();
//
//    printf("%s: exit(%d)\n", cur->name, status);
//
//    /* If its parent is still waiting for it,
//     tell its parent its exit status. */
//    if (cur->parent != NULL)
//    {
//        cur->parent->child_exit_status = status;
//        // printf("parent %s: child_exit(%d)\n", cur->parent->name, cur->parent->child_exit_status);
//    }
//    thread_exit();
//}

static void
syscall_handler (struct intr_frame *f UNUSED) {
    if (!has_valid_args(f->esp, 1)) {
        thread_exit();
        return;
    }
    int n_sc = *(int *) f->esp;

    switch (n_sc) {
        case SYS_EXIT:
        {
            if (!has_valid_args(f->esp + 4, 1)) {
                thread_exit();
                return;
            }
            int status = *(int *) (f->esp + 4);
            f->eax = status;
            break;
        }
        case SYS_WRITE:
        {
            const void *buffer = *(const void **)(f->esp + 8);
            unsigned size = *(unsigned *)(f->esp + 12);

            if (is_valid_ptr(buffer)) {
                putbuf(buffer, size);
                f->eax = size; // Return the number of bytes written.
            } else {
                f->eax = -1;
            }
            break;
        }
        default:
        {
            printf("Other sys_call: %d\n", n_sc);
            break;
        }
    }
}