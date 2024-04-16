#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*System call handler*/
static void syscall_handler (struct intr_frame *f)
{
  int syscall_code = *((int*)f->esp);
  int *esp = f->esp;

  //Manage the system call
  switch (syscall_code) {
      case SYS_EXIT:{ // exit system call
        struct thread* t = thread_current ();
        t->exit_status = *(esp+1);
        thread_exit ();
        break;
      }
      case SYS_WRITE:{ // write system call
        ASSERT (*(esp+1) == 1);     // check if file descriptor is stdout ( so fd ==1 )
        char* buffer = *(esp+2);    // get buffer from stack
        int length = *(esp+3);      // get length of buffer from stack
        putbuf (buffer, length);    // print buffer to console
        f->eax = length;            // return value
          break;
      }
      default:{
          break;
      }
  }
}
