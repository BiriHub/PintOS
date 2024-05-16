#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <string.h>
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "lib/kernel/hash.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#include "devices/input.h"

typedef int (*handler) (uint32_t, uint32_t, uint32_t);
static handler syscall_vec[128];

static int sys_exit (int status);
static int sys_wait (tid_t tid);
static tid_t sys_exec (const char* file_name);
static void syscall_nop(void);
static void sys_halt(void);

bool sys_create(const char* filename, unsigned initial_size);
bool sys_remove(const char* filename);
int sys_open(const char* file);
int sys_filesize(int fd);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);

static int32_t get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);


static void syscall_handler (struct intr_frame *);

struct fd_item {
  int fd;
  struct file* file;
  struct hash_elem elem;
};

int next_fd = 3;
struct hash fd_table;
struct lock filesys_lock;

static unsigned item_hash (const struct hash_elem* e, void* aux) {
  struct fd_item* i = hash_entry(e, struct fd_item, elem);
  return hash_int(i->fd);
}

static bool item_compare(const struct hash_elem* a, const struct hash_elem* b, void* aux) {
  struct fd_item *i_a = hash_entry(a, struct fd_item, elem);
  struct fd_item *i_b = hash_entry(b, struct fd_item, elem);
  return i_a->fd < i_b->fd;
}

/**
 * Reads a single 'byte' at user memory admemory at 'uaddr'.
 * 'uaddr' must be below PHYS_BASE.
 *
 * Returns the byte value if successful (extract the least significant byte),
 * or -1 in case of error (a segfault occurred or invalid uaddr)
 */
static int32_t
get_user (const uint8_t *uaddr) {
  // check that a user pointer `uaddr` points below PHYS_BASE
  if (! ((void*)uaddr < PHYS_BASE)) {
    return -1;
  }

  // as suggested in the reference manual, see (3.1.5)
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes a single byte (content is 'byte') to user address 'udst'.
 * 'udst' must be below PHYS_BASE.
 *
 * Returns true if successful, false if a segfault occurred.
 */
static bool
put_user (uint8_t *udst, uint8_t byte) {
  // check that a user pointer `udst` points below PHYS_BASE
  if (! ((void*)udst < PHYS_BASE)) {
    return false;
  }

  int error_code;

  // as suggested in the reference manual, see (3.1.5)
  asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  memset(syscall_vec, (int)&syscall_nop, 128);
  syscall_vec[SYS_EXIT] = (handler)sys_exit;
  syscall_vec[SYS_WAIT] = (handler)sys_wait;
  syscall_vec[SYS_EXEC] = (handler)sys_exec;
  syscall_vec[SYS_HALT] = (handler)sys_halt;
  syscall_vec[SYS_CREATE] = (handler)sys_create;
  syscall_vec[SYS_REMOVE] = (handler)sys_remove;
  syscall_vec[SYS_OPEN] = (handler)sys_open;
  syscall_vec[SYS_FILESIZE] = (handler)sys_filesize;
  syscall_vec[SYS_SEEK] = (handler)sys_seek;
  syscall_vec[SYS_TELL] = (handler)sys_tell;
  syscall_vec[SYS_CLOSE] = (handler)sys_close;
  syscall_vec[SYS_READ] = (handler)sys_read;
  syscall_vec[SYS_WRITE] = (handler)sys_write;
  hash_init(&fd_table, item_hash, item_compare, NULL);
  lock_init(&filesys_lock);
}

static bool check_ptr(const void* ptr) {
  if (ptr == NULL || is_kernel_vaddr(ptr) || 
      pagedir_get_page(thread_current()->pagedir, ptr) == NULL) {
    sys_exit(-1);
  }
  return false;
}

static
void sys_halt(void) {
  shutdown_power_off();
}

bool sys_create(const char* filename, unsigned initial_size) {
  if (check_ptr(filename)) return 0;
  lock_acquire (&filesys_lock);
  bool return_code = filesys_create(filename, initial_size);
  lock_release (&filesys_lock);
  return return_code;
}

bool sys_remove(const char* filename) {
  if (check_ptr(filename)) return 0;
  lock_acquire (&filesys_lock);
  bool return_code = filesys_remove(filename);
  lock_release (&filesys_lock);
  return return_code;
}

int sys_open(const char* file) {
  if (check_ptr(file)) return -1;
  struct file* file_opened;
  struct fd_item* fd = malloc(sizeof(struct fd_item*));
  if (!fd) {
    return -1;
  }

  lock_acquire (&filesys_lock);
  file_opened = filesys_open(file);
  //printf("File opened: %x\n", file_opened);
  if (!file_opened) {
    free(fd);
    lock_release (&filesys_lock);
    return -1;
  }

  fd->file = file_opened; 
  fd->fd = next_fd++;
  //printf("Hash put: %x %d\n", file_opened, fd->fd);
  hash_insert(&fd_table, &fd->elem);
  lock_release (&filesys_lock);
  return fd->fd;
}

int sys_filesize(int fd) {
  lock_acquire (&filesys_lock);
  struct fd_item i;
  i.fd = fd;
  struct hash_elem* h = hash_find(&fd_table, &i.elem);
  if (h == NULL) sys_exit(-1);
  struct fd_item* file_d = hash_entry(h, struct fd_item, elem);

  if(file_d == NULL) {
    lock_release (&filesys_lock);
    return -1;
  }

  int ret = file_length(file_d->file);
  lock_release (&filesys_lock);
  return ret;
}

void sys_seek(int fd, unsigned position) {
  lock_acquire (&filesys_lock);
  struct fd_item i;
  i.fd = fd;
  struct hash_elem* h = hash_find(&fd_table, &i.elem);
  if (h == NULL) sys_exit(-1);
  struct fd_item* file_d = hash_entry(h, struct fd_item, elem);

  if(file_d && file_d->file) {
    file_seek(file_d->file, position);
  }
  else
    return; 

  lock_release (&filesys_lock);
}

unsigned sys_tell(int fd) {
  lock_acquire (&filesys_lock);
  struct fd_item i;
  i.fd = fd;
  struct hash_elem* h = hash_find(&fd_table, &i.elem);
  if (h == NULL) sys_exit(-1);
  struct fd_item* file_d = hash_entry(h, struct fd_item, elem);

  unsigned ret;
  if(file_d && file_d->file) {
    ret = file_tell(file_d->file);
  }
  else
    ret = -1; 

  lock_release (&filesys_lock);
  return ret;
}

void sys_close(int fd) {
  lock_acquire (&filesys_lock);
  struct fd_item i;
  i.fd = fd;
  struct hash_elem* h = hash_find(&fd_table, &i.elem);
  if (h == NULL) sys_exit(-1);
  struct fd_item* file_d = hash_entry(h, struct fd_item, elem);
  //printf("File close id: %x\n", file_d);
  if(file_d && file_d->file) {
    //printf("File closed: %x\n", file_d->file);
    file_close(file_d->file);
    hash_delete(&fd_table, &(file_d->elem));
    free(file_d);
  }
  lock_release (&filesys_lock);
}

int sys_read(int fd, void *buffer, unsigned size) {
  if (check_ptr(buffer)||check_ptr(buffer+size)) return -1;
  int ret;
  lock_acquire (&filesys_lock);

  if(fd == 0) { 
    unsigned i;
    for(i = 0; i < size; ++i) {
      if(! put_user(buffer + i, input_getc()) ) {
        lock_release (&filesys_lock);
        sys_exit(-1); // segfault
      }
    }
    ret = size;
  } else {
    struct fd_item i;
    i.fd = fd;
    struct hash_elem* h = hash_find(&fd_table, &i.elem);
    if (h == NULL) sys_exit(-1);
    struct fd_item* file_d = hash_entry(h, struct fd_item, elem);

    if (file_d && file_d->file) {
      ret = file_read(file_d->file, buffer, size);
    } else ret = -1;
  }
  lock_release (&filesys_lock);
  return ret;
}

int sys_write(int fd, const void *buffer, unsigned size) {
  unsigned i;
  for (i = 0; i <= size; i++) {
    if (check_ptr(buffer + size)) return -1;
  }
  int ret;

  if(fd == 1) {
    lock_acquire (&filesys_lock);
    putbuf(buffer, size);
    ret = size;
    lock_release (&filesys_lock);
  } else {
    lock_acquire (&filesys_lock);
    struct fd_item i;
    i.fd = fd;
    struct hash_elem* h = hash_find(&fd_table, &i.elem);
    if (h == NULL) sys_exit(-1);
    struct fd_item* file_d = hash_entry(h, struct fd_item, elem);

    if(file_d && file_d->file) {
      ret = file_write(file_d->file, buffer, size);
    }
    else ret = -1;
    lock_release (&filesys_lock);
  }

  return ret;
}

static void
syscall_nop(void) {
  printf("Syscall not implemented");
}

static void
syscall_handler (struct intr_frame *f) 
{
  handler h;
  int *p;
  int ret;
  
  p = f->esp;
  h = syscall_vec[*p];
  ret = h (*(p + 1), *(p + 2), *(p + 3));
  
  f->eax = ret;
}

int
sys_exit (int status)
{
  struct thread* t = thread_current();
  t->exit_status = status;
  thread_exit();
  return -1;
}

int
sys_wait (tid_t tid)
{
  int status = process_wait(tid);
  return status;
}

tid_t
sys_exec (const char* file_name) {
  if (file_name == NULL || is_kernel_vaddr(file_name) || 
      pagedir_get_page(thread_current()->pagedir, file_name) == NULL) {
    return -1;
  }
  return process_execute(file_name);
}