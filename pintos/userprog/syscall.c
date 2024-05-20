
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
#include "hash.h"


typedef void (*handler)(struct intr_frame *);

static void syscall_exit(struct intr_frame *);

static void syscall_exec(struct intr_frame *);

static void syscall_wait(struct intr_frame *);

static void syscall_write(struct intr_frame *);

static bool syscall_create(struct intr_frame *);

static void syscall_remove(struct intr_frame *);

static void syscall_open(struct intr_frame *);

static void syscall_read(struct intr_frame *);

static void syscall_filesize(struct intr_frame *);

static void syscall_tell(struct intr_frame *);

static void syscall_seek(struct intr_frame *);

static void syscall_close(struct intr_frame *);

static void syscall_halt(struct intr_frame *);

static bool check_user_address(void *);

static void syscall_handler(struct intr_frame *);

static struct file *get_fd_elem(int);

#define SYSCALL_MAX_CODE 19
static handler call[SYSCALL_MAX_CODE + 1];


struct fd_elem {
    int fd;
    struct file *file;
    struct hash_elem hash_elem;
    struct thread *holder;
};


struct hash fd_table;


struct lock filesys_lock; /* Lock for filesystem */

/* Hash functions. */
static unsigned elem_hash(const struct hash_elem *e, void *aux UNUSED) {
    struct fd_elem *fd_elem = hash_entry(e, struct fd_elem, hash_elem);
    return hash_int(fd_elem->fd);
}

static bool
elem_compare(const struct hash_elem *a, const struct hash_elem *b, void *aux
           UNUSED) {
    struct fd_elem *fd_a = hash_entry(a, struct fd_elem, hash_elem);
    struct fd_elem *fd_b = hash_entry(b, struct fd_elem, hash_elem);
    return fd_a->fd < fd_b->fd;
}

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

    /* Any syscall not registered here should be NULL (0) in the call array. */
    memset(call, 0, SYSCALL_MAX_CODE + 1);

    /* Check file lib/syscall-nr.h for all the syscall codes and file
     * lib/user/syscall.c for a short explanation of each system call. */
    call[SYS_EXIT] = syscall_exit;   /* Terminate this process. */
    call[SYS_EXEC] = syscall_exec;   /* Start another process. */
    call[SYS_WAIT] = syscall_wait;   /* Wait for a child process to die. */
    call[SYS_WRITE] = syscall_write;  /* Write to a file. */
    call[SYS_CREATE] = syscall_create;
    call[SYS_REMOVE] = syscall_remove;
    call[SYS_OPEN] = syscall_open;
    call[SYS_READ] = syscall_read;
    call[SYS_FILESIZE] = syscall_filesize;
    call[SYS_TELL] = syscall_tell;
    call[SYS_SEEK] = syscall_seek;
    call[SYS_CLOSE] = syscall_close;
    call[SYS_HALT] = syscall_halt;

    hash_init(&fd_table, elem_hash, elem_compare, NULL);
    lock_init(&filesys_lock);
}

static void
syscall_handler(struct intr_frame *f) {
    int syscall_code = *((int *) f->esp);
    call[syscall_code](f);
}

static void
syscall_exit(struct intr_frame *f) {
    int *stack = f->esp;
    struct thread *t = thread_current();
    t->exit_status = *(stack + 1);
    thread_get_child_data(t->parent, t->tid)->exit_status = t->exit_status;
    thread_exit();
}

static void
syscall_exec(struct intr_frame *f) {
    int *stackpointer = f->esp;
    char *command = (char *) *(stackpointer + 1);

    if (check_user_address(command))
        f->eax = process_execute(command);
    else
        f->eax = -1;
}

static void
syscall_wait(struct intr_frame *f) {
    int *stackpointer = (void *) f->esp;
    tid_t child_tid = *(stackpointer + 1);
    f->eax = process_wait(child_tid);
}

static void syscall_write(struct intr_frame *f) {
    int *stack = f->esp;
    int fd = *(stack + 1);
    const void *buffer = (const void *) *(stack + 2);
    unsigned size = *(stack + 3);

    if (check_user_address((void *) buffer) &&
        check_user_address((void *) buffer + size)) {
        if (fd == 1) {  // Write to stdout
            putbuf(buffer, size);
            f->eax = size;
        } else {
            lock_acquire(&filesys_lock);
            struct file *fl = get_fd_elem(fd);
            if (fl) {
                f->eax = file_write(fl, buffer, size);
            } else {
                f->eax = -1;
            }
            lock_release(&filesys_lock);
        }
    } else {
        // f->eax = -1;
        *(stack + 1) = -1;
        syscall_exit(f);
    }
}

static bool syscall_create(struct intr_frame *f) {
    int *stack = f->esp;
    const char *fl = (const char *) *(stack + 1);
    unsigned initial_size = *(stack + 2);

    if (check_user_address((void *) fl)) {
        lock_acquire(&filesys_lock);
        f->eax = filesys_create(fl, initial_size);
        lock_release(&filesys_lock);
    } else {
        *(stack + 1) = -1;
        syscall_exit(f);
    }
    return f->eax;
}

static void syscall_remove(struct intr_frame *f) {
    int *stack = f->esp;
    const char *file = (const char *) *(stack + 1);

    if (check_user_address((void *) file)) {
        lock_acquire(&filesys_lock);
        f->eax = filesys_remove(file);
        lock_release(&filesys_lock);
    } else {
        f->eax = false;
    }
}

static void syscall_open(struct intr_frame *f) {
    int *stack = f->esp;
    const char *file = (const char *) *(stack + 1);

    if (check_user_address((void *) file)) {
        lock_acquire(&filesys_lock);
        struct file *opened_file = filesys_open(file);
        lock_release(&filesys_lock);
        if (opened_file) {
            static int next_fd = 2;
            struct fd_elem *entry = malloc(sizeof(struct fd_elem));
            if (!entry) return -1;

            entry->fd = next_fd++;
            entry->file = opened_file;
            entry->holder = thread_current();
            hash_insert(&fd_table, &entry->hash_elem);
            f->eax = entry->fd;
        } else {
            f->eax = -1;
        }
    } else {
        *(stack + 1) = -1;
        syscall_exit(f);
    }
}

static void syscall_read(struct intr_frame *f) {
    int *stack = f->esp;
    int fd = *(stack + 1);
    void *buffer = (void *) *(stack + 2);
    unsigned size = *(stack + 3);

    if (check_user_address(buffer) && check_user_address(buffer + size)) {
        lock_acquire(&filesys_lock);
        struct file *fl = get_fd_elem(fd);
        if (fl) {
            f->eax = file_read(fl, buffer, size);
        } else {
            f->eax = -1;
        }
        lock_release(&filesys_lock);
    } else {
        *(stack + 1) = -1;
        syscall_exit(f);
    }
}

static void syscall_filesize(struct intr_frame *f) {
    int *stack = f->esp;
    int fd = *(stack + 1);

    lock_acquire(&filesys_lock);
    struct file *file = get_fd_elem(fd);
    if (file) {
        f->eax = file_length(file);
    } else {
        f->eax = -1;
    }
    lock_release(&filesys_lock);
}

static void syscall_close(struct intr_frame *f) {
    int *stack = f->esp;
    int fd = *(stack + 1);
    lock_acquire(&filesys_lock);
    struct fd_elem tmp;
    tmp.fd = fd;
    struct hash_elem *h_elem = hash_find(&fd_table, &tmp.hash_elem);
    if (h_elem) {
        struct fd_elem *h_entry = hash_entry(h_elem, struct fd_elem,
                                             hash_elem);
        if (h_entry->holder == thread_current()) {
            struct hash_elem *e = hash_delete(&fd_table, &tmp.hash_elem);
            if (e) {
                struct fd_elem *entry = hash_entry(e, struct fd_elem,
                                                   hash_elem);
                file_close(entry->file);
                free(entry);
            }
        }
    }
    lock_release(&filesys_lock);
}

static void syscall_tell(struct intr_frame *f) {
    int *stack = f->esp;
    int fd = *(stack + 1);

    lock_acquire(&filesys_lock);
    struct file *fl = get_fd_elem(fd);
    if (fl) {
        f->eax = file_tell(fl);
    } else {
        f->eax = -1;
    }
    lock_release(&filesys_lock);
}

static void syscall_seek(struct intr_frame *f) {
    int *stack = f->esp;
    int fd = *(stack + 1);
    unsigned pos = *(stack + 2);

    lock_acquire(&filesys_lock);
    struct file *fl = get_fd_elem(fd);
    if (fl) {
        file_seek(fl, pos);
    }
    lock_release(&filesys_lock);
}

static void syscall_halt(struct intr_frame *f) {
    shutdown_power_off();
}

static bool check_user_address(void *ptr) {
    return ptr != NULL && is_user_vaddr(ptr) &&
           pagedir_get_page(thread_current()->pagedir, ptr);
}

static struct file *get_fd_elem(int fd) {
    struct fd_elem tmp;
    struct hash_elem *h_elem;
    tmp.fd = fd;
    h_elem = hash_find(&fd_table, &tmp.hash_elem);
    if (h_elem) {
        struct fd_elem *entry = hash_entry(h_elem, struct fd_elem, hash_elem);
        return entry->file;
    }
    return NULL;
}