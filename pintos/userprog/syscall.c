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

static void syscall_handler(struct intr_frame *);

typedef void (*handler)(uint32_t *, uint32_t *);

static void syscall_exit(uint32_t *args, uint32_t *eax);

static void syscall_write(uint32_t *args, uint32_t *eax);

static void syscall_wait(uint32_t *args, uint32_t *eax);

static void syscall_exec(uint32_t *args, uint32_t *eax);

void exit(int status);

static bool check_args_validity(uint32_t *args, int num_args);

static bool check_arg_addr_validity(void *arg);

#define SYSCALL_MAX_CODE 19
static handler call[SYSCALL_MAX_CODE + 1];

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

    /* Any syscall not registered here should be NULL (0) in the call array. */
    memset(call, 0, SYSCALL_MAX_CODE + 1);

    /* Check file lib/syscall-nr.h for all the syscall codes and file
     * lib/user/syscall.c for a short explanation of each system call. */
    call[SYS_EXIT] = syscall_exit;   // Terminate this process.
    call[SYS_WRITE] = syscall_write;  // Write to a file.
    call[SYS_WAIT] = syscall_wait;  // Wait a process.
    call[SYS_EXEC] = syscall_exec;  // Exec a new child.
}

static void
syscall_handler(struct intr_frame *f) {
    if (f == NULL)
        exit(-1);

    uint32_t *args = ((uint32_t *) f->esp);
    if (!check_args_validity(args, 1))
        exit(-1);

    int syscall = (int) args[0];
    args++;
    call[syscall](args, &(f->eax));
}

static void
syscall_exit(uint32_t *args, uint32_t *eax) {
    int status;
    if (!check_args_validity(args, 1))
        status = -1;
    else
        status = (int) args[0];

    exit(status);
}

void
exit(int status) {
    thread_current()->exit_status = status;

    // Print the output
    printf("%s: exit(%d)\n", thread_current()->name, status);
    // And exit
    thread_exit();
}

static void
syscall_write(uint32_t *args, uint32_t *eax) {
    if (!check_args_validity(args, 3) || !check_arg_addr_validity((void *) args[1]))
        exit(-1);

    // Extract the arguments
    int fd = (int) args[0];
    char *buffer = (char *) args[1];
    int length = (int) args[2];

    ASSERT(fd == 1);
    putbuf(buffer, length);
    *eax = length;
}

static void
syscall_wait(uint32_t *args, uint32_t *eax) {
    if (!check_args_validity(args, 1))
        exit(-1);

    *eax = (uint32_t) process_wait((int) *args);
}

static void
syscall_exec(uint32_t *args, uint32_t *eax) {
    if (!check_args_validity(args, 1) || !check_arg_addr_validity((void *) *args))
        exit(-1);

    // Execute the command
    *eax = (uint32_t) process_execute((char *) *args);
}

static bool
check_args_validity(uint32_t *args, int num_args) {

    struct thread *t = thread_current();

    int i;
    for (i = 0; i < num_args + 1; i++) {
        if (args == NULL || !is_user_vaddr(args) ||
            pagedir_get_page(t->pagedir, args) == NULL)
            return false;

        args++;
    }
    return true;
}

static bool
check_arg_addr_validity(void *arg) {
    // Check if pointer is null, if it is an user virtual address and if the address is in the thread
    // page dir
    return arg != NULL && is_user_vaddr(arg) &&
           pagedir_get_page(thread_current()->pagedir, arg) != NULL;
}