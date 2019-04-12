#ifndef SYSCALL_H
#define SYSCALL_H

#include <sys/syscall.h>

#include "./defs.h"

int validate_syscall (int pid, int syscall);

#endif // SYSCALL_H