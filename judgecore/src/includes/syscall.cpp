#include "./syscall.h"

#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>

#include <stdarg.h>
#include <cstring>
#include <iostream>
#include <map>

using namespace std;

enum OP {
  GREATER, EQUAL, LESS, TEST, MASK, SET,
  STARTSWITH, ENDSWITH, CONTAINS, EXACT,
  PREPEND, APPEND, REPLACE,
  QUERY, QUERYSTR
};

inline int get_register(int where) {
  switch (where)
  {
    case 1: return RDI;
    case 2: return RSI;
    case 3: return RDX;
    case 4: return R10;
    case 5: return R8;
    case 6: return R9;
  }
  return -1;
}

int str_starts_with(const char *str, const char *pre)
{
  size_t lenpre = strlen(pre), lenstr = strlen(str);
  return lenstr < lenpre ? false : strncmp(pre, str, lenpre) == 0;
}
int str_ends_with(const char *str, const char *suf) {
  size_t slen = strlen(str);
  size_t suffix_len = strlen(suf);

  return suffix_len <= slen && !strcmp(str + slen - suffix_len, suf);
}
void str_prepend(char *str, const char *pre) {
  int slen = strlen(str);
  int tlen = strlen(pre);

  for (int i = slen; i >= 0; i--) {
    str[i + tlen] = str[i];
  }
  for (int i = 0; i < tlen; i++) {
    str[i] = pre[i];
  }
}
void str_prepend_path_safe(char *str, const char *pre) {
  int slen = strlen(str);
  int tlen = strlen(pre);

  char* buf = new char[slen + 1];
  memcpy(buf, str, slen + 1);

  int i = 0, j = 0;
  bool lastCharIsDot = false;
  for (; i < tlen; i++) {
    str[i] = pre[i];
  }
  while(buf[j] == '\\' || buf[j] == '/' || buf[j] == '.') j++;
  while(buf[j]) {
    if (buf[j] == '.') {
      if (lastCharIsDot) {
        j++;
        continue;
      }
      lastCharIsDot = true;
    } else {
      lastCharIsDot = false;
    }
    str[i++] = buf[j++];
  }
  str[i] = '\0';

  delete buf;
}
void str_append(char *str, const char *pre) {
  int slen = strlen(str);
  for (int i = 0; ; i++) {
    str[i + slen] = pre[i];
    if (pre[i] == 0) return;
  }
}

inline int peek_user(int pid, long addr, char* result) {
  int i;
  do
  {
    long val;
    char *p;

    val = ptrace(PTRACE_PEEKTEXT, pid, (char*)addr, NULL);
    if (val < 0)
      return -1;
    addr += sizeof(long);

    p = (char *)&val;
    for (i = 0; i < (int)sizeof(long); ++i, ++result)
    {
      *result = *p++;
      if (*result == '\0')
        break;
    }
  } while (i == sizeof(long));
  return 0;
}

inline int poke_user(int pid, long where, char* str) {
  char *stack_addr, *file_addr;

  stack_addr = (char *)ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RSP, 0);
  stack_addr -= 128 + PATH_MAX;
  file_addr = stack_addr;

  /* Write new file in lower part of the stack */
  do
  {
    int i;
    char val[sizeof(long)];

    for (i = 0; i < (int)sizeof(long); ++i, ++str)
    {
      val[i] = *str;
      if (*str == '\0')
        break;
    }

    if (ptrace(PTRACE_POKETEXT, pid, stack_addr, *(long *)val) < 0)
      return -1;
    stack_addr += sizeof(long);
  } while (*str);

  /* Change argument to open */
  ptrace(PTRACE_POKEUSER, pid, sizeof(long) * get_register(where), file_addr);
  return 0;
}

int check(int pid, int where, int op, ...) {
  long regvar
    = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * get_register(where), 0);

  va_list ap;
  va_start(ap, op);

  int int_arg;
  char* char_arg;

  static char buf[5000];
  int ret = 0;

  switch (op) {
  case GREATER:
    int_arg = va_arg(ap, int);
    ret = regvar > int_arg;
    break;
  case EQUAL:
    int_arg = va_arg(ap, int);
    ret =  regvar == int_arg;
    break;
  case LESS:
    int_arg = va_arg(ap, int);
    ret =  regvar < int_arg;
    break;
  case TEST:
    int_arg = va_arg(ap, int);
    ret =  regvar & int_arg;
    break;
  case MASK:
    int_arg = va_arg(ap, int);
    regvar = regvar & int_arg;
    ret =  ptrace(PTRACE_POKEUSER, pid, sizeof(long) * get_register(where), regvar) == 0;
    break;
  case SET:
    int_arg = va_arg(ap, int);
    regvar = regvar | int_arg;
    ret =  ptrace(PTRACE_POKEUSER, pid, sizeof(long) * get_register(where), regvar) == 0;
    break;
  case STARTSWITH:
    char_arg = va_arg(ap, char*);
    if (peek_user(pid, regvar, buf) < 0) return -1;
    ret =  str_starts_with(buf, char_arg);
    break;
  case ENDSWITH:
    char_arg = va_arg(ap, char*);
    if (peek_user(pid, regvar, buf) < 0) return -1;
    ret =  str_ends_with(buf, char_arg);
    break;
  case CONTAINS:
    char_arg = va_arg(ap, char*);
    if (peek_user(pid, regvar, buf) < 0) return -1;
    ret =  strstr(buf, char_arg) != NULL;
    break;
  case EXACT:
    char_arg = va_arg(ap, char*);
    if (peek_user(pid, regvar, buf) < 0) return -1;
    ret =  strcmp(buf, char_arg) == 0;
    break;
  case PREPEND:
    char_arg = va_arg(ap, char*);
    if (peek_user(pid, regvar, buf) < 0) return -1;
    str_prepend(buf, char_arg);
    poke_user(pid, where, buf);
    ret =  0;
    break;
  case APPEND:
    char_arg = va_arg(ap, char*);
    if (peek_user(pid, regvar, buf) < 0) return -1;
    str_append(buf, char_arg);
    poke_user(pid, where, buf);
    ret =  0;
    break;
  case REPLACE:
    char_arg = va_arg(ap, char*);
    poke_user(pid, where, char_arg);
    ret =  0;
    break;
  case QUERY:
    *va_arg(ap, int*) = regvar;
    va_end(ap);
    ret =  0;
    break;
  case QUERYSTR:
    char_arg = va_arg(ap, char*);
    va_end(ap);
    peek_user(pid, regvar, char_arg);
    ret =  0;
    break;
  default:
    break;
  }

  va_end(ap);
  return ret;
}

extern bool debug;
extern map<string, string> path;

int validate_syscall (int pid, int syscall) {
  // 0 1 2 3
  //safe, get, write, dangerous
  char buf[5000];
  switch (syscall)
  {
  #ifdef __NR_read // 0
    case __NR_read: return ALLOW;
  #endif

  #ifdef __NR_write // 0
    case __NR_write: return ALLOW;
  #endif

  #ifdef __NR_open // 2
    case __NR_open:
      check(pid, 1, QUERYSTR, buf);
      if (check(pid, 2, TEST, O_WRONLY) || check(pid, 2, TEST, O_RDWR)) {
        if (check(pid, 1, EXACT, "/dev/tty")) {
          if (debug)
            cout << "[" << pid << "] " << buf << " - TTY" << endl;
          return ALLOW;
        }
        str_prepend_path_safe(buf, path["sandbox"].c_str());
        check(pid, 1, REPLACE, buf);
        if (debug)
          cout << "[" << pid << "] " << buf << " - RW" << endl;
        return ALLOW;
      } else {
        if (debug)
          cout << "[" << pid << "] " << buf << " - R" << endl;
      }
      return ALLOW;
  #endif

  #ifdef __NR_close // 0
    case __NR_close: return ALLOW;
  #endif

  #ifdef __NR_stat // 1
    case __NR_stat: return ALLOW;
  #endif

  #ifdef __NR_fstat // 0, get information of opened filess
    case __NR_fstat: return ALLOW;
  #endif

  #ifdef __NR_lstat // 1
    case __NR_lstat: return ALLOW;
  #endif

  #ifdef __NR_poll // 0
    case __NR_poll: return ALLOW;
  #endif

  #ifdef __NR_lseek // 0
    case __NR_lseek: return ALLOW;
  #endif

  #ifdef __NR_mmap // 0
    case __NR_mmap: return ALLOW;
  #endif

  #ifdef __NR_mprotect // 0
    case __NR_mprotect: return ALLOW;
  #endif

  #ifdef __NR_munmap // 0
    case __NR_munmap: return ALLOW;
  #endif

  #ifdef __NR_brk // 0
    case __NR_brk: return ALLOW;
  #endif

  #ifdef __NR_rt_sigaction // 0
    case __NR_rt_sigaction: return ALLOW;
  #endif

  #ifdef __NR_rt_sigprocmask // 0
    case __NR_rt_sigprocmask: return ALLOW;
  #endif

  #ifdef __NR_rt_sigreturn // 0
    case __NR_rt_sigreturn: return ALLOW;
  #endif

  #ifdef __NR_ioctl // 3
    // TODO: why python need this?
    case __NR_ioctl: return ALLOW;
  #endif

  #ifdef __NR_pread64 // 0
    case __NR_pread64: return ALLOW;
  #endif

  #ifdef __NR_pwrite64 // 0
    case __NR_pwrite64: return ALLOW;
  #endif

  #ifdef __NR_readv // 1
    case __NR_readv: return ALLOW;
  #endif

  #ifdef __NR_writev // 1
    case __NR_writev: return ALLOW;
  #endif

  #ifdef __NR_access // 0
    case __NR_access: return ALLOW;
  #endif

  #ifdef __NR_pipe // 0
    case __NR_pipe: return ALLOW;
  #endif

  #ifdef __NR_select // 0
    case __NR_select: return ALLOW;
  #endif

  #ifdef __NR_sched_yield // 1 should not be called, maybe
    case __NR_sched_yield: return ALLOW;
  #endif

  #ifdef __NR_mremap // 0
    case __NR_mremap: return ALLOW;
  #endif

  #ifdef __NR_msync // 0
    case __NR_msync: return ALLOW;
  #endif

  #ifdef __NR_mincore // 0
    case __NR_mincore: return ALLOW;
  #endif

  #ifdef __NR_madvise // 0
    case __NR_madvise: return ALLOW;
  #endif

  #ifdef __NR_shmget // 1
    case __NR_shmget: return ALLOW;
  #endif

  #ifdef __NR_shmat // 1
    case __NR_shmat: return ALLOW;
  #endif

  #ifdef __NR_shmctl // 1
    case __NR_shmctl: return ALLOW;
  #endif

  #ifdef __NR_dup  // 1
    case __NR_dup: return ALLOW;
  #endif

  #ifdef __NR_dup2 // 1
    case __NR_dup2: return ALLOW;
  #endif

  #ifdef __NR_pause // 0
    case __NR_pause: return ALLOW;
  #endif

  #ifdef __NR_nanosleep // 0
    case __NR_nanosleep: return ALLOW;
  #endif

  #ifdef __NR_getitimer // 1 get internal timer
    case __NR_getitimer: return ALLOW;
  #endif

  #ifdef __NR_alarm // 0
    case __NR_alarm: return ALLOW;
  #endif

  #ifdef __NR_setitimer // 1 set internal timer
    case __NR_setitimer: return ALLOW;
  #endif

  #ifdef __NR_getpid // 0
    case __NR_getpid: return ALLOW;
  #endif

  #ifdef __NR_sendfile // 1 copy one file to another
    case __NR_sendfile: return ALLOW;
  #endif

  #ifdef __NR_socket // 2 maybe used by unix socket
    case __NR_socket:
      if (check(pid, 1, EQUAL, AF_UNIX))
        return ALLOW;
      return DENY;
  #endif

  #ifdef __NR_connect // 2
    case __NR_connect: return ALLOW;
  #endif

  #ifdef __NR_accept // 3
    case __NR_accept: return DENY;
  #endif

  #ifdef __NR_sendto // 3
    case __NR_sendto: return DENY;
  #endif

  #ifdef __NR_recvfrom // 3
    case __NR_recvfrom: return DENY;
  #endif

  #ifdef __NR_sendmsg // 3
    case __NR_sendmsg: return DENY;
  #endif

  #ifdef __NR_recvmsg // 3
    case __NR_recvmsg: return DENY;
  #endif

  #ifdef __NR_shutdown // 3
    case __NR_shutdown: return DENY;
  #endif

  #ifdef __NR_bind // 3
    case __NR_bind: return DENY;
  #endif

  #ifdef __NR_listen // 3
    case __NR_listen: return DENY;
  #endif

  #ifdef __NR_getsockname // 3
    case __NR_getsockname: return DENY;
  #endif

  #ifdef __NR_getpeername // 3
    case __NR_getpeername: return DENY;
  #endif

  #ifdef __NR_socketpair // 3
    case __NR_socketpair: return DENY;
  #endif

  #ifdef __NR_setsockopt // 3
    case __NR_setsockopt: return DENY;
  #endif

  #ifdef __NR_getsockopt // 3
    case __NR_getsockopt: return DENY;
  #endif

  #ifdef __NR_clone // 1
    case __NR_clone: return ALLOW;
  #endif

  #ifdef __NR_fork // 1
    case __NR_fork: return ALLOW;
  #endif

  #ifdef __NR_vfork // 1
    case __NR_vfork: return ALLOW; return 1;
  #endif

  #ifdef __NR_execve // 1
    case __NR_execve: return ALLOW;
  #endif

  #ifdef __NR_exit // 0
    case __NR_exit: return ALLOW;
  #endif

  #ifdef __NR_wait4 // 0
    case __NR_wait4: return ALLOW;
  #endif

  #ifdef __NR_kill // 1
    case __NR_kill: return ALLOW;
  #endif

  #ifdef __NR_uname // 0
    case __NR_uname: return ALLOW;
  #endif

  #ifdef __NR_semget // 1 ipc
    case __NR_semget: return ALLOW;
  #endif

  #ifdef __NR_semop // 1 ipc
    case __NR_semop: return ALLOW;
  #endif

  #ifdef __NR_semctl // 1 ipc
    case __NR_semctl: return ALLOW;
  #endif

  #ifdef __NR_shmdt // 1 ipc
    case __NR_shmdt: return ALLOW;
  #endif

  #ifdef __NR_msgget // 1 ipc
    case __NR_msgget: return ALLOW;
  #endif

  #ifdef __NR_msgsnd // 1 ipc
    case __NR_msgsnd: return ALLOW;
  #endif

  #ifdef __NR_msgrcv // 1 ipc
    case __NR_msgrcv: return ALLOW;
  #endif

  #ifdef __NR_msgctl // 1 ipc
    case __NR_msgctl: return ALLOW;
  #endif

  #ifdef __NR_fcntl // 1 cannot update open mode
    case __NR_fcntl: return ALLOW;
  #endif

  #ifdef __NR_flock // 1
    case __NR_flock: return ALLOW;
  #endif

  #ifdef __NR_fsync // 1
    case __NR_fsync: return ALLOW;
  #endif

  #ifdef __NR_fdatasync // 1
    case __NR_fdatasync: return ALLOW;
  #endif

  #ifdef __NR_truncate // 2 could truncate any file, but as all owned by root ,it might be ok
    case __NR_truncate: return DENY;
  #endif

  #ifdef __NR_ftruncate // 1
    case __NR_ftruncate: return ALLOW;
  #endif

  #ifdef __NR_getdents // 2 should not be called by user [EXCEPT python]
    case __NR_getdents: return ALLOW;
  #endif

  #ifdef __NR_getcwd // 0
    case __NR_getcwd: return ALLOW;
  #endif

  #ifdef __NR_chdir // 2
    case __NR_chdir: return DENY;
  #endif

  #ifdef __NR_fchdir // 1
    case __NR_fchdir: return ALLOW;
  #endif

  #ifdef __NR_rename // 2
    case __NR_rename: return DENY;
  #endif

  #ifdef __NR_mkdir // 2
    case __NR_mkdir: return DENY;
  #endif

  #ifdef __NR_rmdir // 2
    case __NR_rmdir: return DENY;
  #endif

  #ifdef __NR_creat // 2
    case __NR_creat: return DENY;
  #endif

  #ifdef __NR_link // 2
    case __NR_link: return DENY;
  #endif

  #ifdef __NR_unlink // 2
    case __NR_unlink: return DENY;
  #endif

  #ifdef __NR_symlink // 2
    case __NR_symlink: return DENY;
  #endif

  #ifdef __NR_readlink // 1
    case __NR_readlink: return ALLOW;
  #endif

  #ifdef __NR_chmod // 2
    case __NR_chmod: return DENY;
  #endif

  #ifdef __NR_fchmod // 1
    case __NR_fchmod: return ALLOW;
  #endif

  #ifdef __NR_chown // 2
    case __NR_chown: return DENY;
  #endif

  #ifdef __NR_fchown // 1
    case __NR_fchown: return ALLOW;
  #endif

  #ifdef __NR_lchown // 2
    case __NR_lchown: return DENY;
  #endif

  #ifdef __NR_umask // 1
    case __NR_umask: return ALLOW;
  #endif

  #ifdef __NR_gettimeofday // 0
    case __NR_gettimeofday: return ALLOW;
  #endif

  #ifdef __NR_getrlimit // 0
    case __NR_getrlimit: return ALLOW;
  #endif

  #ifdef __NR_getrusage // 0
    case __NR_getrusage: return ALLOW;
  #endif

  #ifdef __NR_sysinfo // 1
    case __NR_sysinfo: return ALLOW;
  #endif

  #ifdef __NR_times // 1
    case __NR_times: return ALLOW;
  #endif

  #ifdef __NR_ptrace // 3
    case __NR_ptrace: return DENY;
  #endif

  #ifdef __NR_getuid // 0
    case __NR_getuid: return ALLOW;
  #endif

  #ifdef __NR_syslog // 3
    case __NR_syslog: return DENY;
  #endif

  #ifdef __NR_getgid // 0
    case __NR_getgid: return ALLOW;
  #endif

  #ifdef __NR_setuid // 3
    case __NR_setuid: return DENY;
  #endif

  #ifdef __NR_setgid // 3
    case __NR_setgid: return DENY;
  #endif

  #ifdef __NR_geteuid // 0
    case __NR_geteuid: return ALLOW;
  #endif

  #ifdef __NR_getegid // 0
    case __NR_getegid: return ALLOW;
  #endif

  #ifdef __NR_setpgid // 3
    case __NR_setpgid: return DENY;
  #endif

  #ifdef __NR_getppid // 0
    case __NR_getppid: return ALLOW;
  #endif

  #ifdef __NR_getpgrp // 0
    case __NR_getpgrp: return ALLOW;
  #endif

  #ifdef __NR_setsid // 3
    case __NR_setsid: return DENY;
  #endif

  #ifdef __NR_setreuid // 3
    case __NR_setreuid: return DENY;
  #endif

  #ifdef __NR_setregid // 3
    case __NR_setregid: return DENY;
  #endif

  #ifdef __NR_getgroups // 0
    case __NR_getgroups: return ALLOW;
  #endif

  #ifdef __NR_setgroups // 3
    case __NR_setgroups: return DENY;
  #endif

  #ifdef __NR_setresuid // 3
    case __NR_setresuid: return DENY;
  #endif

  #ifdef __NR_getresuid // 0
    case __NR_getresuid: return ALLOW;
  #endif

  #ifdef __NR_setresgid // 3
    case __NR_setresgid: return DENY;
  #endif

  #ifdef __NR_getresgid // 0
    case __NR_getresgid: return ALLOW;
  #endif

  #ifdef __NR_getpgid // 0
    case __NR_getpgid: return ALLOW;
  #endif

  #ifdef __NR_setfsuid // 3
    case __NR_setfsuid: return DENY;
  #endif

  #ifdef __NR_setfsgid // 3
    case __NR_setfsgid: return DENY;
  #endif

  #ifdef __NR_getsid // 0
    case __NR_getsid: return ALLOW;
  #endif

  #ifdef __NR_capget // 3
    case __NR_capget: return DENY;
  #endif

  #ifdef __NR_capset // 3
    case __NR_capset: return DENY;
  #endif

  #ifdef __NR_rt_sigpending // 0
    case __NR_rt_sigpending: return ALLOW;
  #endif

  #ifdef __NR_rt_sigtimedwait // 0
    case __NR_rt_sigtimedwait: return ALLOW;
  #endif

  #ifdef __NR_rt_sigqueueinfo // 0
    case __NR_rt_sigqueueinfo: return ALLOW;
  #endif

  #ifdef __NR_rt_sigsuspend // 0
    case __NR_rt_sigsuspend: return ALLOW;
  #endif

  #ifdef __NR_sigaltstack // 0
    case __NR_sigaltstack: return ALLOW;
  #endif

  #ifdef __NR_utime  // 2
    case __NR_utime: return DENY;
  #endif

  #ifdef __NR_mknod  // 2
    case __NR_mknod: return DENY;
  #endif

  #ifdef __NR_uselib  // 2 as not used by glibc
    case __NR_uselib: return DENY;
  #endif

  #ifdef __NR_personality  // 2
    case __NR_personality: return DENY;
  #endif

  #ifdef __NR_ustat // 2
    case __NR_ustat: return DENY;
  #endif

  #ifdef __NR_statfs // 2
    case __NR_statfs: return SKIP;
  #endif

  #ifdef __NR_fstatfs // 0
    case __NR_fstatfs: return ALLOW;
  #endif

  #ifdef __NR_sysfs // 0
    case __NR_sysfs: return ALLOW;
  #endif

  #ifdef __NR_getpriority // 0
    case __NR_getpriority: return ALLOW;
  #endif

  #ifdef __NR_setpriority // 3
    case __NR_setpriority: return DENY;
  #endif

  #ifdef __NR_sched_setparam // 3
    case __NR_sched_setparam: return DENY;
  #endif

  #ifdef __NR_sched_getparam // 0
    case __NR_sched_getparam: return ALLOW;
  #endif

  #ifdef __NR_sched_setscheduler // 3
    case __NR_sched_setscheduler: return DENY;
  #endif

  #ifdef __NR_sched_getscheduler // 0
    case __NR_sched_getscheduler: return ALLOW;
  #endif

  #ifdef __NR_sched_get_priority_max // 0
    case __NR_sched_get_priority_max: return ALLOW;
  #endif

  #ifdef __NR_sched_get_priority_min // 0
    case __NR_sched_get_priority_min: return ALLOW;
  #endif

  #ifdef __NR_sched_rr_get_interval // 0
    case __NR_sched_rr_get_interval: return ALLOW;
  #endif

  #ifdef __NR_mlock // 1
    case __NR_mlock: return ALLOW;
  #endif

  #ifdef __NR_munlock // 1
    case __NR_munlock: return ALLOW;
  #endif

  #ifdef __NR_mlockall // 1
    case __NR_mlockall: return ALLOW;
  #endif

  #ifdef __NR_munlockall // 1
    case __NR_munlockall: return ALLOW;
  #endif

  #ifdef __NR_vhangup // 2
    case __NR_vhangup: return DENY;
  #endif

  #ifdef __NR_modify_ldt // 3
    case __NR_modify_ldt: return DENY;
  #endif

  #ifdef __NR_pivot_root // 3
    case __NR_pivot_root: return DENY;
  #endif

  #ifdef __NR__sysctl // 3
    case __NR__sysctl: return DENY;
  #endif

  #ifdef __NR_prctl // 1
    case __NR_prctl: return ALLOW;
  #endif

  #ifdef __NR_arch_prctl // 1
    case __NR_arch_prctl: return ALLOW;
  #endif

  #ifdef __NR_adjtimex // 3
    case __NR_adjtimex: return DENY;
  #endif

  #ifdef __NR_setrlimit // 3
    case __NR_setrlimit: return DENY;
  #endif

  #ifdef __NR_chroot // 3
    case __NR_chroot: return DENY;
  #endif

  #ifdef __NR_sync // 1
    case __NR_sync: return ALLOW;
  #endif

  #ifdef __NR_acct // 3
    case __NR_acct: return DENY;
  #endif

  #ifdef __NR_settimeofday // 3
    case __NR_settimeofday: return DENY;
  #endif

  #ifdef __NR_mount // 3
    case __NR_mount: return DENY;
  #endif

  #ifdef __NR_umount2 // 3
    case __NR_umount2: return DENY;
  #endif

  #ifdef __NR_swapon // 3
    case __NR_swapon: return DENY;
  #endif

  #ifdef __NR_swapoff // 3
    case __NR_swapoff: return DENY;
  #endif

  #ifdef __NR_reboot // 3
    case __NR_reboot: return DENY;
  #endif

  #ifdef __NR_sethostname // 3
    case __NR_sethostname: return DENY;
  #endif

  #ifdef __NR_setdomainname // 3
    case __NR_setdomainname: return DENY;
  #endif

  #ifdef __NR_iopl // 3
    case __NR_iopl: return DENY;
  #endif

  #ifdef __NR_ioperm // 3
    case __NR_ioperm: return DENY;
  #endif

  #ifdef __NR_create_module // 3
    case __NR_create_module: return DENY;
  #endif

  #ifdef __NR_init_module // 3
    case __NR_init_module: return DENY;
  #endif

  #ifdef __NR_delete_module // 3
    case __NR_delete_module: return DENY;
  #endif

  #ifdef __NR_get_kernel_syms // 3
    case __NR_get_kernel_syms: return DENY;
  #endif

  #ifdef __NR_query_module // 3
    case __NR_query_module: return DENY;
  #endif

  #ifdef __NR_quotactl // 3
    case __NR_quotactl: return DENY;
  #endif

  #ifdef __NR_nfsservctl // 3
    case __NR_nfsservctl: return DENY;
  #endif

  #ifdef __NR_getpmsg // 3 not used
    case __NR_getpmsg: return DENY;
  #endif

  #ifdef __NR_putpmsg // 3 not used
    case __NR_putpmsg: return DENY;
  #endif

  #ifdef __NR_afs_syscall // 3 not used
    case __NR_afs_syscall: return DENY;
  #endif

  #ifdef __NR_tuxcall // 3 not used
    case __NR_tuxcall: return DENY;
  #endif

  #ifdef __NR_security // 3 not used
    case __NR_security: return DENY;
  #endif

  #ifdef __NR_gettid // 0
    case __NR_gettid: return ALLOW;
  #endif

  #ifdef __NR_readahead // 0
    case __NR_readahead: return ALLOW;
  #endif

  #ifdef __NR_setxattr // 2
    case __NR_setxattr: return DENY;
  #endif

  #ifdef __NR_lsetxattr // 2
    case __NR_lsetxattr: return DENY;
  #endif

  #ifdef __NR_fsetxattr // 1
    case __NR_fsetxattr: return ALLOW;
  #endif

  #ifdef __NR_getxattr // 0
    case __NR_getxattr: return ALLOW;
  #endif

  #ifdef __NR_lgetxattr // 0
    case __NR_lgetxattr: return ALLOW;
  #endif

  #ifdef __NR_fgetxattr // 0
    case __NR_fgetxattr: return ALLOW;
  #endif

  #ifdef __NR_listxattr // 0
    case __NR_listxattr: return ALLOW;
  #endif

  #ifdef __NR_llistxattr // 0
    case __NR_llistxattr: return ALLOW;
  #endif

  #ifdef __NR_flistxattr // 0
    case __NR_flistxattr: return ALLOW;
  #endif

  #ifdef __NR_removexattr // 2
    case __NR_removexattr: return DENY;
  #endif

  #ifdef __NR_lremovexattr // 2
    case __NR_lremovexattr: return DENY;
  #endif

  #ifdef __NR_fremovexattr // 1
    case __NR_fremovexattr: return ALLOW;
  #endif

  #ifdef __NR_tkill // 1
    case __NR_tkill: return ALLOW;
  #endif

  #ifdef __NR_time // 0
    case __NR_time: return ALLOW;
  #endif

  #ifdef __NR_futex // 1
    case __NR_futex: return ALLOW;
  #endif

  #ifdef __NR_sched_setaffinity // 1
    case __NR_sched_setaffinity: return ALLOW;
  #endif

  #ifdef __NR_sched_getaffinity // 1
    case __NR_sched_getaffinity: return ALLOW;
  #endif

  #ifdef __NR_set_thread_area // 1
    case __NR_set_thread_area: return ALLOW;
  #endif

  #ifdef __NR_io_setup // 3
    case __NR_io_setup: return DENY;
  #endif

  #ifdef __NR_io_destroy // 3
    case __NR_io_destroy: return DENY;
  #endif

  #ifdef __NR_io_getevents // 3
    case __NR_io_getevents: return DENY;
  #endif

  #ifdef __NR_io_submit // 3
    case __NR_io_submit: return DENY;
  #endif

  #ifdef __NR_io_cancel // 3
    case __NR_io_cancel: return DENY;
  #endif

  #ifdef __NR_get_thread_area // 1
    case __NR_get_thread_area: return ALLOW;
  #endif

  #ifdef __NR_lookup_dcookie // 1
    case __NR_lookup_dcookie: return ALLOW;
  #endif

  #ifdef __NR_epoll_create // 1
    case __NR_epoll_create: return ALLOW;
  #endif

  #ifdef __NR_epoll_ctl_old // 1
    case __NR_epoll_ctl_old: return ALLOW;
  #endif

  #ifdef __NR_epoll_wait_old // 1
    case __NR_epoll_wait_old: return ALLOW;
  #endif

  #ifdef __NR_remap_file_pages // 1
    case __NR_remap_file_pages: return ALLOW;
  #endif

  #ifdef __NR_getdents64 // 1
    case __NR_getdents64: return ALLOW;
  #endif

  #ifdef __NR_set_tid_address // 1
    case __NR_set_tid_address: return ALLOW;
  #endif

  #ifdef __NR_restart_syscall // 1
    case __NR_restart_syscall: return ALLOW;
  #endif

  #ifdef __NR_semtimedop // 2
    case __NR_semtimedop: return DENY;
  #endif

  #ifdef __NR_fadvise64 // 1
    case __NR_fadvise64: return ALLOW;
  #endif

  #ifdef __NR_timer_create // 1
    case __NR_timer_create: return ALLOW;
  #endif

  #ifdef __NR_timer_settime // 1
    case __NR_timer_settime: return ALLOW;
  #endif

  #ifdef __NR_timer_gettime // 1
    case __NR_timer_gettime: return ALLOW;
  #endif

  #ifdef __NR_timer_getoverrun // 1
    case __NR_timer_getoverrun: return ALLOW;
  #endif

  #ifdef __NR_timer_delete // 1
    case __NR_timer_delete: return ALLOW;
  #endif

  #ifdef __NR_clock_settime // 1
    case __NR_clock_settime: return ALLOW;
  #endif

  #ifdef __NR_clock_gettime // 1
    case __NR_clock_gettime: return ALLOW;
  #endif

  #ifdef __NR_clock_getres // 1
    case __NR_clock_getres: return ALLOW;
  #endif

  #ifdef __NR_clock_nanosleep // 1
    case __NR_clock_nanosleep: return ALLOW;
  #endif

  #ifdef __NR_exit_group // 0
    case __NR_exit_group: return ALLOW;
  #endif

  #ifdef __NR_epoll_wait // 1
    case __NR_epoll_wait: return ALLOW;
  #endif

  #ifdef __NR_epoll_ctl // 1
    case __NR_epoll_ctl: return ALLOW;
  #endif

  #ifdef __NR_tgkill // 1
    case __NR_tgkill: return ALLOW;
  #endif

  #ifdef __NR_utimes // 2
    case __NR_utimes: return DENY;
  #endif

  #ifdef __NR_vserver // 3 not implemented
    case __NR_vserver: return DENY;
  #endif

  #ifdef __NR_mbind // 3 won't link
    case __NR_mbind: return DENY;
  #endif

  #ifdef __NR_set_mempolicy // 3 won't link
    case __NR_set_mempolicy: return DENY;
  #endif

  #ifdef __NR_get_mempolicy // 3 won't link
    case __NR_get_mempolicy: return DENY;
  #endif

  #ifdef __NR_mq_open // 3 won't link
    case __NR_mq_open: return DENY;
  #endif

  #ifdef __NR_mq_unlink // 3 won't link
    case __NR_mq_unlink: return DENY;
  #endif

  #ifdef __NR_mq_timedsend // 3 won't link
    case __NR_mq_timedsend: return DENY;
  #endif

  #ifdef __NR_mq_timedreceive // 3 won't link
    case __NR_mq_timedreceive: return DENY;
  #endif

  #ifdef __NR_mq_notify // 3 won't link
    case __NR_mq_notify: return DENY;
  #endif

  #ifdef __NR_mq_getsetattr // 3 won't link
    case __NR_mq_getsetattr: return DENY;
  #endif

  #ifdef __NR_kexec_load // 3
    case __NR_kexec_load: return DENY;
  #endif

  #ifdef __NR_waitid // 1
    case __NR_waitid: return ALLOW;
  #endif

  #ifdef __NR_add_key // 3
    case __NR_add_key: return DENY;
  #endif

  #ifdef __NR_request_key // 3
    case __NR_request_key: return DENY;
  #endif

  #ifdef __NR_keyctl // 3
    case __NR_keyctl: return DENY;
  #endif

  #ifdef __NR_ioprio_set // 3
    case __NR_ioprio_set: return DENY;
  #endif

  #ifdef __NR_ioprio_get // 3
    case __NR_ioprio_get: return DENY;
  #endif

  #ifdef __NR_inotify_init // 1
    case __NR_inotify_init: return ALLOW;
  #endif

  #ifdef __NR_inotify_add_watch // 1
    case __NR_inotify_add_watch: return ALLOW;
  #endif

  #ifdef __NR_inotify_rm_watch // 1
    case __NR_inotify_rm_watch: return ALLOW;
  #endif

  #ifdef __NR_migrate_pages // 3
    case __NR_migrate_pages: return DENY;
  #endif

  #ifdef __NR_openat // 2
    case __NR_openat:
      check(pid, 2, QUERYSTR, buf);
      if (check(pid, 3, TEST, O_WRONLY) || check(pid, 3, TEST, O_RDWR)) {
        if (check(pid, 2, EXACT, "/dev/tty")) {
          if (debug)
            cout << "[" << pid << "] " << buf << " - TTY" << endl;
          return ALLOW;
        }
        str_prepend_path_safe(buf, path["sandbox"].c_str());
        check(pid, 2, REPLACE, buf);
        if (debug)
          cout << "[" << pid << "] " << buf << " - RW" << endl;
        return ALLOW;
      } else {
        if (debug)
          cout << "[" << pid << "] " << buf << " - R" << endl;
      }
      return ALLOW;
  #endif

  #ifdef __NR_mkdirat // 2
    case __NR_mkdirat: return DENY;
  #endif

  #ifdef __NR_mknodat // 2
    case __NR_mknodat: return DENY;
  #endif

  #ifdef __NR_fchownat // 2
    case __NR_fchownat: return DENY;
  #endif

  #ifdef __NR_futimesat // 2
    case __NR_futimesat: return DENY;
  #endif

  #ifdef __NR_newfstatat // 2
    case __NR_newfstatat: return DENY;
  #endif

  #ifdef __NR_unlinkat // 2
    case __NR_unlinkat: return DENY;
  #endif

  #ifdef __NR_renameat // 2
    case __NR_renameat: return DENY;
  #endif

  #ifdef __NR_linkat // 2
    case __NR_linkat: return DENY;
  #endif

  #ifdef __NR_symlinkat // 2
    case __NR_symlinkat: return DENY;
  #endif

  #ifdef __NR_readlinkat // 2
    case __NR_readlinkat: return ALLOW;
  #endif

  #ifdef __NR_fchmodat // 2
    case __NR_fchmodat: return ALLOW;
  #endif

  #ifdef __NR_faccessat // 2
    case __NR_faccessat: return ALLOW;
  #endif

  #ifdef __NR_pselect6 // 1
    case __NR_pselect6: return ALLOW;
  #endif

  #ifdef __NR_ppoll // 1
    case __NR_ppoll: return ALLOW;
  #endif

  #ifdef __NR_unshare // 3
    case __NR_unshare: return DENY;
  #endif

  #ifdef __NR_set_robust_list // 1
    case __NR_set_robust_list: return ALLOW;
  #endif

  #ifdef __NR_get_robust_list // 1
    case __NR_get_robust_list: return ALLOW;
  #endif

  #ifdef __NR_splice // 1
    case __NR_splice: return ALLOW;
  #endif

  #ifdef __NR_tee // 1
    case __NR_tee: return ALLOW;
  #endif

  #ifdef __NR_sync_file_range // 1
    case __NR_sync_file_range: return ALLOW;
  #endif

  #ifdef __NR_vmsplice // 1
    case __NR_vmsplice: return ALLOW;
  #endif

  #ifdef __NR_move_pages // 3
    case __NR_move_pages: return DENY;
  #endif

  #ifdef __NR_utimensat // 3
    case __NR_utimensat: return DENY;
  #endif

  #ifdef __NR_epoll_pwait // 1
    case __NR_epoll_pwait: return ALLOW;
  #endif

  #ifdef __NR_signalfd // 1
    case __NR_signalfd: return ALLOW;
  #endif

  #ifdef __NR_timerfd_create // 1
    case __NR_timerfd_create: return ALLOW;
  #endif

  #ifdef __NR_eventfd // 1
    case __NR_eventfd: return ALLOW;
  #endif

  #ifdef __NR_fallocate // 1
    case __NR_fallocate: return ALLOW;
  #endif

  #ifdef __NR_timerfd_settime // 1
    case __NR_timerfd_settime: return ALLOW;
  #endif

  #ifdef __NR_timerfd_gettime // 1
    case __NR_timerfd_gettime: return ALLOW;
  #endif

  #ifdef __NR_accept4 // 2
    case __NR_accept4: return DENY;
  #endif

  #ifdef __NR_signalfd4 // 1
    case __NR_signalfd4: return ALLOW;
  #endif

  #ifdef __NR_eventfd2 // 1
    case __NR_eventfd2: return ALLOW;
  #endif

  #ifdef __NR_epoll_create1 // 1
    case __NR_epoll_create1: return ALLOW;
  #endif

  #ifdef __NR_dup3 // 1
    case __NR_dup3: return ALLOW;
  #endif

  #ifdef __NR_pipe2 // 1
    case __NR_pipe2: return ALLOW;
  #endif

  #ifdef __NR_inotify_init1 // 1
    case __NR_inotify_init1: return ALLOW;
  #endif

  #ifdef __NR_preadv // 1
    case __NR_preadv: return ALLOW;
  #endif

  #ifdef __NR_pwritev // 1
    case __NR_pwritev: return ALLOW;
  #endif

  #ifdef __NR_rt_tgsigqueueinfo // 1
    case __NR_rt_tgsigqueueinfo: return ALLOW;
  #endif

  #ifdef __NR_perf_event_open // 3
    case __NR_perf_event_open: return DENY;
  #endif

  #ifdef __NR_recvmmsg // 2
    case __NR_recvmmsg: return DENY;
  #endif

  #ifdef __NR_fanotify_init // 1
    case __NR_fanotify_init: return ALLOW;
  #endif

  #ifdef __NR_fanotify_mark // 1
    case __NR_fanotify_mark: return ALLOW;
  #endif

  #ifdef __NR_prlimit64 // 2
    case __NR_prlimit64: return DENY;
  #endif

  #ifdef __NR_name_to_handle_at // 3
    case __NR_name_to_handle_at: return DENY;
  #endif

  #ifdef __NR_open_by_handle_at // 3
    case __NR_open_by_handle_at: return DENY;
  #endif

  #ifdef __NR_clock_adjtime // 3
    case __NR_clock_adjtime: return DENY;
  #endif

  #ifdef __NR_syncfs // 1
    case __NR_syncfs: return ALLOW;
  #endif

  #ifdef __NR_sendmmsg // 1
    case __NR_sendmmsg: return ALLOW;
  #endif

  #ifdef __NR_setns // 3
    case __NR_setns: return DENY;
  #endif

  #ifdef __NR_getcpu // 1
    case __NR_getcpu: return ALLOW;
  #endif

  #ifdef __NR_process_vm_readv // 1
    case __NR_process_vm_readv: return ALLOW;
  #endif

  #ifdef __NR_process_vm_writev // 1
    case __NR_process_vm_writev: return ALLOW;
  #endif

  #ifdef __NR_kcmp  // 3
    case __NR_kcmp: return DENY;
  #endif

  #ifdef __NR_finit_module // 3
    case __NR_finit_module: return DENY;
  #endif

  #ifdef __NR_sched_setattr // 1
    case __NR_sched_setattr: return ALLOW;
  #endif

  #ifdef __NR_sched_getattr // 1
    case __NR_sched_getattr: return ALLOW;
  #endif

  #ifdef __NR_renameat2 // 3
    case __NR_renameat2: return DENY;
  #endif

  #ifdef __NR_seccomp // 3
    case __NR_seccomp: return DENY;
  #endif

  #ifdef __NR_getrandom // 1
    case __NR_getrandom: return ALLOW;
  #endif

  #ifdef __NR_memfd_create // 1
    case __NR_memfd_create: return ALLOW;
  #endif

  #ifdef __NR_kexec_file_load // 3
    case __NR_kexec_file_load: return DENY;
  #endif

  #ifdef __NR_bpf // 3
    case __NR_bpf: return DENY; return DENY;
  #endif

  #ifdef __NR_userfaultfd // 1
    case __NR_userfaultfd: return ALLOW;
  #endif

  #ifdef __NR_membarrier // 1
    case __NR_membarrier: return ALLOW;
  #endif

  #ifdef __NR_mlock2 // 1
    case __NR_mlock2: return ALLOW;
  #endif

  #ifdef __NR_copy_file_range // 1
    case __NR_copy_file_range: return ALLOW;
  #endif

  #ifdef __NR_pkey_mprotect // 1
    case __NR_pkey_mprotect: return ALLOW;
  #endif

  #ifdef __NR_pkey_alloc // 1
    case __NR_pkey_alloc: return ALLOW;
  #endif

  #ifdef __NR_pkey_free // 1
    case __NR_pkey_free: return ALLOW;
  #endif

    default: ;

  }
return DENY;
}