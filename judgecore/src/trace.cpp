#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <string>
#include <map>
#include <chrono>
#include <mutex>
#include <thread>

#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <fcntl.h>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/resource.h>
#include <sys/reg.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

using namespace std;

struct THREAD_INFO {
  int pid;
  rusage usage;
  thread* ref;
  int time;
  int memory;
  int status;
  THREAD_INFO* next;
  THREAD_INFO() {
    next = nullptr;
  }
};

map <int, string> syscall_name;
std::mutex g_tail_mutex;
THREAD_INFO* tail = nullptr;

int trace_thread(int pid, THREAD_INFO* info) {
  cout << "[" << pid << "] prepare tracing" << endl;
  int orig_eax, eax, r;
  long last_rip = 0;
  int& status = info->status;
  rusage& usage = info->usage;

  if (ptrace(PTRACE_SEIZE, pid, NULL, NULL)) {
    perror("while attach");
    return -1;
  }
  kill(pid, SIGSTOP);

  if (pid == waitpid(pid, &status, WSTOPPED)) {
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK))
      perror("set options");

    if(ptrace(PTRACE_CONT, pid, 0, 0))
      perror("start tracing child");
  }

  cout << "[" << pid << "] start tracing" << endl;

  while (pid == wait4(pid, &status, 0, &usage))
  {
    cout << "[" << pid << "] stopped" << endl;
    if (status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))
      || status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))
      || status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))) {

      long child_pid;
      ptrace(PTRACE_GETEVENTMSG, pid, NULL, &child_pid);
        cout << "[" << pid << "] cloned process " << child_pid << endl;
      if (!child_pid) {
        cerr << "failed clone process" << endl;
        return -1;
      }
      ptrace(PTRACE_CONT, pid, 0, 0);

      kill(child_pid, SIGSTOP);

      if (waitpid(child_pid, &status, WSTOPPED) < 0)
        perror("while waitpid");

      if (ptrace(PTRACE_DETACH, child_pid, NULL, (void *) SIGSTOP) < 0)
        perror("while detach");

      g_tail_mutex.lock();

      THREAD_INFO* next = new THREAD_INFO;
      tail = tail->next = next;
      next->ref = new std::thread(trace_thread, child_pid, tail);
      next->pid = child_pid;

      g_tail_mutex.unlock();
      continue;
    }
    if (WIFSIGNALED(status))
    {
      kill(pid, SIGKILL);
      cout << "[" << pid << "] user program terminated by system signal " << WTERMSIG(status) << endl;
      return 0;
    }

    if (WIFEXITED(status))
    {
      kill(pid, SIGKILL);
      cout << "[" << pid << "] user program exited normally" << endl;
      cout << "[" << pid << "] status: " << WEXITSTATUS(status) << endl;
      return 0;
    }

    if (status >> 8 == (SIGTRAP | (PTRAVE_EVENT_SECCOMP << 8)))
    {
      // syscall number
      orig_eax = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX, NULL);
      eax = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX, NULL);
      cout << "[" << pid << "] got syscall " << syscall_name[orig_eax] << "(" << orig_eax << ") " << eax << endl;

      if ((r = ptrace(PTRACE_CONT, pid, reinterpret_cast<char *>(1), 0)) == -1)
      {
        cerr << "[" << pid << "] failed to continue from breakpoint" << endl;
        kill(pid, SIGKILL);
        return -1;
      }
    }
    else
    {
      cout << "[" << pid << "] program reveived sig " << strsignal(WSTOPSIG(status)) << "(" << WSTOPSIG(status) << ")" << endl;
      ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status));
      continue;
    }
  }

  cerr << "-----------------------------" << pid << endl;
  return 1;
}

int start_trace(int pid) {
  THREAD_INFO* info = tail = new THREAD_INFO;
  int status;

  if (pid != waitpid(pid, &status, 0))
  {
    kill(pid, SIGKILL);
    cerr << "wait for child failed" << endl;
    return 1;
  }

  if (ptrace(PTRACE_DETACH, pid, NULL, (void *) SIGSTOP))
    perror("while detach");

  info->ref = new std::thread(trace_thread, pid, info);
  info->pid = pid;

  while(info){
    info->ref->join();
    cout << "[-------] thread debugging *" << info->pid << "* exited." << endl;
    cout << "time: " << (int) (info->usage.ru_utime.tv_sec * 1000 +
                                  info->usage.ru_utime.tv_usec / 1000) << ", ";
    cout << "memory: " << info->usage.ru_maxrss << endl;
    info = info->next;
    // delete
  }

  return 0;
}

int set_tracee() {
  struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_close, 35, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execve, 34, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit, 33, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_read, 32, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_write, 31, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getuid, 30, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_brk, 29, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getgid, 28, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_geteuid, 27, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getegid, 26, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getppid, 25, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getpgrp, 24, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getrlimit, 23, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getrusage, 22, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getgroups, 21, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_sigaltstack, 20, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_readlink, 19, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mmap, 18, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_munmap, 17, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_uname, 16, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getpgid, 15, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_stat, 14, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lstat, 13, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fstat, 12, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getuid, 11, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getgid, 10, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getgroups, 9, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getresuid, 8, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getdents, 7, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getdents64, 6, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fcntl, 5, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_ioctl, 4, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lseek, 3, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit_group, 2, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigaction, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
      };
      struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
      };
      ptrace(PTRACE_TRACEME, 0, (void *)(0x1), 0);
      if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
      {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return 1;
      }
      if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
      {
        perror("when setting seccomp filter");
        return 1;
      }
      cerr << "success" << endl;
      return 0;
}

#include "syscall_name.hpp"

int main(int argc, char** argv) {
  initialize(syscall_name);
  int pid;
  if ((pid = fork()) == 0) {
    setuid(99);
    setgid(99);
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    set_tracee();
    // kill(getpid(), SIGSTOP);
    freopen("/dev/null", "w", stdout);
    return execvp(argv[1], argv + 1);
  } else {
    start_trace(pid);
    return 0;
  }
}