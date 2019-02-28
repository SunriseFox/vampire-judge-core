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
    pid = 0;
    ref = nullptr;
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
  int * status = &(info->status);
  rusage* usage = &(info->usage);
  if (ptrace(PTRACE_SEIZE, pid, NULL, NULL)) {
    perror("while attach");
    return -1;
  }
  if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESYSGOOD))
    perror("set options");

  if(ptrace(PTRACE_SYSCALL, pid, 0, 0))
    perror("start tracing child");

  cout << "[" << pid << "] start tracing" << endl;

  while (pid == wait4(pid, status, 0, usage))
  {
    if (*status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)) 
      || *status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))) {

      long child_pid;
      ptrace(PTRACE_GETEVENTMSG, pid, NULL, &child_pid);
      cout << "[" << pid << "] cloned process " << child_pid << endl;
      ptrace(PTRACE_SYSCALL, pid, 0, 0);

      kill(child_pid, SIGSTOP);

      if (waitpid(child_pid, status, WSTOPPED))
        perror("while waitpid");
      
      if (ptrace(PTRACE_DETACH, child_pid, NULL, (void *) SIGSTOP)) 
        perror("while detach");

      g_tail_mutex.lock();
        
      THREAD_INFO* next = new THREAD_INFO;
      tail = tail->next = next;
      next->ref = new std::thread(trace_thread, child_pid, info);
      next->pid = child_pid;

      g_tail_mutex.unlock();
      continue;
    }
    if (WIFSIGNALED(*status))
    {
      kill(pid, SIGKILL);
      cout << "[" << pid << "] user program terminated by system signal " << WTERMSIG(*status) << endl;
      break;
    } 

    if (WIFEXITED(*status))
    {
      kill(pid, SIGKILL);
      cout << "[" << pid << "] user program exited normally" << endl;
      cout << "[" << pid << "] status: " << WEXITSTATUS(*status) << endl;
      return 0;
    }

    if (WSTOPSIG(*status) & 0x80)
    {
      // syscall number
      orig_eax = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX, NULL);
      eax = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX, NULL);
      cout << "[" << pid << "] got syscall " << syscall_name[orig_eax] << "(" << orig_eax << ") " << eax << endl;

      if ((r = ptrace(PTRACE_SYSCALL, pid, reinterpret_cast<char *>(1), 0)) == -1)
      {
        cerr << "[" << pid << "] failed to continue from breakpoint" << endl;
        kill(pid, SIGKILL);
        return -1;
      }
    }
    else
    {
      // siginfo_t siginfo;
      // ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo);
      // cout << endl << "[" << pid << "]" 
      //   << siginfo.si_signo << " " << siginfo.si_errno << " "
      //   << siginfo.si_code << " " << siginfo.si_pid << " " 
      //   << siginfo.si_uid << " " << siginfo.si_status << " " 
      //   << siginfo.si_value.sival_int << " " << siginfo.si_int << endl << endl;
      // long current_rip = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RIP, 0);
      // if (WSTOPSIG(*status) != SIGTRAP && last_rip == current_rip) {
      //   cout << "[" << pid << "] Killed." << endl;
      //   *status = WSTOPSIG(*status);
      //   kill(pid, SIGKILL);
      //   return 0;
      // }
      // last_rip = current_rip;
      cout << "[" << pid << "] program stop with unknown sig " << strsignal(WSTOPSIG(*status)) << "(" << WSTOPSIG(*status) << ")" << endl;
      ptrace(PTRACE_SYSCALL, pid, 0, WSTOPSIG(*status));
      continue;
    }
  }

  cerr << "-----------------------------" << endl;

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
    info = info->next;
  }

  return 0;
}

#include "syscall_name.hpp"

int main(int argc, char** argv) {
  initialize(syscall_name);
  int pid;
  if ((pid = fork()) == 0) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
      perror("prctl(PR_SET_NO_NEW_PRIVS)");
      return 1;
    }
    // kill(getpid(), SIGSTOP);
    return execvp(argv[1], argv + 1);
  } else {
    start_trace(pid);
    return 0;
  }
}