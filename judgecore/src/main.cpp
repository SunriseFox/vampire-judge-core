#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <string>
#include <map>
#include <thread>
#include <cstdlib>
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

#include "includes/syscall.h"

#include "json.hpp"
using json = nlohmann::json;

#define UNUSED(x) (void)x;

using namespace std;

enum RESULT {AC = 0, PE, WA, CE, RE, ME, TE, OLE, SLE, SW};
enum LANGUAGE {LANG_C = 0, LANG_CPP, LANG_JAVASCRIPT, LANG_PYTHON, LANG_GO, LANG_TEXT};
enum SPJ_MODE {SPJ_NO = 0, SPJ_COMPARE, SPJ_INTERACTIVE};
enum SECCOMP_POLICY {POLICY_STRICT_SAFE = 0, POLICY_ALLOW_COMMON, POLICY_BESTEFFORT_SANDBOX, POLICY_CUSTOM};

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

int pid_to_kill = -1;
int lpipe[2], rpipe[2];
int r;

bool debug = false;
SPJ_MODE spj_mode = SPJ_NO;
LANGUAGE language;

json result;

map<string, string> path;
map <int, string> syscall_name;
std::mutex g_tail_mutex;
THREAD_INFO *tail = nullptr, *info = nullptr;

void close_pipe()
{
  close(lpipe[0]);
  close(lpipe[1]);
  close(rpipe[0]);
  close(rpipe[1]);
}

void set_read()
{
  dup2(rpipe[0], STDIN_FILENO);
  dup2(lpipe[1], STDOUT_FILENO);
  close_pipe();
}
  
void set_write()
{
  dup2(lpipe[0], STDIN_FILENO);
  dup2(rpipe[1], STDOUT_FILENO);
  close_pipe();
}

void kill_timeout (int) {
  THREAD_INFO *head = info;
  do {
    if (pid_to_kill > 0) {
      kill(pid_to_kill, SIGKILL);
      cerr << "killed " << pid_to_kill << " for sleeping too long" << endl;
    }
    if (head) {
      pid_to_kill = head->pid;
      head = head->next;
    } else {
      break;
    }
  } while(true) ;
}

int create_folder(string& path) {
    const int error = system((string("mkdir -p ") + path).c_str ());
    if (error != 0)
    {
        cerr << "create directory at " << path << " failed" << endl;
        return -1;
    }
    return 0;
}

int delete_file(string& path) {
    const int error = system((string("rm -rf ") + path).c_str ());
    if (error != 0)
    {
        cerr << "delete file at " << path << " failed" << endl;
        return -1;
    }
    return 0;
}

std::string readFile(const string& filename) {
  ifstream in(filename);
  return static_cast<std::stringstream const&>(std::stringstream() << in.rdbuf()).str();
}

std::string readFile(const string& filename, std::string::size_type count)
{
  ifstream stream(filename);
  std::string result(count, '\x00');
  stream.read(&result[0], count);
  result.resize(stream.gcount());
  return result;
}

string getStatusText(RESULT what) {
  switch (what)
  {
    case SW:
      return "system error";
      break;
    case CE:
      return "compile error";
    case RE: 
      return "runtime error";
    case TE:
      return "time limit exceed";
    case ME:
      return "memory limit exceed";
    case OLE:
      return "output limit exceed";
    case SLE:
      return "syscall not allowed";
    case WA:
      return "wrong answer";
    case PE:
      return "presentation error";
    case AC:
      return "accepted";
    default:
      return "unknown";
  }
}

int finish(RESULT what) {
  result["status"] = what;
  result["result"] = getStatusText(what);
  ofstream of(path["result"]);
  of << (debug ? setw(2) : setw(0)) << result << endl;
  if (debug) 
    cout << setw(2) << result << endl;
  _exit(0);
}

int read_config(int argc, char** argv, json& j) {
  bool has_stdin = false;

  if (argc < 2) {
    cerr << "usage: judge [config.json [stdin]]" << endl;
    return -1;
  }

  for (int i = 1; i < argc; i++) {
    json temp;
    if (strncmp(argv[i], "stdin", 5) == 0) {
      if (!has_stdin) {
        has_stdin = true;
        try {
          cin >> temp;
        } catch (...) {
          cerr << "failed to parse json from stdin" << endl;
          return -1;
        }
      } else {
        cerr << "could only have one stdin" << endl;
        return -1;
      }
    } else {
      ifstream fin(argv[i]);
      if (!fin.is_open()) {
        cerr << "could not open file '"<< argv[i] << "' (at argv " << i << ") for read" << endl;
        return -1;
      }
      try {
        fin >> temp;
      } catch (...) {
        cerr << "failed to parse json from file '"<< argv[i] << "' (at argv " << i << ")" << endl;
        return -1;
      }
    }
    j.merge_patch(temp);
  }

  if (j["debug"].is_boolean() && j["debug"]) {
    debug = true;
  }

  if (debug) {
    cout << setw(2) << j << endl;
  }
  return 0;
}

int validate_config(json& j) {

  int error = 0;

  if (debug)
    cout << "validating configuration" << endl;
  
  if (!j["pid"].is_number_integer() 
    || j["pid"].get<int>() < -1) {
    cerr << "pid is not an integer" << endl;
    error = 1;
  }

  if (!j["sid"].is_number_integer()
    || j["sid"].get<int>() < -1) {
    cerr << "sid is not an integer" << endl;
    error = 1;
  }

  if (!j["filename"].is_string()) {
    cerr << "filename is not a string" << endl;
    error = 1;
  }

  if (!j["lang"].is_string() && !j["lang"].is_number_integer()) {
    cerr << "lang is not valid" << endl;
    error = 1;
  }

  if (j["max_time"].is_null()) {
    if (debug)
      cout << "max time is null, default to 1000ms" << endl;
    j["max_time"] = 1000;
  } else if (!j["max_time"].is_number_integer() 
    || j["max_time"].get<int>() < 0) {
    cerr << "max time is not an integer" << endl;
    error = 1;
  }

  if (j["max_time_total"].is_null()) {
    if (debug)
      cout << "max time total is null, default to 30000ms" << endl;
    j["max_time_total"] = 30000;
  } else if (!j["max_time_total"].is_number_integer() 
    || j["max_time_total"].get<int>() < 0) {
    cerr << "max time total is not an integer" << endl;
    error = 1;
  } 

  if (j["max_memory"].is_null()) {
    if (debug)
      cout << "max memory is null, default to 65535KB" << endl;
    j["max_memory"] = 65535;
  } else if (!j["max_memory"].is_number_integer() 
    || j["max_memory"].get<int>() < 0) {
    cerr << "max memory is not an integer" << endl;
    error = 1;
  }

  if (j["max_output"].is_null()) {
    if (debug)
      cout << "max output is null, default to 10000KB" << endl;
    j["max_output"] = 10000;
  } else if (!j["max_output"].is_number_integer() 
    || j["max_output"].get<int>() < 0) {
    cerr << "max_output is not integer number" << endl;
    error = 1;
  }
  
  if (!j["test_case_count"].is_number_integer() 
    || j["test_case_count"].get<int>() < -1) {
    cerr << "test case count is not acceptable" << endl;
    error = 1;
  }

  if (!j["base_dir"].is_string()) {
    if (debug)
      cout << "base dir defaults to /mnt/data" << endl;
    j["base_dir"] = "/mnt/data";
  }

  if ((j["spj_mode"].is_string() && j["spj_mode"].get<string>() == "compare")
    || (j["spj_mode"].is_number_integer() && j["spj_mode"].get<int>() == 1)) {
    spj_mode = SPJ_COMPARE;
  } else if ((j["spj_mode"].is_string() && j["spj_mode"].get<string>() == "interactive")
    || (j["spj_mode"].is_number_integer() && j["spj_mode"].get<int>() == 2)) {
    spj_mode = SPJ_INTERACTIVE;
  } else {
    spj_mode = SPJ_NO;
  }

  if (j["lang"].is_string()) {
    string lang_str = j["lang"].get<string>();
    if(lang_str == "c") {
      language = LANG_C;
    } else if(lang_str == "c++") {
      language = LANG_CPP;
    } else if(lang_str == "javascript") {
      language = LANG_JAVASCRIPT;
    } else if(lang_str == "python") {
      language = LANG_PYTHON;
    } else if(lang_str == "go") {
      language = LANG_GO;
    } else if(lang_str == "text") {
      language = LANG_TEXT;
    } else {
      cerr << "unknown language " << lang_str << endl;
      error = 1;
    }
  } else if (j["lang"].is_number_integer()) {
    int lang_int = j["lang"].get<int>();
    switch (lang_int)
    {
      case 0: language = LANG_C; break;
      case 1: language = LANG_CPP; break;
      case 2: language = LANG_JAVASCRIPT; break;
      case 3: language = LANG_PYTHON; break;
      case 4: language = LANG_GO; break;
      case 5: language = LANG_TEXT; break;
      default:
        cerr << "unknown language id" << lang_int << endl;
        error = 1;
        break;
    }
  }

  return error;
}

int comile_c_cpp(json& j, const string& compile_command) {
  UNUSED(j);
  if (debug) 
    cout << "compiler command: " << compile_command << endl;    

  pid_t pid = fork();
  if(pid == -1) {
      cerr << "fork complier process failed" << endl;
      return -1;
  }
  if(pid == 0) {
      alarm(10);
      signal(SIGALRM, [](int){exit(-1);});
      int ret = system(compile_command.c_str ());
      unsigned int sec = 10 - alarm(0);
      if (debug)
        cout << "compile time is " << sec << " seconds" << endl;
      if(WIFEXITED(ret))
          exit(WEXITSTATUS(ret));
      raise(WTERMSIG(ret));
  } else {
      int status;
      wait(&status);
      if(!WIFEXITED(status)) {
          cerr << "compiler process killed by sig " << WTERMSIG(status) << endl;
          return WTERMSIG(status);
      }
      status = WEXITSTATUS(status);
      if (debug)
        cout << "compiler return code is : " << status << endl;
      result["compiler"] = readFile(path["cmpinfo"]);
      if(status != 0) {
        finish (CE);
      }
      return 0;
  }
  // should not
  raise(SIGSYS);
  return -1;
}

int compile_exec_c (json& j) {
  if (debug) 
    cout << "language is c" << endl;
  string compile_command = "gcc -DONLINE_JUDGE -lpthread -O2 -static -std=c11 -fno-asm -Wall -Wextra -o "
          + path["exec"] + " " + path["code"] + " >"
          + path["cmpinfo"] + " 2>&1";
  return comile_c_cpp(j, compile_command);
}

int compile_exec_cpp (json& j) {
  if (debug) 
    cout << "language is cpp" << endl;
  string compile_command = "g++ -DONLINE_JUDGE -pthread -O2 -static -std=c++14 -fno-asm -Wall -Wextra -o "
          + path["exec"] + " " + path["code"] + " >"
          + path["cmpinfo"] + " 2>&1";
  return comile_c_cpp(j, compile_command);
}

int compile_exec_javascript (json& j) {
  if (debug) 
    cout << "language is javascript, skip compile" << endl;
  ofstream script(path["exec"] + ".nodejs");
  string s = R"+(const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
  crlfDelay: Infinity,
});

const line = (async function* _readLine() {
  for await (const line of rl) {
    yield line;
  }
})()

async function read() {
  return (await line.next()).value
}

function write(data) {
  process.stdout.write(data.toString())
}

function writeLine(data) {
  process.stdout.write(data + '\n')
}

process.on('unhandledRejection', (reason, p) => {
  console.log('Unhandled Rejection at: Promise', p, 'reason:', reason)
  process.exit(-1)
});

(async function main() {
)+"
+ readFile(path["code"]) +
R"+(
})().then(() => process.exit(0)))+";  
  script << s << endl;
  script.close();
  
  ofstream exec(path["exec"]);
  exec << "#! /bin/bash\n";
  exec << "exec node --no-warnings --max-old-space-size=" + to_string(j["max_memory"].get<int>() / 4000) + " " + path["exec"] + ".nodejs" << endl;
  exec.close();
  return 0;
}

int compile_exec_python (json& j) {
  ofstream script(path["temp"] + "compile_script.py");
  script << "import py_compile\npy_compile.compile('";
  script << path["code"] << "', cfile='" << path["exec"];
  script << ".pyc', doraise=True)" << endl;
  script.close();
  string compile_command = "python3 -OO "
          + path["temp"] + "compile_script.py" + " >"
          + path["cmpinfo"] + " 2>&1";
  int r = comile_c_cpp(j, compile_command);
  if (r) return r;
  ofstream exec(path["exec"]);
  exec << "#! /bin/bash\n";
  exec << "exec python3 " + path["exec"] + ".pyc" << endl;
  exec.close();
  return 0;
}

int compile_exec_go (json& j) {
  string compile_command = "go build -o " + path["exec"] 
          + " " + path["code"] + " >" + path["cmpinfo"] + " 2>&1";
  return comile_c_cpp(j, compile_command);
}

int compile_exec_text (json& j) {
  UNUSED(j);
  ofstream exec(path["exec"]);
  exec << "#! /bin/bash\n";
  exec << "exec cat " + path["code"] << endl;
  exec.close();
  return 0;
}

int generate_exec_args (json& j) {
  switch (language) {
  case LANG_C:
    return compile_exec_c(j);
  case LANG_CPP:
    return compile_exec_cpp(j);
  case LANG_JAVASCRIPT:
    return compile_exec_javascript(j);
  case LANG_PYTHON:
    return compile_exec_python(j);
  case LANG_GO:
    return compile_exec_go(j);
  case LANG_TEXT:
    return compile_exec_text(j);
  default:
    cerr << "unknown language (should not)" << endl;
    return -1;
  }
  return -1;
}

// int load_seccomp_child(SECCOMP_POLICY level, const std::initializer_list<string>& exes) {
//   setuid(99);
//   setgid(99);
//   nice(10);

//   if (level == POLICY_STRICT_SAFE) {
//     struct sock_filter filter[] = {
//       BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_sched_getaffinity, 36, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_arch_prctl, 35, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execve, 34, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit, 33, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_read, 32, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_write, 31, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getuid, 30, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_brk, 29, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getgid, 28, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_geteuid, 27, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getegid, 26, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getppid, 25, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getpgrp, 24, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getrlimit, 23, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getrusage, 22, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getgroups, 21, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_sigaltstack, 20, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_readlink, 19, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mmap, 18, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_munmap, 17, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_uname, 16, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getpgid, 15, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_stat, 14, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lstat, 13, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fstat, 12, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getuid, 11, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getgid, 10, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getgroups, 9, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getresuid, 8, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getdents, 7, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getdents64, 6, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fcntl, 5, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_ioctl, 4, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lseek, 3, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit_group, 2, 0),
//       BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigaction, 1, 0),
//       BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),
//       BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
//     };
//     struct sock_fprog prog = {
//       .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
//       .filter = filter,
//     };
//     ptrace(PTRACE_TRACEME, 0, (void *)(0x1), 0);  
//     if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
//     {
//       perror("prctl(PR_SET_NO_NEW_PRIVS)");
//       return 1;
//     }
//     if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
//     {
//       perror("when setting seccomp filter");
//       return 1;
//     }
//     kill(0, SIGSTOP);
//     return 0;
//   }

//   if (level != POLICY_CUSTOM) {
//     cerr << "unknown secure policy" << endl;
//     return -1;
//   }

//   ptrace(PTRACE_TRACEME, 0, (void *)(0x1), 0);
//   return 0;
// }

// int load_seccomp_parent(const int& pid, SECCOMP_POLICY level, int& status, rusage& usage) {
//   int orig_eax, eax, r;

//   if (pid != wait4(pid, &status, 0, &usage))
//   {
//     kill(pid, SIGKILL);
//     cerr << "wait for child failed" << endl;
//     return 1;
//   }

//   if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESYSGOOD))
//     perror("set options");

//   if (level == POLICY_STRICT_SAFE) {
//     ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP);
//     while (true)
//     {
//       ptrace(PTRACE_CONT, pid, 0, 0);
//       if (pid != wait4(pid, &status, 0, &usage))
//       {
//         kill(pid, SIGKILL);
//         cerr << "continue wait for child failed" << endl;
//         return 1;
//       }

//       if (WIFEXITED(status))
//         return 0;
//       if (status >> 8 == (SIGTRAP | (PTRAVE_EVENT_SECCOMP << 8))) {
//         if (debug) {
//           int syscallno = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX, 0);
//           cout << "got illegal syscall " << syscall_name[syscallno] << "(" << syscallno << ")" << endl;
//           result["extra"] = string("illegal syscall ") + syscall_name[syscallno] + "(" + to_string(syscallno) + ")";
//         }
//         status = SIGSYS;
//         kill(pid, SIGKILL);
//         return 0;
//       } else {
//         cout << "pass down stopsig " << WSTOPSIG(status) << endl;
//         status = WSTOPSIG(status);
//         kill(pid, SIGKILL);
//         return 0;
//       }
//     }
//   }
  
//   if (level != POLICY_CUSTOM) {
//     cerr << "unknown secure policy" << endl;
//     return -1;
//   }

//   if(ptrace(PTRACE_SYSCALL, pid, 0, 0))
//     perror("start tracing child");
//   cout << "start tracing " << pid << endl;

//   long last_rip = 0;

//   while (pid == wait4(pid, &status, 0, &usage))
//   {
//     if (status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)) || status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))) {
//       long child_pid;
//       ptrace(PTRACE_GETEVENTMSG, pid, NULL, &child_pid);
//       cout << "got cloned process " << child_pid << endl;
//       ptrace(PTRACE_SYSCALL, pid, 0, 0);
//       if (waitpid(child_pid, &status, WSTOPPED))
//         perror("while waitpid");
//       if (ptrace(PTRACE_DETACH, child_pid, NULL, (void *) SIGSTOP)) 
//         perror("while detach");
//       new std::thread([=]() {
//         int child_status;
//         rusage child_usage;
//         if (ptrace(PTRACE_SEIZE, child_pid, NULL, NULL)) 
//           perror("while attach");
//         load_seccomp_parent(child_pid, level, child_status, child_usage);
//       });
//       continue;
//     }
//     if (WIFSIGNALED(status))
//     {
//       kill(pid, SIGKILL);
//       cout << "user program terminated by system signal " << WTERMSIG(status) << endl;
//       break;
//     }

//     if (WIFEXITED(status))
//     {
//       kill(pid, SIGKILL);
//       cout << "user program exited normally" << endl;
//       cout << "status: " << WEXITSTATUS(status) << endl;
//       break;
//     }

//     if (WSTOPSIG(status) & 0x80)
//     {
//       // syscall number
//       orig_eax = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX, NULL);
//       eax = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX, NULL);
//       cout << "[" << to_string(pid) << "] got syscall " << syscall_name[orig_eax] << "(" << orig_eax << ") " << eax << endl;

//       if ((r = ptrace(PTRACE_SYSCALL, pid, reinterpret_cast<char *>(1), 0)) == -1)
//       {
//         cout << "failed to continue from breakpoint" << endl;
//         kill(pid, SIGKILL);
//         return -1;
//       }
//     }
//     else
//     {
//       long current_rip = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RIP, 0);
//       if (WSTOPSIG(status) != SIGTRAP && last_rip == current_rip){
//         status = WSTOPSIG(status);
//         kill(pid, SIGKILL);
//         return 0;
//       }
//       last_rip = current_rip;
//       cout << "program stop with unknown sig " << strsignal(WSTOPSIG(status)) << "(" << WSTOPSIG(status) << ")" << endl;
//       ptrace(PTRACE_SYSCALL, pid, 0, 0);
//       continue;
//     }
//   }

//   cerr << "end tracing " << pid << " unexpectedly" << endl;
//   return -1;
// }

int load_seccomp_tracee() {
  setuid(99);
  setgid(99);
  nice(10);
  ptrace(PTRACE_TRACEME, 0, 0, 0);
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    perror("prctl(PR_SET_NO_NEW_PRIVS)");
    return -1;
  }
  return 0;
}

int trace_thread(int pid, THREAD_INFO* info) {
  if (debug)
    cout << "[" << pid << "] prepare tracing" << endl;
  int orig_eax, eax, r;
  int& status = info->status;
  rusage& usage = info->usage;

  if (ptrace(PTRACE_SEIZE, pid, NULL, NULL)) {
    perror("while attach");
    return -1;
  }

  kill(pid, SIGSTOP);

  if (pid == waitpid(pid, &status, WSTOPPED)) {
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESYSGOOD))
      perror("set options");

    if(ptrace(PTRACE_SYSCALL, pid, 0, 0))
      perror("start tracing child");
  } else {    
    kill(pid, SIGKILL);
    cerr << "[" << pid << "] attach failed, kill it" << endl;
    return -1;
  }

  while (pid == wait4(pid, &status, 0, &usage))
  {
    if (status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)) 
      || status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))
      || status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))) {

      long child_pid;
      ptrace(PTRACE_GETEVENTMSG, pid, NULL, &child_pid);
      if (debug)
        cout << "[" << pid << "] cloned process " << child_pid << endl;
      if (!child_pid) {
        cerr << "failed clone process" << endl;
        return -1;
      }
      ptrace(PTRACE_SYSCALL, pid, 0, 0);

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
      if (debug)
        cout << "[" << pid << "] user program terminated by system signal " << WTERMSIG(status) << endl;
      return 0;
    } 

    if (WIFEXITED(status))
    {
      kill(pid, SIGKILL);      
      if (debug) {
        cout << "[" << pid << "] user program exited normally" << endl;
        cout << "[" << pid << "] status: " << WEXITSTATUS(status) << endl;
      }
      return 0;
    }

    if (WSTOPSIG(status) & 0x80)
    {
      // syscall number
      orig_eax = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX, NULL);
      eax = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX, NULL);

      if (debug)
        cout << "[" << pid << "] got syscall " << syscall_name[orig_eax] << "(" << orig_eax << ") " << eax << endl;
      
      if ( validate_syscall(pid, orig_eax) ) {
        cerr << "[" << pid << "] syscall denied by validator" << endl;
        ptrace(PTRACE_POKEUSER, pid, sizeof(long) * ORIG_RAX, (-1));
        kill(pid, SIGSYS);
      } else if ((r = ptrace(PTRACE_SYSCALL, pid, reinterpret_cast<char *>(1), 0)) == -1)
      {
        cerr << "[" << pid << "] failed to continue from breakpoint" << endl;
        kill(pid, SIGKILL);
        return -1;
      }
    }
    else
    {
      if (debug)
        cout << "[" << pid << "] program reveived sig " << strsignal(WSTOPSIG(status)) << "(" << WSTOPSIG(status) << ")" << endl;
      ptrace(PTRACE_SYSCALL, pid, 0, WSTOPSIG(status));
      continue;
    }
  }

  cerr << "-----------------------------" << pid << endl;
  return -1;
}

struct JUDGE_RESULT {
  int status;
  int time;
  int memory; 
  JUDGE_RESULT() {
    status = 0;
    time = 0;
    memory = 0;
  }
};

int load_seccomp_tracer(int pid, JUDGE_RESULT& result) {
  info = tail = new THREAD_INFO;
  int status;

  if (pid != waitpid(pid, &status, 0))
  {
    kill(pid, SIGKILL);
    cerr << "wait for child failed" << endl;
    return -1;
  }

  if (ptrace(PTRACE_DETACH, pid, NULL, (void *) SIGSTOP)) 
    perror("while detach");

  info->ref = new std::thread(trace_thread, pid, info);
  info->pid = pid;

  THREAD_INFO* head = info;

  while(head){
    info->ref->join();
    int time = (int) (info->usage.ru_utime.tv_sec * 1000 + info->usage.ru_utime.tv_usec / 1000);
    result.time += time;
    result.memory += info->usage.ru_maxrss;
    if (result.status == 0 && info->status != 0 && WSTOPSIG(info->status) != 133) 
      result.status = info->status;
    if (debug) {
      cout << "[-------] thread debugging *" << info->pid << "* exited." << endl;
      cout << "time: " << time << ", ";
      cout << "memory: " << info->usage.ru_maxrss << endl;
      if (info->status != 0 && WSTOPSIG(info->status) != 133) {
        cout << "WIFEXITED: " << WIFEXITED(info->status) << endl;
        cout << "WEXITSTATUS: " << WEXITSTATUS(info->status) << endl;
        cout << "WIFSIGNALED: " << WIFSIGNALED(info->status) << endl;
        cout << "WTERMSIG: " << WTERMSIG(info->status) << endl;
        cout << "WIFSTOPPED: " << WIFSTOPPED(info->status) << endl;
        cout << "WSTOPSIG: " << WSTOPSIG(info->status) << endl;
      }
    }
    head = info->next;
    delete info;
    info = head;
  }

  return 0;
}

bool should_continue(json &j, RESULT r)
{
  if (j["on_error_continue"].is_boolean())
    return true;
  if (j["on_error_continue"].is_array()) {
    for (const auto& element : j["on_error_continue"]) {
      if (element.is_string()) {
        if (getStatusText(r) == element.get<string>())
          return true;
      } else if (element.is_number_integer()) {
        if (static_cast<int>(r) == element.get<int>())
          return true;
      } else {
        cerr << "[warn] unknown continue rules" << endl;
      }
    }
    return false;
  }
  cerr << "[warn] unknown continue rules" << endl;
  return true;
}

RESULT do_compare(json& j, const map<string, string>& extra) {
  UNUSED(j);
  if (spj_mode == SPJ_COMPARE) {
    // should do spj
    string spjcmd = path.at("spj") + " " + extra.at("stdin") + " " 
      + extra.at("stdout") + " " + extra.at("output") 
      + " >" + extra.at("log") + " 2>&1";
    if (debug)
      cout << "special judge command: " << spjcmd << endl;
    int status = system(spjcmd.c_str());
    if (debug)
      cout << "special judge returned: " << status << endl;
    if (WIFEXITED(status)) {
      switch  (WEXITSTATUS(status)) {
        case 0: return AC;
        case 1: return PE;
        case 2: return WA;
        default: 
          cerr << "[warn] special judge returned unknown status" << endl;
          return SW;
      }
    }
    cerr << "special judge program is signaled" << endl;
    return SW; 
  } else {
    string difcmd = string("diff --strip-trailing-cr --brief ") + extra.at("stdout") + " " + extra.at("output") + " >" + extra.at("log");
    if (debug)
      cout << "diff: " << difcmd << endl;
    int status = system(difcmd.c_str());

    if (WEXITSTATUS(status) == 0)
      return AC;

    difcmd = string("diff --ignore-space-change --ignore-all-space --ignore-blank-lines --ignore-case --brief ") + extra.at("stdout") + " " + extra.at("output") + " >" + extra.at("log");

    if (debug)
      cout << "diff2: " << difcmd << endl;

    status = system(difcmd.c_str());

    if (WEXITSTATUS(status) == 0)
      return PE;
    return WA;
  }
  return SW;
}

// TODO: sometimes not work?
int set_resource_limit(const int& time_limit, const int& memory_limit, const int& output_limit) {
  rlimit rlimits;

  rlimits.rlim_cur = time_limit / 1000 + 1;
  rlimits.rlim_max = min(time_limit / 1000 * 2 + 1, time_limit / 1000 + 4);
  if ((r = setrlimit(RLIMIT_CPU, &rlimits))) {
    cerr << "set cpu time limit failed, " << r << endl;
    _exit(255);
  }

  if (language != LANG_JAVASCRIPT) {
    rlimits.rlim_cur = memory_limit * 1024 * 2;
    rlimits.rlim_max = memory_limit * 1024 * 2 * 2;
    if ((r = setrlimit(RLIMIT_AS, &rlimits))) {
      cerr << "set memory limit failed, " << r << endl;
      _exit(255);
    }
  } else {
    rlimits.rlim_cur = 0x7fffffff;
    rlimits.rlim_max = 0x7fffffff;
    if ((r = setrlimit(RLIMIT_AS, &rlimits))) {
      cerr << "set memory limit failed, " << r << endl;
      _exit(255);
    }
  }

  rlimits.rlim_cur = output_limit;
  rlimits.rlim_max = output_limit * 2;
  if ((r = setrlimit(RLIMIT_FSIZE, &rlimits))) {
    cerr << "set output limit failed, " << r << endl;
    _exit(255);
  }

  return 0;
}

void do_test(json& j) {
  int time_limit = j["max_time"].get<int>();
  int total_time_limit = j["max_time_total"].get<int>();
  int memory_limit = j["max_memory"].get<int>();
  int output_limit = j["max_output"].get<int>();

  int cases = j["test_case_count"].get<int>();

  int total_time = 0;
  int max_memory = 0;

  RESULT fatal_status = AC;

  struct {
    int time;
    int memory;
    int signal;
    int exitcode;
    RESULT result;
  } case_result;

  if (debug)
    cout << "exec is: " << path["exec"] << endl;

  for (int c = 1; c <= cases; c++) {
    string cs = to_string(c);

    map<string, string> extra;
    extra["stdin"] = path["stdin"] + "/" + cs + ".in";
    extra["stdout"] = path["stdout"] + "/" + cs + ".out";
    extra["output"] = path["output"] + "/" + cs + ".execout";
    extra["log"] = path["log"] + "/" + cs + ".log";

    if (debug) {
      cout << "test case " << cs << endl;
      cout << "input: " << extra["stdin"] << endl;
      cout << "log: " << extra["log"] << endl;
    }

    if (spj_mode == SPJ_INTERACTIVE) {
      // A is special judge process
      // B is user process

      int a_pid, b_pid;
      pipe(lpipe);
      pipe(rpipe);

      if ((a_pid = fork()) < 0) {
        cerr << "fork judge process A failed" << endl;
        finish(SW);
      }

      if (a_pid == 0) { // process A (special judge)
        set_read();

        execlp(path.at("spj").c_str()
          , path.at("spj").c_str()
          , extra["stdin"].c_str()
          , extra["stdout"].c_str()
          , extra["log"].c_str()
          , nullptr
        );

        cerr << "child process A exec failed" << endl;
        _exit(255);
      }

      // interactive parent continues here

      if ((b_pid = fork()) < 0) {
        cerr << "fork judge process B failed" << endl;
        finish(SW);
      }

      if (b_pid == 0) { // process B (user)
        set_resource_limit(time_limit, memory_limit, output_limit);

        if (debug) {
          cout << "execution begin" << endl;
        }
        
        set_write();

        load_seccomp_tracee();

        execlp(path["exec"].c_str(), path["exec"].c_str(), nullptr);

        cerr << "child process B exec failed" << endl;
        _exit(255);
      }

      // interactive parent continues here
      close_pipe();

      JUDGE_RESULT jresult;
      
      alarm(time_limit / 1000 + 10);
      signal(SIGALRM, kill_timeout);

      if (load_seccomp_tracer(b_pid, jresult) == -1) {
        kill(b_pid, SIGKILL);
        kill(a_pid, SIGKILL);
        cerr << "wait on child process failed" << endl;
        finish(SW);
      }

      alarm(0);

      if (debug)
        cout << "user program exited" << endl;

      json r;

      if (WIFSIGNALED(jresult.status)) {
        if (debug) 
          cout << "user program is signaled: " << jresult.status << endl;
        r["signal"] = case_result.signal = WTERMSIG(jresult.status);
        r["signal_str"] = string(strsignal(WTERMSIG(jresult.status)));
      } else {
        case_result.signal = 0;
      }

      r["exitcode"] = case_result.exitcode = WEXITSTATUS(jresult.status);
      r["time"] = case_result.time = jresult.time;
      r["memory"] = case_result.memory = jresult.memory;

      RESULT rs = AC;
      if (case_result.signal) {
        switch (case_result.signal)
        {
        case SIGXCPU: rs = TE; break;
        case SIGXFSZ: rs = OLE; break;
        case SIGABRT: rs = ME; break;
        case SIGSYS:  rs = SLE; break;
        default     : rs = RE; break;
        }
      } else if (case_result.exitcode) {
        rs = RE;
      } else if (case_result.time > time_limit){
        rs = TE;
      } else if (case_result.memory > memory_limit){
        rs = ME;
      } 
      if (rs == AC) {
        // respect result from special judge
        pid_to_kill = a_pid;
        alarm(5);
        signal(SIGALRM, kill_timeout);

        int status;

        if (waitpid(a_pid, &status, WSTOPPED) == -1) {
          kill(a_pid, SIGKILL);
          cerr << "wait on child process failed" << endl;
          finish(SW);
        }

        alarm(0);

        if (WIFSIGNALED(status)) {
          cerr << "spj program is signaled: " << status << endl;
          rs = RE;
        } else {
          switch(WEXITSTATUS(status)){
          case 0: rs = AC; break;
          case 1: rs = PE; break;
          case 2: rs = WA; break;
          default: rs = SW; break;
          }
        }
      } else {
        kill(a_pid, SIGKILL);
      }
      r["status"] = static_cast<int>(rs);
      r["result"] = getStatusText(rs);
      result["detail"].push_back(r);
      string log = readFile(extra.at("log"), 100);
      if (log.size() == 0) {
        result["extra"].push_back(nullptr);
      } else {
        result["extra"].push_back(log);
      }

      total_time += case_result.time;
      max_memory = max(case_result.memory, max_memory);

      if (!should_continue(j, rs)) {
        fatal_status = rs;
        break;
      }
    } else { // not interactive judge
      int pid;

      if ((pid = fork()) < 0) {
        cerr << "fork judge process failed" << endl;
        finish(SW);
      }

      if (pid == 0) { // non interactive child
        set_resource_limit(time_limit, memory_limit, output_limit);  

        if (debug) {
          cout << "execution begin" << endl;
          cout << "stdin:" << extra["stdin"] << endl;
          cout << "execout:" << extra["output"] << endl;
        }

        FILE *file_in = freopen(extra["stdin"].c_str(), "r", stdin);
        FILE *file_out = freopen(extra["output"].c_str(), "w", stdout);

        if (file_in == nullptr || file_out == nullptr) {
          fclose(file_in);
          fclose(file_out);
          cerr << "failed to redirect input & output." << endl;
          exit(255);
        }

        if((r = load_seccomp_tracee())) {
          cerr << "load seccomp rule failed" << endl;
          exit(255);
        };

        execlp(path["exec"].c_str(), path["exec"].c_str(), nullptr);

        fclose(file_in);
        fclose(file_out);

        cerr << "exec failed" << endl;
        exit(255);
      } 
      // non interactive parent continues here

      alarm(time_limit / 1000 + 5);
      signal(SIGALRM, kill_timeout);

      JUDGE_RESULT jresult;
            
      load_seccomp_tracer(pid, jresult);

      alarm(0);

      json r;

      if (WIFSIGNALED(jresult.status)) {
        if (debug) 
          cout << "user program is signaled: " << jresult.status << endl;
        r["signal"] = case_result.signal = WTERMSIG(jresult.status);
        r["signal_str"] = string(strsignal(WTERMSIG(jresult.status)));
      } else {
        case_result.signal = 0;
      }

      r["exitcode"] = case_result.exitcode = WEXITSTATUS(jresult.status);
      r["time"] = case_result.time = jresult.time;
      r["memory"] = case_result.memory = jresult.memory;

      RESULT rs;
      if (case_result.signal) {
        switch (case_result.signal)
        {
        case SIGXCPU: rs = TE; break;
        case SIGXFSZ: rs = OLE; break;
        case SIGSEGV: rs = RE; break;
        case SIGABRT: rs = ME; break;
        case SIGFPE : rs = RE; break;
        case SIGBUS	: rs = RE; break;
        case SIGILL	: rs = RE; break;
        case SIGKILL: rs = RE; break;
        case SIGSYS:  rs = SLE; break;
        default     : rs = RE; break;
        }
      } else if (case_result.exitcode) {
        rs = RE;
      } else if (case_result.time > time_limit){
        rs = TE;
      } else if (case_result.memory > memory_limit){
        rs = ME;
      } else {
        rs = do_compare(j, extra);
      }
      r["status"] = static_cast<int>(rs);
      r["result"] = getStatusText(rs);
      result["detail"].push_back(r);

      total_time += case_result.time;
      max_memory = max(case_result.memory, max_memory);

      if (!should_continue(j, rs)) {
        fatal_status = rs;
        break;
      }
      // non interactive parent end
    } // non interactive judge
  } // case loop

  result["time"] = total_time;
  result["memory"] = max_memory;

  if (fatal_status != AC)
    finish(fatal_status);
  
  if (total_time > total_time_limit) {
    finish(TE);
  } else if (max_memory > memory_limit) {
    cerr << "should not be caught here" << endl;
    finish(ME);
  }

  for (auto& element : result["detail"]) {
    RESULT r = static_cast<RESULT>(element["status"].get<int>());
    if (r != AC)
      finish(r);
  }

  finish(AC);

  cerr << "should not" << endl;
}

#include "syscall_name.hpp"

int main (int argc, char** argv) {
  initialize(syscall_name);

  json j;

  if (read_config(argc, argv, j))
    exit(255);

  if (validate_config(j))
    exit(255);

  string pid = to_string(j["pid"].get<int>());
  string sid = to_string(j["sid"].get<int>());

  path["base"] = j["base_dir"].get<string>();

  path["temp"] = "/tmp/judge-" + pid + "-" + sid + "/";
  delete_file(path["temp"]);
  create_folder(path["temp"]);

  path["output"] = path["base"] + "/result/" + pid + "/" + sid + "/";
  create_folder(path["output"]);

  path["stdin"] = path["base"] + "/case/" + pid +"/";
  path["stdout"] = path["base"] + "/case/" + pid + "/";

  path["log"] = path["temp"];

  // Files
  path["result"] = path["output"] + "/result.json";

  path["code"] = path["base"] + "/code/" + pid + "/" + sid + "/" + j["filename"].get<string>();
  
  path["exec"] = path["temp"] + "/main";
  unlink(path["exec"].c_str());
  ofstream(path["exec"]).close();
  chmod(path["exec"].c_str(), S_IRWXG|S_IRWXU);

  path["spj"] = path["base"] + "/judge/" + pid;
  path["spj"] = j["spj_exec"].is_string() ? j["spj_exec"].get<string>() : path["spj"];

  path["cmpinfo"] = path["output"] + "/result.cmpinfo";
  unlink(path["cmpinfo"].c_str ());

  result["time"] = 0;
  result["memory"] = 0;
  result["result"] = getStatusText(SW);
  result["status"] = static_cast<int>(SW);
  result["detail"] = {};
  result["compiler"] = nullptr;
  result["extra"] = {};

  // compile source or check syntax
  if(generate_exec_args(j))
    exit(255);
  
  // do test

  do_test(j);

  // should not
  exit(254);
}
