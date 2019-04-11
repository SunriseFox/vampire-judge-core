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
#include <random>
#include <climits>

#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <fcntl.h>
#include <dirent.h>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/resource.h>
#include <sys/reg.h>
#include <sys/mount.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

#include "includes/defs.h"
#include "includes/utils.h"
#include "includes/syscall.h"

#include "json.hpp"
using json = nlohmann::json;

#define UNUSED(x) (void)x;

using namespace std;

// syscall.c need it to debug
bool debug = false;
// syscall.c need it to get path["sandbox"]
map<string, string> path;

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

static struct CONFIG_COMPILER compiler {
  .max_time = 120000,
  .max_real_time = 200000,
  .max_memory = 204800,
  .max_output = 52428800,
};

// syscall.c need it to get max_fs_write_count
struct CONFIG_SYS sys {
  .time_system_time = false,
  .max_compiler_size = 5000,
  .max_extra_size = 10240,
  .max_fs_write_count = 20,
  .max_inline_fs_count = 20,
  .max_inline_fs_size = 1000,
  .max_inline_stdout_size = 1000,
};
int fs_write = 0;

static int pid_to_kill = -1;
static int lpipe[2], rpipe[2];
static mode_t code_permission;

static SPJ_MODE spj_mode = SPJ_NO;

static map <int, string> syscall_name;

static mutex g_tail_mutex;
static THREAD_INFO *tail = nullptr, *info = nullptr;
static int process_forked = 0;
static int max_thread = 4;

static json result;
static json config;
static json lang_spec; // convert to null if found
static json language;


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
  bool killed = false;
  do {
    if (pid_to_kill > 0) {
      kill(pid_to_kill, SIGKILL);
      killed = true;
      if (debug)
        cerr << "killed " << pid_to_kill << " - real time limit exceeded" << endl;
    }
    if (head) {
      pid_to_kill = head->pid;
      head = head->next;
    } else {
      break;
    }
  } while(true) ;
  if (killed && result["extra"].is_null()) result["extra"] = "real time limit exceeded";
}

void kill_children(THREAD_INFO * head) {
  while (head) {
    kill(head->pid, SIGKILL);
    head = head->next;
  }
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

[[noreturn]] int finish(RESULT what) {
  // cleanup
  chmod(path.at("code").c_str(), code_permission & (~S_IROTH));
  umount2(path["sandbox"].c_str(), MNT_FORCE);
  rmdir(path["sandbox"].c_str());

  // this may fail, so clean up first
  result["status"] = what;
  result["result"] = getStatusText(what);
  ofstream of(path["result"]);

  auto result_str = result.dump(debug ? 2 : -1, ' ', false, json::error_handler_t::replace);
  of << result_str << endl;
  cout << result_str << endl;

  _exit(0);
  throw std::range_error("finish function should not return");
}

int read_config(int argc, char** argv) {
  if (argc < 2) {
    cerr << "usage: judge [config.json [stdin]]" << endl;
    return -1;
  }

  {
    ifstream fin("./conf/default.json");

    if (!fin.is_open()) {
      cerr << "could not open default config file" << endl;
      return -1;
    }
    try {
      fin >> config;
    } catch(...) {
      cerr << "failed to parse default config file" << endl;
      return -1;
    }
  }

  for (int i = 1; i < argc; i++) {
    json temp;
    if (strncmp(argv[i], "stdin", 5) == 0) {
      try {
        cin >> temp;
      } catch (...) {
        cerr << "failed to parse json from stdin" << endl;
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
    config.merge_patch(temp);
  }

  if (config["debug"].is_boolean() && config["debug"]) {
    debug = true;
    cout << "merged configuration:" << endl;
    cout << setw(2) << config << endl;
  }

  {
    ifstream fin("./conf/lang_spec.json");

    if (!fin.is_open()) {
      cerr << "could not lang spec file" << endl;
      return -1;
    }
    try {
      fin >> lang_spec;
    } catch(...) {
      cerr << "failed to parse lang spec file" << endl;
      return -1;
    }
  }

  return 0;
}

[[noreturn]] void validation_error(const string& error) {
  cerr << "caught json error while validating: " << endl;
  cerr << error << endl;
  cerr << "It is likely related to the default configuration" << endl;
  exit(253);
}

string merge_array(json& root, json& current, json& array, const string& delim = string(), int depth = 0) {
  if (depth > 16) {
    throw std::range_error("possible loop reference detected for " + array.dump());
  }

  if (array.is_string()) {
    string str = array.get<string>();
    if (str.length() != 1 && str.front() == '$') {
      if (current.count(str.substr(1)))
        array = str = merge_array(root, current, current[str.substr(1)], string(), depth + 1);
      else if (root.count(str.substr(1)))
        array = str = merge_array(root, current, root[str.substr(1)], string(), depth + 1);
      else {
        cerr << "[warn] undefined reference " << str << endl;
      }
    }
    return str;
  }

  if (array.is_number_unsigned())
    return to_string(array.get<unsigned>());
  if (array.is_number_integer())
    return to_string(array.get<int>());
  if (array.is_number_float())
    return to_string(array.get<double>());

  if (!array.is_array()) {
    throw std::range_error("converting unknown path");
  }

  stringstream ss;
  json::iterator it = array.begin();
  if (it != array.end()) {
    ss << merge_array(root, current, *it, string(), depth + 1);
    for (++it; it != array.end(); ++it) {
      ss << delim << merge_array(root, current, *it, string(), depth + 1);
    }
  }
  array = ss.str();
  return array.get<string>();
}

int validate_config() {
  int error = 0;

  if (debug)
    cout << "validating configuration" << endl;

  if (!config["path"].is_object())
    validation_error("path is not an object");

  auto merge_path = [](const string& key) {
    try {
      merge_array(config, config["path"], config["path"][key], "/");
    } catch (const std::range_error& e) {
      cerr << "while retriving key " << key << "(" << config["path"][key] << ")"  << endl;
      cerr << "caught " << e.what() << endl;
      validation_error(e.what());
    }
  };

  if (config["lang"].is_string()) {
    string lang_name = config["lang"].get<string>();
    for (auto& lang: lang_spec) {
      if (lang["name"].is_string() &&lang["name"].get<string>() == lang_name) {
        language = lang;
        break;
      }
    }
  } else if (config["lang"].is_number_integer()) {
    int lang_id = config["lang"].get<int>();
    for (auto& lang: lang_spec) {
      if (lang["id"].is_number_integer() && lang["id"].get<int>() == lang_id) {
        language = lang;
        break;
      }
    }
  }
  if (language.is_null()) {
    cerr << "unknown language" << config["lang"] << endl;
    error = 1;
  } else {
    config["lang_name"] = language["name"];
    config["lang_id"] = language["id"];
    config["lang_ext"] = language["ext"];
  }

  merge_path("base");
  merge_path("temp");
  merge_path("output");
  merge_path("stdin");
  merge_path("stdout");
  merge_path("log");
  merge_path("code");
  merge_path("exec");

  auto expect_int = [&error](const string& key) -> void {
    if (!config[key].is_number_integer() || config[key].get<int>() < 0) {
      cerr << key << " is not an integer" << endl;
      error = 1;
    }
  };

  expect_int("max_time");
  if(!config.count("max_real_time"))
    config["max_real_time"] = config["max_time"].get<int>() + 1000;
  expect_int("max_real_time");
  if(!config.count("max_time_total"))
    config["max_time_total"] = 30000;
  expect_int("max_time_total");
  expect_int("max_memory");
  expect_int("max_output");
  expect_int("max_thread");
  expect_int("test_case_count");

  max_thread = config["max_thread"].get<int>();

  auto set_if_long = [](const json& which, long& set) -> void {
    if (which.is_number_integer() && which.get<long>() >= 0)
      which.get_to(set);
  };

  set_if_long(config["compiler"]["max_time"], compiler.max_time);
  set_if_long(config["compiler"]["max_real_time"], compiler.max_real_time);
  set_if_long(config["compiler"]["max_memory"], compiler.max_memory);
  set_if_long(config["compiler"]["max_output"], compiler.max_output);
  set_if_long(config["sys"]["max_compiler_size"], sys.max_compiler_size);
  set_if_long(config["sys"]["max_extra_size"], sys.max_extra_size);
  set_if_long(config["sys"]["max_fs_write_count"], sys.max_fs_write_count);
  set_if_long(config["sys"]["max_inline_fs_count"], sys.max_inline_fs_count);
  set_if_long(config["sys"]["max_inline_fs_size"], sys.max_inline_fs_size);
  set_if_long(config["sys"]["max_inline_stdout_size"], sys.max_inline_stdout_size);
  if (config["sys"]["time_system_time"].is_boolean())
    config["sys"]["time_system_time"].get_to(sys.time_system_time);

  if (config["spj_mode"].is_string()) {
    string str = config["spj_mode"].get<string>();
    if (str == "compare")
      spj_mode = SPJ_COMPARE;
    else if (str == "interactive")
      spj_mode = SPJ_INTERACTIVE;
    else if (str == "inline")
      spj_mode = SPJ_INLINE;
  } else if (config["spj_mode"].is_number_integer()) {
    int mode = config["spj_mode"].get<int>();
    if (mode == SPJ_COMPARE) spj_mode = SPJ_COMPARE;
    else if (mode == SPJ_INTERACTIVE) spj_mode = SPJ_INTERACTIVE;
    else if (mode == SPJ_INLINE) spj_mode = SPJ_INLINE;
  }

  if (spj_mode != SPJ_NO && spj_mode != SPJ_INLINE) {
    merge_path("spj");
  } else {
    config["path"]["spj"] = "";
  }

  if (debug)
    cout << "configuration validated with code " << error << endl;

  if (debug)
    cout << setw(2) << config << endl;

  return error;
}

// time in ms, memory in kb, output limit in bytes
int set_resource_limit(const int& time_limit, const int& memory_limit, const int& output_limit) {
  int r;
  rlimit rlimits;

  rlimits.rlim_cur = time_limit / 1000 + 1;
  rlimits.rlim_max = min(time_limit / 1000 * 2 + 1, time_limit / 1000 + 4);
  if ((r = setrlimit(RLIMIT_CPU, &rlimits))) {
    cerr << "set cpu time limit failed, " << r << endl;
    _exit(255);
  }

  if (__builtin_mul_overflow(memory_limit, 4096l, &rlimits.rlim_max)) {
    rlimits.rlim_max = LONG_MAX;
  }

  if (__builtin_mul_overflow(memory_limit, 2048l, &rlimits.rlim_cur)) {
    rlimits.rlim_cur = LONG_MAX;
  }

  if ((r = setrlimit(RLIMIT_AS, &rlimits))) {
    cerr << "set memory limit failed, " << r << endl;
    _exit(255);
  }

  rlimits.rlim_cur = output_limit;
  if (__builtin_mul_overflow(output_limit, 2l, &rlimits.rlim_max)) {
    rlimits.rlim_max = LONG_MAX;
  }
  if ((r = setrlimit(RLIMIT_FSIZE, &rlimits))) {
    cerr << "set output limit failed, " << r << endl;
    _exit(255);
  }

  return 0;
}

int compile_general(std::vector<const char*> args) {
  if (debug) {
    cout << "compiler command: ";
    for (const auto& i: args) {
      cout << i << ' ';
    }
    cout << endl;
  }
  args.push_back(nullptr);

  pid_t pid = fork();
  if(pid == -1) {
    cerr << "fork complier process failed" << endl;
    result["compiler"] = "fork complier process failed";
    finish(CE);
  }
  if(pid == 0) {
    setenv("HOME", "/tmp/nobody", 1);
    int fd = open(path.at("cmpinfo").c_str(), O_WRONLY);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    set_resource_limit(compiler.max_time, compiler.max_memory, compiler.max_output);
    if (setpgid(0, 0)) {
      cerr << "set pgid failed!" << endl;
    };
    if(setegid(99)) {
      cerr << "set egid failed!" << endl;
      raise(SIGSYS);
    }
    if(seteuid(99)) {
      cerr << "set euid failed!" << endl;
      raise(SIGSYS);
    }
    if (execvp(args[0], const_cast<char**>(&args[0])))
      perror("while exec") ;
    raise(SIGSYS);
  }

  int compile_timeout = compiler.max_real_time / 1000 + 1;
  alarm(compile_timeout);
  pid_to_kill = pid;
  signal(SIGALRM, [](int) {
    if (debug)
      cout << "received sigalrm (compiler timeout)" << endl;
    kill(-pid_to_kill, SIGKILL);
  });
  int status;
  waitpid(pid, &status, 0);
  int sec = compile_timeout - alarm(0);
  pid_to_kill = 0;
  if (debug)
    cout << "compile time is " << sec << " seconds" << endl;

  string compile_info = readFile(path["cmpinfo"], sys.max_compiler_size);
  if(!WIFEXITED(status)) {
    compile_info += "\ncompiler process killed by sig " + string(strsignal(WTERMSIG(status))) + "\n";
    status = WTERMSIG(status);
  } else {
    status = WEXITSTATUS(status);
  }
  result["compiler"] = compile_info;
  if (debug)
    cout << "compiler return code is: " << status << endl;
  if(status != 0) {
    finish (CE);
  }
  return 0;
}

int generate_exec_args () {

  do {
    // generate compile script, then set $script to that file
    // we don't execute the script.
    auto& wants = language["cscript"];

    if (wants.is_boolean())
      break;

    if (wants.is_null() || (wants.is_string() && wants.get<string>() == "$customArgs"))
      wants = config["variant"]["cscript"];

    if (wants.size() == 0)
      break;

    if (wants.is_array()) {
      int n = std::count_if(wants.begin(),wants.end(), [](const json& j){ return j.is_string() && j.get<string>() == "$customArgs";});
      int i = 0;
      for (json::iterator el = wants.begin(); el != wants.end(); ) {
        if (el->get<string>() == "$customArgs") {
          wants.erase(el);
          if (n > 1) {
            if (!config["variant"]["cscript"].is_array() || config["variant"]["cscript"].size() < static_cast<json::size_type>(n)) {
              continue;
            }
            wants.insert(el, config["variant"]["cscript"][i]);
            i++;
          } else {
            if (config["variant"]["cscript"].empty()) {
              continue;
            }
            wants.insert(el, config["variant"]["cscript"]);
          }
        }
        merge_array(config, config["path"], *el);
        ++el;
      }
    }

    merge_array(config, config["path"], wants);

    if (debug) {
      cerr << "compile sripts is:" << endl;
      cerr << wants.get<string>() << endl;
    }

    string filename = path["temp"] + ".cscript";

    ofstream fout(filename);
    fout << wants.get<string>() << endl;

    if (!fout) {
      result["compiler"] = "write compile script failed";
      finish(CE);
    }

    config["path"]["script"] = filename;
  } while(false);

  auto merge_custom_args = [](json& wants, const json& merge){
    int n = std::count_if(wants.begin(), wants.end(), [](const json& j){ return j.is_string() && j.get<string>() == "$customArgs";});
    int i = 0;
    for (json::iterator el = wants.begin(); el != wants.end(); ) {
      if (el->is_string() && el->get<string>() == "$customArgs") {
        wants.erase(el);
        if (n > 1) {
          if (!merge[i].is_array()) {
            continue;
          }
          wants.insert(el, merge[i].begin(), merge[i].end());
          i++;
        } else {
          if (!merge.is_array()) {
            continue;
          }
          wants.insert(el, merge.begin(), merge.end());
        }
      }
      merge_array(config, config["path"], *el);
      ++el;
    }
  };

  do {
    {
      auto& wants = language["compiler"];

      if (wants.is_boolean())
        break;

      if (wants.is_null())
        wants = config["variant"]["compiler"];

      merge_array(config, config["path"], wants);
    }

    auto& wants = language["cargs"];
    if (wants.is_null())
      wants = config["variant"]["cargs"];

    if (wants.is_string()) {
      string str = wants.get<string>();
      wants = json::array();
      wants.push_back(str);
    }

    if (!wants.is_array())
      wants = json::array();

    merge_custom_args(wants, config["variant"]["cargs"]);

    std::vector<const char*> args = {
      language["compiler"].get<string>().c_str()
    };

    for (auto& el: wants) {
      if (!el.empty())
        args.push_back(el.get<string>().c_str());
    }

    if (compile_general(args)) {
      finish(CE);
    };
  } while(false);

  do {
    auto& wants = language["executable"];
    if (wants.is_null())
      wants = config["variant"]["executable"];
    if (wants.is_null())
      wants = "$exec";

    if (wants.is_array()) {
      // if executable is an array, we treat it as script and prepare the $exec
      merge_array(config, config["path"], wants);

      if (debug) {
        cerr << "executable sripts is:" << endl;
        cerr << wants.get<string>() << endl;
      }

      ofstream fout(path["exec"]);
      fout << wants.get<string>() << endl;

      if (!fout) {
        result["compiler"] = "write executable script failed";
        finish(CE);
      }
    } else {
      // if not an array, we still need to merge it
      merge_array(config, config["path"], wants);
    }
  } while(false);

  {
    auto& wants = language["eargs"];
    if (wants.is_null())
      wants = config["variant"]["eargs"];

    if (wants.is_string()) {
      string str = wants.get<string>();
      wants = json::array();
      wants.push_back(str);
    }
    if (!wants.is_array())
      wants = json::array();

    config["case"] = {"$", "case"};
    merge_custom_args(wants, config["variant"]["eargs"]);
  }
  return 0;
}

int load_seccomp_tracee() {
  nice(10);
  if (setgid(99)) {
    perror("set_gid");
    return -1;
  };
  if (setuid(99)) {
    perror("set_uid");
    return -1;
  };
  chdir(path["sandbox"].c_str());
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_read, 39, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_write, 38, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execve, 37, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_gettimeofday, 36, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_futex, 35, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_clock_gettime, 34, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mprotect, 33, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_madvise, 32, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit, 31, 0),
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
  ptrace(PTRACE_TRACEME, 0, 0, 0);
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
  {
    perror("prctl(PR_SET_NO_NEW_PRIVS)");
    return -1;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
  {
    perror("when setting seccomp filter");
    return -1;
  }
  return 0;
}

int trace_thread(int pid, THREAD_INFO* info) {
  if (debug)
    cout << "[" << pid << "] prepare tracing" << endl;
  int orig_eax, eax;
  int& status = info->status;
  rusage& usage = info->usage;

  if (ptrace(PTRACE_SEIZE, pid, NULL, NULL)) {
    perror("while attach");
    status = 255;
    return -1;
  }

  kill(pid, SIGSTOP);

  if (pid == waitpid(pid, &status, WSTOPPED)) {
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK))
      perror("set options");

    if(ptrace(PTRACE_CONT, pid, 0, 0))
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
        kill(pid, SIGKILL);
        cerr << "failed clone process" << endl;
        return -1;
      }
      if (++process_forked > max_thread) {
        kill(pid, SIGKILL);
        kill(child_pid, SIGKILL);
        if (result["extra"].is_null()) result["extra"] = string("using more than ") + to_string(max_thread) + " cores";
        cerr << "[" << pid << "] killed as forking too many children" << endl;
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
      if (debug)
        cerr << "[" << pid << "] user program terminated by system signal " << WTERMSIG(status) << endl;
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

    if (status >> 8 == (SIGTRAP | (PTRAVE_EVENT_SECCOMP << 8)))
    {
      // syscall number
      orig_eax = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX, NULL);
      eax = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX, NULL);

      if (debug)
        cout << "[" << pid << "] got syscall " << syscall_name[orig_eax] << "(" << orig_eax << ") " << eax << endl;

      if ( eax == -38 )
      {
        int res = validate_syscall(pid, orig_eax);
        if(res == DENY) {
          ptrace(PTRACE_POKEUSER, pid, sizeof(long) * ORIG_RAX, (-1));
          ptrace(PTRACE_KILL, pid, reinterpret_cast<char *>(1), SIGSYS);
          kill(pid, SIGSYS);
          if (debug)
            cerr << "[" << pid << "] syscall " << orig_eax <<" denied by validator" << endl;
        } else if (res == SKIP) {
          ptrace(PTRACE_POKEUSER, pid, sizeof(long) * ORIG_RAX, (-1));
          if (debug)
            cerr << "[" << pid << "] syscall " << orig_eax <<" skipped by validator" << endl;
        } else if (res == KILL) {
          kill(pid, SIGKILL);
          if (debug)
            cerr << "[" << pid << "] syscall " << orig_eax <<" killed by validator" << endl;
          continue;
        }
      }

      if (ptrace(PTRACE_CONT, pid, reinterpret_cast<char *>(1), 0) == -1)
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
      ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status));
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

  info->ref->join();
  result.status = info->status;
  kill_children(info->next);

  while(info) {
    int time = (int) (info->usage.ru_utime.tv_sec * 1000 + info->usage.ru_utime.tv_usec / 1000);
    if (sys.time_system_time)
      time += (int) (info->usage.ru_stime.tv_sec * 1000 + info->usage.ru_stime.tv_usec / 1000);
    result.time = max(result.time, time);
    result.memory += info->usage.ru_maxrss;
    if (debug) {
      cout << "[-------] thread debugging *" << info->pid << "* exited." << endl;
      cout << "time: " << time << ", ";
      cout << "memory: " << info->usage.ru_maxrss << endl;
      if (info->status != 0) {
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
    if (info)
      info->ref->join();
  }

  return 0;
}

bool should_continue(RESULT r)
{
  if (config["continue_on"].is_boolean())
    return true;
  if (config["continue_on"].is_array()) {
    for (const auto& element : config["continue_on"]) {
      if (element.is_string()) {
        if (getStatusText(r) == element.get<string>())
          return true;
      } else if (element.is_number_integer()) {
        if (static_cast<int>(r) == element.get<int>())
          return true;
      } else {
        cerr << "[warn] unknown continue_on rules" << endl;
      }
    }
    return false;
  }
  cerr << "[warn] unknown continue_on rules" << endl;
  return true;
}

RESULT do_compare(const map<string, string>& extra) {
  if (spj_mode == SPJ_COMPARE) {
    // should do spj
    string spjcmd = path.at("spj") + " " + extra.at("stdin") + " "
      + extra.at("stdout") + " " + extra.at("output") + " " + path.at("sandbox")
      + " >" + extra.at("log") + " 2>&1";
    if (debug)
      cout << "special judge command: " << spjcmd << endl;
    int pid = fork();
    if (pid == 0) {
      int fd = open(extra.at("log").c_str(), O_WRONLY | O_CREAT | O_TRUNC);
      dup2(fd, STDOUT_FILENO);
      dup2(fd, STDERR_FILENO);
      alarm(10);
      execl (
        path.at("spj").c_str(),
        path.at("spj").c_str(),
        extra.at("stdin").c_str(),
        extra.at("stdout").c_str(),
        extra.at("output").c_str(),
        path.at("sandbox").c_str(),
        NULL
      );
      exit(255);
    }
    int status;
    wait(&status);
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

[[ noreturn ]] void do_test() {
  int time_limit = config["max_time"].get<int>();
  int real_time_limit = config["max_real_time"].get<int>() / 1000 + 1;
  int total_time_limit = config["max_time_total"].get<int>();
  int memory_limit = config["max_memory"].get<int>();
  int output_limit = config["max_output"].get<int>();

  int cases = config["test_case_count"].get<int>();

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

  path["exec"] = language["executable"].get<string>();

  if (debug)
    cout << "exec is: " << path["exec"] << endl;

  for (int c = 1; c <= cases; c++) {
    string cs = to_string(c);
    process_forked = 0;
    fs_write = 0;

    config["case"] = cs;
    json eargs = language["eargs"];
    vector<const char*> args = { path["exec"].c_str() };
    for (auto& el: eargs) {
      merge_array(config, config["path"], el);
      if (!el.empty())
        args.push_back(el.get<string>().c_str());
    }
    args.push_back(nullptr);

    map<string, string> extra;

    if (spj_mode == SPJ_INLINE) {
      extra["stdin"] = path.at("temp") + "/inline-" + cs + ".in";
      extra["stdout"] = "/dev/null";
      extra["output"] = path.at("temp") + "/inline-" + cs + ".out";
    } else {
      extra["stdin"] = path["stdin"] + "/" + cs + ".in";
      extra["stdout"] = path["stdout"] + "/" + cs + ".out";
      extra["output"] = path["output"] + "/" + cs + ".execout";
    }

    if(config["inline"].is_array() && config["inline"].size() >= static_cast<json::size_type>(c)) {
      auto& case_inline = config["inline"][c-1];
      if (spj_mode == SPJ_INLINE && case_inline["stdin"].is_string()) {
        ofstream fout(extra["stdin"]);
        fout << case_inline["stdin"].get<string>();
        if (!fout) {
          extra["stdin"] = "/dev/null";
        }
      }
      if (case_inline["fs"].is_object()) {
        for (const auto& el: case_inline["fs"].items()) {
          string key = el.key();
          key.erase(0, key.find_last_of('/') + 1);
          if (key == "..") key = "[insecure filename]";
          ofstream fout(path.at("sandbox") + "/" + key);
          fout << el.value().get<string>();
        }
      }
    }

    if (access(extra["stdin"].c_str(), R_OK))
      extra["stdin"] = "/dev/null";

    if (access(extra["stdout"].c_str(), R_OK))
      extra["stdout"] = "/dev/null";

    extra["log"] = path["log"] + "/" + cs + ".log";

    if (debug) {
      cout << "test case " << cs << endl;
      cout << "log: " << extra["log"] << endl;
      cout << "args: " << eargs << endl;
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
          , path.at("sandbox").c_str()
          , nullptr
        );

        cerr << "child process A exec failed" << endl;
        exit(255);
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

        execvp(args[0], const_cast<char**>(&args[0]));

        cerr << "child process B exec failed" << endl;
        exit(255);
      }

      // interactive parent continues here
      close_pipe();

      JUDGE_RESULT jresult;

      alarm(real_time_limit);
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
        case SIGPIPE: rs = AC; break;
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
      string log = readFile(extra.at("log"), sys.max_extra_size);
      if (log.size() == 0) {
        r["extra"] = nullptr;
      } else {
        r["extra"] = log;
      }

      result["detail"].push_back(r);

      total_time += case_result.time;
      max_memory = max(case_result.memory, max_memory);

      if (!should_continue(rs)) {
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

        int r = 0;

        int fd_in = open(extra["stdin"].c_str(), O_RDONLY);
        r = dup2(fd_in, STDIN_FILENO);
        if (r == -1)
          perror("fd_in");

        unlink(extra["output"].c_str());
        int fd_out = open(extra["output"].c_str(), O_WRONLY | O_CREAT | O_TRUNC);
        if (r != -1) {
            r = dup2(fd_out, STDOUT_FILENO);
          if (r == -1)
            perror("fd_out");
        }

        if (r != -1) {
            r = dup2(fd_out, STDERR_FILENO);
          if (r == -1)
            perror("fd_err");
        }

        if (r == -1) {
          close(fd_in);
          close(fd_out);
          cerr << "failed to redirect input & output." << endl;
          exit(255);
        }

        if(load_seccomp_tracee()) {
          cerr << "load seccomp rule failed" << endl;
          exit(255);
        };

        execvp(args[0], const_cast<char**>(&args[0]));

        close(fd_in);
        close(fd_out);

        cerr << "exec failed" << endl;
        exit(255);
      }
      // non interactive parent continues here

      alarm(real_time_limit);
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
        if (spj_mode == SPJ_INLINE) {
          rs = AC;
        } else {
          rs = do_compare(extra);
          r["extra"] = readFile(extra.at("log"), sys.max_extra_size);
        }
      }

      if (spj_mode == SPJ_INLINE) {
        struct dirent *dir;
        struct stat sb;
        r["inline"] = json::object();
        DIR *d = opendir(path.at("sandbox").c_str());
        if (d) {
          r["inline"]["fs"] = json::object();
          int count = 0;
          while ((dir = readdir(d)) != NULL) {
          string filename = path.at("sandbox") + "/" + dir->d_name;
            if (dir->d_type == DT_REG) {
              stat(filename.c_str(), &sb);
              if (sb.st_uid == 99 && sb.st_gid == 99) {
                string content = readFile(filename, sys.max_inline_fs_size);
                r["inline"]["fs"][dir->d_name] = content;
                cout << count << " " << sys.max_inline_fs_count << endl;
                if (++count > sys.max_inline_fs_count) break;
              }
            }
            unlink(filename.c_str());
          }
          closedir(d);
        }
        if (r["inline"]["fs"].size() == 0)
          r["inline"].erase("fs");
        r["inline"]["stdout"] = readFile(extra.at("output"), sys.max_inline_stdout_size);
      }
      r["status"] = static_cast<int>(rs);
      r["result"] = getStatusText(rs);
      result["detail"].push_back(r);

      total_time += case_result.time;
      max_memory = max(case_result.memory, max_memory);

      if (!should_continue(rs)) {
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
  finish(SW);
}

int preprocess() {
  path["temp"] = config["path"]["temp"].get<string>();
  remove_folder(path["temp"]);
  create_folder(path["temp"]);
  chmod(path["temp"].c_str(), S_IRWXG|S_IRWXU|S_IXOTH|S_IWOTH);

  path["output"] = config["path"]["output"].get<string>();
  create_folder(path["output"]);

  path["stdin"] = config["path"]["stdin"].get<string>();
  path["stdout"] = config["path"]["stdout"].get<string>();

  path["log"] = config["path"]["log"].get<string>();

  // Files
  path["result"] = path["output"] + "/result.json";

  path["code"] = config["path"]["code"].get<string>();

  path["exec"] = path["temp"] + "/main";
  unlink(path["exec"].c_str());
  ofstream(path["exec"]).close();
  chmod(path["exec"].c_str(), S_IRWXG|S_IRWXU|S_IRWXO);

  path["spj"] = config["path"]["spj"];

  path["cmpinfo"] = path["output"] + "/result.cmpinfo";
  unlink(path["cmpinfo"].c_str ());
  ofstream(path["cmpinfo"]).close();
  chmod(path["cmpinfo"].c_str(), S_IRWXG|S_IRWXU|S_IRWXO);

  path["sandbox"] = path["temp"] + "/sandbox-" + random_string(6) + "/";
  mkdir(path["sandbox"].c_str(), 0777);
  chown(path["sandbox"].c_str(), 99, 99);

  result["time"] = 0;
  result["memory"] = 0;
  result["result"] = getStatusText(SW);
  result["status"] = static_cast<int>(SW);
  result["detail"] = {};
  result["compiler"] = nullptr;

  struct stat fileStat;
  if(stat(path.at("code").c_str(), &fileStat) < 0) {
    cerr << "unable to access code file" << endl;
  }
  code_permission = fileStat.st_mode;
  if (!(code_permission & S_IROTH)) {
    chmod(path.at("code").c_str(), code_permission | S_IROTH);
  }

  // make something special for javascript, pypy3, etc.
  if (language["patch"].is_object()) {
    for (auto& el: language["patch"].items()) {
      string orig_key;
      int orig_val;
      if (el.key().back() == '+' || el.key().back() == '*') {
        orig_key = el.key().substr(0, el.key().length() - 1);
      } else {
        orig_key = el.key();
      }
      if (config.count(orig_key) && config[orig_key].is_number_integer()) {
        config[orig_key].get_to(orig_val);
      } else {
        cerr << "unknown patch rule for: " << orig_key << endl;
        return -1;
      }
      int c;
      if (el.key().back() == '+') {
        if(__builtin_add_overflow(orig_val, el.value().get<int>(), &c)) {
          if (c < 0) config[orig_key] = INT_MAX;
          if (c > 0) config[orig_key] = 0;
        } else {
          config[orig_key] = c;
        };
      } else if (el.key().back() == '*') {
        if(__builtin_mul_overflow(orig_val, el.value().get<int>(), &c)) {
          config[orig_key] = INT_MAX;
        } else {
          config[orig_key] = c;
        };
      } else {
        config[orig_key] = el.value();
      }
      if (debug)
        cout << "patched " << el.key() << "(" << el.value() << ") to " << config[orig_key] << endl;
    }
  }
  if (debug)
    cout << "preprocessed ok." << endl;
  return 0;
}

#include "syscall_name.hpp"

int main (int argc, char** argv) try {
  initialize(syscall_name);

  if (read_config(argc, argv) || validate_config() || preprocess()) {
    exit(255);
  }

  // compile source or check syntax, this function won't fail(?)
  generate_exec_args();

  // do test
  mount("none", path["sandbox"].c_str(), "tmpfs", MS_NOATIME |  MS_NODEV | MS_NODIRATIME | MS_NOEXEC | MS_NOSUID, "");
  do_test();

  throw std::range_error("main function should no return");

} catch (const nlohmann::json::exception& e) {
  result["extra"] = string("core caught json exception: ") + e.what();
  finish(SW);
} catch (const std::exception& e) {
  result["extra"] = string("core caught std exception: ") + e.what();
  finish(SW);
} catch (...) {
  result["extra"] = string("core caught unknown exception");
  finish(SW);
}
