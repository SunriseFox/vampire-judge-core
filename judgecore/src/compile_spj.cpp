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
mode_t code_permission;

bool debug = false;
SPJ_MODE spj_mode = SPJ_NO;

map<string, string> path;
map <int, string> syscall_name;

std::mutex g_tail_mutex;
THREAD_INFO *tail = nullptr, *info = nullptr;
int process_forked = 0;
int max_thread = 4;

json result;
json config;
json lang_spec; // convert to null if found
json language;


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
      cerr << "killed " << pid_to_kill << " - real time limit exceed" << endl;
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
  // this may fail, so clean up first
  result["success"] = what == AC;

  auto result_str = result.dump(debug ? 2 : -1, ' ', false, json::error_handler_t::replace);

  cout << result_str << endl;

  _exit(what != AC);
  throw std::range_error("finish function should not return");
}

int read_config(int argc, char** argv) {
  if (argc < 2) {
    cerr << "usage: compiler [config.json [stdin]]" << endl;
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
  merge_path("spj");

  if (config["code"].is_null()) {
    try {
      config["path"]["code"] = merge_array(config, config["path"], config["spj"]["code"]);
    } catch (...) {
      config["path"]["code"] = nullptr;
    }
  } else {
    try {
      config["path"]["code"] = merge_array(config, config["path"], config["code"]);
    } catch (...) {
      config["path"]["code"] = nullptr;
    }
  }
  if (config["path"]["code"].is_null()) {
    cerr << "code, spj:code is null or failed to merge"  << endl;
    error = 1;
  }

  if (config["target"].is_null()) {
    try {
      string str = merge_array(config, config["path"], config["spj"]["target"]);
      config["path"]["target"] = str;
      config["path"]["exec"] = str + ".exec";
    } catch (...) {
      config["path"]["target"] = nullptr;
      config["path"]["exec"] = nullptr;
    }
  } else {
    try {
      string str = merge_array(config, config["path"], config["target"]);
      config["path"]["target"] = str;
      config["path"]["exec"] = str + ".exec";
    } catch (...) {
      config["path"]["target"] = nullptr;
      config["path"]["exec"] = nullptr;
    }
  }
  if (config["path"]["target"].is_null() || config["path"]["exec"].is_null()) {
    cerr << "target, spj:target is null or failed to merge"  << endl;
    error = 1;
  }

  if (debug)
    cout << "configuration validated with code " << error << endl;

  if (debug)
    cout << setw(2) << config << endl;

  return error;
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
    int fd = open(path.at("cmpinfo").c_str(), O_WRONLY);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (setpgid(0, 0)) {
      cerr << "set pgid failed!" << endl;
    };
    if (execvp(args[0], const_cast<char**>(&args[0])))
      perror("while exec") ;
    raise(SIGSYS);
  }

  int compile_timeout = 30;
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

  string compile_info = readFile(path["cmpinfo"], 5000);
  unlink(path.at("cmpinfo").c_str());
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
      cout << "compile sripts is:" << endl;
      cout << wants.get<string>() << endl;
    }

    string filename = path.at("exec") + ".cscript";

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
        cout << "executable sripts is:" << endl;
        cout << wants.get<string>() << endl;
      }

      ofstream fout(path.at("exec"));
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

  stringstream ss;
  ss << "#!/bin/bash\n";
  ss << "exec $'";

  for (const auto& c: language["executable"].get<string>()) {
    if (c == '\'') ss << "\\'";
    else ss << c;
  }

  ss << "' ";

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
    for (const auto& a: wants) {
      if (!a.empty()) {
        ss << "$'";
        for (const auto& c: a.get<string>()) {
          if (c == '\'') ss << "\\'";
          else ss << c;
        }
        ss << "' ";
      }
    }
  }

  ss << "\"$@\"" << endl;

  ofstream fout(path.at("target"));
  fout << ss.str() << endl;
  if (!fout) {
    result["compiler"] = "failed to write target script";
    finish(CE);
  }
  fout.close();
  finish(AC);
}

int preprocess() {
  path["target"] = config["path"]["target"];
  unlink(path["target"].c_str());
  ofstream(path["target"]).close();
  chmod(path["target"].c_str(), S_IRWXU|S_IXGRP|S_IXOTH);

  path["exec"] = config["path"]["exec"];
  unlink(path["exec"].c_str());
  ofstream(path["exec"]).close();
  chmod(path["exec"].c_str(), S_IRWXU|S_IXGRP|S_IXOTH);

  path["cmpinfo"] = path.at("target") + ".cmpinfo";
  unlink(path["cmpinfo"].c_str ());
  ofstream(path["cmpinfo"]).close();
  chmod(path["cmpinfo"].c_str(), S_IRWXG|S_IRWXU|S_IRWXO);

  result["success"] = false;
  result["compiler"] = nullptr;
  result["target"] = path.at("target");

  if (debug)
    cout << "preprocessed ok." << endl;
  return 0;
}

int main (int argc, char** argv) try {

  if (read_config(argc, argv) || validate_config() || preprocess()) {
    exit(255);
  }

  // compile source or check syntax, this function won't fail(?)
  generate_exec_args();

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
