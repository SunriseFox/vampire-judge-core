#include <iostream>
#include <fstream>
#include <iomanip>
#include <map>

#include <sys/wait.h>

#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "json.hpp"
using json = nlohmann::json;

#define UNUSED(x) (void)x;

using namespace std;

bool debug = false;
map<string, string> path;
json result;

std::string readFile(const string& filename) {
  ifstream in(filename);
  return static_cast<std::stringstream const&>(std::stringstream() << in.rdbuf()).str();
}

int create_folder(const string& path) {
    const int error = system((string("mkdir -p ") + path).c_str ());
    if (error != 0)
    {
        cerr << "create directory at " << path << " failed" << endl;
        return -1;
    }
    return 0;
}

void succeeded() {
  result["success"] = true;
  result["target"] = path["exec"];
  cout << (debug ? setw(2) : setw(0)) << result << endl;
  _exit(0);
}

void failed() {
  result["success"] = false;
  cout << (debug ? setw(2) : setw(0)) << result << endl;
  _exit(255);
}

int read_config(int argc, char** argv, json& j) {
  bool has_stdin = false;

  if (argc < 2) {
    cerr << "usage: compile [config.json [stdin]]" << endl;
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
    cout << setw(4) << j << endl;
  }
  return 0;
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
        failed();
      }
      return 0;
  }
  // should not
  raise(SIGTRAP);
  return -1;
}

int compile_exec_c (json& j) {
  if (debug) 
    cout << "language is c" << endl;
  string compile_command = "gcc -DONLINE_JUDGE -O2 -std=c11 -Wall -Wextra -o "
          + path["exec"] + " " + path["code"] + " >"
          + path["cmpinfo"] + " 2>&1";
  return comile_c_cpp(j, compile_command);
}

int compile_exec_cpp (json& j) {
  if (debug) 
    cout << "language is cpp" << endl;
  string compile_command = "g++ -DONLINE_JUDGE -O2 -std=c++14 -Wall -Wextra -o "
          + path["exec"] + " " + path["code"] + " >"
          + path["cmpinfo"] + " 2>&1";
  return comile_c_cpp(j, compile_command);
}

int compile_exec_javascript (json& j) {
  UNUSED(j);
  if (debug) 
    cout << "language is javascript, skip compile" << endl;

  ofstream script(path["exec"] + ".nodejs");
  string s = readFile(path["code"]);
  script << s << endl;
  script.close();
  
  ofstream exec(path["exec"]);
  exec << "#! /bin/bash\n";
  exec << "exec node --no-warnings " + path["exec"] + ".nodejs" << endl;
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

int compile_exec_custom (json& j) {
  UNUSED(j);
  cerr << "lang not specific or unknown language" << endl;
  return -1;
}

int generate_exec_args (json& j) {
  if (j["lang"].is_string()) {
    if(j["lang"].get<string>() == "c") {
      return compile_exec_c(j);
    } else if(j["lang"].get<string>() == "c++") {
      return compile_exec_cpp(j);
    } else if(j["lang"].get<string>() == "javascript") {
      return compile_exec_javascript(j);
    } else if(j["lang"].get<string>() == "python") {
      return compile_exec_python(j);
    } else if(j["lang"].get<string>() == "go") {
      return compile_exec_go(j);
    } else {
      return compile_exec_custom(j);
    }
  } else if (j["lang"].is_number_integer()) {
    if(j["lang"].get<int>() == 0) {
      return compile_exec_c(j);
    } else if(j["lang"].get<int>() == 1) {
      return compile_exec_cpp(j);
    } else if(j["lang"].get<int>() == 2) {
      return compile_exec_javascript(j);
    } else if(j["lang"].get<int>() == 3) {
      return compile_exec_python(j);
    } else if(j["lang"].get<int>() == 4) {
      return compile_exec_go(j);
    } else {
      return compile_exec_custom(j);
    }
  } else {
    return -1;
  }
}

string get_lang_ext(json& j) {
  if (j["lang"].is_string()) {
    if(j["lang"].get<string>() == "c") {
      return "c";
    } else if(j["lang"].get<string>() == "c++") {
      return "cpp";
    } else if(j["lang"].get<string>() == "javascript") {
      return "js";
    } else if(j["lang"].get<string>() == "python") {
      return "py";
    } else if(j["lang"].get<string>() == "go") {
      return "go";
    }
  } else if (j["lang"].is_number_integer()) {
    if(j["lang"].get<int>() == 0) {
      return "c";
    } else if(j["lang"].get<int>() == 1) {
      return "cpp";
    } else if(j["lang"].get<int>() == 2) {
      return "js";
    } else if(j["lang"].get<int>() == 3) {
      return "py";
    } else if(j["lang"].get<int>() == 4) {
      return "go";
    }
  }
  return "unknown";
}

int main (int argc, char** argv) {
  json j;
  int r;

  if ((r = read_config(argc, argv, j)))
    _exit(255);

  if (j["code"].is_null()) {
    j["code"] = j["base_path"].get<string>() + "/judge/" + to_string(j["pid"].get<int>()) + "." + get_lang_ext(j);
  }
  if (j["target"].is_null()) {
    j["target"] = j["base_path"].get<string>() + "/judge/" + to_string(j["pid"].get<int>());
  }
  string target = j["target"].get<string>();
  size_t pos = target.find_last_of("/");
  if (pos != string::npos) {
    target = target.substr(0, string::npos);
    create_folder(target.c_str());
  }


  path["exec"] = j["target"].get<string>();
  path["code"] = j["code"].get<string>();
  path["temp"] = "/tmp/spj_compile_" + to_string(time(NULL)) +"/";
  create_folder(path["temp"]);
  path["cmpinfo"] = path["temp"] + "/result.cmpinfo";

  if ((r = generate_exec_args(j)))
    _exit(255);
  succeeded();
  return 0;
}