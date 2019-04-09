#include "utils.h"

mt19937 rng(random_device{}());

string random_string(size_t length)
{
    auto randchar = []() -> char
    {
        const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        std::uniform_int_distribution<> dist(0, max_index - 1);
        return charset[ dist(rng) ];
    };
    std::string str(length,0);
    std::generate_n( str.begin(), length, randchar );
    return str;
}

int create_folder(const string& path) {
  int pid = fork();
  if (pid == 0) {

    execl("/usr/bin/mkdir", "/usr/bin/mkdir", "-p", path.c_str(), nullptr);
    exit(1);
  }
  int status;

  if (waitpid(pid, &status, 0) == -1) {
    kill(pid, SIGKILL);
    perror("wait pid");
  }
  if (status != 0) {
    cerr << "create directory at " << path << " failed" << endl;
    return -1;
  }
  return 0;
}

int remove_folder(const string& path) {
  int pid = fork();
  if (pid == 0) {
    execl("/usr/bin/rm", "/usr/bin/rm", "-rf", path.c_str(), nullptr);
    exit(1);
  }
  int status = -1;
  if (waitpid(pid, &status, 0) == -1) {
    kill(pid, SIGKILL);
    perror("wait pid");
  }
  if (status != 0) {
    cerr << "remove directory at " << path << " failed" << endl;
    return -1;
  }
  return 0;
}

int copy_file(const string& from, const string& dest) {
  std::ifstream src(from.c_str(), std::ios::binary);
  std::ofstream dst(dest.c_str(), std::ios::binary);

  if (!src.is_open() || !dst.is_open()) {
    return -1;
  }

  dst << src.rdbuf();
  return 0;
}

string readFile(const string& filename) {
  ifstream in(filename);
  return static_cast<stringstream const&>(stringstream() << in.rdbuf()).str();
}

string readFile(const string& filename, std::string::size_type count)
{
  ifstream stream(filename);
  std::string result(count, '\x00');
  stream.read(&result[0], count);
  result.resize(stream.gcount());
  return result;
}
