#ifndef DEFS_H
#define DEFS_H

#define DEFAULT_JSON_PATH "conf/default.json"
#define LANG_SPEC_PATH "conf/lang_spec.json"

enum RESULT {AC = 0, PE, WA, CE, RE, ME, TE, OLE, SLE, SW};
// enum LANGUAGE {LANG_C = 0, LANG_CPP, LANG_JAVASCRIPT, LANG_PYTHON, LANG_GO, LANG_TEXT, LANG_PYPY3, LANG_BINARY, LANG_CUSTOM};
enum SPJ_MODE {SPJ_NO = 0, SPJ_COMPARE, SPJ_INTERACTIVE, SPJ_INLINE};
enum TRACE_ACTION {ALLOW = 0, SKIP = 1, DENY = 2, KILL = 3};

struct CONFIG_COMPILER {
  long max_time;
  long max_real_time;
  long max_memory;
  long max_output;
};

struct CONFIG_SYS {
  bool time_system_time = false;
  long max_compiler_size = 5000;
  long max_extra_size = 10240;
  long max_fs_write_count = 20;
  long max_inline_fs_count = 20;
  long max_inline_fs_size = 1000;
  long max_inline_stdout_size = 1000;
};

const char* strerr = "[error] ";
const char* strwarn = "[warn] ";

#endif