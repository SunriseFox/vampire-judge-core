#!/bin/bash

set -ex; \
  g++ -pthread -Wall -Wextra -O2 -o judgecore src/main.cppg++ -pthread -Wall -Wextra -O2 -o judgecore src/main.cpp src/includes/syscall.c; \
  g++ -Wall -Wextra -O2 -o compiler src/compile_spj.cpp
