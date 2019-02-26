#!/bin/bash

set -ex; \
  g++ -Wall -Wextra -O2 -o judgecore src/main.cpp; \
  g++ -Wall -Wextra -O2 -o compiler src/compile_spj.cpp
