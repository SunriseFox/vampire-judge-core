#!/bin/bash
set -ex; \
g++ -pthread -static /mnt/data/code/1001/10001/main.cpp -o tracee;\
g++ -pthread src/trace.cpp -o tracer;

./tracer ./tracee