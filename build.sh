#!/bin/bash

set -ex; \
  docker build -t sunrisefox/judgecore:v1.0 .; \
  docker run --name judgecore --cap-add=SYS_PTRACE --cap-add=SYS_ADMIN --security-opt apparmor=unconfined --security-opt seccomp=unconfined -ti -d -v /var/www/onlinejudge:/mnt/data sunrisefox/judgecore:v1.0; \

# echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
