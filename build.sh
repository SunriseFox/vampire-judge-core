#!/bin/bash

MOUNTFOLDER="/var/www/onlinejudge"
MOUNTPOINT="/mnt/data"

# if a warning about SIGNAL occurred on build, use this:
# dpkg -r --force-depends golang-docker-credential-helpers
# this is a bug related to docker-compose

set -ex; \
  docker build -t sunrisefox/judgecore:v1.0 .; \
  docker run --name judgecore --cap-add=SYS_PTRACE --cap-add=SYS_ADMIN --security-opt apparmor=unconfined --security-opt seccomp=unconfined -ti -d -v $MOUNTFOLDER:$MOUNTPOINT --tmpfs /tmp:exec sunrisefox/judgecore:v1.0; \

# echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope