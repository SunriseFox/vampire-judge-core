#!/bin/bash

set -ex; \
  docker build -t sunrisefox/judgecore:v1.0 .; \
  docker run -ti -d -v /var/www/onlinejudge:/mnt/data sunrisefox/judgecore:v1.0; \
  