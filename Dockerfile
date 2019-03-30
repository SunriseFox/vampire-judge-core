FROM centos:latest
LABEL maintainer="sunrisefox@qq.com"

RUN yum -y install centos-release-scl
RUN yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
RUN yum -y update

# gcc

RUN yum -y install devtoolset-8

# node - deprecated

# RUN curl -sL https://rpm.nodesource.com/setup_11.x | bash -
# RUN yum -y install nodejs

# v8

RUN curl -o /tmp/v8.tar https://github.com/SunriseFox/vampire-judge-core/releases/download/latest/d8-latest-prebuild.tar
RUN mkdir /usr/bin/v8
RUN tar -C /usr/bin/v8 -zxvf /tmp/v8.tar x64.release --strip-components 1

# python

RUN yum -y install rh-python36

# go

RUN yum -y install golang

# static lib

RUN yum -y install glibc-static

# enable in path

ENV PATH=/opt/rh/devtoolset-8/root/usr/bin:/opt/rh/rh-python36/root/usr/bin:$PATH

WORKDIR /usr/bin/judgecore
ADD judgecore /usr/bin/judgecore
RUN set -ex; \
    source /usr/bin/judgecore/compile.sh;

# volume

VOLUME /mnt/data
