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

# python

RUN yum -y install rh-python36

# go

RUN yum -y install golang

# static lib

RUN yum -y install glibc-static

# v8

RUN curl -Lo /tmp/v8.tgz https://github.com/SunriseFox/vampire-judge-core/releases/download/latest/v8-latest-prebuild.tgz
RUN mkdir /usr/bin/v8
RUN tar -C /usr/bin/v8 -zxf /tmp/v8.tgz x64.release --strip-components 1

# pypy3

RUN curl -Lo /tmp/pypy.tgz https://github.com/SunriseFox/vampire-judge-core/releases/download/latest/pypy-latest-prebuild.tgz
RUN tar -C /usr/bin -zxf /tmp/pypy.tgz
RUN mv /usr/bin/pypy/bin/libpypy3-c.so /usr/bin/pypy/bin/libpypy3-c.so.debug /lib64

# enable in path

ENV PATH=/opt/rh/devtoolset-8/root/usr/bin:/opt/rh/rh-python36/root/usr/bin:$PATH

WORKDIR /usr/bin/judgecore
ADD judgecore /usr/bin/judgecore
RUN bash -c "/usr/bin/judgecore/compile.sh"

# volume

VOLUME /mnt/data
