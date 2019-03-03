FROM centos:latest
LABEL maintainer="sunrisefox@qq.com"

RUN yum -y install centos-release-scl
RUN yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
RUN yum -y update

# gcc

RUN yum -y install devtoolset-8

# node

RUN curl -sL https://rpm.nodesource.com/setup_11.x | bash -
RUN yum -y install nodejs

# python

RUN yum -y install rh-python36

# go

RUN yum -y install golang

# static lib

RUN yum -y install glibc-static

# enable in path

ADD source.sh /etc/profile.d/

WORKDIR /usr/bin/judgecore
ADD judgecore /usr/bin/judgecore
RUN set -ex; \
    source /etc/profile.d/source.sh; \
    source /usr/bin/judgecore/compile.sh;

# volume

VOLUME /mnt/data
