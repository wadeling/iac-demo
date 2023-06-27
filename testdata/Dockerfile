FROM ubuntu:20.04

ARG TAG=latest
RUN sed -i "s!archive.ubuntu.com/!mirrors.aliyun.com/!g" /etc/apt/sources.list \
    && sed -i "s!ports.ubuntu.com/!mirrors.aliyun.com/!g" /etc/apt/sources.list \
    && apt-get update -y \
    && apt-get full-upgrade -y \
    && apt-get install -y wget \
    && apt-get install -y libclamav-dev zip unzip \
    && apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common iptables \
    && curl -fsSL https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu/gpg | apt-key add - \
    && add-apt-repository "deb [arch=$(dpkg --print-architecture)] https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu $(lsb_release -cs) stable" \
    && apt-get install -y  docker-ce-cli \
    && apt-get full-upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ADD test.tgz /usr/local

RUN mkdir /etc/myapi && mkdir /var/log/myapi && mkdir /run/myapi

ADD clamav/clamav.tgz /var/lib/

ADD configs/myscanner/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
