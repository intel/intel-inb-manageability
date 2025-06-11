# Copyright (c) 2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# base-setup.m4: common set of commands for a base utility image, either x86 or arm

SHELL ["/bin/bash", "-c"]
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends install -y \
    m4  \
    gcc \
    make \
    curl \
    ruby-dev \
    rubygems \
    pkg-config \
    rpm \
    wget \
    unzip \
    git && \
    apt-get clean
RUN gem install public_suffix -v 5.1.1
RUN gem install dotenv -v 2.8.1
RUN gem install rchardet -v 1.8.0
RUN gem install --no-document fpm -v 1.14.0
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends install -y \
    software-properties-common && \
    apt-get clean

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends install -y \
    wget build-essential libssl-dev zlib1g-dev libncurses5-dev \
    libncursesw5-dev libreadline-dev libsqlite3-dev libgdbm-dev \
    libdb5.3-dev libbz2-dev libexpat1-dev liblzma-dev tk-dev \
    libffi-dev uuid-dev libxslt1-dev gcc cpio rsync && \
    wget https://www.python.org/ftp/python/3.12.3/Python-3.12.3.tgz && \
    tar -xzf Python-3.12.3.tgz && \
    cd Python-3.12.3 && \
    ./configure --enable-optimizations --enable-shared && \
    make -j$(nproc) && \
    make altinstall && \
    cd .. && \
    rm -rf Python-3.12.3 Python-3.12.3.tgz

ENV LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}"

RUN python3.12 -m pip install --upgrade pip setuptools
