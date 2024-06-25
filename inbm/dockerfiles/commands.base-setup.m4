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
RUN gem install public_suffix -v 5.0.5 && gem install dotenv -v 2.8.1 && gem install --no-document fpm -v 1.14.0
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends install -y \
    software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get clean
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends install -y \
    python3.11 \
    python3.11-dev \
    python3-pip \
    python3.11-venv \
    python3-setuptools \
    libxslt1-dev \
    gcc \
    libssl-dev \
    libffi-dev \
    cpio \
    rsync \
    && \
    apt-get clean

