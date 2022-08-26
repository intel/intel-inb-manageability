# base-setup.m4: common set of commands for a base utility image, either x86 or arm

SHELL ["/bin/bash", "-c"]
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends install -y \
    software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get clean
RUN gem install public_suffix -v 4.0.7
RUN gem install --no-document fpm -v 1.14.0
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends install -y \
    m4 \
    build-essential \
    curl \
    ruby-dev \
    rubygems \
    pkg-config \
    rpm \
    wget \
    unzip \
    python3.8 \
    python3.8-dev \
    python3-pip \
    python3.8-venv \
    python3-setuptools \
    libxslt1-dev \
    gcc \
    libssl-dev \
    libffi-dev \
    cpio \
    git && \
    apt-get clean
#RUN gem install public_suffix -v 4.0.7
#RUN gem install --no-document fpm -v 1.14.0
