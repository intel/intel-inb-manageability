# Copyright (c) 2021-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM snyk/snyk:python-3.9
RUN apt-get update && apt-get install -y npm
RUN npm install snyk-to-html@2.3.6 -g
COPY inbm-lib /inbm-lib
RUN python3 -m venv /venv3-snyk && . /venv3-snyk/bin/activate && python -m pip install -U pip && python -m pip install -e /inbm-lib
RUN curl https://dl.google.com/go/go1.18.linux-amd64.tar.gz >/go.tar.gz && cd / && tar zxvf ./go.tar.gz
COPY scan-python.sh /scan-python.sh
COPY scan-golang.sh /scan-golang.sh
RUN chmod +x /scan-python.sh && chmod +x /scan-golang.sh

ENTRYPOINT []
