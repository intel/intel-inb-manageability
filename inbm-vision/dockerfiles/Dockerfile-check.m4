# base image with all dependencies for running unit tests/lints
FROM registry.hub.docker.com/library/ubuntu:18.04 as base

ENV http_proxy http://proxy-dmz.intel.com:911/
ENV https_proxy http://proxy-dmz.intel.com:912/
ENV no_proxy intel.com,127.0.0.1,localhost

SHELL ["/bin/bash", "-c"]
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends install -y \
    software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get clean
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends install -y \
    python3.8 \
    python3.8-dev \
    python3-pip \
    python3.8-venv \
    python3-setuptools \
    libxslt1-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    libmagic1 \
    && \
    apt-get clean


# build a virtual environment for each agent to run checks

# py3 venv
FROM base as venv-py3
WORKDIR /
COPY inbm-vision/common-python-config /common-python-config
RUN python3.8 -m venv /venv-py3 && \
    source /venv-py3/bin/activate && \
    pip3 install wheel==0.34.2 && \
    pip3 install \
        nose==1.3.7 \
        flake8==3.7.9 \
        flake8-bandit==2.1.2 \
        coverage==5.1 \
        flakehell==0.3.0 \
        wemake-python-styleguide==0.14.0 \
        teamcity-messages==1.28 \
        mock==4.0.2 \
        pylint==2.4.3 \
        mypy==0.812 \
        -U
COPY inbm-lib /src/inbm-lib
ENV PYTHONPATH=/src/inbm-lib
ENV MYPYPATH=/src/inbm-lib
RUN source /venv-py3/bin/activate && \
    pip3.8 install -e /src/inbm-lib && \
    pip3.8 install /src/inbm-lib[test]

FROM venv-py3 as lint-venv-py3
RUN source /venv-py3/bin/activate && \
    cd /src/inbm-lib && \
    set -o pipefail && \
    flakehell lint | tee /passed.txt


# ---inbm library---

FROM venv-py3 as mypy-libraries
RUN source /venv-py3/bin/activate && \
    cd /src/inbm-lib && \
    ./mypy-py3.sh . && \
    touch /passed.txt

FROM venv-py3 as test-libraries
COPY inbm-vision/node-agent/fpm-template/usr/share/node-agent/intel_manageability_node_schema.xsd /src/inbm-vision/node-agent/fpm-template/usr/share/node-agent/intel_manageability_node_schema.xsd
COPY inbm-vision/node-agent/fpm-template/usr/share/node-agent/node_xlink_schema.xsd /src/inbm-vision/node-agent/fpm-template/usr/share/node-agent/node_xlink_schema.xsd
COPY inbm-vision/node-agent/fpm-template/etc/intel-manageability/public/node-agent/intel_manageability_node.conf /src/inbm-vision/node-agent/fpm-template/etc/intel-manageability/public/node-agent/intel_manageability_node.conf
COPY inbm-vision/vision-agent/fpm-template/usr/share/vision-agent/intel_manageability_vision_schema.xsd /src/inbm-vision/vision-agent/fpm-template/usr/share/vision-agent/intel_manageability_vision_schema.xsd
COPY inbm-vision/vision-agent/fpm-template/usr/share/vision-agent/vision_xlink_schema.xsd /src/inbm-vision/vision-agent/fpm-template/usr/share/vision-agent/vision_xlink_schema.xsd
COPY inbm-vision/vision-agent/fpm-template/etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf /src/inbm-vision/vision-agent/fpm-template/etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf


WORKDIR /src/inbm-lib
RUN source /venv-py3/bin/activate && \
    cd /src/inbm-lib && \
    set -o pipefail && \
    mkdir -p /output/coverage && \
    cd tests/unit && \
    nosetests --with-coverage --cover-erase --cover-inclusive --cover-package=inbm_common_lib inbm_common_lib 2>&1 | tee /output/coverage/inbm-common-lib-coverage.txt && \
    nosetests --with-coverage --cover-erase --cover-inclusive --cover-package=inbm_vision_lib inbm_vision_lib 2>&1 | tee /output/coverage/inbm-vision-lib-coverage.txt && \
    coverage report --show-missing --fail-under=81 && \
    touch /passed.txt


# ---vision agent---

FROM venv-py3 as venv-vision-py3
COPY inbm-vision/vision-agent/requirements.txt /src/vision-agent/requirements.txt
COPY inbm-vision/vision-agent/test-requirements.txt /src/vision-agent/test-requirements.txt
WORKDIR /src/vision-agent
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt && \
    pip3.8 install -r test-requirements.txt
COPY inbm-vision/vision-agent /src/vision-agent
COPY inbm-vision/packaging /src/packaging
RUN source /venv-py3/bin/activate && \
    cp -f /common-python-config/pyproject.toml . && \
    flakehell lint

FROM venv-vision-py3 as mypy-vision
RUN source /venv-py3/bin/activate && \
    /common-python-config/mypy-py3.sh vision && \
    touch /passed.txt

FROM venv-vision-py3 as vision-unit-tests
COPY inbm-vision/packaging/ /src/packaging/
COPY inbm-vision/node-agent/fpm-template/usr/share/node-agent/intel_manageability_node_schema.xsd /src/node-agent/fpm-template/usr/share/node-agent/intel_manageability_node_schema.xsd
COPY inbm-vision/node-agent/fpm-template/usr/share/node-agent/node_xlink_schema.xsd /src/node-agent/fpm-template/usr/share/node-agent/node_xlink_schema.xsd
COPY inbm-vision/node-agent/fpm-template/etc/intel-manageability/public/node-agent/intel_manageability_node.conf /src/node-agent/fpm-template/etc/intel-manageability/public/node-agent/intel_manageability_node.conf
COPY inbm-vision/vision-agent/fpm-template/usr/share/vision-agent/intel_manageability_vision_schema.xsd /src/vision-agent/fpm-template/usr/share/vision-agent/intel_manageability_vision_schema.xsd
COPY inbm-vision/vision-agent/fpm-template/usr/share/vision-agent/vision_xlink_schema.xsd /src/vision-agent/fpm-template/usr/share/vision-agent/vision_xlink_schema.xsd
COPY inbm-vision/vision-agent/fpm-template/etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf /src/vision-agent/fpm-template/etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf

RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    nosetests --with-coverage --cover-erase --cover-inclusive --cover-package=vision vision/tests/unit 2>&1 | tee /output/coverage/vision-coverage.txt && \
    coverage report --show-missing --fail-under=91

# ---node agent---

FROM venv-py3 as venv-node-py3
COPY inbm-vision/node-agent/requirements.txt /src/node-agent/requirements.txt
COPY inbm-vision/node-agent/test-requirements.txt /src/node-agent/test-requirements.txt
WORKDIR /src/node-agent
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt && \
    pip3.8 install -r test-requirements.txt
COPY inbm-vision/node-agent /src/node-agent
COPY inbm-vision/packaging /src/packaging
RUN source /venv-py3/bin/activate && \
    cp -f /common-python-config/pyproject.toml . && \
    flakehell lint

FROM venv-node-py3 as mypy-node
RUN source /venv-py3/bin/activate && \
    /common-python-config/mypy-py3.sh node && \
    touch /passed.txt

FROM venv-node-py3 as node-unit-tests
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    nosetests --with-coverage --cover-erase --cover-inclusive --cover-package=node node/tests/unit 2>&1 | tee /output/coverage/node-coverage.txt && \
    coverage report --show-missing --fail-under=93


# ---inbc---

FROM venv-py3 as venv-inbc-py3
COPY inbc-program/requirements.txt /src/inbc-program/requirements.txt
COPY inbc-program/test-requirements.txt /src/inbc-program/test-requirements.txt
WORKDIR /src/inbc-program
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt && \
    pip3.8 install -r test-requirements.txt
COPY inbm-vision/common-python-config /common-python-config
COPY inbc-program /src/inbc-program
COPY inbm-vision/packaging /src/packaging
RUN source /venv-py3/bin/activate && \
    cp -f /common-python-config/pyproject.toml . && \
    flakehell lint

FROM venv-inbc-py3 as mypy-inbc
RUN source /venv-py3/bin/activate && \
    /common-python-config/mypy-py3.sh inbc && \
    touch /passed.txt

FROM venv-inbc-py3 as inbc-unit-tests
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    nosetests --with-coverage --cover-erase --cover-inclusive --cover-package=inbc tests/unit 2>&1 | tee /output/coverage/inbc-coverage.txt && \
    coverage report --fail-under=85


# output container
FROM base as output
COPY --from=test-libraries /passed.txt /passed-test-libraries.txt
COPY --from=vision-unit-tests /output /vision
COPY --from=node-unit-tests /output /node
COPY --from=test-libraries /output /test-libraries
COPY --from=mypy-libraries /passed.txt /passed-mypy-libraries.txt
COPY --from=mypy-node /passed.txt /passed-mypy-node.txt
COPY --from=mypy-vision /passed.txt /passed-mypy-vision.txt
COPY --from=lint-venv-py3 /passed.txt /passed-lint-venv-py3.txt
RUN mkdir -p /output/ && \
    cp -rv \
    /test-libraries/* \
    /vision/* \
    /node/* \
    /output
