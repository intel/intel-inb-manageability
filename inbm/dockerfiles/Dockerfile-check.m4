# Copyright (c) 2021-2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# base image with all dependencies for running unit tests/lints
FROM registry.hub.docker.com/library/ubuntu:20.04 AS base
include(`commands.base-setup.m4')


# build a virtual environment for each agent to run checks

# py3 venv
FROM base AS venv-py3
WORKDIR /
RUN python3.12 -m venv /venv-py3
RUN source /venv-py3/bin/activate && \
    pip3.12 install wheel==0.40.0 && \
    pip3.12 install \
        flake8==7.1.1 \
        flake8-commas==4.0.0.dev0 \
        bandit==1.7.3 \
        flake8-bandit==4.1.1 \
        coverage==7.2.5 \
        wemake-python-styleguide \
        teamcity-messages==1.32 \
        pylint==3.2.6 \
        mypy==1.7.1 \
        types-requests==2.31.0.1 \
        types-protobuf==5.26.0.20240422 \
    	pytest==7.4.3 \
        pytest-timeout==2.3.1 \
    	pytest-cov==4.1.0 \
        pytest-mock==3.12.0 \
        pytest-xdist==3.3.1 \
        -U
COPY inbm-lib /src/inbm-lib
ENV PYTHONPATH=/src/inbm-lib
ENV MYPYPATH=/src/inbm-lib
RUN source /venv-py3/bin/activate && \
    pip3.12 install -e /src/inbm-lib && \
    pip3.12 install /src/inbm-lib[test]

FROM venv-py3 AS lint-venv-py3
RUN source /venv-py3/bin/activate && \
    cd /src/inbm-lib && \
    set -o pipefail && \
    flake8 | tee /passed.txt


# ---inbm-lib---

FROM venv-py3 AS mypy-inbm-lib
RUN source /venv-py3/bin/activate && \
    cd /src/inbm-lib && \
    rm -rf build && \
    mypy . && \
    touch /passed.txt

FROM venv-py3 AS test-inbm-lib
WORKDIR /src/inbm-lib
# for unit test
COPY inbm/dispatcher-agent/fpm-template/usr/share/dispatcher-agent/manifest_schema.xsd /src/inbm/dispatcher-agent/fpm-template/usr/share/dispatcher-agent/manifest_schema.xsd 
RUN source /venv-py3/bin/activate && \
    cd /src/inbm-lib && \
    set -o pipefail && \
    mkdir -p /output/coverage && \
    cd tests/unit && \
    pytest --timeout=10 -n 1 --cov=inbm_common_lib --cov-report=term-missing --cov-fail-under=82 inbm_common_lib 2>&1 | tee /output/coverage/inbm-common-lib-coverage.txt && \
    pytest --timeout=10 -n 1 --cov=inbm_lib --cov-report=term-missing --cov-fail-under=82 inbm_lib 2>&1 | tee /output/coverage/inbm-lib-coverage.txt && \
    export PYTHONPATH=$PYTHONPATH:$(pwd) && \
    touch /passed.txt

# ---inbc---

FROM venv-py3 AS venv-inbc-py3
COPY inbc-program/requirements.txt /src/inbc-program/requirements.txt
COPY inbc-program/test-requirements.txt /src/inbc-program/test-requirements.txt
WORKDIR /src/inbc-program
RUN source /venv-py3/bin/activate && \
    pip3.12 install -r requirements.txt && \
    pip3.12 install -r test-requirements.txt
COPY inbc-program /src/inbc-program
COPY inbm/packaging /src/packaging
RUN source /venv-py3/bin/activate && \
    flake8

FROM venv-inbc-py3 AS mypy-inbc
RUN source /venv-py3/bin/activate && \
    mypy inbc && \
    touch /passed.txt

FROM venv-inbc-py3 AS inbc-unit-tests
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    export PYTHONPATH=$PYTHONPATH:$(pwd) && \
    pytest --timeout=10 -n 1 --cov=inbc --cov-report=term-missing --cov-fail-under=84 tests/unit 2>&1 | tee /output/coverage/inbc-coverage.txt

# ---diagnostic agent---

FROM venv-py3 AS venv-diagnostic-py3
COPY inbm/diagnostic-agent/requirements.txt /src/diagnostic-agent/requirements.txt
COPY inbm/diagnostic-agent/test-requirements.txt /src/diagnostic-agent/test-requirements.txt
WORKDIR /src/diagnostic-agent
RUN source /venv-py3/bin/activate && \
    pip3.12 install -r requirements.txt && \
    pip3.12 install -r test-requirements.txt
COPY inbm/diagnostic-agent /src/diagnostic-agent
COPY inbm/packaging /src/packaging
RUN source /venv-py3/bin/activate && \
    flake8

FROM venv-diagnostic-py3 AS mypy-diagnostic
RUN source /venv-py3/bin/activate && \
    mypy diagnostic && \
    touch /passed.txt

FROM venv-diagnostic-py3 AS diagnostic-unit-tests
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    export PYTHONPATH=$PYTHONPATH:$(pwd) && \
    pytest --timeout=10 -n 1 --cov=diagnostic --cov-report=term-missing --cov-fail-under=80 tests/unit 2>&1 | tee /output/coverage/diagnostic-coverage.txt

# ---dispatcher agent---

FROM venv-py3 AS venv-dispatcher-py3
COPY inbm/dispatcher-agent/requirements.txt /src/dispatcher-agent/requirements.txt
COPY inbm/dispatcher-agent/test-requirements.txt /src/dispatcher-agent/test-requirements.txt
WORKDIR /src/dispatcher-agent
RUN source /venv-py3/bin/activate && \
    ln -sf /usr/bin/pip /usr/bin/pip3 && \
    pip3.12 install --upgrade pip && \
    pip3.12 install setuptools-rust && \
    pip3.12 install -r requirements.txt && \
    pip3.12 install -r test-requirements.txt
COPY inbm/dispatcher-agent /src/dispatcher-agent
COPY inbm/packaging /src/packaging
RUN source /venv-py3/bin/activate && \
    flake8

FROM venv-dispatcher-py3 AS mypy-dispatcher
RUN source /venv-py3/bin/activate && \
    mypy dispatcher && \
    mypy tests && \
    touch /passed.txt

FROM venv-dispatcher-py3 AS dispatcher-unit-tests
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    export PYTHONPATH=$PYTHONPATH:$(pwd) && \
    pytest --timeout=10 -n 3 --cov=dispatcher --cov-report=term-missing --cov-fail-under=81 tests/unit 2>&1 | tee /output/coverage/dispatcher-coverage.txt

# ---cloudadapter agent---

FROM venv-py3 AS venv-cloudadapter-py3
COPY inbm/cloudadapter-agent/requirements.txt /src/cloudadapter-agent/requirements.txt
COPY inbm/cloudadapter-agent/test-requirements.txt /src/cloudadapter-agent/test-requirements.txt
WORKDIR /src/cloudadapter-agent
RUN source /venv-py3/bin/activate && \
    pip3.12 install -r requirements.txt && \
    pip3.12 install -r test-requirements.txt
COPY inbm/cloudadapter-agent /src/cloudadapter-agent
COPY inbm/packaging /src/packaging
RUN source /venv-py3/bin/activate && \
    flake8

FROM venv-cloudadapter-py3 AS mypy-cloudadapter
RUN source /venv-py3/bin/activate && \
    mypy cloudadapter && \
    touch /passed.txt

FROM venv-cloudadapter-py3 AS cloudadapter-unit-tests
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    export PYTHONPATH=$PYTHONPATH:$(pwd) && \
    pytest --timeout=10 -n 10 --cov=cloudadapter --cov-report=term-missing --cov-fail-under=90 tests/unit 2>&1 | tee /output/coverage/cloudadapter-coverage.txt

# ---telemetry agent---

FROM venv-py3 AS venv-telemetry-py3
COPY inbm/telemetry-agent/requirements.txt /src/telemetry-agent/requirements.txt
COPY inbm/telemetry-agent/test-requirements.txt /src/telemetry-agent/test-requirements.txt
WORKDIR /src/telemetry-agent
RUN source /venv-py3/bin/activate && \
    pip3.12 install -r requirements.txt && \
    pip3.12 install -r test-requirements.txt
COPY inbm/telemetry-agent /src/telemetry-agent
COPY inbm/packaging /src/packaging
RUN source /venv-py3/bin/activate && \
    flake8

FROM venv-telemetry-py3 AS mypy-telemetry
RUN source /venv-py3/bin/activate && \
    mypy telemetry && \
    touch /passed.txt

FROM venv-telemetry-py3 AS telemetry-unit-tests
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    export PYTHONPATH=$PYTHONPATH:$(pwd) && \
    pytest --timeout=10 -n 1 --cov=telemetry --cov-report=term-missing --cov-fail-under=83 telemetry/tests/unit 2>&1 | tee /output/coverage/telemetry-coverage.txt

# ---configuration agent---

FROM venv-py3 AS venv-configuration-py3
COPY inbm/configuration-agent/requirements.txt /src/configuration-agent/requirements.txt
COPY inbm/configuration-agent/test-requirements.txt /src/configuration-agent/test-requirements.txt
WORKDIR /src/configuration-agent
RUN source /venv-py3/bin/activate && \
    pip3.12 install -r requirements.txt && \
    pip3.12 install -r test-requirements.txt
COPY inbm/configuration-agent /src/configuration-agent
COPY inbm/packaging /src/packaging
RUN source /venv-py3/bin/activate && \
    flake8
    
FROM venv-configuration-py3 AS mypy-configuration
RUN source /venv-py3/bin/activate && \
    mypy configuration && \
    touch /passed.txt

FROM venv-configuration-py3 AS configuration-unit-tests
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    export PYTHONPATH=$PYTHONPATH:$(pwd) && \
    pytest --timeout=10 -n 1 --cov=configuration --cov-report=term-missing --cov-fail-under=88 configuration/tests/unit 2>&1 | tee /output/coverage/configuration-coverage.txt

# output container
FROM base AS output
COPY --from=test-inbm-lib /passed.txt /passed-test-inbm-lib.txt
COPY --from=inbc-unit-tests /output /inbc
COPY --from=diagnostic-unit-tests /output /diagnostic
COPY --from=cloudadapter-unit-tests /output /cloudadapter
COPY --from=dispatcher-unit-tests /output /dispatcher
COPY --from=telemetry-unit-tests /output /telemetry
COPY --from=configuration-unit-tests /output /configuration
COPY --from=test-inbm-lib /output /test-inbm-lib
COPY --from=lint-venv-py3 /passed.txt /passed-lint-inbm-lib.txt
COPY --from=mypy-inbm-lib /passed.txt /passed-mypy-inbm-lib.txt
COPY --from=mypy-dispatcher /passed.txt /passed-mypy-dispatcher.txt
COPY --from=mypy-configuration /passed.txt /passed-mypy-dispatcher.txt
COPY --from=mypy-diagnostic /passed.txt /passed-mypy-diagnostic.txt
COPY --from=mypy-telemetry /passed.txt /passed-mypy-telemetry.txt
COPY --from=mypy-cloudadapter /passed.txt /passed-mypy-cloudadapter.txt
COPY --from=mypy-inbc /passed.txt /passed-mypy-inbc.txt


RUN mkdir -p /output/ && \
    cp -rv \
    /inbc/* \
    /diagnostic/* \
    /cloudadapter/* \
    /dispatcher/* \
    /telemetry/* \
    /configuration/* \
    /output
