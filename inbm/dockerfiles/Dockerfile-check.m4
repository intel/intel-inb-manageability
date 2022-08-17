# base image with all dependencies for running unit tests/lints
FROM registry.hub.docker.com/library/ubuntu:20.04 as base
include(`commands.base-setup.m4')


# build a virtual environment for each agent to run checks

# py3 venv
FROM base as venv-py3
WORKDIR /
RUN python3.8 -m venv /venv-py3
RUN source /venv-py3/bin/activate && \
    pip3 install wheel==0.34.2 && \
    pip3 install \
        nose==1.3.7 \
        flake8==3.7.9 \
        bandit==1.7.2 \
        flake8-bandit==2.1.2 \
        coverage==5.1 \
        flakehell==0.3.0 \
        wemake-python-styleguide==0.14.0 \
        teamcity-messages==1.28 \
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


# ---inbm-lib---

FROM venv-py3 as mypy-inbm-lib
RUN source /venv-py3/bin/activate && \
    cd /src/inbm-lib && \
    rm -rf build && \
    ./mypy-py3.sh . && \
    touch /passed.txt


FROM venv-py3 as test-inbm-lib
WORKDIR /src/inbm-lib
RUN source /venv-py3/bin/activate && \
    cd /src/inbm-lib && \
    set -o pipefail && \
    mkdir -p /output/coverage && \
    cd tests/unit && \
    nosetests --with-coverage --cover-erase --cover-inclusive --cover-package=inbm_common_lib inbm_common_lib 2>&1 | tee /output/coverage/inbm-common-lib-coverage.txt && \
    nosetests --with-coverage --cover-erase --cover-inclusive --cover-package=inbm_lib inbm_lib 2>&1 | tee /output/coverage/inbm-lib-coverage.txt && \
    coverage report --show-missing --fail-under=82 && \
    touch /passed.txt

# ---inbc---

FROM venv-py3 as venv-inbc-py3
COPY inbc-program/requirements.txt /src/inbc-program/requirements.txt
COPY inbc-program/test-requirements.txt /src/inbc-program/test-requirements.txt
WORKDIR /src/inbc-program
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt && \
    pip3.8 install -r test-requirements.txt
COPY inbm/common-python-config /common-python-config
COPY inbc-program /src/inbc-program
COPY inbm/packaging /src/packaging
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
    coverage report --fail-under=84

# ---diagnostic agent---

FROM venv-py3 as venv-diagnostic-py3
COPY inbm/diagnostic-agent/requirements.txt /src/diagnostic-agent/requirements.txt
COPY inbm/diagnostic-agent/test-requirements.txt /src/diagnostic-agent/test-requirements.txt
WORKDIR /src/diagnostic-agent
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt && \
    pip3.8 install -r test-requirements.txt
COPY inbm/common-python-config /common-python-config
COPY inbm/diagnostic-agent /src/diagnostic-agent
COPY inbm/packaging /src/packaging
RUN source /venv-py3/bin/activate && \
    cp -f /common-python-config/pyproject.toml . && \
    flakehell lint

FROM venv-diagnostic-py3 as mypy-diagnostic
COPY inbm/common-python-config /common-python-config/
RUN source /venv-py3/bin/activate && \
    /common-python-config/mypy-py3.sh diagnostic && \
    touch /passed.txt

FROM venv-diagnostic-py3 as diagnostic-unit-tests
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    nosetests --with-coverage --cover-erase --cover-inclusive --cover-package=diagnostic tests/unit 2>&1 | tee /output/coverage/diagnostic-coverage.txt && \
    coverage report --fail-under=80

# ---dispatcher agent---

FROM venv-py3 as venv-dispatcher-py3
COPY inbm/dispatcher-agent/requirements.txt /src/dispatcher-agent/requirements.txt
COPY inbm/dispatcher-agent/test-requirements.txt /src/dispatcher-agent/test-requirements.txt
WORKDIR /src/dispatcher-agent
RUN source /venv-py3/bin/activate && \
    ln -sf /usr/bin/pip /usr/bin/pip3 && \
    pip3.8 install --upgrade pip && \
    pip3.8 install setuptools-rust && \
    pip3.8 install -r requirements.txt && \
    pip3.8 install -r test-requirements.txt
COPY inbm/common-python-config /common-python-config
COPY inbm/dispatcher-agent /src/dispatcher-agent
COPY inbm/packaging /src/packaging
RUN source /venv-py3/bin/activate && \
    cp -f /common-python-config/pyproject.toml . && \
    flakehell lint

FROM venv-dispatcher-py3 as mypy-dispatcher
RUN source /venv-py3/bin/activate && \
    /common-python-config/mypy-py3.sh dispatcher && \
    /common-python-config/mypy-py3.sh tests && \
    touch /passed.txt

FROM venv-dispatcher-py3 as dispatcher-unit-tests
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    nosetests --with-coverage --cover-erase --cover-inclusive --cover-package=dispatcher tests/unit 2>&1 | tee /output/coverage/dispatcher-coverage.txt && \
    coverage report --fail-under=50

# ---cloudadapter agent---

FROM venv-py3 as venv-cloudadapter-py3
COPY inbm/cloudadapter-agent/requirements.txt /src/cloudadapter-agent/requirements.txt
COPY inbm/cloudadapter-agent/test-requirements.txt /src/cloudadapter-agent/test-requirements.txt
WORKDIR /src/cloudadapter-agent
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt && \
    pip3.8 install -r test-requirements.txt
COPY inbm/common-python-config /common-python-config
COPY inbm/cloudadapter-agent /src/cloudadapter-agent
COPY inbm/packaging /src/packaging
RUN source /venv-py3/bin/activate && \
    cp -f /common-python-config/pyproject.toml . && \
    flakehell lint

FROM venv-cloudadapter-py3 as mypy-cloudadapter
RUN source /venv-py3/bin/activate && \
    /common-python-config/mypy-py3.sh cloudadapter && \
    touch /passed.txt

FROM venv-cloudadapter-py3 as cloudadapter-unit-tests
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    nosetests --with-coverage --cover-erase --cover-inclusive --cover-package=cloudadapter tests/unit 2>&1 | tee /output/coverage/cloudadapter-coverage.txt && \
    coverage report --fail-under=90

# ---telemetry agent---

FROM venv-py3 as venv-telemetry-py3
COPY inbm/telemetry-agent/requirements.txt /src/telemetry-agent/requirements.txt
COPY inbm/telemetry-agent/test-requirements.txt /src/telemetry-agent/test-requirements.txt
WORKDIR /src/telemetry-agent
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt && \
    pip3.8 install -r test-requirements.txt
COPY inbm/common-python-config /common-python-config
COPY inbm/telemetry-agent /src/telemetry-agent
COPY inbm/packaging /src/packaging
RUN source /venv-py3/bin/activate && \
    cp -f /common-python-config/pyproject.toml . && \
    flakehell lint

FROM venv-telemetry-py3 as mypy-telemetry
RUN source /venv-py3/bin/activate && \
    /common-python-config/mypy-py3.sh telemetry && \
    touch /passed.txt

FROM venv-telemetry-py3 as telemetry-unit-tests
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    nosetests --with-coverage --cover-erase --cover-inclusive --cover-package=telemetry telemetry/tests/unit 2>&1 | tee /output/coverage/telemetry-coverage.txt && \
    coverage report --fail-under=84

# ---configuration agent---

FROM venv-py3 as venv-configuration-py3
COPY inbm/configuration-agent/requirements.txt /src/configuration-agent/requirements.txt
COPY inbm/configuration-agent/test-requirements.txt /src/configuration-agent/test-requirements.txt
WORKDIR /src/configuration-agent
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt && \
    pip3.8 install -r test-requirements.txt
COPY inbm/common-python-config /common-python-config
COPY inbm/configuration-agent /src/configuration-agent
COPY inbm/packaging /src/packaging
RUN source /venv-py3/bin/activate && \
    cp -f /common-python-config/pyproject.toml . && \
    flakehell lint
    
FROM venv-configuration-py3 as mypy-configuration
RUN source /venv-py3/bin/activate && \
    /common-python-config/mypy-py3.sh configuration && \
    touch /passed.txt

FROM venv-configuration-py3 as configuration-unit-tests
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    nosetests --with-coverage --cover-erase --cover-inclusive --cover-package=configuration configuration/tests/unit 2>&1 | tee /output/coverage/configuration-coverage.txt && \
    coverage report --fail-under=88

# output container
FROM base as output
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
