# Copyright (C) 2017-2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

.PHONY: tests # `make tests` doesn't run because of the tests directory
AGENT=dispatcher
LOGGING_INI=/etc/intel-manageability/public/$(AGENT)-agent/logging.ini

LOCAL_PIP_PATH=$(shell python3 -m site --user-site)

init: init_script init_tests init_copy

init_script:
	@echo INSTALLING SCRIPT REQUIREMENTS
	pip3 install -r requirements.txt --user

init_tests:
	@echo INSTALLING UNIT TEST REQUIREMENTS
	pip3 install -r test-requirements.txt --user

init_copy:
	@echo COPYING REQUIRED FILES
	sudo cp -r ./fpm-template$(LOGGING_INI) $(LOGGING_INI)
	sudo cp -r ./fpm-template/usr /usr

logging:
	if ! [[ "$(LEVEL)" =~ ^(ERROR|DEBUG|INFO)$$ ]]; then exit 1; fi;
	sudo sed -i "s/level=\(DEBUG\|ERROR\|INFO\)/level=$(LEVEL)/g" "$(LOGGING_INI)"
	@echo Agent logging level now: $(LEVEL)

run:
	sudo MQTT_HOST=localhost MQTT_CA_CERTS=/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt \
	PYTHONDONTWRITEBYTECODE=x PYTHONPATH=$(LOCAL_PIP_PATH) python3 -m $(AGENT).$(AGENT)

tests:
	PYTHONPATH="${PYTHONPATH}:$(shell pwd):$(shell pwd)/../../inbm-lib" PYTHONDONTWRITEBYTECODE=x pytest -n 3 --cov=$(AGENT) --cov-report=term-missing tests/unit

deb-eval-py3:
	./package-py3.sh deb EVAL

rpm-ehl-py3:
	./package-py3.sh rpm EHL
