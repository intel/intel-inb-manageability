.PHONY: tests # `make tests` doesn't run because of the tests directory
AGENT=node

LOCAL_PIP_PATH=$(shell python3 -m site --user-site)

init: init_script init_tests 

init_script:
	@echo INSTALLING SCRIPT REQUIREMENTS
	pip3 install -r requirements.txt --user

init_tests:
	@echo INSTALLING UNIT TEST REQUIREMENTS
	pip3 install -r test-requirements.txt --user

run:
	sudo MQTT_HOST=localhost MQTT_CA_CERTS=/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt \
        PYTHONDONTWRITEBYTECODE=x PYTHONPATH=$(LOCAL_PIP_PATH) python3 -m $(AGENT).$(AGENT)

tests:
	PYTHONDONTWRITEBYTECODE=x nosetests --with-coverage --cover-erase --cover-inclusive --cover-html --cover-package=$(AGENT)

deb-eval-py3:
	./package-py3.sh deb EVAL

rpm-kmb-py3:
	./package-py3.sh rpm KMB
