.PHONY: tests # `make tests` doesn't run because of the tests directory
PROGRAM=inbc
COMMAND_TO_TRIGGER=sota
LOCAL_PIP_PATH=$(shell python3 -m site --user-site)

init: init_script init_tests

init_script:
	@echo INSTALLING SCRIPT REQUIREMENTS
	pip3 install -r requirements.txt --user

init_tests:
	@echo INSTALLING UNIT TEST REQUIREMENTS
	pip3 install -r test-requirements.txt --user

run:
	sudo PYTHONPATH=$(LOCAL_PIP_PATH) python3 -m $(PROGRAM).$(PROGRAM) $(COMMAND_TO_TRIGGER)

tests:
	PYTHONPATH="${PYTHONPATH}:$(shell pwd):$(shell pwd)/../inbm-lib" PYTHONDONTWRITEBYTECODE=x pytest --cov=$(PROGRAM) --cov-report=term-missing tests/unit

deb-eval-py3:
	./package-py3.sh deb EVAL

rpm-ehl-py3:
	./package-py3.sh rpm EHL
