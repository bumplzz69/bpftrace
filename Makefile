#!/bin/bash

DEFAULT_PATH = ../../build-release/src/bpftrace

test-runtime:
	gcc -o tests/python/pro.exe tests/python/pro.c
ifeq ("$(BPFTRACE_RUNTIME)","")
	export BPFTRACE_RUNTIME=$(DEFAULT_PATH); \
	cd tests/python; \
	python -m unittest discover --pattern=*.py
else
	cd tests/python; \
	python -m unittest discover --pattern=*.py
endif
