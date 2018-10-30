#!/bin/bash
cd ./tests/python

# read an argument to run a specific test file
# no argument to run the entire test suite
if [ -z "$1" ]; then
    sudo python -m unittest discover --pattern=*.py
else
    sudo python $1
fi
