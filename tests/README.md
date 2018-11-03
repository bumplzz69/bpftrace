# BPFtrace Tests

There is 2 test suite in the project.

## Unit test

These tests can be run with the `bpftrace_test` executable.

The code generation tests are based on the output of LLVM 5, so may give errors if run with different version. They can be excluded by running:

`bpftrace_test --gtest_filter=-codegen*`

## Runtime

  Runtime tests will call bpftrace executable.
  * Default: `make test-runtime`
  * Change path to bpftrace executable provisorily: `make test_runtime DEFAULT_PATH=path/to/bpftrace`
  * Change path to bpftrace executable permanently: Edit the `/etc/environment` file by adding the variable `BPFTRACE_PATH=path/to/bpftrace` then run `make test-runtime`
