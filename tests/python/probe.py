#!/usr/bin/env python

import unittest
import subprocess


class TestProbe(unittest.TestCase):

    def run_test(self, cmd, expected):
        p = subprocess.Popen(
            [cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertRegexpMatches(p.stdout.readline(), expected)

    def test_kprobe(self):
        cmd = """test=kprobe; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
		'kprobe:do_nanosleep { printf(\"SUCCESS '$test' %d\\n\", pid); exit(); }' \
		 | grep '^SUCCESS '$test' [0-9][0-9]*$' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "^(SUCCESS kprobe) [0-9][0-9]*$")

        cmd = """test=pid; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
		'k:do_nanosleep { printf(\"SUCCESS '$test' %d\\n\", pid); exit(); }' \
		 | grep '^SUCCESS '$test' [0-9][0-9]*$' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "^(SUCCESS pid) [0-9][0-9]*$")

        cmd = """test=pid; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
        'kprobe:syscalls:sys_exit_nanosleep { printf(\"SUCCESS '$test' %d\\n\", pid); exit(); }' \
         | grep 'kprobes should not have a target' || echo "FAILURE $test"
        """
        self.run_test(cmd, "kprobes should not have a target")

    def test_kretprobe(self):
        cmd = """test=kretprobe; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
		'kretprobe:do_nanosleep { printf(\"SUCCESS '$test' %d\\n\", pid); exit(); }' \
		 | grep '^SUCCESS '$test' [0-9][0-9]*$' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "^(SUCCESS kretprobe) [0-9][0-9]*$")

        cmd = """test=kr; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
		'kr:do_nanosleep { printf(\"SUCCESS '$test' %d\\n\", pid); exit(); }' \
		 | grep '^SUCCESS '$test' [0-9][0-9]*$' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "^(SUCCESS kr) [0-9][0-9]*$")

        cmd = """test=pid; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
        'kretprobe:syscalls:sys_exit_nanosleep { printf(\"SUCCESS '$test' %d\\n\", pid); exit(); }' \
         | grep 'kprobes should not have a target' || echo "FAILURE $test"
        """
        self.run_test(cmd, "kprobes should not have a target")

    def test_uprobe(self):
        cmd = """test=uprobe; sleep 1 && ./exe & ../.././build-release/src/bpftrace -e \
        'uprobe:./exe:somefunc {printf("a: %d, b: %d", arg0, arg1); exit();}' \
        | grep 'a: 10, b: 20' || echo "FAILURE $test"
        """
        self.run_test(cmd, "a: 10, b: 20")

    def test_uretprobe(self):
        cmd = """test=uretprobe; sleep 1 && ./exe & ../.././build-release/src/bpftrace -e \
        'uretprobe:./exe:somefunc {printf("ret: %d", retval); exit();} ' \
        | grep 'ret: 30' || echo "FAILURE $test"
        """
        self.run_test(cmd, "ret: 30")

    def test_tracepoint(self):
        cmd = """test=tra; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
		'tracepoint:syscalls:sys_exit_nanosleep { printf(\"SUCCESS '$test' %d\\n\", gid); exit(); }' \
		 | grep '^SUCCESS '$test' [0-9][0-9]*$' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "^(SUCCESS tra) [0-9][0-9]*$")

        cmd = """test=t; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
		't:syscalls:sys_exit_nanosleep { printf(\"SUCCESS '$test' %d\\n\", gid); exit(); }' \
		 | grep '^SUCCESS '$test' [0-9][0-9]*$' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "^(SUCCESS t) [0-9][0-9]*$")

    def test_profile(self):
        cmd = """test=profile; ../.././build-release/src/bpftrace -e \
		'profile:hz:99 { @[tid] = count(); exit();}' \
		 | grep '\\@\\[[0-9]*\\]\\:\\s[0-9]' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "\\@\\[[0-9]*\\]\\:\\s[0-9]")

        cmd = """test=p; ../.././build-release/src/bpftrace -e \
		'p:hz:99 { @[tid] = count(); exit();}' \
		 | grep '\\@\\[[0-9]*\\]\\:\\s[0-9]' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "\\@\\[[0-9]*\\]\\:\\s[0-9]")

        cmd = """test=p_int; ../.././build-release/src/bpftrace -e \
		'p:ms:nan { @[tid] = count(); exit();}' \
		 | grep 'profile probe must have an integer frequency' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "profile probe must have an integer frequency")

        cmd = """test=p_time; ../.././build-release/src/bpftrace -e \
		'p:unit { @[tid] = count(); exit();}' \
		 | grep 'profile probe must have unit of time' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "profile probe must have unit of time")

    def test_interval(self):
        cmd = """test=interval; ../.././build-release/src/bpftrace -e \
		't:raw_syscalls:sys_enter { @syscalls = count(); } interval:s:1 { print(@syscalls);\
		 clear(@syscalls); exit();}' | grep '\\@syscalls\\:\\s[0-9]*' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "\\@syscalls\\:\\s[0-9]*")

        cmd = """test=i; ../.././build-release/src/bpftrace -e \
		't:raw_syscalls:sys_enter { @syscalls = count(); } i:s:1 { print(@syscalls);\
		 clear(@syscalls); exit();}' | grep '\\@syscalls\\:\\s[0-9]*' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "\\@syscalls\\:\\s[0-9]*")

        cmd = """test=i_freq; ../.././build-release/src/bpftrace -e \
		't:raw_syscalls:sys_enter { @syscalls = count(); } interval:ms:nan { print(@syscalls);\
		 clear(@syscalls); exit();}' | grep 'interval probe must have an integer frequency'\
          || echo "FAILURE $test"
		"""
        self.run_test(cmd, "interval probe must have an integer frequency")

        cmd = """test=i_time; ../.././build-release/src/bpftrace -e \
		't:raw_syscalls:sys_enter { @syscalls = count(); } interval:s { print(@syscalls);\
		 clear(@syscalls); exit();}' | grep 'interval probe must have unit of time' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "interval probe must have unit of time")

    def test_software(self):
        cmd = """test=software; ../.././build-release/src/bpftrace -e \
		'software:faults:100 { @[comm] = count(); exit();}'\
		 | grep '@\\[' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "@\\[.+\\]\\:\\s[0-9]+")

    def test_hardware(self):
        cmd = """test=hardware; ../.././build-release/src/bpftrace -e \
		'hardware:cache-misses:1000000 { @[pid] = count(); exit(); } i:ms:2000{exit();}'\
		 | grep '\\@\\[[0-9]*\\]\\:\\s[0-9]*' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "\\@\\[[0-9]*\\]\\:\\s[0-9]")


if __name__ == "__main__":
    unittest.main()
