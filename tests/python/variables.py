#!/usr/bin/env python

import unittest
import subprocess


class TestVariables(unittest.TestCase):

    def run_test(self, cmd, expected):
        p = subprocess.Popen(
            [cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertRegexpMatches(p.stdout.readline(), expected)

    def test_global_int(self):
        cmd = """test=global_int; ../.././build-release/src/bpftrace -e \
		'i:ms:1{@a = 10; printf("%d\\n", @a); exit();}' \
		 | grep '@a: 10' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "@a: 10")

    def test_global_string(self):
        cmd = """test=global_string; ../.././build-release/src/bpftrace -e \
		'i:ms:1{@a = "hi"; printf("%s\\n", @a); exit();}' \
		 | grep '@a: hi' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "@a: hi")

    def test_local_int(self):
        cmd = """test=local_int; ../.././build-release/src/bpftrace -e \
		'i:ms:1 {$a = 10; printf("a=%d\\n", $a); exit();}' \
		 | grep 'a=10' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "a=10")

    def test_local_string(self):
        cmd = """test=local_string; ../.././build-release/src/bpftrace -e \
		'i:ms:1 {$a = "hi"; printf("a=%s\\n", $a); exit();}' \
		 | grep 'a=hi' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "a=hi")

    def test_global_associative_arrays(self):
        cmd = """test=global_arrays; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
		'kprobe:do_nanosleep { @start[tid] = nsecs; } kretprobe:do_nanosleep /@start[tid] != 0/ \
        { printf("slept for %d ms\\n", (nsecs - @start[tid]) / 1000000); delete(@start[tid]); exit();}' \
		 | grep '@start\\[[0-9]' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "@start\\[[0-9]+\\]\\:\\s[0-9]+")

    def test_scratch(self):
        cmd = """test=scratch; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
		'kprobe:do_nanosleep { @start[tid] = nsecs; } kretprobe:do_nanosleep /@start[tid] != 0/ \
        { $delta = nsecs - @start[tid]; printf("slept for %d ms\\n", $delta / 1000000); delete(@start[tid]); exit(); }' \
		 | grep '@start\\[[0-9]' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "@start\\[[0-9]+\\]\\:\\s[0-9]+")


if __name__ == "__main__":
    unittest.main()
