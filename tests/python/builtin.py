#!/usr/bin/env python

import unittest
import subprocess


class TestBuiltin(unittest.TestCase):

    def run_test(self, cmd, expected):
        p = subprocess.Popen(
            [cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertRegexpMatches(p.stdout.readline(), expected)

    def test_pid(self):
        cmd = """test=pid; ../.././build-release/src/bpftrace -e \
		'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", pid); exit(); }' \
		 | grep '^SUCCESS '$test' [0-9][0-9]*$' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "^(SUCCESS pid) [0-9][0-9]*$")

    def test_tid(self):
        cmd = """test=tid; ../.././build-release/src/bpftrace -e \
		'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", tid); exit(); }' \
		 | grep '^SUCCESS '$test' [0-9][0-9]*$' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "^(SUCCESS tid) [0-9][0-9]*$")

    def test_uid(self):
        cmd = """test=uid; ../.././build-release/src/bpftrace -e \
        'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", uid); exit(); }' \
         | grep '^SUCCESS '$test' [0-9][0-9]*$' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS uid) [0-9][0-9]*$")

    def test_gid(self):
        cmd = """test=gid; ../.././build-release/src/bpftrace -e \
        'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", gid); exit(); }' \
         | grep '^SUCCESS '$test' [0-9][0-9]*$' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS gid) [0-9][0-9]*$")

    def test_nsecs(self):
        cmd = """test=nsecs; ../.././build-release/src/bpftrace -e \
        'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", nsecs); exit(); }' \
         | grep '^SUCCESS '$test' -\\?[0-9][0-9]*$' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS nsecs) -?[0-9]+")

    def test_cpu(self):
        cmd = """test=cpu; ../.././build-release/src/bpftrace -e \
        'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", cpu); exit(); }' \
         | grep '^SUCCESS '$test' [0-9][0-9]*$' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS cpu) [0-9][0-9]*$")

    def test_comm(self):
        cmd = """test=comm; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
        'k:do_nanosleep { printf(\"SUCCESS '$test' %s\\n\", comm); exit(); }' \
         | grep '^SUCCESS '$test' [a-z][a-z]*$' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS comm) [a-z][a-z]*$")

    def test_stack(self):
            # grep does not work with mutiple lines
        cmd = """test=stack; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
        'k:do_nanosleep { printf(\"SUCCESS '$test' %s\\n\", stack); exit(); }' \
         | grep '^SUCCESS '$test' \\n*' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS stack)")

    def test_ustack(self):
            # ustack - grep does not work with mutiple lines
        cmd = """test=ustack; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
        'k:do_nanosleep { printf(\"SUCCESS '$test' %s\\n\", ustack); exit(); }' \
         | grep '^SUCCESS '$test' \\n*' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS ustack)")

    def test_arg(self):
        cmd = """test=arg0; ../.././build-release/src/bpftrace -e \
        'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", arg0); exit(); }' \
         | grep '^SUCCESS '$test' -\\?[0-9][0-9]*$' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS arg0) -?[0-9][0-9]*$")

    def test_retval(self):
        cmd = """test=retval; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
        'k:do_nanosleep { printf(\"SUCCESS '$test' %d\\n\", retval); exit(); }' \
         | grep '^SUCCESS '$test' [0-9][0-9]*$' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS retval) [0-9][0-9]*$")

    def test_func(self):
        cmd = """test=func; ../.././build-release/src/bpftrace -e \
        'i:ms:1 { printf(\"SUCCESS '$test' %s\\n\", func); exit(); }' \
         | grep '^SUCCESS '$test' [a-z][a-z]*$' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS func) [a-z][a-z]*$")

    def test_username(self):
        cmd = """test=username; ../.././build-release/src/bpftrace -e \
        'i:ms:1 { printf(\"SUCCESS '$test' %s\\n\", username); exit(); }' \
         | grep '^SUCCESS '$test' [a-z][a-z]*$' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS username) [a-z][a-z]*$")

    def test_probe(self):
        cmd = """test=probe; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
        'k:do_nanosleep { printf(\"SUCCESS '$test' %s\\n\", probe); exit(); }' \
         | grep '^SUCCESS '$test' kprobe:do_nanosleep' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS probe kprobe:do_nanosleep)")

    def test_curtask(self):
            # curtask TODO: sometimes the task is negative. Should it happen?
        cmd = """test=curtask; ../.././build-release/src/bpftrace -e \
        'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", curtask); exit(); }' \
         | grep '^SUCCESS '$test' -\\?[0-9][0-9]*$' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS curtask) -?[0-9]+")

    def test_rand(self):
        cmd = """test=rand; ../.././build-release/src/bpftrace -e \
        'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", rand); exit(); }' \
         | grep '^SUCCESS '$test' -\\?[0-9][0-9]*$' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS rand) -?[0-9][0-9]*$")

    def test_cgroup(self):
            #cgroup - TODO: not working
        cmd = """test=cgroup; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
        'i:ms:1 { printf(\"SUCCESS '$test' %d\\n\", cgroup); exit(); }' \
         | grep '^SUCCESS '$test' -\\?[0-9][0-9]*$' || echo "FAILURE $test"
        """
        self.run_test(cmd, "^(SUCCESS cgroup) -?[0-9]+")


if __name__ == "__main__":
    unittest.main()
