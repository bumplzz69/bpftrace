#!/usr/bin/env python

import unittest
import subprocess


class TestCall(unittest.TestCase):

    def run_test(self, cmd, expected):
        p = subprocess.Popen(
            [cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertRegexpMatches(p.stdout.readline(), expected)

    def test_printf(self):
        cmd = """test=printf; ../.././build-release/src/bpftrace -e \
		'i:ms:1 { printf(\"hi\\n\"); exit();}' \
		 | grep 'hi' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "hi")

        cmd = """test=printf_value; ../.././build-release/src/bpftrace -e \
		'i:ms:1 { printf(\"value: %d\\n\", 100); exit();}' \
		 | grep 'value: 100' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "value: 100")

    def test_time(self):
        cmd = """test=time; ../.././build-release/src/bpftrace -e \
		'i:ms:1 { time(\"%H:%M:%S\\n\"); exit();}' \
		 | grep '[0-9]*:[0-9]*' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "[0-9]+:[0-9]+:[0-9]+")

        cmd = """test=time_2; ../.././build-release/src/bpftrace -e \
		'i:ms:1 { time(\"%H-%M:\\n\"); exit();}' \
		 | grep '[0-9]*-[0-9]*' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "[0-9]+-[0-9]+")

    def test_join(self):
        cmd = """test=join; ../.././build-release/src/bpftrace -e \
		'i:ms:1 { system("echo 'A'"); } kprobe:sys_execve { join(arg1); exit();}' \
		 | grep 'echo A' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "echo A")

    def test_str(self):
        cmd = """test=str; ../.././build-release/src/bpftrace -e \
		'i:ms:1{ system(\"echo 10\"); } kprobe:sys_execve { printf(\"P: %s\\n\", str(arg0)); exit();}' \
		 | grep 'P: /bin/sh' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "P: /bin/sh")

    def test_sym(self):
        cmd = """test=sym; sleep 1 & sleep 15 & ../.././build-release/src/bpftrace -e \
		'kprobe:do_nanosleep { printf(\"%s\\n\", sym(reg(\"ip\"))); exit();}' \
		 | grep 'do_nanosleep' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "do_nanosleep")

    def test_system(self):
        cmd = """test=system; ../.././build-release/src/bpftrace -e \
		'i:ms:1 { system(\"echo 'ok_system'\"); exit();}' \
		 | grep 'ok_system' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "ok_system")

    def test_count(self):
        cmd = """test=count; ../.././build-release/src/bpftrace -e \
		'i:ms:100 { @[sym(reg(\"ip\"))] = count(); exit();}' \
		 | grep '@\\[[0-9]*\\]\\:\\s[0-9]*' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "@\\[[0-9]+\\]\\:\\s[0-9]+")

    def test_sum(self):
        cmd = """test=sum; ../.././build-release/src/bpftrace -e \
	    ' kprobe:vfs_read { @bytes[comm] = sum(arg2); exit();}' \
		 | grep '@[a-Z]*\\[[a-Z]*' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "@.+\\[.+\\]\\:\\s[0-9]+")

    def test_avg(self):
        cmd = """test=avg; ../.././build-release/src/bpftrace -e \
	    ' kprobe:vfs_read { @bytes[comm] = avg(arg2); exit();}' \
		 | grep '@[a-Z]*\\[[a-Z]*' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "@.+\\[.+\\]\\:\\s[0-9]+")

    def test_min(self):
        cmd = """test=min; ../.././build-release/src/bpftrace -e \
	    ' kprobe:vfs_read { @bytes[comm] = min(arg2); exit();}' \
		 | grep '@[a-Z]*\\[[a-Z]*' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "@.+\\[.+\\]\\:\\s[0-9]+")

    def test_max(self):
        cmd = """test=min; ../.././build-release/src/bpftrace -e \
	    ' kprobe:vfs_read { @bytes[comm] = max(arg2); exit();}' \
		 | grep '@[a-Z]*\\[[a-Z]*' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "@.+\\[.+\\]\\:\\s[0-9]+")

    def test_stats(self):
        cmd = """test=stats; ../.././build-release/src/bpftrace -e \
	    ' kprobe:vfs_read { @bytes[comm] = stats(arg2); exit();}' \
		 | grep '@[a-Z]*\\[[a-Z]*' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "@.+\\[.+\\]\\:\\scount\\s[0-9]+\\,\\saverage\\s[0-9]+\\,\\stotal\\s[0-9]+")

    def test_hist(self):
        cmd = """test=hist; ../.././build-release/src/bpftrace -e \
	    ' kretprobe:vfs_read { @bytes = hist(retval); exit();}' \
		 | grep '@bytes:' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "@bytes:")

        cmd = """test=hist2; ../.././build-release/src/bpftrace -e \
	    ' kretprobe:vfs_read { @bytes = hist(retval); exit();}' \
		 | grep '\\[[a-zA-Z0-9_]*\\,\\s[a-zA-Z0-9_]*' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "\\[.+\\,\\s.+\\]?\\)?\\s")


    def test_lhist(self):
        cmd = """test=lhist; ../.././build-release/src/bpftrace -e \
	    ' kretprobe:vfs_read { @bytes = lhist(retval, 0, 10000, 1000); exit()}' \
		 | grep '@bytes:' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "@bytes:")

        cmd = """test=lhist2; ../.././build-release/src/bpftrace -e \
	     ' kretprobe:vfs_read { @bytes = lhist(retval, 0, 10000, 1000); exit()}' \
		 | grep '\\[[a-zA-Z0-9_]*\\,\\s[a-zA-Z0-9_]*' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "\\[.+\\,\\s.+\\]?\\)?\\s")


if __name__ == "__main__":
    unittest.main()
