#!/usr/bin/env python

import unittest
import subprocess


class TestOther(unittest.TestCase):

    def run_test(self, cmd, expected):
        p = subprocess.Popen(
            [cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertRegexpMatches(p.stdout.readline(), expected)

    def test_if(self):
        cmd = """test=if; ../.././build-release/src/bpftrace -e \
		'i:ms:1{$a = 10; if ($a > 2) { $a = 20 }; printf("a=%d\\n", $a); exit();}' \
		 | grep 'a=20' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "a=20")

        cmd = """test=if; ../.././build-release/src/bpftrace -e \
		'i:ms:1{$a = 10; if ($a < 2) { $a = 20 }; printf("a=%d\\n", $a); exit();}' \
		 | grep 'a=10' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "a=10")

    def test_ifelse(self):
        cmd = """test=ifelse; ../.././build-release/src/bpftrace -e \
		'i:ms:1{$a = ""; if (10 < 2) { $a = "hi" } else {$a = "hello"}; printf("a=%s\\n", $a); exit();}' \
		 | grep 'a=hello' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "a=hello")

        cmd = """test=ifelse; ../.././build-release/src/bpftrace -e \
		'i:ms:1{$a = ""; if (10 > 2) { $a = "hi" } else {$a = "hello"}; printf("a=%s\\n", $a); exit();}' \
		 | grep 'a=hi' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "a=hi")

    def test_unroll(self):
        cmd = """test=unroll; ../.././build-release/src/bpftrace -e \
		'i:ms:1{$a = 1; unroll (10) { $a = $a + 2; }; printf("a=%d\\n", $a); exit();}' \
		 | grep 'a=21' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "a=21")

        cmd = """test=unroll_max; ../.././build-release/src/bpftrace -e \
		'i:ms:1{$a = 1; unroll (30) { $a = $a + 2; }; printf("a=%d\\n", $a); exit();}' \
		 | grep 'unroll maximum value is 20' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "unroll maximum value is 20")

        cmd = """test=unroll_min; ../.././build-release/src/bpftrace -e \
		'i:ms:1{$a = 1; unroll (0) { $a = $a + 2; }; printf("a=%d\\n", $a); exit();}' \
		 | grep 'unroll minimum value is 1' || echo "FAILURE $test"
		"""
        self.run_test(cmd, "unroll minimum value is 1")


if __name__ == "__main__":
    unittest.main()
