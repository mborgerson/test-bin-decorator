#!/usr/bin/env python3
import logging
import unittest
import subprocess

import angr

import util_compile_decorator
from util_compile_decorator import compiled, Binary


log = logging.getLogger(__name__)


class BasicTest(unittest.TestCase):
    """Basic test"""

    @compiled('''
        #include <stdio.h>

        void f0(void) { puts("f0"); }
        void f1(void) { puts("f1"); }
        void f2(void) { puts("f2"); }
        void f3(void) { puts("f3"); }

        int main(int argc, char *argv[]) {
            switch (argc) {
            case 0:  f0(); break;
            case 1:  f1(); break;
            case 2:  f2(); break;
            default: f3(); break;
            }
            return 0;
        }
        ''')
    def test_executable(self, binary: Binary):
        subprocess.check_call(['file', binary.path])
        proj = angr.Project(binary.path, auto_load_libs=False)
        print(proj)


if __name__ == '__main__':
    unittest.main()
