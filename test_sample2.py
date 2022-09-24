#!/usr/bin/env python3
import logging
import unittest
import subprocess

import angr

import util_compile_decorator
from util_compile_decorator import compiled, Binary


log = logging.getLogger(__name__)


class BasicTest2(unittest.TestCase):
    """Basic test"""

    @compiled('''
        void f0(void);
        void f1(void);
        void f2(void);
        void f3(void);

        int call_function(int v) {
            switch (v) {
            case 0:  f0(); break;
            case 1:  f1(); break;
            case 2:  f2(); break;
            default: f3(); break;
            }
            return 0;
        }
        ''', compile_without_linking=True)
    def test_object(self, binary: Binary):
        subprocess.check_call(['file', binary.path])
        proj = angr.Project(binary.path, auto_load_libs=False)
        print(proj)


if __name__ == '__main__':
    unittest.main()
