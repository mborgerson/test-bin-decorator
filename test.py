import logging
import unittest
import subprocess

from util_compile_decorator import compiled, main, Binary


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
    def test_demo(self, binary: Binary):
        path = binary.path
        subprocess.check_call(['file', path])
        import angr
        proj = angr.Project(path, auto_load_libs=False)
        print(proj)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
