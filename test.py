import logging
import unittest
# import angr
from compile_decorator import compiled, main, Binary
import subprocess

log = logging.getLogger(__name__)


class BasicTest(unittest.TestCase):
    """
    Basic test.
    """

    @compiled('''
    #include <stdio.h>

    void f0(void) { puts("f0"); }
    void f1(void) { puts("f1"); }
    void f2(void) { puts("f2"); }
    void f3(void) { puts("f3"); }

    int main(int argc, char *argv[]) {
        switch (argc) {
        case 0: f0(); break;
        case 1: f1(); break;
        case 2: f2(); break;
        default: f3(); break;
        }
        return 0;
    }
    ''')
    def test_demo(binary: Binary):
        log.info('Testing %s', binary)
        path = binary.path
        subprocess.check_call(['file', path])
        # angr.Project(binary.path, auto_load_libs=False)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
