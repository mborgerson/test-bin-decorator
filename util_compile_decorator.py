"""
Utilities to parameterize tests with source code compiled with different tools, architectures, and compilation flags.
"""

import hashlib
import itertools
import logging
import os

from typing import Iterator, Sequence, Any, Optional
from dataclasses import dataclass


log = logging.getLogger(__name__)
binaries_dir = os.path.join('.', 'binaries')


def gen_hash_str(hashable):
    r = repr(hashable)
    return hashlib.md5(r.encode('utf-8')).hexdigest()


@dataclass
class Source:
    """Container for input source text"""
    text: str

    @property
    def path(self) -> str:
        return f's_{gen_hash_str(self.text)}.c'

    def __repr__(self) -> str:
        return f"Source(path='{self.path}')"


@dataclass
class Binary:
    """Container for generated binary"""
    src: Source
    arch: str
    tool: 'Tool'
    cmd: str
    path: str


class Tool:
    """Container for tool that processes input source to generate binary"""

    def gen_binaries(self, src: Source, **kwargs) -> Iterator[Binary]:
        """Generate Binary objects for this tool given parameters"""

    @staticmethod
    def gen_output_path(hashable: Any) -> str:
        return os.path.join(binaries_dir, 'b_' + gen_hash_str(hashable))


class ClangTool(Tool):
    """Clang compiler"""
    name = 'clang'
    arch_to_clang = {
        'x86':    'clang',
        'x86_64': 'clang',
    }
    archs = list(sorted(arch_to_clang.keys()))

    def gen_binaries(self,
                     src: Source,
                     clang_archs: Optional[Sequence[str]] = None,
                     clang_opt_levels: Optional[Sequence[str]] = None,
                     **kwargs) -> Iterator[Binary]:
        """Generate Binary objects for this tool given parameters"""
        if clang_archs is None:
            clang_archs = self.archs
        if clang_opt_levels is None:
            clang_opt_levels = ['-Og', '-Os', '-O1', '-O2', '-O3']
        arch_cflags = {
            'x86': ['-m32']
        }
        extra_cflags = ['-Wall']
        if kwargs.get('compile_without_linking', False):
            extra_cflags.append('-c')
            output_ext = '.o'
        else:
            output_ext = ''

        for arch in clang_archs:
            for opt in clang_opt_levels:
                cflags = arch_cflags.get(arch, []) + [opt] + extra_cflags
                path = self.gen_output_path((arch, opt, src.path)) + output_ext
                cmd = [self.arch_to_clang[arch], '-o', path] + cflags + [src.path]
                yield Binary(src, arch, self, cmd, path)


class GccTool(Tool):
    """GCC compiler"""
    name = 'gcc'
    arch_to_gcc = {
        'x86':       'gcc',
        'x86_64':    'gcc',
        'aarch64':   'aarch64-linux-gnu-gcc',
        'arm':       'arm-linux-gnueabi-gcc',
        'mips':      'mips-linux-gnu-gcc',
        'mips64':    'mips64-linux-gnuabi64-gcc',
        'mipsel':    'mipsel-linux-gnu-gcc',
        'powerpc':   'powerpc-linux-gnu-gcc',
        'powerpc64': 'powerpc64-linux-gnu-gcc',
        's390x':     's390x-linux-gnu-gcc',

        # FIXME: Automatic object load for these architectures before making test default
        # 'alpha':     'alpha-linux-gnu-gcc',
        # 'hppa':      'hppa-linux-gnu-gcc',
        # 'm68k':      'm68k-linux-gnu-gcc',
        # 'riscv64':   'riscv64-linux-gnu-gcc',
        # 'sh4':       'sh4-linux-gnu-gcc',
        # 'sparc64':   'sparc64-linux-gnu-gcc',

        # arch_avr
        # arch_soot
    }
    archs = list(sorted(arch_to_gcc.keys()))

    def gen_binaries(self,
                     src: Source,
                     gcc_archs: Optional[Sequence[str]] = None,
                     gcc_opt_levels: Optional[Sequence[str]] = None,
                     **kwargs) -> Iterator[Binary]:
        """Generate Binary objects for this tool given parameters"""
        if gcc_archs is None:
            gcc_archs = self.archs
        if gcc_opt_levels is None:
            gcc_opt_levels = ['-Og', '-Os', '-O1', '-O2', '-O3']
        arch_cflags = {
            'x86': ['-m32']
        }
        extra_cflags = ['-Wall']
        if kwargs.get('compile_without_linking', False):
            extra_cflags.append('-c')
            output_ext = '.o'
        else:
            output_ext = ''

        for arch in gcc_archs:
            for opt in gcc_opt_levels:
                cflags = arch_cflags.get(arch, []) + [opt] + extra_cflags
                path = self.gen_output_path((arch, opt, src.path)) + output_ext
                cmd = [self.arch_to_gcc[arch], '-o', path] + cflags + [src.path]
                yield Binary(src, arch, self, cmd, path)


class MsvcTool(Tool):
    """MSVC compiler"""
    name = 'msvc'
    archs = ['x86', 'x86_64']

    def gen_binaries(self,
                     src: Source,
                     msvc_archs: Optional[Sequence[str]] = None,
                     msvc_opt_levels: Optional[Sequence[str]] = None,
                     **kwargs) -> Iterator[Binary]:
        """Generate Binary objects for this tool given parameters"""
        if msvc_archs is None:
            msvc_archs = self.archs
        if msvc_opt_levels is None:
            msvc_opt_levels = ['/Od', '/O1', '/O2']
        extra_cflags = []
        if kwargs.get('compile_without_linking', False):
            extra_cflags.append('/c')
            output_ext = '.obj'
            output_switch = '/Fo'
        else:
            output_ext = '.exe'
            output_switch = '/Fe:'

        for arch in msvc_archs:
            assert arch in self.archs
            for opt in msvc_opt_levels:
                cflags = [opt] + extra_cflags
                path = self.gen_output_path((arch, opt, src.path)) + output_ext
                cmd = ['cl.exe', output_switch + path] + cflags + [src.path]
                yield Binary(src, arch, self, cmd, path)


clang = ClangTool()
gcc = GccTool()
msvc = MsvcTool()
all_tools = [clang, gcc, msvc]
all_binaries = []


def compiled(text: str, tools: Optional[Sequence[Tool]] = None, **kwargs):
    """
    Decorator to parameterize a test with source code compiled using different tools, targeting multiple architectures
    with different compilation flags.

    When used to decorate a function, the decorator input argument `text` is processed with the set of `tools` to
    produce a number of different binaries. The function being decorated is replaced with a wrapper function that runs
    the test, as a subtest, on each binary produced by the tools. The prototype of the test function is expected to be
    of the form:

        def testcase(self, binary: Binary):
            ...

    The path to the binary to be tested is accessible through the `binary.path` property.

    Setup options
    -------------
    :param text:  Source code.
    :param tools: List of tools to process `text` with to produce binaries.

    Available tools are listed in this module under `all_tools`. There are general options that apply to all tools, and
    tool-specific options available.

    General options
    ---------------
    :param bool compile_without_linking: Compile only an object file, do not link to create an executable.

    Tool-specific options
    ---------------------
    Each tool supports a number of CPU architectures. See tool `archs` property for list of supported architectures.
    By default, all supported architectures will be targeted. You may specify a subset of architectures to build for
    with one of the following keyword arguments.

    :param Optional[Sequence[str]] msvc_archs   Target architectures for MSVC.
    :param Optional[Sequence[str]] clang_archs: Target architectures for Clang.
    :param Optional[Sequence[str]] gcc_archs:   Target architectures for GCC.
    """
    if tools is None:
        tools = all_tools
    src = Source(text)
    def make_decorator(inner):
        binaries = list(itertools.chain.from_iterable(t.gen_binaries(src, **kwargs) for t in tools))
        all_binaries.extend(binaries)
        def outer(self):
            for binary in binaries:
                with self.subTest(binary=binary):
                    log.info('Running test %s with binary %s', inner.__name__, binary)
                    if not os.path.exists(binary.path):
                        raise FileNotFoundError('Binary not available for testing')
                    inner(self, binary)
        return outer
    return make_decorator
