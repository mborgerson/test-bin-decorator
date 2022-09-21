#!/usr/bin/env python3
"""
Test suite to parameterize over binaries compiled with various tools for multiple architectures from same source code.
"""

import argparse
import hashlib
import itertools
import logging
import os
import subprocess
import sys
import unittest

from typing import Iterator, Sequence, Any, Optional
from dataclasses import dataclass


log = logging.getLogger(__name__)
root_dir = os.path.dirname(os.path.realpath(__file__))
binaries_dir = os.path.join(root_dir, 'binaries')


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


class GccTool(Tool):
    """GCC compiler"""
    name = 'gcc'
    arch_to_gcc = {
        'x86':       'gcc',
        'x86_64':    'gcc',
        'aarch64':   'aarch64-linux-gnu-gcc',
        'alpha':     'alpha-linux-gnu-gcc',
        'arm':       'arm-linux-gnueabi-gcc',
        'hppa':      'hppa-linux-gnu-gcc',
        'm68k':      'm68k-linux-gnu-gcc',
        'mips':      'mips-linux-gnu-gcc',
        'mips64':    'mips64-linux-gnuabi64-gcc',
        'mipsel':    'mipsel-linux-gnu-gcc',
        'powerpc':   'powerpc-linux-gnu-gcc',
        'powerpc64': 'powerpc64-linux-gnu-gcc',
        'riscv64':   'riscv64-linux-gnu-gcc',
        's390x':     's390x-linux-gnu-gcc',
        'sh4':       'sh4-linux-gnu-gcc',
        'sparc64':   'sparc64-linux-gnu-gcc',
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
            gcc_opt_levels = ['-Og', '-O1', '-O2', '-O3']
        arch_cflags = {
            'x86': ['-m32']
        }
        extra_cflags = ['-Wall']
        for arch in gcc_archs:
            for opt in gcc_opt_levels:
                cflags = arch_cflags.get(arch, []) + [opt] + extra_cflags
                path = self.gen_output_path((arch, opt, src.path))
                cmd = [self.arch_to_gcc[arch], '-o', path] + cflags + [src.path]
                yield Binary(src, arch, self, cmd, path)


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
            clang_opt_levels = ['-Og', '-O1', '-O2', '-O3']
        arch_cflags = {
            'x86': ['-m32']
        }
        extra_cflags = ['-Wall']
        for arch in clang_archs:
            for opt in clang_opt_levels:
                cflags = arch_cflags.get(arch, []) + [opt] + extra_cflags
                path = self.gen_output_path((arch, opt, src.path))
                cmd = [self.arch_to_clang[arch], '-o', path] + cflags + [src.path]
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
        for arch in msvc_archs:
            assert arch in self.archs
            for opt in msvc_opt_levels:
                cflags = [opt] + extra_cflags
                path = self.gen_output_path((arch, opt, src.path)) + '.exe'
                cmd = ['cl.exe', '/Fe:' + path] + cflags + [src.path]
                yield Binary(src, arch, self, cmd, path)


gcc = GccTool()
clang = ClangTool()
msvc = MsvcTool()
all_tools = [gcc, clang, msvc]
all_binaries = []


def compiled(text: str, tools: Optional[Sequence[Tool]] = None, **kwargs):
    """Test case decorator to parameterize a test over generated binaries"""
    if tools is None:
        tools = all_tools
    src = Source(text)
    def make_decorator(inner):
        binaries = list(itertools.chain.from_iterable(t.gen_binaries(src, **kwargs) for t in tools))
        all_binaries.extend(binaries)
        def outer(self):
            for binary in binaries:
                with self.subTest(binary=binary):
                    if not os.path.exists(binary.path):
                        raise FileNotFoundError('Binary not available for testing')
                    inner(binary)
        return outer
    return make_decorator


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'build':
        logging.basicConfig(level=logging.INFO)
        log.setLevel(logging.INFO)

        ap = argparse.ArgumentParser()
        ap.add_argument('--tool', nargs='*')
        ap.add_argument('--arch', nargs='*')
        args = ap.parse_args(sys.argv[2:])

        if args.tool:
            unknown_tools = set(args.tool).difference({t.name for t in all_tools})
            if len(unknown_tools):
                log.error('Unknown tool(s): %s', unknown_tools)
                sys.exit(1)
            selected_tools = {t for t in all_tools if t.name in args.tool}
        else:
            selected_tools = all_tools

        all_archs = set(itertools.chain(t.archs for t in all_tools))
        if args.arch:
            unknown_archs = set(args.arch).difference(all_archs)
            if len(unknown_archs):
                log.error('Unknown arch(s): %s', unknown_archs)
                sys.exit(1)
            selected_archs = args.arch
        else:
            selected_archs = all_archs

        os.makedirs(binaries_dir, exist_ok=True)

        for binary in all_binaries:
            if binary.tool not in selected_tools or binary.arch not in selected_archs:
                continue

            if not os.path.exists(binary.src.path):
                with open(binary.src.path, 'w', encoding='utf-8') as f:
                    f.write(binary.src.text)

            if not os.path.exists(binary.path):
                log.info('Running: %s', ' '.join(binary.cmd))
                subprocess.check_call(binary.cmd)
                assert os.path.exists(binary.path)

    else:
        # Run tests
        unittest.main()


if __name__ == '__main__':
    main()
