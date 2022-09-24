#!/usr/bin/env python3
import argparse
import itertools
import logging
import os
import subprocess
import sys
import unittest
import json

from util_compile_decorator import all_binaries, all_tools, Source, Binary


log = logging.getLogger(__name__)
root_dir = os.path.dirname(os.path.realpath(__file__))
binaries_dir = os.path.join(root_dir, 'binaries')


def main():
    global all_binaries
    logging.basicConfig(level=logging.INFO)

    ap = argparse.ArgumentParser()
    ap.add_argument('--tool', nargs='*', help='Tools to filter-in, or all tools if not specified')
    ap.add_argument('--arch', nargs='*', help='Archs to filter-in, or all archs if not specified')
    ap.add_argument('--discover', action='store_true', help='Discover test cases and build manifest of binaries')
    ap.add_argument('--save', metavar='MANIFEST', help='Save manifest of binaries')
    ap.add_argument('--load', metavar='MANIFEST', help='Load manifest of binaries')
    ap.add_argument('--build', action='store_true', help='Compile binaries (filtered by tool, arch)')
    ap.add_argument('--check', action='store_true', help='Check if all binaries are available')
    args = ap.parse_args()

    name_to_tool = {t.name: t for t in all_tools}

    # Discover all tests, importing test modules and populating `all_binaries` global with set of binaries to target
    if args.discover:
        log.info('Discovering tests...')
        unittest.TestLoader().discover(root_dir)
        log.info('Discovered %d binary definitions', len(all_binaries))

    if args.save:
        log.info('Saving binary manifest...')
        with open(args.save, 'w', encoding='utf-8') as f:
            json.dump({
                'sources': list({b.src.text for b in all_binaries}),
                'binaries': [{'src': b.src.path, 'arch': b.arch, 'tool': b.tool.name, 'cmd': b.cmd, 'path': b.path}
                             for b in all_binaries]
                }, f, indent=2)
            log.info('Saved %d binary definitions', len(all_binaries))

    if args.load:
        log.info('Loading binary manifest...')
        with open(args.load, 'r', encoding='utf-8') as f:
            serialized = json.load(f)
            path_to_src = {s.path: s for s in [Source(text=text) for text in serialized['sources']]}
            all_binaries = [Binary(src=path_to_src[b['src']],
                                   arch=b['arch'],
                                   tool=name_to_tool[b['tool']],
                                   cmd=b['cmd'],
                                   path=b['path']) for b in serialized['binaries']]
            log.info('Loaded %d binary definitions', len(all_binaries))

    # Filter by selected tools
    if args.tool:
        unknown_tools = set(args.tool).difference({t.name for t in all_tools})
        if len(unknown_tools):
            log.error('Unknown tool(s): %s', unknown_tools)
            sys.exit(1)
        selected_tools = {t for t in all_tools if t.name in args.tool}
    else:
        selected_tools = all_tools

    # Filter by selected architectures
    all_archs = set(itertools.chain.from_iterable(t.archs for t in all_tools))
    if args.arch:
        unknown_archs = set(args.arch).difference(all_archs)
        if len(unknown_archs):
            log.error('Unknown arch(s): %s', unknown_archs)
            sys.exit(1)
        selected_archs = args.arch
    else:
        selected_archs = all_archs

    # Build
    if args.build:
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

    # Check if all binaries are available
    if args.check:
        all_available = True
        for binary in all_binaries:
            if binary.tool not in selected_tools or binary.arch not in selected_archs:
                continue
            if not os.path.exists(binary.path):
                log.info('Binary %s is not available', binary)
                all_available = False
        if not all_available:
            sys.exit(1)


if __name__ == '__main__':
    main()
