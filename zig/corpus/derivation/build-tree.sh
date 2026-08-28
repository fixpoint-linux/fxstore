#!/bin/sh
# Canonical U2 fixture-tree definition (mirrored byte-for-byte by the Zig test
# helper build_fixture_tree in zig/src/derivation.zig).  Goldens in
# zig/corpus/derivation/golden.txt come from running the C implementation
# against THIS tree.
set -e
root="$1"
rm -rf "$root"
mkdir -p "$root"

w() { printf '%s' "$2" > "$root/$1"; }               # w <rel> <content>
wd() { mkdir -p "$root/$1"; }                        # wd <dir>

wd .cache;              w .cache/c 'cache
'
wd .git;                w .git/config 'gitconfig
'
w .ape-obj 'ape prefix file
'
w .gitignore '*.o
'
w .hidden 'hidden content
'
w .o 'exactly dot o
'
wd .py-site;            w .py-site/s 's
'
w Makefile 'all:
	echo hi
'; chmod 755 "$root/Makefile"
w README.md '# fixture
'
wd __pycache__;         w __pycache__/p.pyc 'pyc
'
w app.elf 'elf
'
ln -s no-such-target "$root/broken"
wd build;               w build/out.bin 'binary
'
wd build-tmp;           w build-tmp/t 't
'
w debug.dbg 'dbg
'
wd dl-test-sandbox;     w dl-test-sandbox/x 'x
'
wd doc;                 w doc/note.txt 'doc note
'
wd docs;                w docs/keep.txt 'docs keep
'
wd docs/cache;          w docs/cache/c.txt 'cache
'
w lib.a 'ar
'
ln -s README.md "$root/link"
w mod.wasm 'wasm
'
wd objects;             w objects/foo.o 'obj
'; w objects/keep.o.txt 'not an object
'
w plugin.so 'so
'
w prog.com 'com
'
wd pydl;                w pydl/d 'd
'
w setuid-src 's
'; chmod 4755 "$root/setuid-src"
wd sub;                 w sub/.git 'gitdir: /real/git
'; w sub/nested.txt 'nested
'
wd sub/deeper;          w sub/deeper/deep.txt 'deep
'
