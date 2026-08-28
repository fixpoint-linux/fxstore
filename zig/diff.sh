#!/bin/sh
# zig/diff.sh — U6 differential harness (THE FINAL GATE).
#
# Runs the C oracle (./fxstore, cosmocc-built) and the Zig port
# (./zig-out/bin/fxstore) over an IDENTICAL corpus of commands — each phase
# starting from a FRESH project/store at the SAME absolute paths (wiped
# between phases, so store paths printed into stdout match byte-for-byte) —
# and byte-compares stdout, stderr, exit code, and the resulting project +
# store trees.
#
# SEQUENTIAL by construction (one binary after the other, never parallel):
# dl_open holds a process-lifetime fcntl F_SETLK single-writer lock.
#
# Recipes in the corpus are the init scaffold's Touch/Echo only — in-process
# actions, no child processes — so C stdio buffering cannot reorder output
# between the two implementations.
#
# Usage: sh zig/diff.sh            (from the repo root, after `zig build`)
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd)
C_BIN="$REPO/fxstore"
Z_BIN="$REPO/zig-out/bin/fxstore"
WORK=/tmp/fxstore-diff-work

fail() { echo "diff.sh: $*" >&2; exit 2; }

[ -x "$C_BIN" ] || fail "C oracle not found/runnable at $C_BIN (build with ./dhake/dhake.com)"
[ -x "$Z_BIN" ] || fail "Zig binary not found at $Z_BIN (run: zig build)"

"$C_BIN" --help >/dev/null 2>&1 || fail "C oracle does not run (--help failed)"
"$Z_BIN" --help >/dev/null 2>&1 || fail "Zig binary does not run (--help failed)"

# run_corpus <binary> <results-dir>: the whole corpus, fresh state.
run_corpus() {
    bin="$1"
    out="$2"
    rm -rf "$WORK"
    mkdir -p "$WORK" "$out" "$WORK/proj2"
    : >"$WORK/afile"    # init target that is a FILE (mkdir EEXIST + not-dir)

    i=0
    # run <label> <cwd> [args...] — captures out/err/rc per command
    run() {
        i=$((i + 1))
        label="$1"
        cwd="$2"
        shift 2
        (cd "$cwd" && "$bin" "$@" \
            >"$out/$label.out" 2>"$out/$label.err"; echo $? >"$out/$label.rc")
    }

    # -- top-level CLI surface (no project needed) --
    run 001help      "$WORK" --help
    run 002h         "$WORK" -h
    run 003noargs    "$WORK"
    run 004unknown   "$WORK" bogus
    run 005init      "$WORK" init "$WORK/proj"
    run 006reinit    "$WORK" init "$WORK/proj"
    run 007initdot   "$WORK/proj2" init .
    run 008initfile  "$WORK" init "$WORK/afile"

    # -- the build/query/gc/timeline/rollback flow (cwd = scaffolded proj) --
    run 010buildapp   "$WORK/proj" build --store "$WORK/store" app
    run 011buildall   "$WORK/proj" build --store "$WORK/store"
    run 012queryapp   "$WORK/proj" query app --store "$WORK/store"
    run 013querylib   "$WORK/proj" query lib "--store=$WORK/store"
    run 014timeline   "$WORK/proj" timeline --store "$WORK/store"
    run 015rollback   "$WORK/proj" rollback 1 --store "$WORK/store"
    run 016gclib      "$WORK/proj" gc lib --store "$WORK/store"
    run 017gcretain   "$WORK/proj" gc --retain 1 --store "$WORK/store"
    run 018rollbackh  "$WORK/proj" rollback --hard 1 --store "$WORK/store"

    # -- error surfaces (exact messages + rc 0/1/2) --
    run 020querybad    "$WORK/proj" query nosuchpkg --store "$WORK/store"
    run 021querynone   "$WORK/proj" query
    run 022querytwo    "$WORK/proj" query a b
    run 023buildnostore "$WORK/proj" build --store
    run 024gcnone      "$WORK/proj" gc
    run 025gctworoots  "$WORK/proj" gc a b
    run 026rbadtxt     "$WORK/proj" rollback xyz
    run 027rbadzero    "$WORK/proj" rollback 0
    run 028rbadneg     "$WORK/proj" rollback -- -1
    run 029rbadbig     "$WORK/proj" rollback 4294967296
    run 030tlextra     "$WORK/proj" timeline extra --store "$WORK/store"
    run 031nops        "$WORK" query app --store "$WORK/store"   # no package-set.dhall here
    run 032badpset     "$WORK/proj2" query app --store "$WORK/store"  # init-dot pset is fine; use a broken one below

    # a malformed package-set: point a fresh dir at garbage
    mkdir -p "$WORK/badproj"
    echo "this is : not : valid dhall ]" >"$WORK/badproj/package-set.dhall"
    run 033badpset  "$WORK/badproj" query app --store "$WORK/store"

    # -- final state of the world: tree shapes + file contents + hashes --
    # (.db contents are engine-internal mmap/WAL pages; layout listing only)
    (cd "$WORK" && find proj proj2 badproj store -name .db -prune -o -printf '%m %y %p\n' 2>/dev/null | sort) \
        >"$out/900tree.txt"
    (cd "$WORK" && find proj proj2 badproj store -name .db -prune -o -type f -print0 2>/dev/null \
        | sort -z | xargs -0 sha256sum 2>/dev/null) >"$out/901hashes.txt"
    (cd "$WORK" && find store/.db -type f 2>/dev/null | sort) >"$out/902dbfiles.txt"
}

echo "== phase 1/2: C oracle =="
run_corpus "$C_BIN" /tmp/fxstore-diff-c

echo "== phase 2/2: Zig port =="
run_corpus "$Z_BIN" /tmp/fxstore-diff-z

echo "== comparing =="
if diff -r /tmp/fxstore-diff-c /tmp/fxstore-diff-z >/tmp/fxstore-diff-report.txt 2>&1; then
    n=$(ls /tmp/fxstore-diff-c | wc -l)
    echo "DIFF PASS: $n captured streams (out/err/rc per command) + tree/hashes identical."
    exit 0
else
    echo "DIFF FAIL — first differences:"
    head -60 /tmp/fxstore-diff-report.txt
    echo "full report: /tmp/fxstore-diff-report.txt"
    exit 1
fi
