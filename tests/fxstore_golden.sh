#!/bin/sh
# tests/fxstore_golden.sh — U6 golden test for the fxstore CLI.
# Usage: tests/fxstore_golden.sh ./fxstore/fxstore
#
# Exercises: `init` scaffolding, `build` of a worked example (lib -> app)
# into a temp store with content-addressed <hex64>-<name> store paths,
# `query` closure reporting, and `gc <root>` pruning an orphan while keeping
# everything reachable from the root.
set -eu

FX="${1:-./fxstore/fxstore}"
# Resolve to an absolute path: the test cds into a temp project dir later,
# so a relative FX would break.
FX="$(cd "$(dirname "$FX")" && pwd)/$(basename "$FX")"
WORK="$(mktemp -d /tmp/fxstore-golden.XXXXXX)"
STORE="$WORK/store"
PROJ="$WORK/proj"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

# --- init scaffolds a worked-example project ---
"$FX" init "$PROJ" >/dev/null
[ -f "$PROJ/package-set.dhall" ] || fail "init did not create package-set.dhall"
[ -d "$PROJ/src/lib" ] && [ -d "$PROJ/src/app" ] || fail "init did not create source dirs"
ok "init scaffolds package-set.dhall + src/{lib,app}"

# --- build the worked example (root=app => closure {lib, app}) ---
BUILD="$WORK/build.out"
(cd "$PROJ" && "$FX" build --store "$STORE" app) >"$BUILD" 2>"$WORK/build.err"
[ -s "$BUILD" ] || fail "build produced no output (stderr: $(cat "$WORK/build.err"))"
for name in lib app; do
    if ! grep -qE "^fxstore: built ${STORE}/[0-9a-f]{64}-${name}\$" "$BUILD"; then
        fail "build log lacks a <64hex>-<name> store path for '$name': $(cat "$BUILD")"
    fi
done
ok "build emits <64hex>-<name> store paths for lib + app"

# --- content store dirs exist and hold the recipe output ---
LIBDIR="$(find "$STORE" -maxdepth 1 -type d -name '*-lib' | head -n1)"
APPDIR="$(find "$STORE" -maxdepth 1 -type d -name '*-app' | head -n1)"
[ -n "$LIBDIR" ] || fail "lib store dir missing"
[ -n "$APPDIR" ] || fail "app store dir missing"
[ -f "$LIBDIR/lib.txt" ] || fail "lib recipe did not produce lib.txt"
[ -f "$APPDIR/app.txt" ] || fail "app recipe did not produce app.txt"
ok "content store dirs created and hold recipe output"

# --- build scratch area is a SIBLING of the store, emptied on success ---
# (the scratch dir must live outside the store: run_sandboxed ro-binds the
# whole store, and a rw workdir nested under that ro bind is unmountable)
[ -d "$STORE.build" ] || fail "build scratch dir '$STORE.build' missing"
[ ! -e "$STORE/.tmp" ] || fail "legacy scratch '$STORE/.tmp' was created"
if [ -n "$(ls -A "$STORE.build")" ]; then
    fail "build scratch dir not emptied after successful builds: $(ls -A "$STORE.build")"
fi
ok "build scratch lives in '$STORE.build' (outside the store), empty after build"

# --- query returns the closure + the root's store path ---
QOUT="$(cd "$PROJ" && "$FX" query app --store "$STORE")"
echo "$QOUT" | grep -q '  lib'   || fail "query closure lacks lib: $QOUT"
echo "$QOUT" | grep -q '  app'   || fail "query closure lacks app: $QOUT"
echo "$QOUT" | grep -qE "${STORE}/[0-9a-f]{64}-app" || fail "query lacks app store path: $QOUT"
ok "query app returns closure {lib, app} + its store path"

# --- gc <root> prunes an orphan, keeps everything reachable from the root ---
STRAY_HEX="$(printf 'a%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 \
                      17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 \
                      33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 \
                      49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64)"
STRAY="$STORE/${STRAY_HEX}-stray"
mkdir -p "$STRAY"
: > "$STRAY/x"
(cd "$PROJ" && "$FX" gc app --store "$STORE") >/dev/null
[ ! -e "$STRAY" ] || fail "gc did not remove the orphan store dir"
[ -d "$LIBDIR" ] || fail "gc removed live lib dir"
[ -d "$APPDIR" ] || fail "gc removed live app dir"
ok "gc app prunes the orphan, keeps lib + app"

echo "ALL FXSTORE GOLDEN TESTS PASSED"
