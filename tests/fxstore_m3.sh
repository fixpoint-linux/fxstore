#!/bin/sh
# tests/fxstore_m3.sh — M3 self-hosting golden test.
# Usage: tests/fxstore_m3.sh ./fxstore
#
# Exercises the M3 self-hosting package set (fxstore/m3/package-set.dhall):
# builds the two cheapest leaf packages (dafsa, dhall-c) into a temp store
# under the REAL bwrap + palisade stage3 sandbox, and asserts the artifacts
# land as content-addressed store paths and are executable.
#
# The leaf packages were chosen (not visage/compendium/dhake) so the test
# runs fast: dafsa and dhall-c are dependency-free cosmocc-only builds (a
# single compile each), whereas visage pulls in mbedtls + datalog-dafsa and
# takes minutes.  The FULL closure (all 6) is exercised manually / optionally
# via `fxstore build --store ...` in fxstore/m3.
#
# The sandboxed build needs bwrap + stage3 (as in fxstore_sandboxed.sh part B).
# If bwrap cannot actually sandbox on this host (e.g. an outer sandbox whose
# seccomp blocks userns setup), this test LOUDLY SKIPS with the probe's error —
# it does not falsely pass or silently degrade.
set -eu

FX="${1:-./fxstore/fxstore}"
# Resolve to an absolute path: the test cds into fxstore/m3 later.
FX="$(cd "$(dirname "$FX")" && pwd)/$(basename "$FX")"
WORK="$(mktemp -d /tmp/fxstore-m3.XXXXXX)"
STORE="$WORK/store"
M3DIR="$(cd "$(dirname "$FX")/m3" && pwd)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

# --- the M3 package set must exist ---
[ -f "$M3DIR/package-set.dhall" ] || fail "m3/package-set.dhall missing"
ok "m3/package-set.dhall present"

# --- gate: can we actually sandbox here? (mirror fxstore_sandboxed.sh part B) ---
if ! command -v bwrap >/dev/null 2>&1; then
    echo "SKIP: bwrap not found — cannot exercise the sandboxed M3 build"
    exit 0
fi
# Probe the real stack: if bwrap is present but cannot sandbox (userns setup
# blocked, e.g. inside another sandbox), skip loudly rather than fail the build.
PROBE_ERR="$WORK/probe.err"
if ! bwrap --unshare-all --ro-bind / / --ro-bind /usr /usr --dev /dev \
           --proc /proc --tmpfs /tmp \
           -- /bin/sh -c 'exit 0' >"$PROBE_ERR" 2>&1; then
    echo "SKIP: bwrap cannot sandbox on this host (probe: $(head -n1 "$PROBE_ERR"))"
    echo "      (e.g. inside another sandbox whose seccomp blocks userns setup)"
    exit 0
fi

# --- build the two leaf packages (dafsa, dhall-c) ---
BUILD="$WORK/build.out"
(cd "$M3DIR" && "$FX" build --store "$STORE" dafsa dhall-c) \
    >"$BUILD" 2>"$WORK/build.err"
[ -s "$BUILD" ] || fail "build produced no output (stderr: $(cat "$WORK/build.err"))"

# --- assert content-addressed store paths for both ---
for name in dafsa dhall-c; do
    if ! grep -qE "^fxstore: built ${STORE}/[0-9a-f]{64}-${name}\$" "$BUILD"; then
        fail "build log lacks a <64hex>-<name> store path for '$name': $(cat "$BUILD")"
    fi
done
ok "build emits <64hex>-<name> store paths for dafsa + dhall-c"

# --- assert the artifacts exist and are executable ---
DAFSADIR="$(find "$STORE" -maxdepth 1 -type d -name '*-dafsa' | head -n1)"
DHALLDIR="$(find "$STORE" -maxdepth 1 -type d -name '*-dhall-c' | head -n1)"
[ -n "$DAFSADIR" ] || fail "dafsa store dir missing"
[ -n "$DHALLDIR" ] || fail "dhall-c store dir missing"
[ -f "$DAFSADIR/dafsa" ] && [ -x "$DAFSADIR/dafsa" ] || fail "dafsa artifact not an executable"
[ -f "$DHALLDIR/dhall.com" ] && [ -x "$DHALLDIR/dhall.com" ] || fail "dhall.com artifact not an executable"
ok "dafsa/dafsa + dhall-c/dhall.com are executable store artifacts"

# --- no NON-HERMETIC fallback: the build must have gone through bwrap ---
if grep -qiE "non-hermetic|bwrap not found|unsandboxed" "$WORK/build.err" "$BUILD"; then
    fail "M3 build fell back to the NON-HERMETIC path (bwrap should be present)"
fi
ok "build was hermetic (no non-hermetic fallback under real bwrap)"

echo "ALL FXSTORE M3 TESTS PASSED"
