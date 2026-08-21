#!/bin/sh
# tests/fxstore_repro.sh — M3 reproducibility test (bwrap-FREE).
# Usage: tests/fxstore_repro.sh ./fxstore
#
# Proves the fix for the .git-in-hash reproducibility bug: the store path of a
# package must be a pure function of SOURCE CONTENT, independent of git/checkout
# state and committed build artifacts.  Builds two source trees with IDENTICAL
# content but DIFFERENT .git state (and a fake committed artifact) and asserts:
#   1. both produce the SAME <64hex>-probe store path  (git-state-independence)
#   2. the clean-source artifact <STORE>/<64hex>-probe-src exists and contains
#      NO .git and NO committed artifact  (clean-copy materialization)
#
# Uses pure-FS recipes (Touch only, no Shell/Run) so no bwrap/stage3 sandbox is
# needed — runs everywhere, exactly like the golden lib/app worked example.
set -eu

FX="${1:-./fxstore/fxstore}"
FX="$(cd "$(dirname "$FX")" && pwd)/$(basename "$FX")"
WORK="$(mktemp -d /tmp/fxstore-repro.XXXXXX)"
STORE="$WORK/store"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

# --- two identical-content source trees, different .git state + a committed artifact ---
for base in "$WORK/A" "$WORK/B"; do
    mkdir -p "$base/proj/src/.git"
    echo "hello from probe" > "$base/proj/src/hello.txt"
    # a fake COMMITTED build artifact — must NOT enter the clean hash/copy
    printf 'not a real binary' > "$base/proj/src/app.com"
done
# different .git internals (the reproducibility crux)
echo "ref A" > "$WORK/A/proj/src/.git/HEAD"
echo "ref B" > "$WORK/B/proj/src/.git/HEAD"
echo "extra-object" > "$WORK/B/proj/src/.git/objects"

# --- one package-set.dhall per tree, single package name="probe" ---
mkpset() {
    cat > "$1" <<EOF
let Action = < Shell : Text | Copy : { from : Text, to : Text } | Mkdir : Text | Rm : Text | Touch : Text | Move : { from : Text, to : Text } | Symlink : { from : Text, to : Text } | Chmod : { path : Text, mode : Text } | Echo : Text | Env : { key : Text, value : Text } | Run : { argv : List Text } >
let Src = < Path : Text | Fetch : { url : Text, hash : Text } >
let Build = { target : Text, recipe : List Action }
let Package = { name : Text, version : Text, src : Src, deps : List Text, build : Build }
let PackageSet = { packages : List Package }
in  { packages = [ { name = "probe", version = "1.0.0", src = < Path = "$2" >, deps = [] : List Text, build = { target = "out.txt", recipe = [ < Touch = "out.txt" > ] } } ] } : PackageSet
EOF
}
mkpset "$WORK/A/package-set.dhall" "$WORK/A/proj/src"
mkpset "$WORK/B/package-set.dhall" "$WORK/B/proj/src"

# --- build both ---
PA="$(cd "$WORK/A" && "$FX" build --store "$WORK/storeA" probe 2>&1 | sed -n 's/.*built .*\//built /p' | tail -n1)"
PB="$(cd "$WORK/B" && "$FX" build --store "$WORK/storeB" probe 2>&1 | sed -n 's/.*built .*\//built /p' | tail -n1)"
[ -n "$PA" ] || fail "tree A produced no store path"
[ -n "$PB" ] || fail "tree B produced no store path"
ok "tree A built: $PA"
ok "tree B built: $PB"

# --- 1. git-state independence ---
[ "$PA" = "$PB" ] || fail "store paths differ across .git states (A=$PA B=$PB) — NOT reproducible"
ok "identical store path across differing .git state (git-state independent)"

# --- 2. clean-copy materialization: <hex>-probe-src has no .git / committed artifact ---
SRCDIR="$(find "$WORK/storeA" -maxdepth 1 -type d -name '*-probe-src' | head -n1)"
[ -n "$SRCDIR" ] || fail "clean-source artifact <hex>-probe-src missing in storeA"
[ -f "$SRCDIR/hello.txt" ] || fail "clean source lost hello.txt"
if ls -a "$SRCDIR" | grep -qE '^\.git$' || [ -e "$SRCDIR/app.com" ]; then
    fail "clean source contains .git or committed artifact"
fi
ok "clean-source artifact <hex>-probe-src present; no .git / committed artifact"

echo "ALL FXSTORE REPRO TESTS PASSED"
