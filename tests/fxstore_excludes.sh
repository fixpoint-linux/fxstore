#!/bin/sh
# tests/fxstore_excludes.sh — per-package excludes + mode-bits preservation (bwrap-FREE).
# Usage: tests/fxstore_excludes.sh ./fxstore
#
# Proves two clean-source refinements on top of fxstore_repro.sh:
#   1. PER-PACKAGE EXCLUDES: an excluded RELATIVE subtree is
#      (a) HASH-INDEPENDENT — two trees identical except for excluded content
#          produce the SAME store path; and
#      (b) OMITTED from the clean-copy artifact (<hex>-<name>-src), which
#          otherwise keeps un-excluded content.
#   2. MODE-BITS PRESERVATION: the clean copy of a checked-in executable script
#      keeps its exec bit, and a 0600 source file is not widened.
# Also re-checks BACKWARD COMPAT: a package-set WITHOUT the `excludes` field
# (the pre-refinement schema) still loads and builds unchanged.
#
# Pure-FS recipes (Touch only) — no bwrap/stage3 needed; runs everywhere.
set -eu

FX="${1:-./fxstore/fxstore}"
FX="$(cd "$(dirname "$FX")" && pwd)/$(basename "$FX")"
WORK="$(mktemp -d /tmp/fxstore-excludes.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

# ─── 1. per-package excludes: hash-independence + clean-copy omission ─────────
# two identical trees except the EXCLUDED subtree differs
for base in X Y; do
    mkdir -p "$WORK/$base/src/keep" "$WORK/$base/src/models"
    echo "source" > "$WORK/$base/src/keep/main.c"
done
echo "weights-A" > "$WORK/X/src/models/embed.gguf"
echo "weights-B-different" > "$WORK/Y/src/models/embed.gguf"

mkpset_excl() {  # $1=pset path  $2=src path
    cat > "$1" <<EOF
let Action = < Shell : Text | Copy : { from : Text, to : Text } | Mkdir : Text | Rm : Text | Touch : Text | Move : { from : Text, to : Text } | Symlink : { from : Text, to : Text } | Chmod : { path : Text, mode : Text } | Echo : Text | Env : { key : Text, value : Text } | Run : { argv : List Text } >
let Src = < Path : Text | Fetch : { url : Text, hash : Text } >
let Build = { target : Text, recipe : List Action }
let Package = { name : Text, version : Text, src : Src, deps : List Text, excludes : List Text, build : Build }
let PackageSet = { packages : List Package }
in  { packages = [ { name = "excl", version = "1.0.0", src = < Path = "$2" >, deps = [] : List Text, excludes = [ "models" ], build = { target = "out.txt", recipe = [ < Touch = "out.txt" > ] } } ] } : PackageSet
EOF
}
mkpset_excl "$WORK/X/package-set.dhall" "$WORK/X/src"
mkpset_excl "$WORK/Y/package-set.dhall" "$WORK/Y/src"

PX="$(cd "$WORK/X" && "$FX" build --store "$WORK/storeX" excl 2>&1 | sed -n 's/.*built .*\//built /p' | tail -n1)"
PY="$(cd "$WORK/Y" && "$FX" build --store "$WORK/storeY" excl 2>&1 | sed -n 's/.*built .*\//built /p' | tail -n1)"
[ -n "$PX" ] && [ -n "$PY" ] || fail "excludes build produced no store path (X='$PX' Y='$PY')"
[ "$PX" = "$PY" ] || fail "excluded-content change altered store path (X=$PX Y=$PY) — NOT hash-independent"
ok "excluded subtree difference -> SAME store path (excludes are hash-independent)"

SRCDIR="$(find "$WORK/storeX" -maxdepth 1 -type d -name '*-excl-src' | head -n1)"
[ -n "$SRCDIR" ] || fail "clean-source artifact <hex>-excl-src missing"
[ -f "$SRCDIR/keep/main.c" ] || fail "clean copy lost un-excluded content keep/main.c"
if [ -e "$SRCDIR/models" ]; then fail "excluded subtree 'models' present in clean copy"; fi
ok "clean copy omits excluded subtree, retains un-excluded content"

# ─── 2. mode-bits preservation: exec bit kept, 0600 not widened ───────────────
mkdir -p "$WORK/B/src"
printf '#!/bin/sh\necho hi\n' > "$WORK/B/src/run.sh"
chmod 0755 "$WORK/B/src/run.sh"        # checked-in executable script
printf 's3cr3t\n' > "$WORK/B/src/secret.txt"
chmod 0600 "$WORK/B/src/secret.txt"

mkpset_plain() {  # NO excludes field — pre-refinement schema (backward compat)
    cat > "$1" <<EOF
let Action = < Shell : Text | Copy : { from : Text, to : Text } | Mkdir : Text | Rm : Text | Touch : Text | Move : { from : Text, to : Text } | Symlink : { from : Text, to : Text } | Chmod : { path : Text, mode : Text } | Echo : Text | Env : { key : Text, value : Text } | Run : { argv : List Text } >
let Src = < Path : Text | Fetch : { url : Text, hash : Text } >
let Build = { target : Text, recipe : List Action }
let Package = { name : Text, version : Text, src : Src, deps : List Text, build : Build }
let PackageSet = { packages : List Package }
in  { packages = [ { name = "mode", version = "1.0.0", src = < Path = "$2" >, deps = [] : List Text, build = { target = "out.txt", recipe = [ < Touch = "out.txt" > ] } } ] } : PackageSet
EOF
}
mkpset_plain "$WORK/B/package-set.dhall" "$WORK/B/src"
PB="$(cd "$WORK/B" && "$FX" build --store "$WORK/storeB" mode 2>&1 | sed -n 's/.*built .*\//built /p' | tail -n1)"
[ -n "$PB" ] || fail "backward-compat (no-excludes) build produced no store path"
ok "backward compat: package-set WITHOUT excludes field loads & builds"

BINSRC="$(find "$WORK/storeB" -maxdepth 1 -type d -name '*-mode-src' | head -n1)"
[ -n "$BINSRC" ] || fail "clean-source artifact <hex>-mode-src missing"
[ -x "$BINSRC/run.sh" ] || fail "exec bit NOT preserved on checked-in script in clean copy"
ok "exec bit preserved on checked-in script in clean copy"
if [ "$(stat -c '%a' "$BINSRC/secret.txt")" != "600" ]; then
    fail "0600 source widened in clean copy (got $(stat -c '%a' "$BINSRC/secret.txt"))"
fi
ok "0600 source file not widened in clean copy"

echo "ALL FXSTORE EXCLUDES TESTS PASSED"
