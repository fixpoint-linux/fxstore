#!/bin/sh
# tests/fxstore_timeline.sh — M5 timeline/rollback test for the fxstore CLI.
# Usage: tests/fxstore_timeline.sh ./fxstore/fxstore
#
# Exercises: `timeline` snapshot listing (roots/closure/store/srcstore counts),
# `rollback <v>` (roll-forward: two new versions, CURRENT advances, restores the
# rolled-back root set), `rollback --hard <v>` (CURRENT re-marked at <v>), and
# `gc --retain N` (generation GC prunes snapshot versions down to N).
# bwrap-free: pure store metadata-db operations (the worked-example recipes are
# Touch/Echo, which run in-process).
set -eu

FX="${1:-./fxstore/fxstore}"
# Resolve to an absolute path: the test cds into a temp project dir later,
# so a relative FX would break.
FX="$(cd "$(dirname "$FX")" && pwd)/$(basename "$FX")"
WORK="$(mktemp -d /tmp/fxstore-timeline.XXXXXX)"
STORE="$WORK/store"
PROJ="$WORK/proj"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

timeline()  { (cd "$PROJ" && "$FX" timeline --store "$STORE"); }
# version numbers in timeline order (ascending)
versions()  { timeline | sed -n 's/^  \([0-9][0-9]*\) .*/\1/p'; }
nversions() { versions | wc -l | tr -d ' '; }

# --- (a) init a project ---
"$FX" init "$PROJ" >/dev/null
ok "init scaffolds the worked-example project"

# --- (b) build app -> timeline shows a version with roots: app and closure 2 ---
(cd "$PROJ" && "$FX" build --store "$STORE" app) >/dev/null
TL="$(timeline)"
echo "$TL" | grep -qE '^  [0-9]+ \[CURRENT\] roots: app  closure: 2' \
    || fail "build app timeline lacks a CURRENT roots:app closure:2 line: $TL"
ok "build app -> timeline CURRENT version has roots:app, closure:2"

# --- (c) build lib -> timeline shows a version with roots: lib closure 1 ---
(cd "$PROJ" && "$FX" build --store "$STORE" lib) >/dev/null
TL="$(timeline)"
echo "$TL" | grep -qE '^  [0-9]+ \[CURRENT\] roots: lib  closure: 1' \
    || fail "build lib timeline lacks a CURRENT roots:lib closure:1 line: $TL"
ok "build lib -> timeline CURRENT version has roots:lib, closure:1"

# --- (d) capture the app version and roll FORWARD to it: +2 versions, CURRENT
#        restores roots:app ---
N0="$(nversions)"
APP_LINE="$(timeline | grep -E 'roots: app  closure: 2' | head -n1)"
APP_V="$(printf '%s\n' "$APP_LINE" | sed -n 's/^  \([0-9][0-9]*\).*/\1/p')"
[ -n "$APP_V" ] || fail "could not find an app-root version in: $(timeline)"
(cd "$PROJ" && "$FX" rollback "$APP_V" --store "$STORE") >/dev/null
TL="$(timeline)"
N1="$(nversions)"
[ "$N1" -eq $((N0 + 2)) ] \
    || fail "rollback did not add 2 versions (was $N0, now $N1): $TL"
echo "$TL" | grep -qE '^  [0-9]+ \[CURRENT\] roots: app  closure: 2' \
    || fail "post-rollback CURRENT is not roots:app closure:2: $TL"
ok "rollback $APP_V -> +2 versions, CURRENT roots:app closure:2"

# --- (e) rollback --hard to the app version -> CURRENT re-marked there,
#        version count unchanged ---
N1c="$(nversions)"
(cd "$PROJ" && "$FX" rollback --hard "$APP_V" --store "$STORE") >/dev/null
TL="$(timeline)"
echo "$TL" | grep -qE "^  ${APP_V} \[CURRENT\] roots: app" \
    || fail "--hard did not re-mark CURRENT at $APP_V: $TL"
N2="$(nversions)"
[ "$N2" -eq "$N1c" ] || fail "--hard changed the version count ($N1c -> $N2)"
ok "rollback --hard $APP_V -> CURRENT re-marked at $APP_V, count unchanged"

# --- (f) gc --retain refuses while CURRENT is stale (post --hard), then
#        after restoring CURRENT to newest it prunes to 2 versions ---
# After (e) CURRENT was --hard-repointed at the old $APP_V, so the gc publish
# would renumber + the by-number prune could drop the CURRENT-pointed version
# (dangling CURRENT). The guard must refuse loudly.
if (cd "$PROJ" && "$FX" gc --retain 2 --store "$STORE" >/dev/null 2>&1); then
    fail "gc --retain 2 unexpectedly succeeded with a stale CURRENT (post --hard)"
fi
ok "gc --retain 2 refused while CURRENT is stale (post --hard)"
# Restore CURRENT to the newest version, then generation GC works.
NEWEST_V="$(versions | tail -n1 | tr -d ' ')"
[ -n "$NEWEST_V" ] || fail "could not determine newest version"
(cd "$PROJ" && "$FX" rollback --hard "$NEWEST_V" --store "$STORE") >/dev/null
(cd "$PROJ" && "$FX" gc --retain 2 --store "$STORE") >/dev/null
N3="$(nversions)"
[ "$N3" -eq 2 ] || fail "gc --retain 2 left $N3 version(s), expected 2"
ok "after restoring CURRENT, gc --retain 2 -> version count 2"

# --- (g) negative: rollback to a nonexistent version errors cleanly ---
if (cd "$PROJ" && "$FX" rollback 999999 --store "$STORE" >/dev/null 2>&1); then
    fail "rollback 999999 unexpectedly succeeded"
fi
ok "rollback 999999 errors cleanly"

# --- (h) timeline on an empty store prints "no versions" ---
EMPTY="$WORK/empty"
(cd "$PROJ" && "$FX" timeline --store "$EMPTY") | grep -q 'no versions' \
    || fail "timeline on empty store lacks 'no versions'"
ok "timeline on empty store prints 'no versions'"

echo "ALL FXSTORE TIMELINE TESTS PASSED"
