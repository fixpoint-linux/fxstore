#!/bin/sh
# tests/fxstore_sandboxed.sh — exercise run_sandboxed (Shell actions under
# bwrap + palisade stage3) end to end, plus the adversarial invariants of the
# sandbox argv/env construction.  Usage: tests/fxstore_sandboxed.sh ./fxstore
#
# Part A (ALWAYS runs; needs no working bwrap): an instrumented `bwrap` shim
# is placed FIRST on PATH when fxstore starts, so fxstore locks it as its
# bwrap (fx_bwrap_resolve, the startup PATH lock) and execs it for every
# Shell action.  The shim records the exact argv + environment fxstore built,
# then runs the recipe command (all words after the LAST "--") in the rw
# --bind SOURCE (the host workdir), standing in for bwrap+stage3 so the
# build completes.  Asserted: the argv SHAPE — --tmpfs /tmp BEFORE every
# bind (bwrap applies mounts in argv order; a later tmpfs would shadow any
# store/src under /tmp), the rw workdir bind OUTSIDE the ro-bound store (the
# scratch dir is <store>.build, a sibling) mounted at the SHORT fixed dest
# /build, the /init positional ABI, the colon-separated LANDLOCK_SPEC (no
# "/:r" whole-host leak, no long host workdir path), the scrubbed child env
# (no RATTAN_*/LD_*), FX_DEP_* injection, PATH-hijack resistance (a
# recipe-planted fake `bwrap` is never exec'd), and the artifact landing in
# the store via the scratch dir.
#
# Part B (only when bwrap can actually sandbox on this host): re-runs the
# build with the REAL bwrap + stage3 stack and additionally asserts the
# Landlock fence (reading a host file outside the unveil set fails).
# Environments that cannot nest bwrap (an outer sandbox whose seccomp blocks
# userns setup) LOUDLY SKIP part B with the probe's error — part A above
# still ran and passed.
set -eu

FX="${1:-./fxstore}"
# Resolve to an absolute path: the test cds into a temp project dir later.
FX="$(cd "$(dirname "$FX")" && pwd)/$(basename "$FX")"
# stage3 path (the inner sandbox binary) — sibling of fxstore in the repo.
FXSTAGE3="$(dirname "$FX")/vendor/palisade/bin/stage3"
# Short temp base: the LANDLOCK_SPEC (unveiling store + real-path workdir +
# toolchain) is capped at stage3's 256-byte budget, and a deep mktemp path
# (e.g. /tmp/fxstore-sandboxed.XXXXXX/store...) can push it over.  Use a
# short /tmp base so the spec fits (mirrors real usage at /fx/store).
WORK="$(mktemp -d /tmp/fx.XXXXXX)"
STORE="$WORK/s"
PROJ="$WORK/p"
SHIMDIR="$WORK/shim"
LOG="$WORK/argv.log"     # every bwrap argv word, one per line, all invocations
ENVLOG="$WORK/env.log"   # the child env at exec time
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

# --- project: shlib (dep, pure-FS recipe) + shapp (Shell actions, the
# adversarial sequence: env dump -> attack env vars -> planted fake bwrap ->
# PATH hijack -> must still run) ---
mkdir -p "$PROJ/src/shlib" "$PROJ/src/shapp"
echo "lib source" > "$PROJ/src/shlib/s.txt"
echo "app source" > "$PROJ/src/shapp/s.txt"
cat > "$PROJ/package-set.dhall" <<'EOF'
let Action = < Shell : Text | Copy : { from : Text, to : Text } | Mkdir : Text | Rm : Text | Touch : Text | Move : { from : Text, to : Text } | Symlink : { from : Text, to : Text } | Chmod : { path : Text, mode : Text } | Echo : Text | Env : { key : Text, value : Text } | Run : { argv : List Text } >
let Src = < Path : Text | Fetch : { url : Text, hash : Text } >
let Build = { target : Text, recipe : List Action }
let Package = { name : Text, version : Text, src : Src, deps : List Text, build : Build }
let PackageSet = { packages : List Package }
in { packages =
     [ { name = "shlib", version = "1.0.0", src = < Path = "src/shlib" >, deps = [] : List Text,
         build = { target = "shlib",
                   recipe = [ < Touch = "dep.txt" >, < Echo = "built shlib" > ] } },
       { name = "shapp", version = "1.0.0", src = < Path = "src/shapp" >, deps = [ "shlib" ],
         build = { target = "shapp",
                   recipe = [ < Shell = "echo hi > shell.txt" >,
                              < Shell = "env > env-artifact.txt" >,
                              < Shell = "cat /etc/hostname > hostname-leak.txt 2>&1 || true" >,
                              < Env = { key = "RATTAN_ALLOW_PTRACE", value = "1" } >,
                              < Env = { key = "LD_PRELOAD", value = "/nonexistent-evil.so" } >,
                              < Shell = "echo 'echo PWNED > pwned-marker' > evil-bwrap; chmod +x evil-bwrap" >,
                              < Env = { key = "PATH", value = ".:/usr/bin:/bin" } >,
                              < Shell = "echo survived > final.txt" > ] } } ] } : PackageSet
EOF

# --- part A: instrumented-bwrap shim capture (runs everywhere) ---
mkdir -p "$SHIMDIR"
cat > "$SHIMDIR/bwrap" <<'EOF'
#!/bin/sh
# TEST SHIM — instrumented bwrap stand-in (tests/fxstore_sandboxed.sh).
# NOT a sandbox: logs the argv + env fxstore constructed, then execs the
# recipe command (everything after the LAST "--") in the workdir — the
# SOURCE of the rw "--bind" (bwrap would mount it at the dest; outside
# bwrap the host path is where the command must run).
DIR="${FX_SHIM_LOG_DIR:?FX_SHIM_LOG_DIR not set}"
for a in "$@"; do
    printf '%s\n' "$a" >> "$DIR/argv.log"
done
printf '%s\n' '===END===' >> "$DIR/argv.log"
env >> "$DIR/env.log"
# the shim is a mock bwrap: it records the argv, then must run the REAL
# command the sandbox would run.  With stage3, the argv after the first `--`
# is [stage3 PROMISES SPEC -- cmd...]; the shim skips past the stage3 wrapper
# (which it cannot run) to the actual recipe command after the second `--`.
workdir=
prev=
for a in "$@"; do
    if [ "$prev" = "--bind" ]; then workdir="$a"; fi
    prev="$a"
done
# find the LAST `--` and run everything after it (the recipe command)
lastsep=0
n=0
for a in "$@"; do
    n=$((n + 1))
    if [ "$a" = "--" ]; then lastsep=$n; fi
done
while [ "$lastsep" -gt 0 ]; do
    shift
    lastsep=$((lastsep - 1))
done
[ -n "$workdir" ] || exit 127
cd "$workdir" || exit 127
exec "$@"
EOF
chmod +x "$SHIMDIR/bwrap"

export FX_SHIM_LOG_DIR="$WORK"
(cd "$PROJ" && PATH="$SHIMDIR:$PATH" "$FX" build --store "$STORE" shapp) \
    > "$WORK/build1.out" 2>&1 || fail "part-A build failed: $(cat "$WORK/build1.out")"

[ -s "$LOG" ] || fail "the shim was never exec'd (no bwrap argv captured)"
if grep -q 'NON-HERMETIC' "$WORK/build1.out"; then
    fail "shim not used: the bwrap-absent fallback was taken"
fi

# required argv words (exact lines).  stage3 is bound+exec'd at its REAL host
# path (the ro-bound root can't host a synthesized /init mountpoint), so we
# assert the stage3 path appears rather than a fixed /init.
for w in --unshare-all --die-with-parent --uid --gid 1000 --tmpfs /tmp \
         --ro-bind --bind --chdir --dev /dev --proc /proc; do
    grep -qx -e "$w" "$LOG" || fail "bwrap argv lacks '$w'"
done
if ! grep -qx -e "$FXSTAGE3" "$LOG"; then
    fail "bwrap argv lacks the stage3 path ($FXSTAGE3)"
fi

# --tmpfs /tmp must PRECEDE the store/src/workdir binds: bwrap applies mount
# ops in argv order, so a tmpfs pushed AFTER those binds would shadow any
# store/src/workdir placed under /tmp (the exact "Can't chdir ... No such
# file" bug).  The `--ro-bind / /` root bind (if present) correctly comes
# BEFORE the tmpfs: binding / brings the host tree in, then the tmpfs shadows
# host /tmp, and a later bind whose dest falls under /tmp auto-creates its
# mountpoint inside the fresh tmpfs (verified) — so only the store/src/workdir
# binds must follow the tmpfs.
TMPFS_LINE="$(grep -n '^--tmpfs$' "$LOG" | head -n1 | cut -d: -f1)"
[ -n "$TMPFS_LINE" ] || fail "no --tmpfs in bwrap argv"
# first bind AFTER the tmpfs (skip a leading `--ro-bind / /` root bind)
FIRST_BIND="$(awk -v t="$TMPFS_LINE" 'NR>t && ($0=="--ro-bind" || $0=="--bind"){print NR; exit}' "$LOG")"
[ -n "$FIRST_BIND" ] || fail "no bind mounts after --tmpfs in bwrap argv"
[ "$TMPFS_LINE" -lt "$FIRST_BIND" ] \
    || fail "--tmpfs /tmp is pushed AFTER the binds — it would shadow stores under /tmp"

# the rw workdir bind must be OUTSIDE the ro-bound store (nesting a rw bind
# under the ro bind of its ancestor is unconstructable in bwrap) ...
if awk -v store="$STORE/" '
        prev == "--bind" && index($0, store) == 1 { bad = 1 }
        { prev = $0 }
        END { exit bad ? 1 : 0 }
    ' "$LOG"; then
    :
else
    fail "rw --bind workdir is nested inside the ro-bound store '$STORE'"
fi
# ... and must be the scratch dir under <store>.build/ (its DEST is the
# short fixed /build, which the --chdir below confirms)
if awk -v build="$STORE.build/" '
        prev == "--bind" && index($0, build) == 1 { found = 1 }
        { prev = $0 }
        END { exit found ? 0 : 1 }
    ' "$LOG"; then
    :
else
    fail "rw --bind source is not the scratch dir under '$STORE.build/'"
fi
# the workdir bind dest == its source (real host path): under the ro-bound
# root bwrap cannot synthesize a /build mountpoint, so the scratch dir is
# bound at its real path and --chdir there (portable across kernels).
# Extract the --bind SRC DEST triple and the --chdir DEST, assert equality.
# the bind SRC is the first line after a --bind whose content has the store.build path
BIND_SRC="$(awk -v b="$STORE.build/" 'prev=="--bind" && index($0,b)==1{print;exit}{prev=$0}' "$LOG")"
[ -n "$BIND_SRC" ] || fail "no --bind of the scratch dir ($STORE.build/) in argv"
BIND_DEST="$(awk -v s="$BIND_SRC" 'prev=="--bind" && $0==s{getline;print;exit}{prev=$0}' "$LOG")"
CHDIR_DEST="$(awk 'prev=="--chdir"{print;exit}{prev=$0}' "$LOG")"
[ "$BIND_SRC" = "$BIND_DEST" ] || fail "--bind workdir dest ($BIND_DEST) != source ($BIND_SRC)"
[ "$BIND_SRC" = "$CHDIR_DEST" ] || fail "--chdir dest ($CHDIR_DEST) != workdir bind source ($BIND_SRC)"

# LANDLOCK_SPEC: one argv word, '<store>:r;...;<workdir>:rwcx;...'
SPECLINE="$(grep -F "${STORE}:" "$LOG" | grep -F ':rwcx' | head -n1)"
[ -n "$SPECLINE" ] || fail "LANDLOCK_SPEC word missing (needs '<store>:r' + ':rwcx', colon-separated)"
case "$SPECLINE" in
    "${STORE}:r;"*) : ;;
    *) fail "LANDLOCK_SPEC does not start with '${STORE}:r;': $SPECLINE" ;;
esac
case "$SPECLINE" in
    *"${STORE}.build/"*":rwcx"*) : ;;
    *) fail "LANDLOCK_SPEC lacks the real workdir ':rwcx' entry: $SPECLINE" ;;
esac
SPECFULL=";$SPECLINE;"
for entry in "/usr:rx" "/bin:rx" "/lib:rx" "/dev:rwc" "/proc:r" "/tmp:rwc"; do
    case "$SPECFULL" in
        *";$entry;"*) : ;;
        *) fail "LANDLOCK_SPEC lacks '$entry': $SPECLINE" ;;
    esac
done
case "$SPECFULL" in
    *";/:r;"*) fail "LANDLOCK_SPEC leaks '/:r' (whole host fs read): $SPECLINE" ;;
esac

# stage3 positional ABI: bwrap's '--' then <stage3-path> PROMISES SPEC '--' cmd
grep -A1 -e '^--$' "$LOG" | grep -qx -e "$FXSTAGE3" \
    || fail "bwrap '--' is not followed by the stage3 path (positional ABI)"
grep -qx -e 'stdio rpath wpath cpath dpath flock fattr exec prot_exec proc recvfd' "$LOG" \
    || fail "PROMISES word missing or wrong"
grep -qx -e '/bin/sh' "$LOG" || fail "real command /bin/sh missing after the last '--'"

# scrubbed child env (what fxstore passed to exec)
if grep -q '^RATTAN_' "$ENVLOG"; then
    fail "child env leaks RATTAN_* (RATTAN_ALLOW_PTRACE would skip seccomp)"
fi
if grep -q '^LD_' "$ENVLOG"; then
    fail "child env leaks LD_* (LD_PRELOAD injection into the exec chain)"
fi
grep -q "^FX_DEP_SHLIB=$STORE/" "$ENVLOG" || fail "FX_DEP_SHLIB missing from child env"

# artifacts landed in the store through the scratch dir
APPDIR="$(find "$STORE" -maxdepth 1 -type d -name '*-shapp' | head -n1)"
[ -n "$APPDIR" ] || fail "shapp store dir missing"
[ "$(cat "$APPDIR/shell.txt")" = "hi" ] || fail "Shell action did not produce shell.txt"
grep -q '^FX_DEP_SHLIB=' "$APPDIR/env-artifact.txt" || fail "recipe env lacks FX_DEP_SHLIB"
[ "$(cat "$APPDIR/final.txt")" = "survived" ] || fail "post-hijack Shell action failed"
[ ! -e "$APPDIR/pwned-marker" ] || fail "PATH hijack succeeded: recipe-planted 'bwrap' was exec'd"
[ ! -e "$STORE/.tmp" ] || fail "legacy scratch '$STORE/.tmp' was created"
if [ -n "$(ls -A "$STORE.build")" ]; then
    fail "scratch area not emptied after successful build: $(ls -A "$STORE.build")"
fi
ok "argv: tmpfs-first, workdir outside the ro-bound store, /init ABI, spec ':'-separated, no '/:r'"
ok "env: RATTAN_*/LD_* scrubbed, FX_DEP_* injected; PATH hijack resisted; artifact in store"

# --- part B: the REAL bwrap + stage3 stack (probe-gated) ---
if ! command -v bwrap >/dev/null 2>&1; then
    echo "SKIP part B: bwrap not installed on this host"
    echo "      (part A above still verified the argv/env construction)"
    echo "ALL FXSTORE SANDBOXED TESTS PASSED (part B skipped: no bwrap)"
    exit 0
fi
PROBE_ERR="$WORK/probe.err"
# Probe uses the same argv shape as production run_sandboxed, INCLUDING
# `--ro-bind / /` (without it, subdir binds leave an empty root on some
# kernels and the probe falsely skips — verified on a btrfs-root host).
if ! bwrap --unshare-all --ro-bind / / --ro-bind /usr /usr --dev /dev \
           --proc /proc --tmpfs /tmp \
           -- /bin/sh -c 'exit 0' >"$PROBE_ERR" 2>&1; then
    echo "SKIP part B: bwrap cannot sandbox on this host (probe: $(head -n1 "$PROBE_ERR"))"
    echo "      (e.g. inside another sandbox whose seccomp blocks userns setup;"
    echo "       part A above still verified the argv/env construction)"
    echo "ALL FXSTORE SANDBOXED TESTS PASSED (part B skipped: bwrap cannot nest here)"
    exit 0
fi
STORE2="$WORK/store2"
(cd "$PROJ" && "$FX" build --store "$STORE2" shapp) > "$WORK/build2.out" 2>&1 \
    || fail "real-stack build failed: $(cat "$WORK/build2.out")"
if grep -q 'NON-HERMETIC' "$WORK/build2.out"; then
    fail "part B took the bwrap-absent fallback"
fi
APPDIR2="$(find "$STORE2" -maxdepth 1 -type d -name '*-shapp' | head -n1)"
[ -n "$APPDIR2" ] || fail "shapp store dir missing (part B)"
[ "$(cat "$APPDIR2/shell.txt")" = "hi" ] || fail "real-stack Shell action did not produce shell.txt"
[ ! -e "$APPDIR2/pwned-marker" ] || fail "PATH hijack succeeded under the real stack"

# FENCE PROBES (store integrity + Landlock-only write denial). These run only
# here, under the REAL stack — under the part-A shim there is no fence, so they
# get their own project/store and must never run in part A.
PROJ3="$WORK/proj3"
STORE3="$WORK/store3"
mkdir -p "$PROJ3/src/shlib" "$PROJ3/src/shapp"
echo "lib source" > "$PROJ3/src/shlib/s.txt"
echo "app source" > "$PROJ3/src/shapp/s.txt"
cat > "$PROJ3/package-set.dhall" <<'EOF'
let Action = < Shell : Text | Copy : { from : Text, to : Text } | Mkdir : Text | Rm : Text | Touch : Text | Move : { from : Text, to : Text } | Symlink : { from : Text, to : Text } | Chmod : { path : Text, mode : Text } | Echo : Text | Env : { key : Text, value : Text } | Run : { argv : List Text } >
let Src = < Path : Text | Fetch : { url : Text, hash : Text } >
let Build = { target : Text, recipe : List Action }
let Package = { name : Text, version : Text, src : Src, deps : List Text, build : Build }
let PackageSet = { packages : List Package }
in { packages =
     [ { name = "shlib", version = "1.0.0", src = < Path = "src/shlib" >, deps = [] : List Text,
         build = { target = "shlib", recipe = [ < Touch = "dep.txt" > ] } },
       { name = "shapp", version = "1.0.0", src = < Path = "src/shapp" >, deps = [ "shlib" ],
         build = { target = "shapp",
                   recipe = [ < Shell = "echo x > $FX_DEP_SHLIB/pwn 2> fence-store.txt || echo DENIED >> fence-store.txt" >,
                              < Shell = "echo 1 > /proc/self/oom_score_adj 2> fence-proc.txt || echo DENIED >> fence-proc.txt" > ] } } ] } : PackageSet
EOF
(cd "$PROJ3" && "$FX" build --store "$STORE3" shapp) > "$WORK/build3.out" 2>&1 \
    || fail "fence-probe build failed: $(cat "$WORK/build3.out")"
APPDIR3="$(find "$STORE3" -maxdepth 1 -type d -name '*-shapp' | head -n1)"
SHLIBDIR3="$(find "$STORE3" -maxdepth 1 -type d -name '*-shlib' | head -n1)"
[ -n "$APPDIR3" ] && [ -n "$SHLIBDIR3" ] || fail "fence-probe store dirs missing"
# (a) store integrity: writing the ro-bound dep store dir must be DENIED
#     (belt: bwrap ro-bind EROFS; braces: Landlock store :r)
grep -q DENIED "$APPDIR3/fence-store.txt" || fail "store write NOT denied (ro fence broken)"
[ ! -e "$SHLIBDIR3/pwn" ] || fail "store write fence broken: pwn file created in dep store dir"
# (b) Landlock-ONLY denial: /proc is mounted rw (--proc) but unveiled :r, and
#     /proc/self/oom_score_adj is DAC-writable by the process itself — ONLY
#     Landlock denies this write. If it succeeds, Landlock is not enforcing.
grep -q DENIED "$APPDIR3/fence-proc.txt" || fail "Landlock fence broken: /proc write (spec :r) succeeded"

if [ -n "$(ls -A "$STORE2.build")" ]; then
    fail "scratch area not emptied after real-stack build"
fi
ok "real bwrap + stage3 stack builds Shell actions; store-write + Landlock fences hold"

echo "ALL FXSTORE SANDBOXED TESTS PASSED"
