/* build.c — (U5) recipe executor + bwrap/palisade stage3 sandbox.
 *
 * run_action/print_action are PORTED from dhake/src/dhake.c (453-557 /
 * 560-579) with the two fxstore changes from the plan (Decision 6):
 *   (a) relative output paths resolve against the package's temp BUILD
 *       dir (workdir — the dir that becomes the store path); each direct
 *       dep's store path is exported as FX_DEP_<NAME> (read-only content:
 *       deps were built before this package and are content-addressed);
 *   (b) the two EXECUTING actions (Shell, Run) run under a bwrap sandbox
 *       with the palisade stage3 inner binary (vendor/palisade) as /init:
 *         bwrap --unshare-all --die-with-parent --uid 1000 --gid 1000
 *               --tmpfs /tmp (FIRST mount op: bwrap applies mounts in argv
 *                order, so a tmpfs pushed after the binds would shadow any
 *                store/src/workdir placed under /tmp; bind SOURCES resolve
 *                in the original namespace, so tmpfs-first never hides them)
 *               [binds: ro-bind store, /usr /bin /lib [/lib64], ro-bind src,
 *                bind workdir -> /build, --dev /dev, --proc /proc,
 *                ro-bind stage3 /init]
 *               -- /init <PROMISES> <LANDLOCK_SPEC> -- <real_argv...>
 *       stage3 (applied no_new_privs -> Landlock -> rlimits -> seccomp, in
 *       that order) hardens the bwrap namespaces: the recipe's syscalls are
 *       whitelist-filtered (pledge) and the filesystem is unveil()ed down
 *       to exactly the bind-mounted paths (Landlock).  workdir is the
 *       package's scratch dir under <store_root>.build — a SIBLING of the
 *       store, rw-bound at the short fixed path /build: bwrap constructs a
 *       rw bind by mkdir()ing the missing destination at mount time through
 *       the mounts already in place, which a read-only ancestor makes
 *       impossible ("Can't chdir"/"Can't mkdir"), and the long host scratch
 *       path (store + ".build/" + 64 hex + name + pid) would eat stage3's
 *       256-byte LANDLOCK_SPEC budget.  The
 *       pure-filesystem actions (Copy/Mkdir/Rm/Touch/Move/Symlink/Chmod/
 *       Echo/Env) are trusted declarative ops and run in-process without
 *       a sandbox.
 *     SECURITY invariants of this executor:
 *       - RATTAN_ and LD_ variables are scrubbed from the child environment
 *         before exec: stage3 reads RATTAN_ALLOW_PTRACE (which skips seccomp
 *         entirely) plus RATTAN_EXTRA_PROMISES/RATTAN_RLIMITS from the
 *         environment, and LD_PRELOAD/LD_* would inject into the exec'd
 *         chain — a recipe's Env action must not be able to reach any of
 *         them.
 *       - The LANDLOCK_SPEC unveils ONLY the bind-mounted paths, never
 *         "/:r" — unlike rattan, fxstore's bwrap keeps the HOST / as the
 *         sandbox root, so "/:r" would expose the whole host fs.
 *       - stage3-absent is a LOUD failure (exit 127), never a fallback;
 *         the LOUD NON-HERMETIC fallback below is reserved for the
 *         bwrap-absent case only.
 *     If bwrap is absent the child prints a LOUD NON-HERMETIC warning and
 *     falls back to plain fork/exec in the workdir — never a silent
 *     fallback.
 *
 * The toolchain ro-binds (/usr /bin /lib [/lib64]) are MVP pragmatics: with
 * --unshare-all and no host bind, /bin/sh itself would be missing inside
 * the sandbox.  Full Nix-style hermeticity (deny all host fs, tmpfs) is
 * post-MVP per the plan.
 */
#include "fxstore.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/* ─── Path resolution against the workdir ──────────────────────────────── */

/* malloc'd absolute path: p itself if absolute, else workdir/p */
static char *resolve_path(const char *p, const char *workdir) {
    if (!p) return NULL;
    if (p[0] == '/') return strdup(p);
    size_t n = strlen(workdir) + 1 + strlen(p) + 1;
    char *out = malloc(n);
    if (!out) return NULL;
    snprintf(out, n, "%s/%s", workdir, p);
    return out;
}

/* ─── dhake filesystem helpers (verbatim) ──────────────────────────────── */

static bool copy_file(const char *from, const char *to) {
    FILE *in = fopen(from, "rb");
    if (!in) { fprintf(stderr, "fxstore: copy: cannot open '%s'\n", from); return false; }
    FILE *out = fopen(to, "wb");
    if (!out) { fprintf(stderr, "fxstore: copy: cannot open '%s'\n", to); fclose(in); return false; }
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0)
        if (fwrite(buf, 1, n, out) != n) { fprintf(stderr, "fxstore: copy: write error to '%s'\n", to); fclose(in); fclose(out); return false; }
    fclose(in);
    fclose(out);
    return true;
}

static bool touch_file(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) { fprintf(stderr, "fxstore: touch: cannot open '%s'\n", path); return false; }
    close(fd);
    struct timeval tv[2];
    gettimeofday(&tv[0], NULL);
    tv[1] = tv[0];
    utimes(path, tv);
    return true;
}

/* ─── FX_DEP_<NAME> environment injection ──────────────────────────────── */

/* Build the sanitized env var name for a dep: "FX_DEP_" + uppercased name
 * with non-alphanumerics mapped to '_'.  Returns a malloc'd string. */
static char *dep_env_name(const char *dep) {
    size_t n = strlen(dep);
    char *out = malloc(7 + n + 1);
    if (!out) return NULL;
    memcpy(out, "FX_DEP_", 7);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)dep[i];
        out[7 + i] = (char)(isalnum(c) ? toupper(c) : '_');
    }
    out[7 + n] = '\0';
    return out;
}

/* Replace the FX_DEP_* environment with exactly this package's deps.
 * (fx_build_recipe runs once per package in one process; without the clear,
 * a previous package's FX_DEP_* would leak into the next recipe.) */
static int set_dep_env(char *const *dep_names, char *const *dep_paths, int ndeps) {
    /* collect the current FX_DEP_* names, then unset (unsetenv mutates
       environ, so the collection pass must finish first) */
    char **stale = NULL;
    int nstale = 0, cap = 0;
    for (char **e = environ; e && *e; e++) {
        if (strncmp(*e, "FX_DEP_", 7) != 0) continue;
        size_t len = strchr(*e, '=') ? (size_t)(strchr(*e, '=') - *e) : strlen(*e);
        char *name = malloc(len + 1);
        if (!name) continue;
        memcpy(name, *e, len);
        name[len] = '\0';
        if (nstale == cap) {
            cap = cap ? cap * 2 : 8;
            char **ns = realloc(stale, (size_t)cap * sizeof *ns);
            if (!ns) { free(name); continue; }
            stale = ns;
        }
        stale[nstale++] = name;
    }
    for (int i = 0; i < nstale; i++) { unsetenv(stale[i]); free(stale[i]); }
    free(stale);

    for (int i = 0; i < ndeps; i++) {
        char *var = dep_env_name(dep_names[i]);
        if (!var) return -1;
        setenv(var, dep_paths[i], 1);
        free(var);
    }
    return 0;
}

/* ─── bwrap sandbox wrapper ────────────────────────────────────────────── */

static int is_dir2(const char *p) {
    struct stat st;
    return p && stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Append a string pointer to a growable argv array. */
static int argv_push(char ***av, int *n, int *cap, const char *s) {
    if (*n == *cap) {
        *cap = *cap ? *cap * 2 : 32;
        char **na = realloc(*av, (size_t)*cap * sizeof *na);
        if (!na) return -1;
        *av = na;
    }
    (*av)[(*n)++] = (char *)s;        /* bwrap does not mutate its argv */
    return 0;
}

/* ─── stage3 (palisade) inner sandbox binary ──────────────────────────── */

/* Pledge promise set for build recipes: rattan's agent baseline (stdio
 * rpath wpath cpath flock exec prot_exec proc recvfd) plus dpath (rm -rf /
 * rmdir in recipes, make clean) and fattr (chmod/utimes — assimilate and
 * make artifact stamping).  NO inet/dns/tty: builds run network-off.
 * prot_exec is required for dynamically-linked binaries to map their
 * libraries at all. */
#define FXSTORE_PROMISES \
    "stdio rpath wpath cpath dpath flock fattr exec prot_exec proc recvfd"

#ifndef FXSTORE_STAGE3_PATH
#define FXSTORE_STAGE3_PATH "vendor/palisade/bin/stage3"
#endif

/* Resolved stage3 path: the FXSTORE_STAGE3 environment override if it was
 * set when fxstore started, else the compile-time FXSTORE_STAGE3_PATH (the
 * Makefile bakes the vendor/palisade submodule's bin/stage3 here).
 * Resolved EXACTLY ONCE (first call wins); fx_stage3_resolve() is called
 * from main() before any package-set is loaded, because a recipe's Env
 * action can set arbitrary environment variables — reading the override
 * lazily would let a recipe point the sandbox's inner binary at its own
 * code for a later action or package (shedding the stage3 layer while
 * keeping the weaker bwrap-only isolation). */
static const char *g_stage3_path;

void fx_stage3_resolve(void) {
    if (g_stage3_path) return;
    const char *p = getenv("FXSTORE_STAGE3");
    g_stage3_path = (p && *p) ? p : FXSTORE_STAGE3_PATH;
}

static const char *stage3_bin(void) {
    if (!g_stage3_path) fx_stage3_resolve();
    return g_stage3_path;
}

/* Resolved absolute bwrap path (NULL when not resolvable at startup).
 * Looked up ONCE, before any recipe Env action runs: execvp("bwrap")
 * searches the CURRENT PATH, which recipes control — a recipe could plant
 * a fake `bwrap` in /tmp (unveiled rwc) or the workdir (rwcx via /build) and redirect
 * PATH to it, substituting the sandbox layer itself. The child execs this
 * ABSOLUTE path (no PATH search); NULL means take the LOUD fallback branch
 * directly. */
static char *g_bwrap_path;

void fx_bwrap_resolve(void) {
    if (g_bwrap_path) return;
    const char *path = getenv("PATH");
    char *dup = path ? strdup(path) : NULL;
    if (dup) {
        for (char *tok = strtok(dup, ":"); tok; tok = strtok(NULL, ":")) {
            char cand[PATH_MAX];
            if (*tok && snprintf(cand, sizeof cand, "%s/bwrap", tok) < (int)sizeof cand
                && access(cand, X_OK) == 0) {
                g_bwrap_path = strdup(cand);
                break;
            }
        }
        free(dup);
    }
}

/* Drop every RATTAN_* and LD_* variable from the (fork'd child's)
 * environment before exec.  stage3 reads RATTAN_ALLOW_PTRACE=1 as "skip
 * seccomp entirely" and RATTAN_EXTRA_PROMISES/RATTAN_RLIMITS as config;
 * LD_PRELOAD and friends inject into every exec'd binary.  A recipe's Env
 * action (or the invoking shell) must not be able to reach any of them.
 * Same collect-then-unset pattern as set_dep_env: unsetenv mutates
 * environ, so the scan must finish before the first unsetenv. */
static void scrub_env(void) {
    char **drop = NULL;
    int nd = 0, cap = 0;
    for (char **e = environ; e && *e; e++) {
        if (strncmp(*e, "RATTAN_", 7) != 0 && strncmp(*e, "LD_", 3) != 0)
            continue;
        size_t len = strchr(*e, '=') ? (size_t)(strchr(*e, '=') - *e) : strlen(*e);
        char *name = malloc(len + 1);
        if (!name) continue;
        memcpy(name, *e, len);
        name[len] = '\0';
        if (nd == cap) {
            cap = cap ? cap * 2 : 8;
            char **t = realloc(drop, (size_t)cap * sizeof *t);
            if (!t) { free(name); continue; }
            drop = t;
        }
        drop[nd++] = name;
    }
    for (int i = 0; i < nd; i++) { unsetenv(drop[i]); free(drop[i]); }
    free(drop);
}

/* stage3 parses LANDLOCK_SPEC through a fixed 256-byte buffer and dies on
 * anything longer; use the same limit here so an oversized spec fails with
 * OUR message instead of stage3's. */
#define FX_LANDLOCK_SPEC_MAX 256

/* Append "path:perms" (with a ';' separator) to buf at *off.  Returns 0 on
 * success, -1 when it would not fit in cap (path NULL/"" is a skip, not an
 * error — SRC_FETCH packages have no src tree). */
static int spec_append(char *buf, size_t cap, size_t *off, int *first,
                       const char *path, const char *perms) {
    if (!path || !path[0]) return 0;
    size_t l = strlen(path), pl = strlen(perms), sep = *first ? 0 : 1;
    if (*off + l + 1 + pl + sep + 1 > cap) return -1;   /* +1 for the ':' */
    if (sep) buf[(*off)++] = ';';
    memcpy(buf + *off, path, l); *off += l;
    buf[(*off)++] = ':';
    memcpy(buf + *off, perms, pl); *off += pl;
    buf[*off] = '\0';
    *first = 0;
    return 0;
}

/* Build the LANDLOCK_SPEC "path:perms;path:perms;..." unveiled for this
 * invocation.  SECURITY: unveils ONLY the bind-mounted paths — never "/:r"
 * (fxstore's bwrap keeps the HOST / as the sandbox root; "/:r" would grant
 * recipes read access to the entire host filesystem — a regression vs the
 * bind-only isolation).  The workdir is unveiled by its SHORT sandbox
 * mountpoint "/build" (run_sandboxed binds <store_root>.build/<hash>-<name>-
 * <pid> there): stage3 parses the spec through a fixed 256-byte buffer and
 * dies on longer specs, and the host workdir path (store + ".build/" + 64
 * hex chars + name + pid) alone can approach that budget.  /lib64 is
 * included exactly when it is bind-mounted (is_dir2), so every unveiled
 * path exists inside the sandbox — stage3's unveil() on a missing path
 * dies.  workdir gets rwcx (builds exec ./configure and write their own
 * artifacts, mirroring rattan's exec-workspace choice) and is the scratch
 * dir under <store_root>.build — a SIBLING of the store, so its rwcx grant
 * never widens the store's :r (store_root stays read-only for the recipe
 * at BOTH fences: the bwrap ro-bind and this Landlock rule).  src_ro is rx
 * (read + exec); store_root is r.  /dev, /proc, /tmp cover the runtime
 * needs of the mounted dev/proc and the fresh --tmpfs /tmp.  Every unveiled
 * path is bind/tmpfs-mounted (or the toolchain ro-binds), so it exists
 * inside the namespace.  Returns a malloc'd spec, or NULL when it would
 * not fit (caller fails LOUDLY — fail closed, never truncate). */
static char *build_landlock_spec(const char *src_ro, const char *store_root) {
    char buf[512];
    size_t off = 0;
    int first = 1;
    if (spec_append(buf, sizeof buf, &off, &first, store_root, "r") != 0 ||
        spec_append(buf, sizeof buf, &off, &first, src_ro,     "rx") != 0 ||
        spec_append(buf, sizeof buf, &off, &first, "/build",   "rwcx") != 0 ||
        spec_append(buf, sizeof buf, &off, &first, "/usr",     "rx") != 0 ||
        spec_append(buf, sizeof buf, &off, &first, "/bin",     "rx") != 0 ||
        spec_append(buf, sizeof buf, &off, &first, "/lib",     "rx") != 0 ||
        (is_dir2("/lib64") &&
         spec_append(buf, sizeof buf, &off, &first, "/lib64", "rx") != 0) ||
        spec_append(buf, sizeof buf, &off, &first, "/dev",     "rwc") != 0 ||
        spec_append(buf, sizeof buf, &off, &first, "/proc",    "r") != 0 ||
        spec_append(buf, sizeof buf, &off, &first, "/tmp",     "rwc") != 0)
        return NULL;
    if (strlen(buf) >= FX_LANDLOCK_SPEC_MAX) return NULL;
    return strdup(buf);
}

/* fork + exec real_argv under bwrap with stage3 as /init; on bwrap-ENOENT
 * fall back LOUDLY to plain exec in the workdir (stage3-absent, by
 * contrast, dies 127 — see the child below).  Returns the child's exit
 * code (2 if signaled). */
static int run_sandboxed(const char *workdir, const char *src_ro,
                         const char *store_root, char **real_argv) {
    pid_t pid = fork();
    if (pid == -1) {
        fprintf(stderr, "fxstore: fork failed: %s\n", strerror(errno));
        return 2;
    }
    if (pid == 0) {
        /* ── child ── nothing below may degrade into a LESS-sandboxed exec:
         * stage3 must be reachable or we die (127) LOUDLY. */
        scrub_env();
        char *spec = build_landlock_spec(src_ro, store_root);
        if (!spec) {
            fprintf(stderr, "fxstore: cannot build LANDLOCK_SPEC for this build "
                            "(store/src paths too long)\n");
            _exit(127);
        }
        const char *st3 = stage3_bin();
        if (access(st3, X_OK) != 0) {
            fprintf(stderr,
                "fxstore: stage3 not found or not executable at '%s': %s\n"
                "fxstore: build it with 'make stage3' (vendor/palisade)\n",
                st3, strerror(errno));
            _exit(127);
        }
        /* ── build: bwrap [binds...] -- /init PROMISES SPEC -- real_argv... */
        char **av = NULL;
        int n = 0, cap = 0;
        int oom = 0;
        #define PUSH(s) do { if (argv_push(&av, &n, &cap, (s)) != 0) oom = 1; } while (0)
        PUSH("bwrap");
        PUSH("--unshare-all");          /* no net, no IPC, no new mounts... */
        PUSH("--die-with-parent");
        /* Bind the host root: bwrap pivots to a fresh root and only what is
         * explicitly bound appears there.  WITHOUT `--ro-bind / /`, binding
         * only subdirs (/usr /bin /lib) leaves the namespace root EMPTY on
         * some kernels (verified on node-infra / btrfs-root, cosmocc 14.1.0):
         * exec of the recipe fails with "No such file or directory" even
         * though /usr is bound.  Binding / first populates the root so the
         * subdir binds resolve.  (This does NOT weaken hermeticity: the
         * read-only binds + Landlock spec still gate what the recipe can
         * touch; see build_landlock_spec.) */
        PUSH("--ro-bind"); PUSH("/"); PUSH("/");
        PUSH("--uid"); PUSH("1000");    /* never uid 0 inside, even when the
                                           caller is root; bwrap maps 1000 ->
                                           the caller's real uid, so workdir/
                                           store writes keep their ownership */
        PUSH("--gid"); PUSH("1000");
        /* Fresh private /tmp, pushed BEFORE every bind.  bwrap applies mount
         * ops in argv order: a tmpfs pushed AFTER the binds would shadow any
         * store/src/workdir living under /tmp (the classic "Can't chdir ...
         * No such file or directory" — the bind dest is covered by the empty
         * tmpfs).  With tmpfs first, a later bind whose dest falls under /tmp
         * simply gets its mountpoint auto-created inside the fresh tmpfs,
         * while bind SOURCES are resolved in the ORIGINAL namespace (bwrap
         * pre-opens them via its original-root proc fd), so they stay
         * reachable either way.  The LANDLOCK_SPEC's /tmp:rwc entry unveils
         * this tmpfs, not the host /tmp. */
        PUSH("--tmpfs"); PUSH("/tmp");
        PUSH("--ro-bind"); PUSH(store_root); PUSH(store_root);
        PUSH("--ro-bind"); PUSH("/usr"); PUSH("/usr");
        PUSH("--ro-bind"); PUSH("/bin"); PUSH("/bin");
        PUSH("--ro-bind"); PUSH("/lib"); PUSH("/lib");
        if (is_dir2("/lib64")) { PUSH("--ro-bind"); PUSH("/lib64"); PUSH("/lib64"); }
        if (src_ro && src_ro[0]) { PUSH("--ro-bind"); PUSH(src_ro); PUSH(src_ro); }
        /* workdir (under <store_root>.build) is OUTSIDE the ro-bound store:
         * a rw bind nested under a ro bind is unconstructable in bwrap, so
         * store.c relocates the scratch dir to a sibling of the store.  It
         * is mounted at the SHORT, fixed sandbox path /build: recipes run
         * relative to their cwd, the fixed path keeps the LANDLOCK_SPEC
         * clear of stage3's 256-byte budget (the host scratch path alone —
         * store + ".build/" + 64 hex + name + pid — can approach it), and
         * a path outside /tmp and the store cannot be shadowed by any
         * other mount op.  The store and src keep their HOST paths: deps
         * are reached via FX_DEP_* store paths, and recipes reference the
         * src tree by path. */
        /* --tmpfs /build FIRST: bwrap applies mounts in argv order and the
         * root is bound read-only (--ro-bind / /), so it cannot auto-create
         * the /build mountpoint for the workdir bind — a tmpfs does it for
         * us (verified on a btrfs-root host), then the workdir rw bind
         * overlays it.  Without this, bwrap dies "Can't mkdir /build:
         * Read-only file system". */
        PUSH("--tmpfs"); PUSH("/build");
        PUSH("--bind"); PUSH(workdir); PUSH("/build");
        PUSH("--chdir"); PUSH("/build");
        PUSH("--dev"); PUSH("/dev");
        PUSH("--proc"); PUSH("/proc");
        PUSH("--ro-bind"); PUSH(st3); PUSH("/init");
        PUSH("--");
        /* stage3's argv is POSITIONAL — it takes NO --promises/--landlock
         * flags: [promises...] [landlock-spec...] -- cmd.  Its parser puts
         * every word containing ':' into the spec and joins the rest into
         * the promise string, so PROMISES (no ':') and spec are each pushed
         * as ONE argv word. */
        PUSH("/init");
        PUSH(FXSTORE_PROMISES);
        PUSH(spec);
        PUSH("--");
        for (int i = 0; real_argv[i]; i++) PUSH(real_argv[i]);
        PUSH(NULL);
        #undef PUSH
        if (oom) { fprintf(stderr, "fxstore: out of memory building bwrap argv\n"); _exit(127); }

        if (!g_bwrap_path) {
            /* bwrap was not resolvable at startup: LOUD fallback directly —
             * never execvp("bwrap"), whose PATH lookup recipes control. */
            fprintf(stderr,
                "\n*** fxstore: WARNING: bwrap not found — running NON-HERMETIC "
                "(unsandboxed): %s ***\n\n", real_argv[0]);
            fflush(stderr);
            if (chdir(workdir) != 0) {
                fprintf(stderr, "fxstore: chdir '%s' failed: %s\n", workdir, strerror(errno));
                _exit(127);
            }
            execvp(real_argv[0], real_argv);
            fprintf(stderr, "fxstore: exec '%s' failed: %s\n", real_argv[0], strerror(errno));
            _exit(127);
        }
        av[0] = g_bwrap_path;              /* argv[0] = the real binary */
        execvp(g_bwrap_path, av);          /* absolute path: no PATH search */
        fprintf(stderr, "fxstore: bwrap exec failed: %s\n", strerror(errno));
        _exit(127);
    }
    /* ── parent ── */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        fprintf(stderr, "fxstore: waitpid failed: %s\n", strerror(errno));
        return 2;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 2;                             /* signaled */
}

/* ─── run_action (dhake.c 453-557, ported) ─────────────────────────────── */

static int run_action(Action *a, const char *workdir, const char *src_ro,
                      const char *store_root) {
    switch (a->kind) {
    case ACT_SHELL: {
        printf("%s\n", a->a);           /* echo, like make */
        fflush(stdout);
        char *sh_argv[4] = { "/bin/sh", "-c", a->a, NULL };
        return run_sandboxed(workdir, src_ro, store_root, sh_argv);
    }
    case ACT_COPY: {
        printf("cp %s %s\n", a->a, a->b);
        fflush(stdout);
        char *from = resolve_path(a->a, workdir);
        char *to   = resolve_path(a->b, workdir);
        bool ok = from && to && copy_file(from, to);
        free(from); free(to);
        return ok ? 0 : 1;
    }
    case ACT_MKDIR: {
        printf("mkdir %s\n", a->a);
        fflush(stdout);
        char *p = resolve_path(a->a, workdir);
        int rc = 1;
        if (p) {
            if (mkdir(p, 0755) != 0 && errno != EEXIST)
                fprintf(stderr, "fxstore: mkdir: %s\n", strerror(errno));
            else rc = 0;
        }
        free(p);
        return rc;
    }
    case ACT_RM: {
        printf("rm %s\n", a->a);
        fflush(stdout);
        char *p = resolve_path(a->a, workdir);
        int rc = 1;
        if (p) {
            if (remove(p) != 0 && errno != ENOENT)
                fprintf(stderr, "fxstore: rm: %s\n", strerror(errno));
            else rc = 0;
        }
        free(p);
        return rc;
    }
    case ACT_TOUCH: {
        printf("touch %s\n", a->a);
        fflush(stdout);
        char *p = resolve_path(a->a, workdir);
        bool ok = p && touch_file(p);
        free(p);
        return ok ? 0 : 1;
    }
    case ACT_MOVE: {
        printf("mv %s %s\n", a->a, a->b);
        fflush(stdout);
        char *from = resolve_path(a->a, workdir);
        char *to   = resolve_path(a->b, workdir);
        int rc = 1;
        if (from && to) {
            if (rename(from, to) != 0)
                fprintf(stderr, "fxstore: move: %s\n", strerror(errno));
            else rc = 0;
        }
        free(from); free(to);
        return rc;
    }
    case ACT_SYMLINK: {
        printf("ln -s %s %s\n", a->a, a->b);
        fflush(stdout);
        char *from = resolve_path(a->a, workdir);
        char *to   = resolve_path(a->b, workdir);
        int rc = 1;
        if (from && to) {
            if (symlink(from, to) != 0)
                fprintf(stderr, "fxstore: symlink: %s\n", strerror(errno));
            else rc = 0;
        }
        free(from); free(to);
        return rc;
    }
    case ACT_CHMOD: {
        printf("chmod %s %s\n", a->b, a->a);
        fflush(stdout);
        char *p = resolve_path(a->a, workdir);
        int rc = 1;
        if (p) {
            char *end = NULL;
            errno = 0;
            long mode = strtol(a->b, &end, 8);
            if (errno != 0 || end == a->b || *end != '\0' || mode < 0 || mode > 07777)
                fprintf(stderr, "fxstore: chmod: invalid mode '%s' (expected octal 0..7777)\n", a->b);
            else if (chmod(p, (mode_t)mode) != 0)
                fprintf(stderr, "fxstore: chmod: %s\n", strerror(errno));
            else rc = 0;
        }
        free(p);
        return rc;
    }
    case ACT_ECHO: {
        printf("%s\n", a->a);
        fflush(stdout);
        return 0;
    }
    case ACT_ENV: {
        printf("export %s=%s\n", a->a, a->b);
        fflush(stdout);
        setenv(a->a, a->b, 1);
        return 0;
    }
    case ACT_RUN: {
        printf("%s", a->av[0]);
        for (int i = 1; i < a->nav; i++) printf(" %s", a->av[i]);
        printf("\n");
        fflush(stdout);
        return run_sandboxed(workdir, src_ro, store_root, a->av);
    }
    }
    return 2;
}

/* ─── fx_build_recipe ──────────────────────────────────────────────────── */

/* Environment snapshot/restore: the Env action mutates THIS process's
 * environment (setenv) and FX_DEP_* are set per package; without a
 * save/restore, package A's exports leak into package B's recipe when both
 * are built in one process — same store path, different build environment
 * (silent nondeterminism).  Snapshot every entry on entry, restore on exit. */
typedef struct { char **v; int n; } EnvSnap;

static void env_snap(EnvSnap *s) {
    int n = 0;
    for (char **e = environ; e && *e; e++) n++;
    s->v = malloc((size_t)(n ? n : 1) * sizeof *s->v);
    s->n = n;
    int i = 0;
    for (char **e = environ; e && *e; e++)
        s->v[i++] = strdup(*e);          /* best-effort; NULL on OOM */
}

static void env_snap_free(EnvSnap *s) {
    for (int i = 0; i < s->n; i++) free(s->v[i]);
    free(s->v);
}

static void env_restore(const EnvSnap *s) {
    /* collect current var NAMES first (unsetenv mutates environ) */
    char **cur = NULL;
    int nc = 0, cap = 0;
    for (char **e = environ; e && *e; e++) {
        const char *eq = strchr(*e, '=');
        size_t len = eq ? (size_t)(eq - *e) : strlen(*e);
        char *name = malloc(len + 1);
        if (!name) continue;
        memcpy(name, *e, len);
        name[len] = '\0';
        if (nc == cap) {
            cap = cap ? cap * 2 : 16;
            char **t = realloc(cur, (size_t)cap * sizeof *t);
            if (!t) { free(name); continue; }
            cur = t;
        }
        cur[nc++] = name;
    }
    for (int i = 0; i < nc; i++) { unsetenv(cur[i]); free(cur[i]); }
    free(cur);
    for (int i = 0; i < s->n; i++) {
        if (!s->v[i]) continue;
        char *eq = strchr(s->v[i], '=');
        if (!eq) continue;
        *eq = '\0';
        setenv(s->v[i], eq + 1, 1);
        *eq = '=';
    }
}

int fx_build_recipe(const Package *p, const char *workdir,
                    char *const *dep_names, char *const *dep_paths, int ndeps,
                    const char *store_root, char *err, size_t errcap) {
    if (!p || !workdir || !store_root) {
        fx_err(err, errcap, "internal: null args to fx_build_recipe");
        return -1;
    }

    EnvSnap snap;
    env_snap(&snap);

    if (set_dep_env(dep_names, dep_paths, ndeps) != 0) {
        env_restore(&snap);
        env_snap_free(&snap);
        return fx_err(err, errcap, "out of memory setting FX_DEP_* env");
    }

    /* Path sources are mounted read-only into the sandbox at their own
       path; Fetch sources have no local tree (network is off in the
       sandbox; fetching is post-MVP). */
    const char *src_ro = (p->src.kind == SRC_PATH) ? p->src.path : NULL;

    int rc = 0;
    for (Action *a = p->recipe; a; a = a->next) {
        rc = run_action(a, workdir, src_ro, store_root);
        if (rc != 0) break;
    }
    env_restore(&snap);
    env_snap_free(&snap);
    return rc;
}

/* ─── print_action (dhake.c 560-579, verbatim) ─────────────────────────── */

void fx_print_action(const Action *a) {
    switch (a->kind) {
    case ACT_SHELL: printf("%s\n", a->a); break;
    case ACT_COPY:  printf("cp %s %s\n", a->a, a->b); break;
    case ACT_MKDIR: printf("mkdir %s\n", a->a); break;
    case ACT_RM:    printf("rm %s\n", a->a); break;
    case ACT_TOUCH: printf("touch %s\n", a->a); break;
    case ACT_MOVE:  printf("mv %s %s\n", a->a, a->b); break;
    case ACT_SYMLINK: printf("ln -s %s %s\n", a->a, a->b); break;
    case ACT_CHMOD: printf("chmod %s %s\n", a->b, a->a); break;
    case ACT_ECHO:  printf("echo %s\n", a->a); break;
    case ACT_ENV:   printf("export %s=%s\n", a->a, a->b); break;
    case ACT_RUN: {
        printf("%s", a->av[0]);
        for (int i = 1; i < a->nav; i++) printf(" %s", a->av[i]);
        printf("\n");
        break;
    }
    }
}
