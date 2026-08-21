/* build.c — (U5) recipe executor + bwrap sandbox.
 *
 * run_action/print_action are PORTED from dhake/src/dhake.c (453-557 /
 * 560-579) with the two fxstore changes from the plan (Decision 6):
 *   (a) relative output paths resolve against the package's temp BUILD
 *       dir (workdir — the dir that becomes the store path); each direct
 *       dep's store path is exported as FX_DEP_<NAME> (read-only content:
 *       deps were built before this package and are content-addressed);
 *   (b) the two EXECUTING actions (Shell, Run) run under a bwrap sandbox:
 *       unshare-all (network OFF), die-with-parent, the store and the
 *       toolchain dirs read-only, the workdir writable, /dev + /proc
 *       mounted.  The pure-filesystem actions (Copy/Mkdir/Rm/Touch/Move/
 *       Symlink/Chmod/Echo/Env) are trusted declarative ops and run
 *       in-process without a sandbox.
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

/* fork + exec real_argv under bwrap; on ENOENT fall back LOUDLY to plain
 * exec in the workdir.  Returns the child's exit code (2 if signaled). */
static int run_sandboxed(const char *workdir, const char *src_ro,
                         const char *store_root, char **real_argv) {
    pid_t pid = fork();
    if (pid == -1) {
        fprintf(stderr, "fxstore: fork failed: %s\n", strerror(errno));
        return 2;
    }
    if (pid == 0) {
        /* ── child ── build: bwrap [binds...] -- real_argv... */
        char **av = NULL;
        int n = 0, cap = 0;
        int oom = 0;
        #define PUSH(s) do { if (argv_push(&av, &n, &cap, (s)) != 0) oom = 1; } while (0)
        PUSH("bwrap");
        PUSH("--unshare-all");          /* no net, no IPC, no new mounts... */
        PUSH("--die-with-parent");
        PUSH("--ro-bind"); PUSH(store_root); PUSH(store_root);
        PUSH("--ro-bind"); PUSH("/usr"); PUSH("/usr");
        PUSH("--ro-bind"); PUSH("/bin"); PUSH("/bin");
        PUSH("--ro-bind"); PUSH("/lib"); PUSH("/lib");
        if (is_dir2("/lib64")) { PUSH("--ro-bind"); PUSH("/lib64"); PUSH("/lib64"); }
        if (src_ro && src_ro[0]) { PUSH("--ro-bind"); PUSH(src_ro); PUSH(src_ro); }
        PUSH("--bind"); PUSH(workdir); PUSH(workdir);
        PUSH("--chdir"); PUSH(workdir);
        PUSH("--dev"); PUSH("/dev");
        PUSH("--proc"); PUSH("/proc");
        PUSH("--");
        for (int i = 0; real_argv[i]; i++) PUSH(real_argv[i]);
        PUSH(NULL);
        #undef PUSH
        if (oom) { fprintf(stderr, "fxstore: out of memory building bwrap argv\n"); _exit(127); }

        execvp("bwrap", av);
        if (errno == ENOENT) {
            /* LOUD, never-silent non-hermetic fallback */
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
