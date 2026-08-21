/* main.c — fxstore CLI entry point (U6).
 *
 *   fxstore init [dir]                  scaffold a project (worked-example package-set.dhall)
 *   fxstore build [--store DIR] [<pkg>...]  build the closure of <pkg>... (all when none)
 *                                       into the store at DIR, print each store path
 *   fxstore query <pkg> [--store DIR]   print <pkg>'s closure names + its store path
 *   fxstore gc <root> [--store DIR]     prune store dirs/facts unreachable from <root>
 *
 * Glue over the five core units: package-set walker (packageset.c), canonical
 * serializer + sha256 store path (derivation.c), datalog closure fixpoint +
 * topo-sort (closure.c), store write + txn metadata + GC (store.c), recipe
 * executor + bwrap (build.c).  build/query load "package-set.dhall" from the
 * current working directory; relative <Path> sources are canonicalized against
 * it at load time (packageset.c realpath fix).
 *
 * Trusted-author model for pure-FS actions in v1 (MVP): the pure filesystem
 * actions (Copy/Mkdir/Rm/Touch/Move/Symlink/Chmod/Echo/Env) run in-process in
 * the store process, while the two EXECUTING actions (Shell/Run) are bwrap
 * sandboxed (loud non-hermetic fallback when bwrap is absent).
 */
#include "fxstore.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEFAULT_STORE_ROOT "/fx/store"
#define ERR_CAP 2048

static void usage(FILE *out) {
    fprintf(out,
        "fxstore — content-addressed build store (M0/M1/M2 MVP)\n"
        "usage:\n"
        "  fxstore init [dir]                     scaffold a project dir\n"
        "  fxstore build [--store DIR] [<pkg>...]  build the closure of <pkg>...\n"
        "                                          (all packages when none), print store paths\n"
        "  fxstore query <pkg> [--store DIR]      print <pkg>'s closure names + store path\n"
        "  fxstore gc <root> [--store DIR]        prune store dirs/facts unreachable from <root>\n"
        "options:\n"
        "  --store DIR   store root (default: %s)\n"
        "  -h, --help    show this help\n"
        "build/query load \"package-set.dhall\" from the current directory.\n",
        DEFAULT_STORE_ROOT);
}

/* ─── CLI arg parsing ───────────────────────────────────────────────────── */

typedef struct {
    const char *store_root;   /* NULL when not given */
    char **pos;               /* positional args (borrowed pointers) */
    int npos;
} CliArgs;

/* Parse argv[start..argc).  Strips --store DIR / --store=DIR and -h/--help.
 * Returns 0 on success, 1 when -h/--help was shown (usage already printed),
 * -1 on a parse error (message already printed). */
static int parse_args(char **argv, int argc, int start, CliArgs *c) {
    memset(c, 0, sizeof *c);
    c->pos = malloc((size_t)(argc - start + 1) * sizeof *c->pos);
    if (!c->pos) { fprintf(stderr, "fxstore: out of memory\n"); return -1; }
    for (int i = start; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--store")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "fxstore: --store requires a directory argument\n");
                free(c->pos); c->pos = NULL;
                return -1;
            }
            c->store_root = argv[++i];
        } else if (!strncmp(a, "--store=", 8)) {
            c->store_root = a + 8;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            free(c->pos); c->pos = NULL;
            return 1;
        } else {
            c->pos[c->npos++] = (char *)a;
        }
    }
    return 0;
}

static void cli_free(CliArgs *c) { free(c->pos); c->pos = NULL; }

/* ─── Store-path computation over the closure (deps-first) ─────────────── */

typedef struct {
    Package *p;
    char *path;               /* store path of p */
    char *hash;               /* derivation sha256 (hex64) */
} PathEntry;

static const char *path_of(const PathEntry *es, int ne, const char *name) {
    for (int i = 0; i < ne; i++)
        if (!strcmp(es[i].p->name, name)) return es[i].path;
    return NULL;
}

static void paths_free(PathEntry *es, int n) {
    for (int i = 0; i < n; i++) { free(es[i].path); free(es[i].hash); }
    free(es);
}

/* Compute the closure of roots (all packages when nroots == 0) and the store
 * path of every package in deps-first topo order.  Each package's hash embeds
 * its direct deps' store paths (the Nix-style fixed point), so the dep paths
 * are tracked as we walk the topo order.  Returns 0/-1 (err set). */
static int compute_paths(const PackageSet *ps, struct dl_db *db,
                         char *const *roots, int nroots, const char *store_root,
                         PathEntry **out, int *n_out, char *err, size_t errcap) {
    if (fx_closure_compute(db, ps, roots, nroots, err, errcap) != 0) return -1;

    char **names = NULL;
    int nn = 0;
    if (fx_closure_names(db, &names, &nn, err, errcap) != 0) return -1;

    Package **ord = NULL;
    int no = 0;
    if (fx_topo_order(ps, names, nn, &ord, &no, err, errcap) != 0) {
        for (int i = 0; i < nn; i++) free(names[i]);
        free(names);
        return -1;
    }
    for (int i = 0; i < nn; i++) free(names[i]);
    free(names);

    PathEntry *es = calloc((size_t)(no ? no : 1), sizeof *es);
    if (!es) { free(ord); return fx_err(err, errcap, "out of memory"); }

    int rc = 0;
    for (int i = 0; i < no; i++) {
        Package *p = ord[i];
        char **dep_paths = p->ndeps ? malloc((size_t)p->ndeps * sizeof *dep_paths) : NULL;
        if (p->ndeps && !dep_paths) { fx_err(err, errcap, "out of memory"); rc = -1; break; }
        int dep_ok = 1;
        for (int j = 0; j < p->ndeps; j++) {
            dep_paths[j] = (char *)path_of(es, i, p->deps[j]);
            if (!dep_paths[j]) {
                fx_err(err, errcap, "internal: dep '%s' of '%s' not resolved (topo order broken)",
                       p->deps[j], p->name);
                dep_ok = 0;
                break;
            }
        }
        if (dep_ok) {
            char h[65], path[PATH_MAX];
            if (fx_derivation_hash(p, dep_paths, p->ndeps, h, err, errcap) == 0) {
                fx_store_path_of(store_root, h, p->name, path, sizeof path);
                es[i].p = p;
                es[i].hash = strdup(h);
                es[i].path = strdup(path);
                if (!es[i].hash || !es[i].path) {
                    fx_err(err, errcap, "out of memory");
                    rc = -1;
                }
            } else {
                rc = -1;
            }
        }
        free(dep_paths);
        if (rc != 0) break;
    }
    free(ord);
    if (rc != 0) { paths_free(es, no); *out = NULL; *n_out = 0; return -1; }
    *out = es;
    *n_out = no;
    return 0;
}

/* ─── Commands ──────────────────────────────────────────────────────────── */

static int cmd_build(char **argv, int argc, int start) {
    CliArgs c;
    int pr = parse_args(argv, argc, start, &c);
    if (pr != 0) { if (pr == 1) return 0; return 2; }
    const char *store_root = c.store_root ? c.store_root : DEFAULT_STORE_ROOT;

    PackageSet ps;
    char err[ERR_CAP];
    if (fx_packageset_load(&ps, "package-set.dhall", err, sizeof err) != 0) {
        fprintf(stderr, "fxstore: %s\n", err);
        cli_free(&c);
        return 1;
    }
    FxStore *s = fx_store_open(store_root, err, sizeof err);
    if (!s) {
        fprintf(stderr, "fxstore: %s\n", err);
        fx_packageset_free(&ps);
        cli_free(&c);
        return 1;
    }

    PathEntry *es = NULL;
    int ne = 0;
    if (compute_paths(&ps, fx_store_db(s), c.pos, c.npos, store_root,
                      &es, &ne, err, sizeof err) != 0) {
        fprintf(stderr, "fxstore: %s\n", err);
        fx_store_close(s);
        fx_packageset_free(&ps);
        cli_free(&c);
        return 1;
    }

    int rc = 0;
    for (int i = 0; i < ne && rc == 0; i++) {
        Package *p = es[i].p;
        char **dep_paths = p->ndeps ? malloc((size_t)p->ndeps * sizeof *dep_paths) : NULL;
        if (p->ndeps && !dep_paths) {
            fprintf(stderr, "fxstore: out of memory\n");
            rc = 1;
            break;
        }
        int dep_ok = 1;
        for (int j = 0; j < p->ndeps; j++) {
            dep_paths[j] = (char *)path_of(es, ne, p->deps[j]);
            if (!dep_paths[j]) {
                fprintf(stderr, "fxstore: internal: dep '%s' of '%s' not resolved\n",
                        p->deps[j], p->name);
                dep_ok = 0;
                rc = 1;
                break;
            }
        }
        if (dep_ok) {
            printf("fxstore: building %s\n", p->name);
            if (fx_store_build(s, p, es[i].hash, es[i].path, p->deps,
                               dep_paths, p->ndeps, err, sizeof err) != 0) {
                fprintf(stderr, "fxstore: build %s failed: %s\n", p->name, err);
                rc = 1;
            } else {
                printf("fxstore: built %s\n", es[i].path);
            }
        }
        free(dep_paths);
    }

    if (rc == 0) {
        if (fx_store_publish(s, err, sizeof err) != 0) {
            fprintf(stderr, "fxstore: %s\n", err);
            rc = 1;
        }
    }

    paths_free(es, ne);
    fx_store_close(s);
    fx_packageset_free(&ps);
    cli_free(&c);
    return rc;
}

static int cmd_query(char **argv, int argc, int start) {
    CliArgs c;
    int pr = parse_args(argv, argc, start, &c);
    if (pr != 0) { if (pr == 1) return 0; return 2; }
    if (c.npos != 1) {
        fprintf(stderr, "fxstore: query requires exactly one package name\n\n");
        cli_free(&c);
        usage(stderr);
        return 2;
    }
    const char *pkg = c.pos[0];
    const char *store_root = c.store_root ? c.store_root : DEFAULT_STORE_ROOT;

    PackageSet ps;
    char err[ERR_CAP];
    if (fx_packageset_load(&ps, "package-set.dhall", err, sizeof err) != 0) {
        fprintf(stderr, "fxstore: %s\n", err);
        cli_free(&c);
        return 1;
    }
    FxStore *s = fx_store_open(store_root, err, sizeof err);
    if (!s) {
        fprintf(stderr, "fxstore: %s\n", err);
        fx_packageset_free(&ps);
        cli_free(&c);
        return 1;
    }

    char *roots[1] = { (char *)pkg };
    PathEntry *es = NULL;
    int ne = 0;
    if (compute_paths(&ps, fx_store_db(s), roots, 1, store_root,
                      &es, &ne, err, sizeof err) != 0) {
        fprintf(stderr, "fxstore: %s\n", err);
        fx_store_close(s);
        fx_packageset_free(&ps);
        cli_free(&c);
        return 1;
    }

    /* closure names (the materialized fixpoint, read through the snapshot) */
    char **names = NULL;
    int nn = 0;
    if (fx_closure_names(fx_store_db(s), &names, &nn, err, sizeof err) != 0) {
        fprintf(stderr, "fxstore: %s\n", err);
        paths_free(es, ne);
        fx_store_close(s);
        fx_packageset_free(&ps);
        cli_free(&c);
        return 1;
    }
    printf("fxstore: closure of '%s' (%d package(s)):\n", pkg, nn);
    for (int i = 0; i < nn; i++) printf("  %s\n", names[i]);
    for (int i = 0; i < nn; i++) free(names[i]);
    free(names);

    const char *path = path_of(es, ne, pkg);
    if (path)
        printf("fxstore: store path: %s\n", path);
    else {
        fprintf(stderr, "fxstore: no store path for '%s'\n", pkg);
        paths_free(es, ne);
        fx_store_close(s);
        fx_packageset_free(&ps);
        cli_free(&c);
        return 1;
    }

    paths_free(es, ne);
    fx_store_close(s);
    fx_packageset_free(&ps);
    cli_free(&c);
    return 0;
}

static int cmd_gc(char **argv, int argc, int start) {
    CliArgs c;
    int pr = parse_args(argv, argc, start, &c);
    if (pr != 0) { if (pr == 1) return 0; return 2; }
    if (c.npos != 1) {
        fprintf(stderr, "fxstore: gc requires exactly one root package\n\n");
        cli_free(&c);
        usage(stderr);
        return 2;
    }
    const char *root = c.pos[0];
    const char *store_root = c.store_root ? c.store_root : DEFAULT_STORE_ROOT;

    char err[ERR_CAP];
    FxStore *s = fx_store_open(store_root, err, sizeof err);
    if (!s) {
        fprintf(stderr, "fxstore: %s\n", err);
        cli_free(&c);
        return 1;
    }
    int rc = fx_store_gc(s, root, err, sizeof err);
    if (rc != 0) fprintf(stderr, "fxstore: %s\n", err);
    fx_store_close(s);
    cli_free(&c);
    return rc != 0 ? 1 : 0;
}

/* ─── init: scaffold a worked-example project ──────────────────────────── */

static int mkdir_if_missing(const char *dir) {
    struct stat st;
    if (mkdir(dir, 0755) == 0) return 0;
    if (errno == EEXIST && stat(dir, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
    return -1;
}

static int write_file(const char *path, const char *content,
                      char *errbuf, size_t errcap) {
    FILE *f = fopen(path, "w");
    if (!f) { snprintf(errbuf, errcap, "cannot create '%s': %s", path, strerror(errno)); return -1; }
    if (fputs(content, f) == EOF || fclose(f) != 0) {
        snprintf(errbuf, errcap, "cannot write '%s': %s", path, strerror(errno));
        return -1;
    }
    return 0;
}

#define TEMPLATE_PACKAGE_SET \
    "-- fxstore worked-example package set (lib -> app)\n" \
    "--\n" \
    "--   Src     = < Path : Text | Fetch : { url : Text, hash : Text } >\n" \
    "--   Build   = { target : Text, recipe : List Action }\n" \
    "--   Package = { name : Text, version : Text, src : Src, deps : List Text, build : Build }\n" \
    "--   body    = { packages : List Package } : PackageSet\n" \
    "--\n" \
    "-- Relative < Path = ... > sources are resolved against this file's\n" \
    "-- directory at load time.  Recipes are self-contained (pure-filesystem\n" \
    "-- actions run in-process; Shell/Run run under bwrap).\n" \
    "let Action = < Shell : Text | Copy : { from : Text, to : Text } | Mkdir : Text | Rm : Text | Touch : Text | Move : { from : Text, to : Text } | Symlink : { from : Text, to : Text } | Chmod : { path : Text, mode : Text } | Echo : Text | Env : { key : Text, value : Text } | Run : { argv : List Text } >\n" \
    "let Src = < Path : Text | Fetch : { url : Text, hash : Text } >\n" \
    "let Build = { target : Text, recipe : List Action }\n" \
    "let Package = { name : Text, version : Text, src : Src, deps : List Text, build : Build }\n" \
    "let PackageSet = { packages : List Package }\n" \
    "in { packages =\n" \
    "     [ { name = \"lib\",\n" \
    "         version = \"1.0.0\",\n" \
    "         src = < Path = \"src/lib\" >,\n" \
    "         deps = [] : List Text,\n" \
    "         build = { target = \"lib\",\n" \
    "                   recipe = [ < Touch = \"lib.txt\" >, < Echo = \"built lib\" > ] } },\n" \
    "       { name = \"app\",\n" \
    "         version = \"1.0.0\",\n" \
    "         src = < Path = \"src/app\" >,\n" \
    "         deps = [ \"lib\" ],\n" \
    "         build = { target = \"app\",\n" \
    "                   recipe = [ < Touch = \"app.txt\" >, < Echo = \"built app\" > ] } } ] } : PackageSet\n"

static int cmd_init(char **argv, int argc, int start) {
    (void)argv; (void)argc;
    const char *dir = start < argc ? argv[start] : ".";
    char err[ERR_CAP];

    char ps_path[PATH_MAX], src_dir[PATH_MAX], lib_dir[PATH_MAX], app_dir[PATH_MAX];
    char lib_file[PATH_MAX], app_file[PATH_MAX];
    if (strcmp(dir, ".") == 0) {
        snprintf(ps_path, sizeof ps_path, "package-set.dhall");
        snprintf(src_dir, sizeof src_dir, "src");
        snprintf(lib_dir, sizeof lib_dir, "src/lib");
        snprintf(app_dir, sizeof app_dir, "src/app");
        snprintf(lib_file, sizeof lib_file, "src/lib/hello.txt");
        snprintf(app_file, sizeof app_file, "src/app/hello.txt");
    } else {
        if (snprintf(ps_path, sizeof ps_path, "%s/package-set.dhall", dir) >= (int)sizeof ps_path ||
            snprintf(src_dir, sizeof src_dir, "%s/src", dir) >= (int)sizeof src_dir ||
            snprintf(lib_dir, sizeof lib_dir, "%s/src/lib", dir) >= (int)sizeof lib_dir ||
            snprintf(app_dir, sizeof app_dir, "%s/src/app", dir) >= (int)sizeof app_dir ||
            snprintf(lib_file, sizeof lib_file, "%s/src/lib/hello.txt", dir) >= (int)sizeof lib_file ||
            snprintf(app_file, sizeof app_file, "%s/src/app/hello.txt", dir) >= (int)sizeof app_file) {
            fprintf(stderr, "fxstore: project path too long\n");
            return 1;
        }
    }

    if (mkdir_if_missing(dir) != 0) {
        fprintf(stderr, "fxstore: cannot create project dir '%s': %s\n", dir, strerror(errno));
        return 1;
    }
    if (mkdir_if_missing(src_dir) != 0) {
        fprintf(stderr, "fxstore: cannot create source dir '%s': %s\n", src_dir, strerror(errno));
        return 1;
    }
    if (mkdir_if_missing(lib_dir) != 0 || mkdir_if_missing(app_dir) != 0) {
        fprintf(stderr, "fxstore: cannot create source dirs: %s\n", strerror(errno));
        return 1;
    }
    if (write_file(ps_path, TEMPLATE_PACKAGE_SET, err, sizeof err) != 0) {
        fprintf(stderr, "fxstore: %s\n", err);
        return 1;
    }
    if (write_file(lib_file, "hello from lib\n", err, sizeof err) != 0 ||
        write_file(app_file, "hello from app\n", err, sizeof err) != 0) {
        fprintf(stderr, "fxstore: %s\n", err);
        return 1;
    }

    printf("fxstore: initialized project in '%s'\n", dir);
    printf("  %s\n", ps_path);
    printf("  %s/  (lib source tree)\n", lib_dir);
    printf("  %s/  (app source tree)\n", app_dir);
    printf("  e.g.  cd '%s' && fxstore build --store /tmp/store app\n", dir);
    return 0;
}

/* ─── main ──────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    const char *cmd = argc > 1 ? argv[1] : NULL;

    /* Resolve the stage3 sandbox binary path ONCE, before any package-set
     * is loaded — recipes can set arbitrary env vars via the Env action,
     * and the FXSTORE_STAGE3 override must be settled before they run. */
    fx_stage3_resolve();
    fx_bwrap_resolve();      /* lock the bwrap path before recipes run */
    fx_cosmo_resolve();      /* lock the cosmocc toolchain tree before recipes run */

    if (!cmd || !strcmp(cmd, "-h") || !strcmp(cmd, "--help")) {
        usage(cmd ? stdout : stderr);
        return cmd ? 0 : 2;
    }

    if (strcmp(cmd, "init") == 0) return cmd_init(argv, argc, 2);
    if (strcmp(cmd, "build") == 0) return cmd_build(argv, argc, 2);
    if (strcmp(cmd, "query") == 0) return cmd_query(argv, argc, 2);
    if (strcmp(cmd, "gc") == 0) return cmd_gc(argv, argc, 2);

    fprintf(stderr, "fxstore: unknown command '%s'\n\n", cmd);
    usage(stderr);
    return 2;
}
