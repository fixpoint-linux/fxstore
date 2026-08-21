/* store.c — (U4) content store layout + atomic install + metadata-LAST
 * txn commit + pinned-snapshot GC.
 *
 * LAYOUT: <root>/ holds content dirs "<hex64>-<name>/" and the metadata DB
 * <root>/.db (dl_open); build scratch dirs live in the SIBLING directory
 * <root>.build/ — OUTSIDE the store, because run_sandboxed ro-binds the
 * whole store read-only and a rw workdir nested under that ro bind cannot
 * be mounted by bwrap.  The DB's `store(hash,name)` relation (arity 2,
 * interned syms) is the durable committed-store index.
 *
 * BUILD ORDER (the crash-consistency invariant):
 *   1. run the recipe into <root>.build/<hash>-<name>-<pid>  (NOT final)
 *   2. atomically rename() the temp dir to <root>/<hash>-<name>
 *      (same filesystem by construction: <root>.build is a sibling whose
 *      st_dev is checked against <root>'s at store-open time)
 *   3. ONLY THEN commit the metadata txn (dl_txn_begin -> dl_txn_add_fact
 *      -> dl_txn_commit): one WAL append + one fsync is THE atomic commit
 *      point.
 * A crash before (3) leaves an orphan dir with no metadata — the safe
 * direction: GC reaps it, and no metadata ever points at a missing path.
 * A crash between (2) and (3) is repaired by the next build of the same
 * derivation: the final path already exists, the build is ADOPTED and only
 * the missing metadata fact is committed (content addressing makes the
 * rebuild byte-identical, so adoption is sound).
 *
 * GC reads from a PINNED snapshot (dl_snapshot_versions +
 * dl_query_version): the pinned version is an immutable on-disk view, so a
 * concurrent build publishing newer snapshots can never race the sweep.
 * Liveness is NAME-level: a dir/fact is live iff its package name is
 * reachable from the gc root over the pinned dep facts.  Deletion order is
 * METADATA FIRST (one atomic txn removing the unreachable store facts),
 * THEN the dirs — so a crash mid-GC also leaves only reapable orphan dirs,
 * never dangling metadata.
 */
#include "fxstore.h"
#include "dl.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define FX_PATH_MAX 4096

struct FxStore {
    char root[FX_PATH_MAX];   /* no trailing '/' */
    char build[FX_PATH_MAX];  /* <root>.build — scratch area, no trailing '/' */
    struct dl_db *db;
};

/* ─── Small filesystem helpers ─────────────────────────────────────────── */

static int is_dir(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* recursive delete; does NOT follow symlinks: lstat each entry and recurse
 * only into real directories, so a symlink child (even one pointing at a
 * directory outside the store) is unlinked, never traversed.  Without the
 * lstat guard a store dir containing `ln -s /victim link` makes GC or the
 * failure-path cleanup delete the CONTENTS of /victim. */
static void rm_rf(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return;      /* gone */
    if (S_ISDIR(st.st_mode)) {
        /* clean-copy artifacts mirror SOURCE modes, so they may contain
         * non-writable dirs (e.g. a `chmod -R a-w` vendored tree); make this
         * dir owner-writable (best-effort, we own everything here) so the
         * remove() of its children below can succeed. */
        chmod(path, 0700);
        DIR *d = opendir(path);
        if (d) {
            struct dirent *e;
            while ((e = readdir(d)) != NULL) {
                if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
                char child[FX_PATH_MAX];
                if (snprintf(child, sizeof child, "%s/%s", path, e->d_name) >= (int)sizeof child)
                    continue;
                rm_rf(child);
            }
            closedir(d);
        }
    }
    remove(path);               /* rmdir for dirs, unlink for files/links */
}

/* best-effort fsync of a directory (durability of a rename before the
 * metadata commit).  Failures are non-fatal: the metadata txn remains the
 * atomic commit point. */
static void fsync_dir_best_effort(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    fsync(fd);
    close(fd);
}

/* ─── Open / close ─────────────────────────────────────────────────────── */

FxStore *fx_store_open(const char *root, char *err, size_t errcap) {
    if (!root || !root[0]) { fx_err(err, errcap, "store root must be non-empty"); return NULL; }

    FxStore *s = calloc(1, sizeof *s);
    if (!s) { fx_err(err, errcap, "out of memory"); return NULL; }

    /* normalize: strip trailing slashes (but keep a bare "/") */
    size_t n = strlen(root);
    while (n > 1 && root[n - 1] == '/') n--;
    if (n >= sizeof s->root) { fx_err(err, errcap, "store root too long"); free(s); return NULL; }
    memcpy(s->root, root, n);
    s->root[n] = '\0';

    if (mkdir(s->root, 0755) != 0 && errno != EEXIST) {
        fx_err(err, errcap, "cannot create store root '%s': %s", s->root, strerror(errno));
        free(s);
        return NULL;
    }
    if (!is_dir(s->root)) {
        fx_err(err, errcap, "store root '%s' is not a directory", s->root);
        free(s);
        return NULL;
    }

    char dbp[FX_PATH_MAX];
    if (snprintf(s->build, sizeof s->build, "%s%s", s->root, FX_BUILD_SUFFIX)
            >= (int)sizeof s->build ||
        snprintf(dbp, sizeof dbp, "%s/%s", s->root, FX_DB_SUBDIR) >= (int)sizeof dbp) {
        fx_err(err, errcap, "store path too long");
        free(s);
        return NULL;
    }
    /* Build scratch area: a SIBLING of the store root, never inside it —
       run_sandboxed ro-binds the whole store, so a rw workdir nested under
       it could not be mounted inside the bwrap sandbox.  It must sit on the
       SAME filesystem as the store root: the atomic install below
       rename()s <root>.build/<hash>-<name>-<pid> into <root>/<hash>-<name>,
       and rename(2) across filesystems fails with EXDEV.  Check the device
       ids here and fail loudly at open time instead of mid-build (a root
       that is itself a mount point puts the sibling on the parent fs — the
       one layout this rejects). */
    if (mkdir(s->build, 0755) != 0 && errno != EEXIST) {
        fx_err(err, errcap, "cannot create build dir '%s': %s", s->build, strerror(errno));
        free(s);
        return NULL;
    }
    if (!is_dir(s->build)) {
        fx_err(err, errcap, "build dir '%s' is not a directory", s->build);
        free(s);
        return NULL;
    }
    {
        struct stat st_root, st_build;
        if (stat(s->root, &st_root) != 0 || stat(s->build, &st_build) != 0) {
            fx_err(err, errcap, "cannot stat store root / build dir: %s", strerror(errno));
            free(s);
            return NULL;
        }
        if (st_root.st_dev != st_build.st_dev) {
            fx_err(err, errcap,
                   "build dir '%s' is on a different filesystem than the store "
                   "root '%s': the atomic install rename(2)s between them and "
                   "cannot cross filesystems; use a store root that is a plain "
                   "directory on the target filesystem",
                   s->build, s->root);
            free(s);
            return NULL;
        }
    }

    s->db = dl_open(dbp);
    if (!s->db) {
        fx_err(err, errcap, "cannot open store metadata db '%s'", dbp);
        free(s);
        return NULL;
    }
    /* the durable store index (idempotent declare) */
    if (dl_declare_relation(s->db, "store", 2) != 0) {
        fx_err(err, errcap, "cannot declare relation 'store'");
        dl_close(s->db);
        free(s);
        return NULL;
    }
    /* the clean-source artifact index (idempotent declare) */
    if (dl_declare_relation(s->db, "srcstore", 2) != 0) {
        fx_err(err, errcap, "cannot declare relation 'srcstore'");
        dl_close(s->db);
        free(s);
        return NULL;
    }
    return s;
}

void fx_store_close(FxStore *s) {
    if (!s) return;
    dl_close(s->db);
    free(s);
}

struct dl_db *fx_store_db(FxStore *s) { return s ? s->db : NULL; }
const char *fx_store_root(const FxStore *s) { return s ? s->root : ""; }

int fx_store_publish(FxStore *s, char *err, size_t errcap) {
    if (!s) return fx_err(err, errcap, "internal: null store");
    if (dl_publish_snapshot(s->db) != 0)
        return fx_err(err, errcap, "cannot publish store metadata snapshot");
    return 0;
}

/* ─── Metadata commit (the LAST step of a build) ───────────────────────── */

/* Commit store(hash,name) as one atomic txn (one WAL append + one fsync).
 * Idempotent: an already-committed fact is a no-op. */
static int commit_store_fact(FxStore *s, const char *hash, const char *name,
                             char *err, size_t errcap) {
    uint32_t cols[2] = { dl_intern_str(s->db, hash), dl_intern_str(s->db, name) };
    if (!cols[0] || !cols[1])
        return fx_err(err, errcap, "out of memory interning store fact");
    if (dl_lookup(s->db, "store", cols, 2))
        return 0;                              /* already committed */

    if (dl_txn_begin(s->db) != 0)
        return fx_err(err, errcap, "txn begin failed (another txn open?)");
    if (dl_txn_add_fact(s->db, "store", cols, 2) != 0 || dl_txn_commit(s->db) != 0) {
        dl_txn_rollback(s->db);
        return fx_err(err, errcap, "metadata commit failed for '%s-%s' "
                                   "(dir is an orphan; gc will reap it)", hash, name);
    }
    return 0;
}

/* Commit srcstore(hash,name) — the clean-source artifact index — as one
 * atomic txn, mirroring commit_store_fact exactly (idempotent no-op when the
 * fact is already present). */
static int commit_srcstore_fact(FxStore *s, const char *hash, const char *name,
                                char *err, size_t errcap) {
    uint32_t cols[2] = { dl_intern_str(s->db, hash), dl_intern_str(s->db, name) };
    if (!cols[0] || !cols[1])
        return fx_err(err, errcap, "out of memory interning srcstore fact");
    if (dl_lookup(s->db, "srcstore", cols, 2))
        return 0;                              /* already committed */

    if (dl_txn_begin(s->db) != 0)
        return fx_err(err, errcap, "txn begin failed (another txn open?)");
    if (dl_txn_add_fact(s->db, "srcstore", cols, 2) != 0 || dl_txn_commit(s->db) != 0) {
        dl_txn_rollback(s->db);
        return fx_err(err, errcap, "metadata commit failed for srcstore '%s-%s' "
                                   "(dir is an orphan; gc will reap it)", hash, name);
    }
    return 0;
}

/* ─── fx_store_build ───────────────────────────────────────────────────── */

int fx_store_build(FxStore *s, const Package *p, const char *hash,
                   const char *final_path, const char *src_path,
                   char *const *dep_names, char *const *dep_paths, int ndeps,
                   char *err, size_t errcap) {
    if (!s || !p || !hash || !final_path)
        return fx_err(err, errcap, "internal: null args to fx_store_build");

    /* idempotent adoption: a previous run (or a crashed run repaired by a
       rerun) already installed this exact content — just ensure metadata */
    if (is_dir(final_path))
        return commit_store_fact(s, hash, p->name, err, errcap);

    const char *base = strrchr(final_path, '/');
    base = base ? base + 1 : final_path;

    char tmp[FX_PATH_MAX];
    if (snprintf(tmp, sizeof tmp, "%s/%s-%ld", s->build,
                 base, (long)getpid()) >= (int)sizeof tmp)
        return fx_err(err, errcap, "temp build path too long");

    if (is_dir(tmp)) rm_rf(tmp);               /* stale same-pid leftover */
    if (mkdir(tmp, 0755) != 0)
        return fx_err(err, errcap, "cannot create temp dir '%s': %s", tmp, strerror(errno));

    int rc = fx_build_recipe(p, tmp, dep_names, dep_paths, ndeps, s->root,
                             src_path, err, errcap);
    if (rc != 0) {
        if (err && err[0] == '\0')
            snprintf(err, errcap, "recipe action failed with exit code %d", rc);
        rm_rf(tmp);
        return -1;
    }

    /* ATOMIC INSTALL: rename temp -> final.  EEXIST/ENOTEMPTY means a
       concurrent build installed the same content — adopt theirs. */
    if (rename(tmp, final_path) != 0) {
        if ((errno == EEXIST || errno == ENOTEMPTY) && is_dir(final_path)) {
            rm_rf(tmp);
            return commit_store_fact(s, hash, p->name, err, errcap);
        }
        fx_err(err, errcap, "cannot install '%s': %s", final_path, strerror(errno));
        rm_rf(tmp);
        return -1;
    }

    /* durability of the rename before the metadata commit (best-effort) */
    fsync_dir_best_effort(s->root);

    /* METADATA LAST: the single atomic commit point.  A crash before this
       leaves the installed dir as a reapable orphan — never the reverse. */
    if (commit_store_fact(s, hash, p->name, err, errcap) != 0)
        return -1;
    return 0;
}

/* ─── fx_store_ensure_source ───────────────────────────────────────────── */

int fx_store_ensure_source(FxStore *s, const Package *p, const char *src_hash,
                           char *src_path_out, size_t cap,
                           char *err, size_t errcap) {
    if (!s || !p || !src_hash || !src_path_out)
        return fx_err(err, errcap, "internal: null args to fx_store_ensure_source");
    if (p->src.kind != SRC_PATH)
        return fx_err(err, errcap, "internal: ensure_source on a non-Path source");

    /* content-addressed clean-source artifact, in the STORE (already covered
       by the existing --ro-bind store_root + Landlock store_root:r) */
    if (snprintf(src_path_out, cap, "%s/%s-%s-src", s->root, src_hash, p->name)
            >= (int)cap)
        return fx_err(err, errcap, "clean source path too long");

    /* idempotent adoption: the artifact already exists — ensure metadata */
    if (is_dir(src_path_out))
        return commit_srcstore_fact(s, src_hash, p->name, err, errcap);

    /* materialize into the SAME build scratch area as fx_store_build (a
       sibling of the store on the same filesystem, so the rename is atomic) */
    char tmp[FX_PATH_MAX];
    if (snprintf(tmp, sizeof tmp, "%s/%s-%s-src-%ld", s->build, src_hash,
                 p->name, (long)getpid()) >= (int)sizeof tmp)
        return fx_err(err, errcap, "temp clean-source path too long");

    if (is_dir(tmp)) rm_rf(tmp);               /* stale same-pid leftover */
    if (mkdir(tmp, 0755) != 0)
        return fx_err(err, errcap, "cannot create temp src dir '%s': %s", tmp, strerror(errno));

    /* copy + hash in ONE walk; the streamed hash MUST equal the precomputed
       src_hash, else the source changed between compute_paths and build
       (TOCTOU) — fail loudly rather than build from different bytes */
    char actual[65];
    if (fx_clean_tree(p->src.path, tmp, p->excludes, p->nexcludes,
                      actual, err, errcap) != 0) {
        rm_rf(tmp);
        return -1;
    }
    if (strcmp(actual, src_hash) != 0) {
        rm_rf(tmp);
        return fx_err(err, errcap,
                      "source '%s' changed between path computation and build "
                      "(expected clean hash %.16s..., got %.16s...); "
                      "re-run fxstore build", p->src.path, src_hash, actual);
    }

    /* ATOMIC INSTALL: rename temp -> artifact.  EEXIST/ENOTEMPTY means a
       concurrent build materialized the same content — adopt theirs. */
    if (rename(tmp, src_path_out) != 0) {
        if ((errno == EEXIST || errno == ENOTEMPTY) && is_dir(src_path_out)) {
            rm_rf(tmp);
            return commit_srcstore_fact(s, src_hash, p->name, err, errcap);
        }
        fx_err(err, errcap, "cannot install clean source '%s': %s", src_path_out, strerror(errno));
        rm_rf(tmp);
        return -1;
    }

    /* durability of the rename before the metadata commit (best-effort) */
    fsync_dir_best_effort(s->root);

    /* METADATA LAST: the single atomic commit point, mirroring fx_store_build */
    if (commit_srcstore_fact(s, src_hash, p->name, err, errcap) != 0)
        return -1;
    return 0;
}

/* ─── GC ───────────────────────────────────────────────────────────────── */

/* pinned-snapshot fact bag (strings resolved via the interner) */
typedef struct {
    struct dl_db *db;
    char **a, **b;              /* dep: from,to / store: hash,name */
    int n, cap;
    int oom;
} PairBag;

static int pair_cb(const uint32_t *cols, uint8_t arity, void *user) {
    PairBag *pb = user;
    if (pb->n == pb->cap) {
        pb->cap = pb->cap ? pb->cap * 2 : 16;
        char **na = realloc(pb->a, (size_t)pb->cap * sizeof *na);
        if (!na) { pb->oom = 1; return 1; }
        pb->a = na;                           /* keep the bag consistent */
        char **nb = realloc(pb->b, (size_t)pb->cap * sizeof *nb);
        if (!nb) { pb->oom = 1; return 1; }
        pb->b = nb;
    }
    /* arity-1 relations (pkg) have NO second column — never read cols[1]
       (an out-of-bounds read yields a garbage sym id and a false failure) */
    const char *x = dl_intern_str_of(pb->db, cols[0]);
    const char *y = (arity >= 2) ? dl_intern_str_of(pb->db, cols[1]) : "";
    if (!x || !y) { pb->oom = 1; return 1; }
    pb->a[pb->n] = strdup(x);
    pb->b[pb->n] = strdup(y);
    if (!pb->a[pb->n] || !pb->b[pb->n]) { pb->oom = 1; return 1; }
    pb->n++;
    return 0;
}

static void pairbag_free(PairBag *pb) {
    for (int i = 0; i < pb->n; i++) { free(pb->a[i]); free(pb->b[i]); }
    free(pb->a);
    free(pb->b);
}

/* string-set membership (small MVP sizes: linear scan is fine) */
static int in_set(char **set, int n, const char *s) {
    for (int i = 0; i < n; i++)
        if (!strcmp(set[i], s)) return 1;
    return 0;
}

/* name-level reachability fixpoint over pinned dep edges (worklist BFS) */
static int reachable_names(const PairBag *deps, const char *root,
                           char ***out, int *n_out) {
    int cap = 16, n = 0;
    char **set = malloc((size_t)cap * sizeof *set);
    if (!set) return -1;
    set[n++] = strdup(root);
    if (!set[0]) { free(set); return -1; }
    int progress = 1;
    while (progress) {
        progress = 0;
        for (int i = 0; i < deps->n; i++) {
            if (!in_set(set, n, deps->a[i])) continue;
            if (in_set(set, n, deps->b[i])) continue;
            if (n == cap) {
                cap *= 2;
                char **ns = realloc(set, (size_t)cap * sizeof *ns);
                if (!ns) goto oom;
                set = ns;
            }
            set[n] = strdup(deps->b[i]);
            if (!set[n]) goto oom;
            n++;
            progress = 1;
        }
    }
    *out = set;
    *n_out = n;
    return 0;
oom:
    for (int i = 0; i < n; i++) free(set[i]);
    free(set);
    return -1;
}

static int hex64(const char *s) {
    for (int i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

/* Sweep ONE scratch directory for crash leftovers whose owning pid is
   gone: the current <root>.build area plus the legacy <root>/.tmp of
   stores built before the scratch dir moved out of the store.  Entries
   are named <hash>-<name>-<pid>; a live pid (possibly a concurrent
   build) is never touched — only orphaned scratch dirs.  An absent
   directory (legacy .tmp on a fresh store) is simply nothing to do. */
static void sweep_orphan_scratch(const char *dir) {
    DIR *td = opendir(dir);
    if (!td) return;
    struct dirent *te;
    while ((te = readdir(td)) != NULL) {
        if (!strcmp(te->d_name, ".") || !strcmp(te->d_name, "..")) continue;
        const char *lastdash = strrchr(te->d_name, '-');
        if (!lastdash) continue;
        char *end = NULL;
        long pid = strtol(lastdash + 1, &end, 10);
        if (!end || *end != '\0' || pid <= 0) continue;
        if (kill((pid_t)pid, 0) == 0 || errno != ESRCH) continue; /* alive/unknown */
        char junk[FX_PATH_MAX];
        if (snprintf(junk, sizeof junk, "%s/%s", dir, te->d_name) >= (int)sizeof junk)
            continue;
        rm_rf(junk);
    }
    closedir(td);
}

int fx_store_gc(FxStore *s, const char *root_pkg, char *err, size_t errcap) {
    if (!s || !root_pkg) return fx_err(err, errcap, "internal: null args to fx_store_gc");

    /* 0. PUBLISH FIRST, then pin: the pinned read must include every fact
       durably committed since the last publish (a build that crashed, or a
       caller that omitted the final publish).  Without this, the dir sweep
       (name-based) can remove a dir whose committed store fact is invisible
       to the pinned view, leaving DANGLING metadata — the exact state the
       crash invariant forbids. */
    if (dl_publish_snapshot(s->db) != 0)
        return fx_err(err, errcap, "cannot publish store snapshot before gc");

    /* 1. pin the LATEST published snapshot (immutable on-disk view; never
       races a concurrent build publishing newer versions) */
    long total = dl_snapshot_versions(s->db, NULL, 0);
    if (total <= 0)
        return fx_err(err, errcap, "no published snapshot in the store db — run a build first");
    uint32_t *vers = malloc((size_t)total * sizeof *vers);
    if (!vers) return fx_err(err, errcap, "out of memory");
    dl_snapshot_versions(s->db, vers, (size_t)total);
    uint32_t pinned = vers[total - 1];
    free(vers);

    /* 2. read pkg / dep / store / srcstore from the PINNED version */
    PairBag deps  = { s->db, NULL, NULL, 0, 0, 0 };
    PairBag stores = { s->db, NULL, NULL, 0, 0, 0 };
    PairBag srcstores = { s->db, NULL, NULL, 0, 0, 0 };
    PairBag pkgs  = { s->db, NULL, NULL, 0, 0, 0 };
    {
        long rd = dl_query_version(s->db, pinned, "dep", pair_cb, &deps);
        long rs = dl_query_version(s->db, pinned, "store", pair_cb, &stores);
        long rss = dl_query_version(s->db, pinned, "srcstore", pair_cb, &srcstores);
        long rp = dl_query_version(s->db, pinned, "pkg", pair_cb, &pkgs);
        if (rd < 0 || rs < 0 || rss < 0 || rp < 0 ||
            deps.oom || stores.oom || srcstores.oom || pkgs.oom) {
            fx_err(err, errcap,
                   "pinned snapshot read failed (version %u): dep=%ld store=%ld "
                   "srcstore=%ld pkg=%ld oom=%d%d%d%d",
                   pinned, rd, rs, rss, rp, deps.oom, stores.oom,
                   srcstores.oom, pkgs.oom);
            pairbag_free(&deps); pairbag_free(&stores); pairbag_free(&srcstores);
            pairbag_free(&pkgs);
            return -1;
        }
    }

    if (!in_set(pkgs.a, pkgs.n, root_pkg)) {
        pairbag_free(&deps); pairbag_free(&stores); pairbag_free(&srcstores);
        pairbag_free(&pkgs);
        return fx_err(err, errcap, "gc root '%s' is not a package in the pinned snapshot", root_pkg);
    }

    /* 3. liveness: name-level reachability from the root */
    char **live = NULL;
    int nlive = 0;
    if (reachable_names(&deps, root_pkg, &live, &nlive) != 0) {
        pairbag_free(&deps); pairbag_free(&stores); pairbag_free(&srcstores);
        pairbag_free(&pkgs);
        return fx_err(err, errcap, "out of memory computing reachability");
    }

    /* 4. METADATA FIRST: atomically txn-delete the unreachable store AND
       srcstore facts (a crash after this leaves reapable orphan dirs — never
       dangling metadata pointing at missing dirs, which the dir-first order
       would create) */
    int removed_facts = 0;
    for (int i = 0; i < stores.n; i++) {
        if (in_set(live, nlive, stores.b[i])) continue;   /* name reachable */
        uint32_t cols[2] = { dl_intern_str(s->db, stores.a[i]),
                             dl_intern_str(s->db, stores.b[i]) };
        if (!cols[0] || !cols[1]) { fx_err(err, errcap, "out of memory interning gc fact"); goto fail; }
        if (dl_txn_begin(s->db) != 0) { fx_err(err, errcap, "txn begin failed"); goto fail; }
        if (dl_txn_delete_fact(s->db, "store", cols, 2) != 0 || dl_txn_commit(s->db) != 0) {
            dl_txn_rollback(s->db);
            fx_err(err, errcap, "gc metadata txn failed for '%s-%s'", stores.a[i], stores.b[i]);
            goto fail;
        }
        removed_facts++;
    }
    /* srcstore facts are unreachable exactly when their NAME is unreachable:
       liveness is name-level, so a clean-source artifact for an unreachable
       package is unreachable too */
    for (int i = 0; i < srcstores.n; i++) {
        if (in_set(live, nlive, srcstores.b[i])) continue;   /* name reachable */
        uint32_t cols[2] = { dl_intern_str(s->db, srcstores.a[i]),
                             dl_intern_str(s->db, srcstores.b[i]) };
        if (!cols[0] || !cols[1]) { fx_err(err, errcap, "out of memory interning gc fact"); goto fail; }
        if (dl_txn_begin(s->db) != 0) { fx_err(err, errcap, "txn begin failed"); goto fail; }
        if (dl_txn_delete_fact(s->db, "srcstore", cols, 2) != 0 || dl_txn_commit(s->db) != 0) {
            dl_txn_rollback(s->db);
            fx_err(err, errcap, "gc metadata txn failed for srcstore '%s-%s'", srcstores.a[i], srcstores.b[i]);
            goto fail;
        }
        removed_facts++;
    }

    /* 5. then sweep the unreachable DIRS (well-formed <64hex>-<name> and
       <64hex>-<name>-src only; malformed entries are reported loudly, never
       deleted) */
    int removed_dirs = 0;
    DIR *d = opendir(s->root);
    if (!d) { fx_err(err, errcap, "cannot read store root: %s", strerror(errno)); goto fail; }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;                 /* .db/CURRENT */
        size_t len = strlen(e->d_name);
        if (len < 66 || e->d_name[64] != '-' || !hex64(e->d_name)) {
            fprintf(stderr, "fxstore: gc: skipping malformed store entry '%s'\n", e->d_name);
            continue;
        }
        /* liveness: check the FULL name first (a built dir "<64hex>-<NAME>"
           where NAME itself ends in "-src"), then the "-src"-stripped base
           (a clean-source dir "<64hex>-<NAME>-src").  Keep the dir if EITHER
           is live — GC must never delete a live package's dir and leave
           dangling store metadata (package names are arbitrary Text). */
        char name[FX_PATH_MAX];
        size_t nl = len - 65;                /* NAME + optional -src */
        if (nl >= sizeof name) continue;
        memcpy(name, e->d_name + 65, nl);
        name[nl] = '\0';
        if (in_set(live, nlive, name)) continue;
        if (nl > 4 && !strcmp(name + nl - 4, "-src")) {
            name[nl - 4] = '\0';
            if (in_set(live, nlive, name)) continue;
        }
        char path[FX_PATH_MAX];
        if (snprintf(path, sizeof path, "%s/%s", s->root, e->d_name) >= (int)sizeof path)
            continue;
        rm_rf(path);
        removed_dirs++;
    }
    closedir(d);

    /* 6. sweep crash leftovers whose owning pid is gone: the current
       <root>.build scratch area, plus the legacy <root>/.tmp of stores
       built before the scratch dir moved out of the store. */
    sweep_orphan_scratch(s->build);
    {
        char legacy[FX_PATH_MAX];
        if (snprintf(legacy, sizeof legacy, "%s/%s", s->root, FX_TMP_SUBDIR)
                < (int)sizeof legacy)
            sweep_orphan_scratch(legacy);
    }

    printf("fxstore gc: root '%s' — %d store fact(s) and %d dir(s) removed "
           "(%d live package name(s))\n", root_pkg, removed_facts, removed_dirs, nlive);

    for (int i = 0; i < nlive; i++) free(live[i]);
    free(live);
    pairbag_free(&deps); pairbag_free(&stores); pairbag_free(&srcstores);
    pairbag_free(&pkgs);
    return 0;
fail:
    for (int i = 0; i < nlive; i++) free(live[i]);
    free(live);
    pairbag_free(&deps); pairbag_free(&stores); pairbag_free(&srcstores);
    pairbag_free(&pkgs);
    return -1;
}

/* ─── M5 timeline/rollback: as-of fact reader + roll-forward ────────────── */

/* raw sym-id fact bag over dl_query_version (tuples are interned sym ids that
 * resolve directly against the live db's shared/persisted interner) */
typedef struct {
    uint32_t *tuples;   /* arity * n values */
    size_t n, cap;
    uint8_t arity;
} RawBag;

static int raw_cb(const uint32_t *cols, uint8_t arity, void *user) {
    RawBag *bag = user;
    bag->arity = arity;
    if (bag->n == bag->cap) {
        bag->cap = bag->cap ? bag->cap * 2 : 16;
        uint32_t *nt = realloc(bag->tuples, bag->cap * arity * sizeof *nt);
        if (!nt) return 1;              /* OOM: stop enumeration */
        bag->tuples = nt;
    }
    memcpy(&bag->tuples[bag->n * arity], cols, (size_t)arity * sizeof *cols);
    bag->n++;
    return 0;
}

static void rawbag_free(RawBag *bag) {
    free(bag->tuples);
    bag->tuples = NULL; bag->n = bag->cap = 0;
}

/* Read all facts of `rel` as-of `version`.  A relation ABSENT from that
 * version (dl_query_version returns -1; older snapshots predate srcstore) is
 * treated as EMPTY when allow_absent — hard-error only when allow_absent is 0
 * ('store' is always present in every snapshot). */
static int version_bag(struct dl_db *db, uint32_t version, const char *rel,
                       int allow_absent, RawBag *out, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    long n = dl_query_version(db, version, rel, raw_cb, out);
    if (n < 0) {
        if (allow_absent) { rawbag_free(out); return 0; }
        return fx_err(err, errcap, "snapshot %u has no '%s' relation", version, rel);
    }
    return 0;
}

/* txn helpers: buffer delete/add of every fact in a bag (relations must be
 * declared; the swap txn below declares them idempotently first). */
static int txn_delete_bag(struct dl_db *db, const char *rel, const RawBag *bag) {
    for (size_t i = 0; i < bag->n; i++)
        if (dl_txn_delete_fact(db, rel, &bag->tuples[i * bag->arity], bag->arity) != 0)
            return -1;
    return 0;
}
static int txn_add_bag(struct dl_db *db, const char *rel, const RawBag *bag) {
    for (size_t i = 0; i < bag->n; i++)
        if (dl_txn_add_fact(db, rel, &bag->tuples[i * bag->arity], bag->arity) != 0)
            return -1;
    return 0;
}

int fx_store_current_version(const FxStore *s, uint32_t *out,
                             char *err, size_t errcap) {
    if (!s || !out) return fx_err(err, errcap, "internal: null args");
    char cur[FX_PATH_MAX];
    if (snprintf(cur, sizeof cur, "%s/%s/snapshots/CURRENT", s->root, FX_DB_SUBDIR)
            >= (int)sizeof cur)
        return fx_err(err, errcap, "CURRENT path too long");
    FILE *f = fopen(cur, "r");
    if (f) {
        unsigned long v = 0;
        if (fscanf(f, "%lu", &v) == 1 && v > 0 && v <= UINT32_MAX) {
            fclose(f);
            *out = (uint32_t)v;
            return 0;
        }
        fclose(f);
    }
    /* fall back to the highest published version */
    long total = dl_snapshot_versions(s->db, NULL, 0);
    if (total <= 0)
        return fx_err(err, errcap,
                      "no published snapshot in the store db — run a build first");
    uint32_t *vers = malloc((size_t)total * sizeof *vers);
    if (!vers) return fx_err(err, errcap, "out of memory");
    dl_snapshot_versions(s->db, vers, (size_t)total);
    *out = vers[total - 1];
    free(vers);
    return 0;
}

int fx_store_timeline(FxStore *s, char *err, size_t errcap) {
    if (!s) return fx_err(err, errcap, "internal: null store");
    long total = dl_snapshot_versions(s->db, NULL, 0);
    if (total < 0)
        return fx_err(err, errcap, "cannot enumerate snapshot versions");
    printf("fxstore: timeline of %s (%ld version(s)):\n", s->root, total);
    if (total == 0) { printf("  no versions\n"); return 0; }

    uint32_t *vers = malloc((size_t)total * sizeof *vers);
    if (!vers) return fx_err(err, errcap, "out of memory");
    dl_snapshot_versions(s->db, vers, (size_t)total);

    uint32_t cur = 0;
    (void)fx_store_current_version(s, &cur, NULL, 0);   /* best-effort */

    int rc = 0;
    for (long i = 0; i < total && rc == 0; i++) {
        uint32_t v = vers[i];
        RawBag roots = {0}, closure = {0}, store = {0}, srcstore = {0};
        if (version_bag(s->db, v, "root", 1, &roots, err, errcap) != 0 ||
            version_bag(s->db, v, "closure", 1, &closure, err, errcap) != 0 ||
            version_bag(s->db, v, "store", 0, &store, err, errcap) != 0 ||
            version_bag(s->db, v, "srcstore", 1, &srcstore, err, errcap) != 0) {
            rc = -1;
        } else {
            printf("  %u%s roots: ", v, v == cur ? " [CURRENT]" : "");
            if (roots.n == 0) {
                printf("(none)");
            } else {
                for (size_t k = 0; k < roots.n; k++) {
                    const char *nm = dl_intern_str_of(s->db, roots.tuples[k]);
                    if (k) printf(",");
                    printf("%s", nm ? nm : "?");
                }
            }
            printf("  closure: %zu  store: %zu  srcstore: %zu\n",
                   closure.n, store.n, srcstore.n);
        }
        rawbag_free(&roots); rawbag_free(&closure);
        rawbag_free(&store); rawbag_free(&srcstore);
    }
    free(vers);
    return rc;
}

/* Atomic rewrite of the CURRENT file (write CURRENT.tmp + fsync + rename),
 * mirroring datalog-dafsa's own atomic CURRENT flip. */
static int write_current(FxStore *s, uint32_t version, char *err, size_t errcap) {
    char dir[FX_PATH_MAX], tmp[FX_PATH_MAX], final[FX_PATH_MAX];
    if (snprintf(dir, sizeof dir, "%s/%s/snapshots", s->root, FX_DB_SUBDIR)
            >= (int)sizeof dir ||
        snprintf(tmp, sizeof tmp, "%s/CURRENT.tmp", dir) >= (int)sizeof tmp ||
        snprintf(final, sizeof final, "%s/CURRENT", dir) >= (int)sizeof final)
        return fx_err(err, errcap, "snapshot path too long");
    char buf[32];
    int len = snprintf(buf, sizeof buf, "%lu\n", (unsigned long)version);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return fx_err(err, errcap, "cannot open '%s': %s", tmp, strerror(errno));
    ssize_t w = write(fd, buf, (size_t)len);
    if (w != len || fsync(fd) != 0) {
        int e = errno;
        close(fd); remove(tmp);
        return fx_err(err, errcap, "cannot write '%s': %s", tmp, strerror(e));
    }
    close(fd);
    if (rename(tmp, final) != 0) {
        int e = errno;
        remove(tmp);
        return fx_err(err, errcap, "cannot rename '%s' -> '%s': %s", tmp, final, strerror(e));
    }
    return 0;
}

int fx_store_rollback(FxStore *s, uint32_t version, int hard,
                      char *err, size_t errcap) {
    if (!s) return fx_err(err, errcap, "internal: null store");

    /* validate `version` is a published snapshot */
    long total = dl_snapshot_versions(s->db, NULL, 0);
    if (total <= 0)
        return fx_err(err, errcap,
                      "no published snapshot in the store db — run a build first");
    uint32_t *vers = malloc((size_t)total * sizeof *vers);
    if (!vers) return fx_err(err, errcap, "out of memory");
    dl_snapshot_versions(s->db, vers, (size_t)total);
    int found = 0;
    for (long i = 0; i < total && !found; i++) if (vers[i] == version) found = 1;
    free(vers);
    if (!found)
        return fx_err(err, errcap, "no such version %u (have %ld version(s))",
                      version, total);

    if (hard)
        return write_current(s, version, err, errcap);

    /* ── roll-forward ── */

    /* 1. PUBLISH FIRST: un-published facts (a crashed build) fold into a
     * version, and the just-published latest == live (dl_query/dl_count read
     * the mmap snapshot when snap_version > 0, so the swap below must be
     * diffed against the published latest, not the live WAL).  This also
     * preserves the pre-rollback state as an undoable version. */
    if (dl_publish_snapshot(s->db) != 0)
        return fx_err(err, errcap, "cannot publish store snapshot before rollback");

    /* 2. read `version`'s store/srcstore/pkg/dep/root facts (NOT closure —
     * an IDB re-derived below).  srcstore is optional (old snapshots predate
     * the clean-source work). */
    RawBag vstore = {0}, vsrcstore = {0}, vpkg = {0}, vdep = {0}, vroot = {0};
    if (version_bag(s->db, version, "store", 0, &vstore, err, errcap) != 0 ||
        version_bag(s->db, version, "srcstore", 1, &vsrcstore, err, errcap) != 0 ||
        version_bag(s->db, version, "pkg", 1, &vpkg, err, errcap) != 0 ||
        version_bag(s->db, version, "dep", 1, &vdep, err, errcap) != 0 ||
        version_bag(s->db, version, "root", 1, &vroot, err, errcap) != 0)
        goto fail;

    /* 3. enumerate the CURRENT (== just-published latest) facts to delete. */
    {
        long total2 = dl_snapshot_versions(s->db, NULL, 0);
        if (total2 <= 0) {
            fx_err(err, errcap, "no published snapshot after rollback publish");
            goto fail;
        }
        uint32_t *vers2 = malloc((size_t)total2 * sizeof *vers2);
        if (!vers2) { fx_err(err, errcap, "out of memory"); goto fail; }
        dl_snapshot_versions(s->db, vers2, (size_t)total2);
        uint32_t live = vers2[total2 - 1];
        free(vers2);

        RawBag curstore = {0}, cursrcstore = {0}, curpkg = {0}, curdep = {0}, curroot = {0};
        if (version_bag(s->db, live, "store", 0, &curstore, err, errcap) != 0 ||
            version_bag(s->db, live, "srcstore", 1, &cursrcstore, err, errcap) != 0 ||
            version_bag(s->db, live, "pkg", 1, &curpkg, err, errcap) != 0 ||
            version_bag(s->db, live, "dep", 1, &curdep, err, errcap) != 0 ||
            version_bag(s->db, live, "root", 1, &curroot, err, errcap) != 0) {
            rawbag_free(&curstore); rawbag_free(&cursrcstore);
            rawbag_free(&curpkg); rawbag_free(&curdep); rawbag_free(&curroot);
            goto fail;
        }

        /* 4. declare the swap relations idempotently — guarantees the txn
         * add/delete succeed even on a freshly re-opened db whose relation
         * schema is in-memory only (fx_store_open declares store/srcstore;
         * pkg/dep/root are normally declared by fx_closure_compute). */
        if (dl_declare_relation(s->db, "store", 2) != 0 ||
            dl_declare_relation(s->db, "srcstore", 2) != 0 ||
            dl_declare_relation(s->db, "pkg", 1) != 0 ||
            dl_declare_relation(s->db, "dep", 2) != 0 ||
            dl_declare_relation(s->db, "root", 1) != 0) {
            fx_err(err, errcap, "cannot declare relations for rollback");
            rawbag_free(&curstore); rawbag_free(&cursrcstore);
            rawbag_free(&curpkg); rawbag_free(&curdep); rawbag_free(&curroot);
            goto fail;
        }

        /* 5. ONE atomic txn: delete every current fact, add every `version`
         * fact (the atomic index+EDB switch; one WAL + one fsync). */
        if (dl_txn_begin(s->db) != 0) {
            fx_err(err, errcap, "txn begin failed (another txn open?)");
            rawbag_free(&curstore); rawbag_free(&cursrcstore);
            rawbag_free(&curpkg); rawbag_free(&curdep); rawbag_free(&curroot);
            goto fail;
        }
        if (txn_delete_bag(s->db, "store", &curstore) != 0 ||
            txn_delete_bag(s->db, "srcstore", &cursrcstore) != 0 ||
            txn_delete_bag(s->db, "pkg", &curpkg) != 0 ||
            txn_delete_bag(s->db, "dep", &curdep) != 0 ||
            txn_delete_bag(s->db, "root", &curroot) != 0 ||
            txn_add_bag(s->db, "store", &vstore) != 0 ||
            txn_add_bag(s->db, "srcstore", &vsrcstore) != 0 ||
            txn_add_bag(s->db, "pkg", &vpkg) != 0 ||
            txn_add_bag(s->db, "dep", &vdep) != 0 ||
            txn_add_bag(s->db, "root", &vroot) != 0 ||
            dl_txn_commit(s->db) != 0) {
            dl_txn_rollback(s->db);
            fx_err(err, errcap, "rollback metadata txn failed");
            rawbag_free(&curstore); rawbag_free(&cursrcstore);
            rawbag_free(&curpkg); rawbag_free(&curdep); rawbag_free(&curroot);
            goto fail;
        }
        rawbag_free(&curstore); rawbag_free(&cursrcstore);
        rawbag_free(&curpkg); rawbag_free(&curdep); rawbag_free(&curroot);
    }

    /* 6. re-derive closure from `version`'s pkg/dep/root.  Re-clearing and
     * re-adding pkg/dep/root is harmless (the swap already set them); this
     * re-materializes the fixpoint through dl_load_rules+dl_compile and
     * publishes a NEW version (the rollback result). */
    if (fx_closure_rebuild(s->db, vpkg.tuples, vpkg.n, vdep.tuples, vdep.n,
                           vroot.tuples, vroot.n, err, errcap) != 0)
        goto fail;

    rawbag_free(&vstore); rawbag_free(&vsrcstore);
    rawbag_free(&vpkg); rawbag_free(&vdep); rawbag_free(&vroot);
    return 0;
fail:
    rawbag_free(&vstore); rawbag_free(&vsrcstore);
    rawbag_free(&vpkg); rawbag_free(&vdep); rawbag_free(&vroot);
    return -1;
}

int fx_store_gc_retain(FxStore *s, unsigned n, char *err, size_t errcap) {
    if (!s) return fx_err(err, errcap, "internal: null store");
    if (n == 0) return fx_err(err, errcap, "gc --retain requires N >= 1");
    /* Guard the --hard interaction: if CURRENT (from the file) no longer
     * points at the newest published version, this process's publish would
     * RENUMBER (new = CURRENT+1) and rm_rf() real snapshot dirs, and the
     * retention prune could then drop the CURRENT-pointed version — leaving
     * a dangling CURRENT and shredded history.  Refuse loudly instead. */
    {
        uint32_t cur = 0;
        if (fx_store_current_version(s, &cur, NULL, 0) == 0) {
            long total = dl_snapshot_versions(s->db, NULL, 0);
            if (total > 0) {
                uint32_t *vers = malloc((size_t)total * sizeof *vers);
                if (vers) {
                    dl_snapshot_versions(s->db, vers, (size_t)total);
                    uint32_t newest = vers[total - 1];
                    free(vers);
                    if (cur != newest)
                        return fx_err(err, errcap,
                                      "CURRENT (%u) is not the newest version (%u) — "
                                      "a 'rollback --hard' repointed it; fix that first "
                                      "('fxstore rollback --hard %u'), then retry gc --retain",
                                      cur, newest, newest);
                }
            }
        }
    }
    if (dl_set_snapshot_retain(s->db, n) != 0)
        return fx_err(err, errcap, "cannot set snapshot retention to %u", n);
    /* the prune is applied at the END of a successful publish */
    if (dl_publish_snapshot(s->db) != 0)
        return fx_err(err, errcap, "cannot publish to apply snapshot retention");
    return 0;
}
