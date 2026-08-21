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
    if (fx_clean_tree(p->src.path, tmp, actual, err, errcap) != 0) {
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
