/* fxstore.h — shared header for the fxstore tool.
 *
 * fxstore links the datalog-dafsa engine (for closure fixpoint computation)
 * with the dhall-c core (for package-set walking and store-path hashing).
 *
 * Units:
 *   - packageset.c (U1): Dhall package-set parser/walker
 *   - derivation.c (U2): canonical serializer + sha256 store path computation
 *   - closure.c (U3): Datalog closure fixpoint (pkg/dep/root/closure relations)
 *                     + C-side topo-sort / cycle rejection
 *   - store.c (U4): store layout, atomic writes, txn/CAS metadata, GC
 *   - build.c (U5): recipe executor + bwrap sandbox
 *   - main.c  (U6): CLI wiring
 *
 * The Action union is byte-compatible with the dhake Action union
 * (dhake/src/dhake.c, Dhakefile.dhall): < Shell : Text | Copy : {from,to} |
 * Mkdir : Text | Rm : Text | Touch : Text | Move : {from,to} |
 * Symlink : {from,to} | Chmod : {path,mode} | Echo : Text | Env : {key,value}
 * | Run : {argv : List Text} >.
 *
 * The package-set schema (see fxstore init / docs):
 *   let Src    = < Path : Text | Fetch : { url : Text, hash : Text } >
 *   let Build  = { target : Text, recipe : List Action }
 *   let Package = { name : Text, version : Text, src : Src,
 *                   deps : List Text, build : Build }
 *   in  { packages : List Package } : PackageSet
 */
#ifndef FXSTORE_H
#define FXSTORE_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration of the datalog engine handle (src/dl.h defines the
 * real one; a file-scope tag is needed so parameter-list declarations
 * don't create per-prototype scoped struct tags). */
struct dl_db;

/* ─── Shared error helper ────────────────────────────────────────────────
 * Every API returns 0 on success and -1 on error with a human-readable
 * message written into (err, errcap).  Both may be NULL/0 to discard. */
static inline int fx_err(char *err, size_t errcap, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (err && errcap > 0) vsnprintf(err, errcap, fmt, ap);
    va_end(ap);
    return -1;
}

/* ─── Actions (dhake Action union; build.c owns execution) ─────────────── */

typedef enum {
    ACT_SHELL, ACT_COPY, ACT_MKDIR, ACT_RM, ACT_TOUCH,
    ACT_MOVE, ACT_SYMLINK, ACT_CHMOD, ACT_ECHO, ACT_ENV, ACT_RUN
} ActionKind;

typedef struct Action {
    ActionKind kind;
    char *a;               /* shell command / mkdir / rm / touch path / copy-from / move-from / symlink-from / chmod-path / echo-text / env-key / run-program */
    char *b;               /* copy-to / move-to / symlink-to / chmod-mode / env-value */
    char **av;             /* argv for Run (NULL-terminated; NULL for others) */
    int nav;               /* argc for Run (0 for others) */
    struct Action *next;   /* recipe linked list, package-set order */
} Action;

/* ─── Package source ───────────────────────────────────────────────────── */

typedef enum { SRC_PATH, SRC_FETCH } SrcKind;

typedef struct {
    SrcKind kind;
    char *path;            /* SRC_PATH: filesystem path to the source tree */
    char *url;             /* SRC_FETCH */
    char *hash;            /* SRC_FETCH: expected sha256 (hex) */
} Src;

/* ─── Package + package set ────────────────────────────────────────────── */

typedef struct Package {
    char *name;
    char *version;
    Src src;
    char **deps;           /* direct dep NAMES, package-set order */
    int ndeps;
    char *target;          /* build.target (output name; informational) */
    Action *recipe;        /* linked list, package-set ORDER (semantic) */
    struct Package *next;  /* package-set order */
} Package;

typedef struct PackageSet {
    Package *head;
    int count;
} PackageSet;

/* ─── U1: packageset.c — Dhall package-set walker ──────────────────────── */

/* Evaluate package-set.dhall (parse_source -> infer_type [best-effort,
 * see packageset.c header comment] -> normalize -> structural walk) into a
 * malloc'd C package table.  Validates: unique names, safe name syntax,
 * src shape, deps present in the set.  Returns 0/-1 (err set). */
int fx_packageset_load(PackageSet *out, const char *path, char *err, size_t errcap);

/* Find a package by name (NULL if absent). */
Package *fx_find_package(const PackageSet *ps, const char *name);

/* Free a package table loaded by fx_packageset_load (NULL-safe). */
void fx_packageset_free(PackageSet *ps);

/* ─── U2: derivation.c — canonical serializer + sha256 store path ─────── */

/* Content-address a source TREE (Merkle): every direct child of `dir`, sorted
 * by relative path, contributes (u32be len + relpath, type byte 'd'|'f',
 * u32be len + content-sha256-hex); directories hash their own entry stream
 * recursively; the result is sha256_hex over the top-level stream.  Rejects
 * non-regular/non-dir entries loudly (no silent skips). */
int fx_content_hash_dir(const char *dir, char hash_out[65], char *err, size_t errcap);

/* sha256 over the canonical derivation serialization (Decision 4):
 *   magic "fxstore-drv-v1\n" | name | version | src ('P' + content-hash |
 *   'F' + url + hash) | target | recipe (u32be count, order-preserved,
 *   per-action tag + len-prefixed fields) | deps (u32be count, each direct
 *   dep's FULL store path, SORTED lexicographically).  All strings are
 *   u32be-length-prefixed (never NUL/whitespace-delimited).
 * dep_paths are the direct deps' store paths in ANY order; they are sorted
 * internally so the invariant is enforced here. */
int fx_derivation_hash(const Package *p, char *const *dep_paths, int ndeps,
                       char hash_out[65], char *err, size_t errcap);

/* Store path layout: "<store_root>/<hex64>-<name>". */
void fx_store_path_of(const char *store_root, const char *hash,
                      const char *name, char *out, size_t cap);

/* Convenience: derivation hash + store path in one call. */
int fx_derivation_store_path(const Package *p, char *const *dep_paths, int ndeps,
                             const char *store_root, char *path_out, size_t cap,
                             char *err, size_t errcap);

/* ─── U3: closure.c — Datalog closure fixpoint + topo-sort ────────────── */

/* The datalog DB directory inside a store (root/.db).  Metadata relations:
 * pkg(name) dep(from,to) root(name) closure(name) store(hash,name). */
#define FX_DB_SUBDIR ".db"
#define FX_TMP_SUBDIR ".tmp"

/* The closure program (engine syntax, cf. tests/test_m4.c transitive
 * closure): the least fixed point of
 *   closure(X) :- root(X).
 *   closure(Y) :- closure(X), dep(X,Y).  */
#define FX_CLOSURE_RULES \
    "closure(X):-root(X).\n" \
    "closure(Y):-closure(X),dep(X,Y).\n"

/* Compute the closure fixpoint over the persisted DB: clear stale per-run
 * EDB (pkg/dep/root + previously materialized closure), load fresh facts
 * from the package set (interned syms), roots = requested names (all
 * packages when nroots == 0; every root must exist), load + compile the
 * 2-rule program, and publish a snapshot.  Returns 0/-1. */
int fx_closure_compute(struct dl_db *db, const PackageSet *ps,
                       char *const *roots, int nroots,
                       char *err, size_t errcap);

/* Collect the materialized closure names (dl_query on `closure`, resolving
 * sym_ids via the interner) into a malloc'd, NULL-terminated array.
 * Caller frees each string and the array. */
int fx_closure_names(struct dl_db *db, char ***names_out, int *n_out,
                     char *err, size_t errcap);

/* Topo-sort `names` (a subset of the package set, typically the closure) so
 * every package follows its deps; reject cycles ("no finite store path")
 * and deps outside the given name set.  Returns a malloc'd array of
 * Package* (deps-first); caller frees the array only. */
int fx_topo_order(const PackageSet *ps, char **names, int n,
                  Package ***order_out, int *n_out, char *err, size_t errcap);

/* ─── U4: store.c — store layout + atomic write + txn metadata + GC ───── */

typedef struct FxStore FxStore;

/* Open (create if needed) a store at `root`: root/, root/.tmp/, and the
 * metadata DB at root/.db (dl_open).  NULL on error (err set). */
FxStore *fx_store_open(const char *root, char *err, size_t errcap);

void fx_store_close(FxStore *s);            /* NULL-safe; closes the DB */

struct dl_db *fx_store_db(FxStore *s);      /* the metadata DB handle */
const char *fx_store_root(const FxStore *s);/* store root, no trailing '/' */

/* Publish a snapshot of the metadata DB (must not be called inside a txn). */
int fx_store_publish(FxStore *s, char *err, size_t errcap);

/* Build ONE package into the store (deps are already built; their store
 * paths are dep_paths, parallel to dep_names):
 *   1. run the recipe into root/.tmp/<hash>-<name>-<pid>   (U5 executor)
 *   2. atomically rename() the temp dir to final_path
 *   3. ONLY THEN commit the metadata txn: store(hash,name) — one WAL +
 *      fsync is the atomic commit point.  A crash before (3) leaves a
 *      reapable orphan dir, never dangling metadata.
 * If final_path already exists the build is ADOPTED (content addressing is
 * idempotent) and only the missing metadata fact is committed.
 * hash is the derivation sha256 (hex64), name the package name. */
int fx_store_build(FxStore *s, const Package *p, const char *hash,
                   const char *final_path,
                   char *const *dep_names, char *const *dep_paths, int ndeps,
                   char *err, size_t errcap);

/* GC sweep relative to `root_pkg`: pin the LATEST published snapshot
 * (dl_snapshot_versions + dl_query_version, so a concurrent build never
 * races this read), compute name-level reachability from root_pkg over the
 * pinned dep facts, then — metadata FIRST (one atomic txn deletes the
 * unreachable store facts), then dirs — delete every well-formed store dir
 * whose name is not reachable.  Malformed dir names are reported, not
 * deleted.  Deleting facts before dirs keeps the crash invariant: a crash
 * mid-GC leaves reapable orphan dirs, never dangling metadata. */
int fx_store_gc(FxStore *s, const char *root_pkg, char *err, size_t errcap);

/* ─── U5: build.c — recipe executor + bwrap/stage3 sandbox ───────────── */

/* Resolve (exactly once, from the FXSTORE_STAGE3 environment override if
 * set at startup, else the compile-time vendor/palisade bin/stage3 path)
 * the stage3 sandbox binary that Shell/Run actions exec as /init inside
 * their bwrap sandbox (seccomp + Landlock hardening).  Call from main()
 * before loading any package set: recipes can set arbitrary env vars via
 * the Env action, and this must already be settled when they run. */
void fx_stage3_resolve(void);

/* Execute the package's recipe inside `workdir` (the temp build dir):
 * relative paths resolve against workdir; deps are exported as
 * FX_DEP_<NAME> environment variables (NAME uppercased, non-alnum -> '_');
 * the two EXECUTING actions (Shell, Run) run under
 *   bwrap --unshare-all --die-with-parent --uid 1000 --gid 1000
 *        --ro-bind <store_root> <store_root>
 *        --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib
 *        [--ro-bind /lib64 /lib64] [--ro-bind <src> <src>]
 *        --bind <workdir> <workdir> --chdir <workdir>
 *        --dev /dev --proc /proc
 *        --ro-bind <stage3> /init
 *        -- /init <PROMISES> <LANDLOCK_SPEC> -- <argv | /bin/sh -c cmd>
 * where stage3 (palisade, vendor/palisade) applies no_new_privs ->
 * Landlock (unveil of exactly the bind-mounted paths — never "/") ->
 * rlimits -> seccomp before exec'ing the recipe command.  RATTAN_ and LD_
 * env vars are scrubbed from the child first (stage3 reads
 * RATTAN_ALLOW_PTRACE/RATTAN_EXTRA_PROMISES/RATTAN_RLIMITS; LD_PRELOAD
 * injects into the exec chain).  stage3-absent fails LOUDLY (127); if
 * bwrap is absent the child prints a LOUD NON-HERMETIC warning and falls
 * back to plain fork/exec in the workdir.  Returns the first failing
 * action's exit code, or -1 on an executor error (err set). */
int fx_build_recipe(const Package *p, const char *workdir,
                    char *const *dep_names, char *const *dep_paths, int ndeps,
                    const char *store_root, char *err, size_t errcap);

/* Echo one action to stdout (like make / dhake). */
void fx_print_action(const Action *a);

#ifdef __cplusplus
}
#endif

#endif /* FXSTORE_H */
