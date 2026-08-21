/* closure.c — (U3) datalog closure fixpoint + C-side topo-sort.
 *
 * NAME-LEVEL transitive reachability is computed by the engine as the least
 * fixed point of the 2-rule program (FX_CLOSURE_RULES, exact engine syntax
 * proven by tests/test_m4.c's transitive-closure test):
 *
 *     closure(X) :- root(X).
 *     closure(Y) :- closure(X), dep(X,Y).
 *
 * The content-addressed store-path hash is computed SEPARATELY in C
 * (derivation.c) — it needs sha256 + canonical serialization + recursion
 * over content, which pure Datalog cannot express.  Do not try to force the
 * hash into Datalog.
 *
 * EDB per run: pkg(name), dep(from,to), root(name) — facts are interned
 * symbol ids.  The per-run EDB is REBUILT from the current package-set:
 * stale facts from a previous run (older package set) are enumerated and
 * deleted first, including previously materialized closure tuples (the
 * fixpoint engine is monotone; without the clear, a package removed from
 * the set would linger in closure).  `closure` is NEVER pre-declared: rule
 * heads are auto-declared by dl_load_rules as IDB, and pre-declaring an
 * IDB breaks the engine's fixpoint treatment (dlp/workflow.c precedent).
 *
 * After loading facts we load + compile the program and publish a snapshot
 * (dl_query prefers the published mmap view; publish also re-materializes
 * derived relations).  fxstore query / gc then read the closure through
 * the normal engine paths, and gc pins a specific version so it never
 * races a concurrent build.
 *
 * The C-side topo-sort (dhake.c topo_order pattern) then orders the closure
 * deps-first (the build order) and REJECTS CYCLES: a cyclic dep graph has
 * no finite store path (the hash is a fixed point over the derivation
 * graph, which does not exist for a cycle), so this is a hard error.
 */
#include "fxstore.h"
#include "dl.h"

#include <stdlib.h>
#include <string.h>

/* ─── Stale-fact clearing ──────────────────────────────────────────────── */

typedef struct {
    uint32_t *tuples;   /* arity * count values */
    size_t n, cap;      /* tuple count */
    uint8_t arity;
} FactBag;

static int bag_cb(const uint32_t *cols, uint8_t arity, void *user) {
    FactBag *bag = user;
    bag->arity = arity;                    /* fixed-arity relation: constant */
    if (bag->n == bag->cap) {
        bag->cap = bag->cap ? bag->cap * 2 : 16;
        uint32_t *nt = realloc(bag->tuples, bag->cap * arity * sizeof *nt);
        if (!nt) return 1;              /* OOM: stop enumeration */
        bag->tuples = nt;
    }
    for (uint8_t i = 0; i < arity; i++)
        bag->tuples[bag->n * arity + i] = cols[i];
    bag->n++;
    return 0;
}

/* Enumerate all facts of `rel` via dl_query and delete each durably.
 * Unknown relations (first run, closure not yet auto-declared) are a no-op:
 * dl_count returns UINT64_MAX for an unknown relation. */
static int clear_relation(struct dl_db *db, const char *rel,
                          char *err, size_t errcap) {
    if (dl_count(db, rel) == UINT64_MAX) return 0;   /* not declared yet */

    FactBag bag = {0};
    long n = dl_query(db, rel, bag_cb, &bag);
    if (n < 0) return fx_err(err, errcap, "cannot enumerate '%s' for clearing", rel);
    int rc = 0;
    for (size_t i = 0; i < bag.n && rc == 0; i++) {
        if (dl_delete_fact(db, rel, &bag.tuples[i * bag.arity], bag.arity) < 0)
            { fx_err(err, errcap, "cannot delete stale fact from '%s'", rel); rc = -1; }
    }
    free(bag.tuples);
    return rc;
}

/* ─── fx_closure_rebuild — re-derive the fixpoint over given facts ─────── */

int fx_closure_rebuild(struct dl_db *db,
                       const uint32_t *pkg, size_t npkg,
                       const uint32_t *dep, size_t ndep,
                       const uint32_t *root, size_t nroot,
                       char *err, size_t errcap) {
    if (!db) return fx_err(err, errcap, "internal: null db");

    /* EDB declarations (idempotent).  closure is auto-declared by the rules. */
    if (dl_declare_relation(db, "pkg", 1) != 0)
        return fx_err(err, errcap, "cannot declare relation 'pkg'");
    if (dl_declare_relation(db, "dep", 2) != 0)
        return fx_err(err, errcap, "cannot declare relation 'dep'");
    if (dl_declare_relation(db, "root", 1) != 0)
        return fx_err(err, errcap, "cannot declare relation 'root'");

    /* Rebuild the per-run EDB: clear stale facts (a previous run / a previous
     * version's EDB), including previously materialized closure tuples. */
    if (clear_relation(db, "pkg", err, errcap) != 0) return -1;
    if (clear_relation(db, "dep", err, errcap) != 0) return -1;
    if (clear_relation(db, "root", err, errcap) != 0) return -1;
    if (clear_relation(db, "closure", err, errcap) != 0) return -1;

    /* Fresh EDB from the given tuples (already-interned sym_ids). */
    for (size_t i = 0; i < npkg; i++) {
        if (dl_add_fact(db, "pkg", &pkg[i], 1) < 0)
            return fx_err(err, errcap, "cannot add pkg fact");
    }
    for (size_t i = 0; i < ndep; i++) {
        if (dl_add_fact(db, "dep", &dep[i * 2], 2) < 0)
            return fx_err(err, errcap, "cannot add dep fact");
    }
    for (size_t i = 0; i < nroot; i++) {
        if (dl_add_fact(db, "root", &root[i], 1) < 0)
            return fx_err(err, errcap, "cannot add root fact");
    }

    /* The closure program + compile (materializes closure in-place). */
    if (dl_load_rules(db, FX_CLOSURE_RULES) != 0)
        return fx_err(err, errcap, "cannot load closure rules");
    if (dl_compile(db) != 0)
        return fx_err(err, errcap, "cannot compile closure rules");

    /* Publish so query/gc read a stable mmap view of the fixpoint. */
    if (dl_publish_snapshot(db) != 0)
        return fx_err(err, errcap, "cannot publish closure snapshot");
    return 0;
}

/* ─── fx_closure_compute ───────────────────────────────────────────────── */

int fx_closure_compute(struct dl_db *db, const PackageSet *ps,
                       char *const *roots, int nroots,
                       char *err, size_t errcap) {
    if (!db || !ps) return fx_err(err, errcap, "internal: null db/package-set");

    /* First pass: sizes for the fact arrays (pkg arity1, dep arity2 pairs,
     * root arity1). */
    size_t npkg = 0, ndep = 0;
    for (const Package *p = ps->head; p; p = p->next) {
        npkg++;
        ndep += (size_t)p->ndeps;
    }
    size_t nroot = (size_t)(nroots > 0 ? nroots : ps->count);

    uint32_t *pkg = npkg ? malloc(npkg * sizeof *pkg) : NULL;
    uint32_t *dep = ndep ? malloc(ndep * 2 * sizeof *dep) : NULL;
    uint32_t *root = nroot ? malloc(nroot * sizeof *root) : NULL;
    if ((npkg && !pkg) || (ndep && !dep) || (nroot && !root)) {
        free(pkg); free(dep); free(root);
        return fx_err(err, errcap, "out of memory");
    }

    /* Fill pkg + dep from the current package set (interned syms). */
    size_t ip = 0, id = 0;
    for (const Package *p = ps->head; p; p = p->next) {
        uint32_t sym = dl_intern_str(db, p->name);
        if (!sym) goto oom_intern;
        pkg[ip++] = sym;
        for (int i = 0; i < p->ndeps; i++) {
            uint32_t pair[2] = { dl_intern_str(db, p->name),
                                 dl_intern_str(db, p->deps[i]) };
            if (!pair[0] || !pair[1]) goto oom_intern;
            dep[id * 2] = pair[0];
            dep[id * 2 + 1] = pair[1];
            id++;
        }
    }

    /* Roots: the requested build targets, or every package when none. */
    size_t ir = 0;
    if (nroots > 0) {
        for (int i = 0; i < nroots; i++) {
            if (!fx_find_package(ps, roots[i])) {
                free(pkg); free(dep); free(root);
                return fx_err(err, errcap,
                              "unknown package '%s' (not in the package set)", roots[i]);
            }
            uint32_t sym = dl_intern_str(db, roots[i]);
            if (!sym) goto oom_intern;
            root[ir++] = sym;
        }
    } else {
        for (const Package *p = ps->head; p; p = p->next) {
            uint32_t sym = dl_intern_str(db, p->name);
            if (!sym) goto oom_intern;
            root[ir++] = sym;
        }
    }

    int rc = fx_closure_rebuild(db, pkg, ip, dep, id, root, ir, err, errcap);
    free(pkg); free(dep); free(root);
    return rc;

oom_intern:
    free(pkg); free(dep); free(root);
    return fx_err(err, errcap, "out of memory interning package name");
}

/* ─── fx_closure_names ─────────────────────────────────────────────────── */

typedef struct {
    struct dl_db *db;
    char **names;
    int n, cap;
    int oom;
} NameBag;

static int name_cb(const uint32_t *cols, uint8_t arity, void *user) {
    NameBag *nb = user;
    (void)arity;                          /* closure is arity 1 */
    const char *s = dl_intern_str_of(nb->db, cols[0]);
    if (!s) { nb->oom = 1; return 1; }
    if (nb->n == nb->cap) {
        nb->cap = nb->cap ? nb->cap * 2 : 16;
        char **nn = realloc(nb->names, (size_t)nb->cap * sizeof *nn);
        if (!nn) { nb->oom = 1; return 1; }
        nb->names = nn;
    }
    nb->names[nb->n] = strdup(s);
    if (!nb->names[nb->n]) { nb->oom = 1; return 1; }
    nb->n++;
    return 0;
}

int fx_closure_names(struct dl_db *db, char ***names_out, int *n_out,
                     char *err, size_t errcap) {
    if (!db || !names_out || !n_out) return fx_err(err, errcap, "internal: null args");
    NameBag nb = { db, NULL, 0, 0, 0 };
    long n = dl_query(db, "closure", name_cb, &nb);
    if (n < 0 || nb.oom) {
        for (int i = 0; i < nb.n; i++) free(nb.names[i]);
        free(nb.names);
        return fx_err(err, errcap, "closure query failed%s", nb.oom ? " (out of memory)" : "");
    }
    *names_out = nb.names;
    *n_out = nb.n;
    return 0;
}

/* ─── fx_topo_order — deps-first order + cycle rejection (dhake pattern) ─ */

/* state flags on Package (borrowed scratch: next pointer is list linkage, so
 * keep a parallel state array indexed by position in a local array) */
typedef struct {
    Package *p;
    int state;                            /* 0 unvisited, 1 visiting, 2 done */
} TNode;

static TNode *tnode_of(TNode *nodes, int n, const Package *p) {
    for (int i = 0; i < n; i++)
        if (nodes[i].p == p) return &nodes[i];
    return NULL;
}

int fx_topo_order(const PackageSet *ps, char **names, int n,
                  Package ***order_out, int *n_out, char *err, size_t errcap) {
    if (!ps || !order_out || !n_out) return fx_err(err, errcap, "internal: null args");
    if (n < 0) return fx_err(err, errcap, "internal: negative name count");
    if (n == 0) { *order_out = NULL; *n_out = 0; return 0; }

    TNode *nodes = calloc((size_t)n, sizeof *nodes);
    Package **order = malloc((size_t)n * sizeof *order);
    if (!nodes || !order) {
        free(nodes); free(order);
        return fx_err(err, errcap, "out of memory");
    }
    for (int i = 0; i < n; i++) {
        Package *p = fx_find_package(ps, names[i]);
        if (!p) {
            free(nodes); free(order);
            return fx_err(err, errcap, "closure contains '%s' which is not in the package set", names[i]);
        }
        /* duplicate names in the input are harmless: dedup by skipping */
        nodes[i].p = p;
    }

    int nn = 0;
    typedef struct { TNode *t; int i; } Frame;
    Frame *stk = malloc((size_t)n * sizeof *stk);
    if (!stk) { free(nodes); free(order); return fx_err(err, errcap, "out of memory"); }

    int rc = 0;
    for (int r = 0; r < n && rc == 0; r++) {
        if (nodes[r].state != 0) continue;
        int top = 0;
        stk[top++] = (Frame){ &nodes[r], 0 };
        nodes[r].state = 1;
        while (top > 0) {
            Frame *f = &stk[top - 1];
            Package *cur = f->t->p;
            if (f->i < cur->ndeps) {
                Package *dp = fx_find_package(ps, cur->deps[f->i++]);
                TNode *dn = dp ? tnode_of(nodes, n, dp) : NULL;
                if (!dn) {
                    fx_err(err, errcap,
                           "package '%s' depends on '%s' which is not in the closure "
                           "(incomplete closure — engine bug or stale EDB)",
                           cur->name, cur->deps[f->i - 1]);
                    rc = -1;
                    break;
                }
                if (dn->state == 1) {
                    fx_err(err, errcap,
                           "dependency cycle detected involving '%s' "
                           "(cyclic deps have no finite store path)",
                           dn->p->name);
                    rc = -1;
                    break;
                }
                if (dn->state == 0) { dn->state = 1; stk[top++] = (Frame){ dn, 0 }; }
            } else {
                f->t->state = 2;
                order[nn++] = f->t->p;    /* deps-first (post-order) */
                top--;
            }
        }
    }
    free(stk);
    free(nodes);
    if (rc != 0) { free(order); return -1; }

    /* Each package is emitted exactly once (the visiting/done state
       machine), so nn <= n.  A duplicated name in `names` is harmless: it
       only adds an extra DFS root over already-done nodes. */
    *order_out = order;
    *n_out = nn;
    return 0;
}
