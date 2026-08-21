/* packageset.c — (U1) evaluate a Dhall package-set.dhall and walk its normal
 * form into a C package table:
 *
 *     parse_source -> infer_type (best-effort, see below) -> normalize
 *     -> walk the PackageSet Term tree
 *
 * ABOUT infer_type: the plan's pipeline calls infer_type, but the dhake
 * precedent (dhake/src/dhake.c header comment, verified against dhall-c
 * HEAD) is that the shorthand Action union literal < Tag = v > infers as a
 * *singleton* union < Tag : T >, so a recipe list mixing different tags does
 * not typecheck even though it normalizes correctly.  A package set written
 * with the dhake-style shorthand (byte-compatible Action union) would
 * therefore be rejected by a hard infer_type gate.  We run infer_type as a
 * WARNING-ONLY check (a real error is printed but the walk continues — the
 * structural walk below is the source of truth, exactly as in dhake), so
 * both the shorthand and the projection style (Action.Shell "...", which
 * does typecheck) are accepted.
 *
 * The term-walker helpers rec_get / text_flat / list_elems are copied
 * VERBATIM from dlp/schema_load.c (proven in the dlp walker; they in turn
 * came from compendium/src/config.c); union_selected / map_action follow
 * dhake/src/dhake.c:174-248 with die() rerouted to the (err,errcap)
 * channel so the library never exits the process.
 *
 * normalize() sorts record fields alphabetically, so every field access is
 * BY LABEL (rec_get), never by index.  Text interpolation that did not
 * collapse is rejected loudly (a stuck ${...} means the file references
 * something the evaluator could not resolve — a wrong package table here
 * silently corrupts every downstream hash).
 */
#include "fxstore.h"
#include "dhall.h"

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* ─── Term-tree helpers (verbatim from dlp/schema_load.c) ──────────────── */

/* The proven helpers rec_get (record field BY LABEL — normalize() sorts
 * fields alphabetically, so index-based access is wrong) and term_text_cstr
 * (collapsed Text with stuck-interpolation rejection) are used below; the
 * deps/recipe lists are walked dhake-style (TmCons chains), which is the
 * pattern dhake.c uses for exactly these shapes. */

/* Look up a record-literal field BY LABEL. normalize() sorts fields
   alphabetically, so index-based access is wrong.  (verbatim from
   dlp/schema_load.c) */
static Term *rec_get(Term *t, const char *label) {
    if (!t || t->tag != TmRecordLit) return NULL;
    for (int i = 0; i < t->as.rec.n; i++)
        if (!strcmp(t->as.rec.fs[i].label, label)) return t->as.rec.fs[i].value;
    return NULL;
}

/* Extract a fully-collapsed Text literal as a malloc'd C string.
 * (dhake/src/dhake.c term_text_cstr, verbatim.)  Returns NULL if t is not
 * Text or still has unresolved interpolation. */
static char *term_text_cstr(Term *t) {
    if (!t || t->tag != TmText) return NULL;
    size_t len = 0;
    for (TextPart *p = t->as.text; p; p = p->next) {
        if (p->expr) return NULL;          /* stuck interpolation */
        if (p->lit) len += strlen(p->lit);
    }
    char *out = malloc(len + 1);
    if (!out) return NULL;
    char *q = out;
    for (TextPart *p = t->as.text; p; p = p->next)
        if (p->lit) { size_t l = strlen(p->lit); memcpy(q, p->lit, l); q += l; }
    *q = '\0';
    return out;
}

/* ─── Union helpers (dhake.c pattern) ──────────────────────────────────── */

/* the selected alternative of a union literal: the field carrying a value */
static Field *union_selected(Term *u) {
    if (!u || u->tag != TmUnionLit) return NULL;
    for (int i = 0; i < u->as.uni.n; i++)
        if (u->as.uni.fs[i].value) return &u->as.uni.fs[i];
    return NULL;
}

static char *need_text(Term *rec, const char *label, const char *where,
                       char *err, size_t errcap) {
    Term *f = rec_get(rec, label);
    if (!f) { fx_err(err, errcap, "%s: missing field '%s'", where, label); return NULL; }
    char *s = term_text_cstr(f);
    if (!s) { fx_err(err, errcap, "%s: field '%s' must be Text", where, label); return NULL; }
    return s;
}

/* ─── Action mapping (dhake.c map_action, errors rerouted) ─────────────── */

static Action *map_action(Term *u, const char *pkg, char *err, size_t errcap) {
    if (!u || u->tag != TmUnionLit)
        { fx_err(err, errcap, "package '%s': recipe element must be an Action union (< Tag = v >)", pkg); return NULL; }
    Field *sel = union_selected(u);
    if (!sel) { fx_err(err, errcap, "package '%s': malformed Action union", pkg); return NULL; }
    Action *a = calloc(1, sizeof *a);
    if (!a) { fx_err(err, errcap, "out of memory"); return NULL; }
    const char *tag = sel->label;
    const char *w = pkg;
    if (!strcmp(tag, "Shell")) {
        a->kind = ACT_SHELL;
        a->a = term_text_cstr(sel->value);
        if (!a->a) { fx_err(err, errcap, "package '%s': < Shell = ... > value must be Text", w); goto fail; }
    } else if (!strcmp(tag, "Copy")) {
        a->kind = ACT_COPY;
        if (sel->value->tag != TmRecordLit) { fx_err(err, errcap, "package '%s': Copy must be a { from, to } record", w); goto fail; }
        a->a = need_text(sel->value, "from", w, err, errcap);
        a->b = need_text(sel->value, "to", w, err, errcap);
        if (!a->a || !a->b) goto fail;
    } else if (!strcmp(tag, "Mkdir")) {
        a->kind = ACT_MKDIR;
        a->a = term_text_cstr(sel->value);
        if (!a->a) { fx_err(err, errcap, "package '%s': < Mkdir = ... > value must be Text", w); goto fail; }
    } else if (!strcmp(tag, "Rm")) {
        a->kind = ACT_RM;
        a->a = term_text_cstr(sel->value);
        if (!a->a) { fx_err(err, errcap, "package '%s': < Rm = ... > value must be Text", w); goto fail; }
    } else if (!strcmp(tag, "Touch")) {
        a->kind = ACT_TOUCH;
        a->a = term_text_cstr(sel->value);
        if (!a->a) { fx_err(err, errcap, "package '%s': < Touch = ... > value must be Text", w); goto fail; }
    } else if (!strcmp(tag, "Move")) {
        a->kind = ACT_MOVE;
        if (sel->value->tag != TmRecordLit) { fx_err(err, errcap, "package '%s': Move must be a { from, to } record", w); goto fail; }
        a->a = need_text(sel->value, "from", w, err, errcap);
        a->b = need_text(sel->value, "to", w, err, errcap);
        if (!a->a || !a->b) goto fail;
    } else if (!strcmp(tag, "Symlink")) {
        a->kind = ACT_SYMLINK;
        if (sel->value->tag != TmRecordLit) { fx_err(err, errcap, "package '%s': Symlink must be a { from, to } record", w); goto fail; }
        a->a = need_text(sel->value, "from", w, err, errcap);
        a->b = need_text(sel->value, "to", w, err, errcap);
        if (!a->a || !a->b) goto fail;
    } else if (!strcmp(tag, "Chmod")) {
        a->kind = ACT_CHMOD;
        if (sel->value->tag != TmRecordLit) { fx_err(err, errcap, "package '%s': Chmod must be a { path, mode } record", w); goto fail; }
        a->a = need_text(sel->value, "path", w, err, errcap);
        a->b = need_text(sel->value, "mode", w, err, errcap);
        if (!a->a || !a->b) goto fail;
    } else if (!strcmp(tag, "Echo")) {
        a->kind = ACT_ECHO;
        a->a = term_text_cstr(sel->value);
        if (!a->a) { fx_err(err, errcap, "package '%s': < Echo = ... > value must be Text", w); goto fail; }
    } else if (!strcmp(tag, "Env")) {
        a->kind = ACT_ENV;
        if (sel->value->tag != TmRecordLit) { fx_err(err, errcap, "package '%s': Env must be a { key, value } record", w); goto fail; }
        a->a = need_text(sel->value, "key", w, err, errcap);
        a->b = need_text(sel->value, "value", w, err, errcap);
        if (!a->a || !a->b) goto fail;
    } else if (!strcmp(tag, "Run")) {
        a->kind = ACT_RUN;
        if (sel->value->tag != TmRecordLit) { fx_err(err, errcap, "package '%s': Run must be a { argv : List Text } record", w); goto fail; }
        Term *argv_list = rec_get(sel->value, "argv");
        if (!argv_list) { fx_err(err, errcap, "package '%s': Run must have an 'argv' field", w); goto fail; }
        int n = 0;
        for (Term *p = argv_list; p && p->tag == TmCons; p = p->as.cons.tail) n++;
        if (n == 0) { fx_err(err, errcap, "package '%s': Run argv must be non-empty", w); goto fail; }
        a->av = calloc((size_t)(n + 1), sizeof(char *));
        if (!a->av) { fx_err(err, errcap, "out of memory"); goto fail; }
        a->nav = n;
        int i = 0;
        for (Term *p = argv_list; p && p->tag == TmCons; p = p->as.cons.tail) {
            a->av[i++] = term_text_cstr(p->as.cons.head);
            if (!a->av[i-1]) { fx_err(err, errcap, "package '%s': Run argv elements must be Text", w); goto fail; }
        }
        a->av[n] = NULL;
        a->a = a->av[0];  /* store program name in a for compatibility */
    } else {
        fx_err(err, errcap, "package '%s': unknown action '< %s = ... >'", w, tag);
        goto fail;
    }
    return a;
fail:
    /* caller frees via fx_packageset_free on failure paths; partial fields
       of `a` are owned by the table once appended, so free the orphan now */
    if (a->av) { for (int i = 0; i < a->nav && a->av[i]; i++) free(a->av[i]); }
    free(a->av);
    free(a);
    return NULL;
}

/* ─── Package-name safety ────────────────────────────────────────────────
 * Store dirs are named "<hex64>-<name>", so a package name with '/' or a
 * leading '.' could escape the store root (path traversal).  Enforce:
 * first char alphanumeric, rest alnum or . _ + -. */
static bool name_safe(const char *s) {
    if (!s || !s[0] || !isalnum((unsigned char)s[0])) return false;
    for (const char *q = s + 1; *q; q++) {
        unsigned char c = (unsigned char)*q;
        if (!isalnum(c) && c != '.' && c != '_' && c != '+' && c != '-') return false;
    }
    return true;
}

/* ─── Structural walk ──────────────────────────────────────────────────── */

/* Canonicalize a path: if relative, resolve against base_dir using realpath.
 * Returns a malloc'd absolute path, or NULL on error. */
static char *canonicalize_path(const char *path, const char *base_dir) {
    if (!path || !path[0]) return NULL;
    if (path[0] == '/') return strdup(path);
    
    /* Build the full path: base_dir/path */
    size_t n = strlen(base_dir) + 1 + strlen(path) + 1;
    char *full = malloc(n);
    if (!full) return NULL;
    snprintf(full, n, "%s/%s", base_dir, path);
    
    /* realpath resolves symlinks and normalizes */
    char resolved[PATH_MAX];
    if (!realpath(full, resolved)) {
        free(full);
        return NULL;
    }
    free(full);
    return strdup(resolved);
}

static int list_length(Term *list) {
    int n = 0;
    for (Term *p = list; p && p->tag == TmCons; p = p->as.cons.tail) n++;
    return n;
}

/* map one Src union: < Path = "..."> | < Fetch = { url, hash } > */
static bool map_src(Src *out, Term *u, const char *pkg, const char *base_dir, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    if (!u || u->tag != TmUnionLit)
        { fx_err(err, errcap, "package '%s': src must be < Path = Text | Fetch = { url, hash } >", pkg); return false; }
    Field *sel = union_selected(u);
    if (!sel) { fx_err(err, errcap, "package '%s': malformed src union", pkg); return false; }
    if (!strcmp(sel->label, "Path")) {
        out->kind = SRC_PATH;
        char *raw_path = term_text_cstr(sel->value);
        if (!raw_path) { fx_err(err, errcap, "package '%s': < Path = ... > value must be Text", pkg); return false; }
        /* Canonicalize relative paths to absolute using realpath against base_dir */
        out->path = canonicalize_path(raw_path, base_dir);
        if (!out->path) { fx_err(err, errcap, "package '%s': cannot canonicalize src path '%s'", pkg, raw_path); free(raw_path); return false; }
        free(raw_path);
    } else if (!strcmp(sel->label, "Fetch")) {
        out->kind = SRC_FETCH;
        if (sel->value->tag != TmRecordLit)
            { fx_err(err, errcap, "package '%s': Fetch must be a { url, hash } record", pkg); return false; }
        out->url  = need_text(sel->value, "url",  pkg, err, errcap);
        out->hash = need_text(sel->value, "hash", pkg, err, errcap);
        if (!out->url || !out->hash) return false;
    } else {
        fx_err(err, errcap, "package '%s': unknown src alternative '< %s = ... >' (expected Path or Fetch)", pkg, sel->label);
        return false;
    }
    return true;
}

/* map one normalized Package record literal into a malloc'd Package */
static Package *map_package(Term *rec, const char *base_dir, char *err, size_t errcap) {
    Package *p = calloc(1, sizeof *p);
    if (!p) { fx_err(err, errcap, "out of memory"); return NULL; }

    p->name = need_text(rec, "name", "package", err, errcap);
    if (!p->name) goto fail;
    char where[160];
    snprintf(where, sizeof where, "package '%s'", p->name);

    if (!name_safe(p->name))
        { fx_err(err, errcap, "%s: invalid package name (need [A-Za-z0-9][A-Za-z0-9._+-]*)", where); goto fail; }

    p->version = need_text(rec, "version", where, err, errcap);
    if (!p->version) goto fail;

    Term *src_t = rec_get(rec, "src");
    if (!src_t) { fx_err(err, errcap, "%s: missing field 'src'", where); goto fail; }
    if (!map_src(&p->src, src_t, p->name, base_dir, err, errcap)) goto fail;

    Term *deps = rec_get(rec, "deps");
    if (!deps) { fx_err(err, errcap, "%s: missing field 'deps'", where); goto fail; }
    if (deps->tag != TmNil && deps->tag != TmCons)
        { fx_err(err, errcap, "%s: 'deps' must be a List Text", where); goto fail; }
    p->ndeps = list_length(deps);
    p->deps = calloc((size_t)(p->ndeps ? p->ndeps : 1), sizeof(char *));
    if (!p->deps) { fx_err(err, errcap, "out of memory"); goto fail; }
    int i = 0;
    for (Term *q = deps; q && q->tag == TmCons; q = q->as.cons.tail) {
        char *d = term_text_cstr(q->as.cons.head);
        if (!d) { fx_err(err, errcap, "%s: dependency name must be Text", where); goto fail; }
        p->deps[i++] = d;
    }

    /* optional `excludes : List Text` — absent field => empty list (backward
       compat: a package-set without `excludes` still loads unchanged) */
    Term *excl = rec_get(rec, "excludes");
    if (excl) {
        if (excl->tag != TmNil && excl->tag != TmCons)
            { fx_err(err, errcap, "%s: 'excludes' must be a List Text", where); goto fail; }
        p->nexcludes = list_length(excl);
        if (p->nexcludes > 0) {
            p->excludes = calloc((size_t)p->nexcludes, sizeof(char *));
            if (!p->excludes) { fx_err(err, errcap, "out of memory"); goto fail; }
            int j = 0;
            for (Term *q = excl; q && q->tag == TmCons; q = q->as.cons.tail) {
                char *x = term_text_cstr(q->as.cons.head);
                if (!x) { fx_err(err, errcap, "%s: excludes entry must be Text", where); goto fail; }
                /* LOUD rejection of entries that can never match: relative
                   paths within the src tree never start with '/' or "./",
                   never end with '/', never contain "//", and "" / "." / ".."
                   are meaningless.  Silent acceptance would silently keep
                   hashing the content the author meant to exclude. */
                size_t xl = strlen(x);
                if (xl == 0 || x[0] == '/' || (xl >= 2 && x[0] == '.' && x[1] == '/') ||
                    x[xl - 1] == '/' || strstr(x, "//") ||
                    !strcmp(x, ".") || !strcmp(x, "..")) {
                    fx_err(err, errcap, "%s: excludes entry '%s' is not a clean relative path within the src tree", where, x);
                    free(x);
                    goto fail;
                }
                p->excludes[j++] = x;
            }
        }
        /* excludes only apply to a local src TREE (SRC_PATH); on a Fetch
           source (url+hash) they would be silently ignored, so reject them
           loudly rather than let the author think the exclusion took effect. */
        if (p->nexcludes > 0 && p->src.kind != SRC_PATH) {
            fx_err(err, errcap, "%s: 'excludes' is only valid for a Path src (Fetch src is content-addressed by its own url+hash)", where);
            goto fail;
        }
    }

    Term *build = rec_get(rec, "build");
    if (!build || build->tag != TmRecordLit)
        { fx_err(err, errcap, "%s: missing or non-record 'build' (need { target, recipe })", where); goto fail; }
    p->target = need_text(build, "target", where, err, errcap);
    if (!p->target) goto fail;

    Term *recipe = rec_get(build, "recipe");
    if (!recipe) { fx_err(err, errcap, "%s: build missing 'recipe'", where); goto fail; }
    if (recipe->tag != TmNil && recipe->tag != TmCons)
        { fx_err(err, errcap, "%s: 'recipe' must be a List Action", where); goto fail; }
    Action **tail = &p->recipe;
    for (Term *q = recipe; q->tag == TmCons; q = q->as.cons.tail) {
        Action *a = map_action(q->as.cons.head, p->name, err, errcap);
        if (!a) goto fail;
        *tail = a;
        tail = &a->next;
    }
    return p;
fail:
    fx_packageset_free(&(PackageSet){ p, 1 });
    return NULL;
}

static bool build_packageset(PackageSet *out, Term *nf, const char *base_dir, char *err, size_t errcap) {
    memset(out, 0, sizeof *out);
    if (!nf || nf->tag != TmRecordLit)
        { fx_err(err, errcap, "package-set must be a record { packages : List Package }"); return false; }
    Term *packages = rec_get(nf, "packages");
    if (!packages) { fx_err(err, errcap, "package-set missing 'packages'"); return false; }
    if (packages->tag != TmNil && packages->tag != TmCons)
        { fx_err(err, errcap, "package-set 'packages' must be a List Package"); return false; }

    Package **tail = &out->head;
    for (Term *q = packages; q->tag == TmCons; q = q->as.cons.tail) {
        Term *item = q->as.cons.head;
        if (!item || item->tag != TmRecordLit)
            { fx_err(err, errcap, "each 'packages' element must be a Package record"); return false; }
        Package *p = map_package(item, base_dir, err, errcap);
        if (!p) return false;
        if (fx_find_package(out, p->name))
            { fx_err(err, errcap, "duplicate package name '%s'", p->name); return false; }
        *tail = p;
        tail = &p->next;
        out->count++;
    }

    /* every dep must exist in the set (a wrong dep silently produces a
       wrong closure -> wrong hash, so reject here, loudly) */
    for (Package *p = out->head; p; p = p->next)
        for (int i = 0; i < p->ndeps; i++) {
            if (!fx_find_package(out, p->deps[i]))
                { fx_err(err, errcap, "package '%s' depends on '%s' which is not in the package set",
                         p->name, p->deps[i]); return false; }
            if (!strcmp(p->deps[i], p->name))
                { fx_err(err, errcap, "package '%s' depends on itself", p->name); return false; }
        }
    return true;
}

/* ─── Evaluation pipeline (dlp/schema_load.c dlp_schema_load pattern) ──── */

static char *read_all(FILE *f) {
    size_t cap = 65536, len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (len == cap) { cap *= 2; char *nb = realloc(buf, cap); if (!nb) { free(buf); return NULL; } buf = nb; }
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) break;
    }
    buf[len] = '\0';
    return buf;
}

int fx_packageset_load(PackageSet *out, const char *path, char *err, size_t errcap) {
    if (err && errcap > 0) err[0] = '\0';
    FILE *in = fopen(path, "rb");
    if (!in) return fx_err(err, errcap, "cannot open package-set file '%s'", path);
    char *src = read_all(in);
    fclose(in);
    if (!src) return fx_err(err, errcap, "out of memory reading '%s'", path);

    if (!dhall_arena) dhall_arena = arena_new();
    arena_reset(dhall_arena);

    ImportLoader *loader = import_loader_new();
    import_loader_push_root(loader, path);

    Parser p;
    memset(&p, 0, sizeof p);
    p.loader = loader;
    DhallError derr;
    dhall_error_clear(&derr);

    Term *t = parse_source(&p, src, path, &derr);
    free(src);
    if (!t) {
        snprintf(err, errcap, "package-set parse error: %s", derr.msg);
        import_loader_free(loader);
        return -1;
    }

    /* Best-effort typecheck: WARNING-only (see file header — the dhake-style
     * shorthand Action literal infers as a singleton union, so heterogeneous
     * recipes do not typecheck even though they normalize correctly). */
    Term *ty = infer_type(&p, t, &derr);
    if (!ty) {
        fprintf(stderr,
                "fxstore: warning: package-set does not typecheck "
                "(shorthand Action literals infer as singleton unions; "
                "structural walk continues):\n  %s\n", derr.msg);
    }

    normalize_clear_error();
    Term *nf = normalize(t);
    if (normalize_has_error()) {
        derr = *normalize_get_error();
        snprintf(err, errcap, "package-set normalize error: %s", derr.msg);
        import_loader_free(loader);
        return -1;
    }
    import_loader_free(loader);

    /* Extract the base directory from the package-set path for canonicalizing
     * relative Src paths. */
    char base_dir[PATH_MAX];
    const char *bp = strrchr(path, '/');
    if (bp) {
        size_t len = (size_t)(bp - path);
        if (len >= sizeof base_dir) {
            fx_err(err, errcap, "package-set path too long for canonicalization");
            return -1;
        }
        memcpy(base_dir, path, len);
        base_dir[len] = '\0';
    } else {
        base_dir[0] = '.';
        base_dir[1] = '\0';
    }

    if (!build_packageset(out, nf, base_dir, err, errcap))
        return -1;
    return 0;
}

Package *fx_find_package(const PackageSet *ps, const char *name) {
    if (!ps || !name) return NULL;
    for (Package *p = ps->head; p; p = p->next)
        if (!strcmp(p->name, name)) return p;
    return NULL;
}

void fx_packageset_free(PackageSet *ps) {
    if (!ps || !ps->head) return;
    Package *p = ps->head;
    while (p) {
        Package *next = p->next;
        free(p->name);
        free(p->version);
        free(p->src.path);
        free(p->src.url);
        free(p->src.hash);
        for (int i = 0; i < p->ndeps; i++) free(p->deps[i]);
        free(p->deps);
        for (int i = 0; i < p->nexcludes; i++) free(p->excludes[i]);
        free(p->excludes);
        free(p->target);
        Action *a = p->recipe;
        while (a) {
            Action *an = a->next;
            if (a->av) {
                for (int i = 0; i < a->nav && a->av[i]; i++) free(a->av[i]);
                free(a->av);
            } else {
                free(a->a);
                free(a->b);
            }
            free(a);
            a = an;
        }
        free(p);
        p = next;
    }
    ps->head = NULL;
    ps->count = 0;
}
