/* derivation.c — (U2) canonical derivation serializer + sha256 store path.
 *
 * THE CONTENT-ADDRESSING CONTRACT (plan Decision 4).  A store path is
 *     <store_root>/<hex64>-<name>
 * where hex64 = sha256_hex(canonical_derivation(P)).  canonical_derivation
 * is a single unambiguous byte stream — every string is prefixed with its
 * u32-BIG-ENDIAN length (never NUL- or whitespace-delimited: paths and
 * commands may contain either), every list is prefixed with a u32-BE count,
 * and the one-byte tags are positionally fixed:
 *
 *   1. magic            len-prefixed "fxstore-drv-v1\n"
 *   2. name             len-prefixed
 *   3. version          len-prefixed
 *   4. src              1 byte 'P'|'F'
 *        'P': len-prefixed content-hash of the source TREE (content_hash_dir
 *             below — a source change MUST change the store path)
 *        'F': len-prefixed url, then len-prefixed hash (verbatim)
 *   5. target           len-prefixed
 *   6. recipe           u32-BE action count, then per action IN ORDER
 *                       (order is semantic):
 *                         1 tag byte: S C M R T V L H E N X
 *                         len-prefixed fields per kind (see act_tag/fields)
 *                         X (Run): u32-BE argc then each arg len-prefixed
 *   7. deps             u32-BE count, then each DIRECT dep's FULL store-path
 *                       string, len-prefixed, SORTED lexicographically
 *                       (dep order is NOT semantic)
 *
 * Because every dep's store path embeds ITS deps' hashes, the hash is the
 * Nix-style fixed point over the derivation graph: any transitive input
 * change changes every downstream store path.
 *
 * Determinism notes: u32-BE is machine-independent; action order is the
 * package-set order (walked in order); dep paths are sorted with strcmp
 * (byte order, locale-independent); content_hash_dir sorts entries by
 * relative path with strcmp.  Nothing here depends on readdir order, the
 * build machine, or the arena state.
 *
 * sha256_hex is dhall-c's (src/sha256.c, dhall.h:316) FIPS 180-4 over raw
 * bytes, lowercase hex into out[65].
 */
#include "fxstore.h"
#include "dhall.h"

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ─── Growable byte buffer ─────────────────────────────────────────────── */

typedef struct { char *d; size_t len, cap; } Buf;

static int buf_grow(Buf *b, size_t need) {
    if (b->len + need <= b->cap) return 0;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + need) cap *= 2;
    char *nd = realloc(b->d, cap);
    if (!nd) return -1;
    b->d = nd;
    b->cap = cap;
    return 0;
}

static int buf_put(Buf *b, const void *bytes, size_t n) {
    if (buf_grow(b, n) != 0) return -1;
    memcpy(b->d + b->len, bytes, n);
    b->len += n;
    return 0;
}

/* u32 big-endian (network order): machine-independent canonical lengths */
static int buf_u32be(Buf *b, uint32_t v) {
    unsigned char q[4] = {
        (unsigned char)(v >> 24), (unsigned char)(v >> 16),
        (unsigned char)(v >> 8),  (unsigned char)v
    };
    return buf_put(b, q, 4);
}

static int buf_byte(Buf *b, unsigned char c) {
    return buf_put(b, &c, 1);
}

/* canonical string: u32-BE length + raw bytes, NO NUL terminator */
static int buf_str(Buf *b, const char *s, char *err, size_t errcap) {
    size_t n = strlen(s);
    if (n > 0xFFFFFFFFULL) return fx_err(err, errcap, "string too long for u32 length: %.32s...", s);
    if (buf_u32be(b, (uint32_t)n) != 0 || buf_put(b, s, n) != 0)
        return fx_err(err, errcap, "out of memory");
    return 0;
}

/* ─── Clean-source exclusion table ──────────────────────────────────────
 * 'Clean' = the source inputs a `make -B <target>` recipe recompiles from.
 * Everything else — git/checkout state, committed build binaries, caches —
 * must NOT influence the store path (the reproducibility bug this fixes), so
 * it is EXCLUDED from the clean-tree hash AND from the materialized clean
 * copy.  This list is the AUTHORITATIVE spec (verified against all 6 repo
 * trees; see handoff-fxstore-cleansrc-artifact-1):
 *   DIRS (basename match, any depth): .git .cache build build-tmp
 *       __pycache__ .py-site pydl  — plus the dl-test-* test-dir prefix
 *   FILES (suffix): .o .a .so .com .dbg .elf .wasm
 *   FILES (prefix): .ape-
 * `.git` matches BOTH a top-level .git directory AND a submodule gitfile
 * (basename `.git`, regardless of file/dir).  Excluded entries are SILENT
 * SKIPS, not errors — a source tree may legitimately contain them, and the
 * hash must be independent of their presence/absence.  Everything else
 * (data files, .dhall, .md, headers) is SOURCE and is hashed/copied. */
static int fx_clean_excluded(const char *basename, int is_dir) {
    if (!strcmp(basename, ".git")) return 1;    /* dir OR submodule gitfile */
    if (is_dir) {
        static const char *const dirs[] = {
            ".cache", "build", "build-tmp", "__pycache__", ".py-site", "pydl"
        };
        for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++)
            if (!strcmp(basename, dirs[i])) return 1;
        if (!strncmp(basename, "dl-test-", 8)) return 1;
    } else {
        static const char *const exts[] = {
            ".o", ".a", ".so", ".com", ".dbg", ".elf", ".wasm"
        };
        size_t bl = strlen(basename);
        for (size_t i = 0; i < sizeof exts / sizeof exts[0]; i++) {
            size_t el = strlen(exts[i]);
            if (bl > el && !strcmp(basename + bl - el, exts[i])) return 1;
        }
        if (!strncmp(basename, ".ape-", 5)) return 1;
    }
    return 0;
}

/* ─── File content hashing (with optional streaming copy) ──────────────── */

/* sha256 of a regular file's bytes; when `dst` is non-NULL the file is
 * stream-copied to it in the SAME single pass, so the bytes written are
 * exactly the bytes hashed — the copy-mode hash is byte-identical to the
 * hash-only walk BY CONSTRUCTION (no second serializer to drift). */
static int sha256_file_copy(const char *path, const char *dst, char out[65],
                            char *err, size_t errcap) {
    FILE *f = fopen(path, "rb");
    if (!f) return fx_err(err, errcap, "cannot open source file '%s': %s", path, strerror(errno));
    FILE *g = NULL;
    if (dst) {
        g = fopen(dst, "wb");
        if (!g) { fclose(f); return fx_err(err, errcap, "cannot create '%s': %s", dst, strerror(errno)); }
    }
    size_t cap = 1 << 16, len = 0;
    char *buf = malloc(cap);
    if (!buf) { if (g) fclose(g); fclose(f); return fx_err(err, errcap, "out of memory"); }
    int rc = -1;
    for (;;) {
        if (len == cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { fx_err(err, errcap, "out of memory"); goto out; }
            buf = nb;
        }
        size_t n = fread(buf + len, 1, cap - len, f);
        if (g && n > 0 && fwrite(buf + len, 1, n, g) != n) {
            fx_err(err, errcap, "write error on '%s'", dst);
            goto out;
        }
        len += n;
        if (n == 0) break;
    }
    if (ferror(f)) { fx_err(err, errcap, "read error on '%s'", path); goto out; }
    sha256_hex(buf, len, out);
    rc = 0;
out:
    if (g) fclose(g);
    fclose(f);
    free(buf);
    return rc;
}

/* ─── fx_clean_tree — clean Merkle hash of a source tree + optional copy ──
 * The ONE Merkle serializer, in two modes:
 *   dst == NULL : hash-only walk (compute_paths' source hashing, verify)
 *   dst != NULL : copy+hash in a single walk (fx_store_ensure_source) —
 *                 dirs are mkdir'd, files stream-copied, symlinks recreated,
 *                 ALL with the SAME serializer as the hash-only mode, so the
 *                 materialized copy's hash == the hash-only walk's hash.
 * Stream = for each NON-EXCLUDED direct child of `dir` (SORTED by name,
 * strcmp): buf_str(child_name) + byte 'd'|'f'|'l' + buf_str(child content
 * hash); a directory child's hash is its own recursive stream hash, a
 * regular file child's is sha256 of its bytes, a symlink child's is sha256
 * of its readlink target (type 'l' — preserved from the original hashing).
 * The returned hash is sha256 over the top-level stream.  Hidden files are
 * CONTENT (only "." and ".." are skipped); excluded entries are SILENT
 * SKIPS; special files (sockets, devices, fifos) are rejected loudly. */
typedef struct { char *name; char hash[65]; unsigned char type; } DirEnt;

static int dirent_cmp(const void *a, const void *b) {
    return strcmp(((const DirEnt *)a)->name, ((const DirEnt *)b)->name);
}

int fx_clean_tree(const char *dir, const char *dst, char hash_out[65],
                  char *err, size_t errcap) {
    DIR *d = opendir(dir);
    if (!d) return fx_err(err, errcap, "cannot open source dir '%s': %s", dir, strerror(errno));

    DirEnt *ents = NULL;
    size_t n = 0, cap = 0;
    struct dirent *e;
    int rc = -1;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 16;
            DirEnt *ne = realloc(ents, cap * sizeof *ents);
            if (!ne) { fx_err(err, errcap, "out of memory"); goto out; }
            ents = ne;
        }
        /* full child path (bounded: dir + '/' + name) */
        size_t plen = strlen(dir) + 1 + strlen(e->d_name) + 1;
        char *child = malloc(plen);
        if (!child) { fx_err(err, errcap, "out of memory"); goto out; }
        snprintf(child, plen, "%s/%s", dir, e->d_name);

        struct stat st;
        if (lstat(child, &st) != 0) {
            fx_err(err, errcap, "cannot stat '%s': %s", child, strerror(errno));
            free(child);
            goto out;
        }
        /* silent skip of excluded entries (git state, committed binaries,
         * caches) — see fx_clean_excluded */
        if (fx_clean_excluded(e->d_name, S_ISDIR(st.st_mode))) {
            free(child);
            continue;
        }

        /* copy-mode destination child path (NULL in hash-only mode) */
        char *dchild = NULL;
        if (dst) {
            size_t dlen = strlen(dst) + 1 + strlen(e->d_name) + 1;
            dchild = malloc(dlen);
            if (!dchild) { fx_err(err, errcap, "out of memory"); free(child); goto out; }
            snprintf(dchild, dlen, "%s/%s", dst, e->d_name);
        }

        if (S_ISDIR(st.st_mode)) {
            if (dchild && mkdir(dchild, 0755) != 0) {
                fx_err(err, errcap, "cannot create '%s': %s", dchild, strerror(errno));
                free(child); free(dchild); goto out;
            }
            ents[n].type = 'd';
            if (fx_clean_tree(child, dchild, ents[n].hash, err, errcap) != 0) {
                free(child); free(dchild); goto out;
            }
        } else if (S_ISREG(st.st_mode)) {
            ents[n].type = 'f';
            if (sha256_file_copy(child, dchild, ents[n].hash, err, errcap) != 0) {
                free(child); free(dchild); goto out;
            }
        } else if (S_ISLNK(st.st_mode)) {
            /* A symlink is content: its TARGET (readlink bytes) is hashed,
             * type 'l'.  This keeps the store path a function of the actual
             * tree content — a symlink retarget changes the hash — while
             * accepting trees that legitimately contain symlinks (e.g. the
             * vendored ggml in datalog-dafsa).  In copy mode it is recreated
             * via symlink(); a broken symlink (readlink succeeds, target
             * missing) is still hashed and copied faithfully. */
            char target[PATH_MAX];
            ssize_t tl = readlink(child, target, sizeof target - 1);
            if (tl < 0) {
                fx_err(err, errcap, "readlink '%s': %s", child, strerror(errno));
                free(child); free(dchild); goto out;
            }
            target[tl] = '\0';
            sha256_hex((const unsigned char *)target, (size_t)tl, ents[n].hash);
            ents[n].type = 'l';
            if (dchild && symlink(target, dchild) != 0) {
                fx_err(err, errcap, "symlink '%s': %s", dchild, strerror(errno));
                free(child); free(dchild); goto out;
            }
        } else {
            fx_err(err, errcap, "unsupported special source entry '%s'", child);
            free(child); free(dchild); goto out;
        }
        free(child);
        free(dchild);
        ents[n].name = strdup(e->d_name);
        if (!ents[n].name) { fx_err(err, errcap, "out of memory"); goto out; }
        n++;
    }
    closedir(d);
    d = NULL;

    /* readdir order is filesystem-dependent: SORT for determinism */
    qsort(ents, n, sizeof *ents, dirent_cmp);

    Buf b = {0};
    for (size_t i = 0; i < n; i++) {
        if (buf_str(&b, ents[i].name, err, errcap) != 0) goto out2;
        if (buf_byte(&b, ents[i].type) != 0) goto out2;
        if (buf_str(&b, ents[i].hash, err, errcap) != 0) goto out2;
    }
    sha256_hex(b.d ? b.d : "", b.len, hash_out);
    rc = 0;
out2:
    free(b.d);
out:
    if (d) closedir(d);
    for (size_t i = 0; i < n; i++) free(ents[i].name);
    free(ents);
    return rc;
}

int fx_content_hash_dir(const char *dir, char hash_out[65], char *err, size_t errcap) {
    /* thin wrapper: hash-only clean walk (no copy) */
    return fx_clean_tree(dir, NULL, hash_out, err, errcap);
}

/* ─── Canonical action tags (fixed one-byte kind markers) ──────────────── */

static unsigned char act_tag(ActionKind k) {
    switch (k) {
    case ACT_SHELL:   return 'S';
    case ACT_COPY:    return 'C';
    case ACT_MKDIR:   return 'M';
    case ACT_RM:      return 'R';
    case ACT_TOUCH:   return 'T';
    case ACT_MOVE:    return 'V';
    case ACT_SYMLINK: return 'L';
    case ACT_CHMOD:   return 'H';
    case ACT_ECHO:    return 'E';
    case ACT_ENV:     return 'N';
    case ACT_RUN:     return 'X';
    }
    return '?';
}

static int buf_action(Buf *b, const Action *a, char *err, size_t errcap) {
    if (buf_byte(b, act_tag(a->kind)) != 0) return fx_err(err, errcap, "out of memory");
    if (a->kind == ACT_RUN) {
        if ((uint32_t)a->nav != (size_t)a->nav)
            return fx_err(err, errcap, "Run argv too long");
        if (buf_u32be(b, (uint32_t)a->nav) != 0) return fx_err(err, errcap, "out of memory");
        for (int i = 0; i < a->nav; i++)
            if (buf_str(b, a->av[i], err, errcap) != 0) return -1;
        return 0;
    }
    /* every other action: one or two len-prefixed Text fields (a [, b]) */
    if (buf_str(b, a->a ? a->a : "", err, errcap) != 0) return -1;
    switch (a->kind) {
    case ACT_COPY: case ACT_MOVE: case ACT_SYMLINK:
    case ACT_CHMOD: case ACT_ENV:
        if (buf_str(b, a->b ? a->b : "", err, errcap) != 0) return -1;
        break;
    default:
        break;
    }
    return 0;
}

static int pcmp(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Canonical derivation serialization with a PRECOMPUTED clean source hash:
 * for SRC_PATH, `src_hash` is the clean-tree hash (fx_content_hash_dir /
 * fx_clean_tree) computed by the caller ONCE and stored in PathEntry.src_hash
 * so compute_paths and fx_store_ensure_source share it (no double hash walk,
 * and the derivation hash and the materialized src are provably the same
 * content).  For SRC_FETCH, src_hash must be NULL and url+hash are used. */
int fx_derivation_hash_ex(const Package *p, const char *src_hash,
                          char *const *dep_paths, int ndeps,
                          char hash_out[65], char *err, size_t errcap) {
    if (!p || !hash_out) return fx_err(err, errcap, "internal: null package/hash");
    if (ndeps < 0) return fx_err(err, errcap, "internal: negative dep count");
    if (p->src.kind == SRC_PATH && !src_hash)
        return fx_err(err, errcap, "internal: SRC_PATH without a precomputed src hash");

    Buf b = {0};

    /* (1) magic — versioned so a format change can never silently alias */
    if (buf_str(&b, "fxstore-drv-v1\n", err, errcap) != 0) goto fail;

    /* (2) name, (3) version */
    if (buf_str(&b, p->name, err, errcap) != 0) goto fail;
    if (buf_str(&b, p->version, err, errcap) != 0) goto fail;

    /* (4) src: 'P' + clean content-hash of the tree | 'F' + url + hash */
    if (p->src.kind == SRC_PATH) {
        if (buf_byte(&b, 'P') != 0) { fx_err(err, errcap, "out of memory"); goto fail; }
        if (buf_str(&b, src_hash, err, errcap) != 0) goto fail;
    } else {
        if (buf_byte(&b, 'F') != 0) { fx_err(err, errcap, "out of memory"); goto fail; }
        if (buf_str(&b, p->src.url, err, errcap) != 0) goto fail;
        if (buf_str(&b, p->src.hash, err, errcap) != 0) goto fail;
    }

    /* (5) target */
    if (buf_str(&b, p->target, err, errcap) != 0) goto fail;

    /* (6) recipe: u32 count + actions IN ORDER (order is semantic) */
    {
        uint32_t na = 0;
        for (const Action *a = p->recipe; a; a = a->next) na++;
        if (buf_u32be(&b, na) != 0) { fx_err(err, errcap, "out of memory"); goto fail; }
        for (const Action *a = p->recipe; a; a = a->next)
            if (buf_action(&b, a, err, errcap) != 0) goto fail;
    }

    /* (7) deps: u32 count + each direct dep's FULL store path, SORTED
     * (enforced here — callers may pass any order) */
    {
        char **sorted = NULL;
        if (ndeps > 0) {
            sorted = malloc((size_t)ndeps * sizeof *sorted);
            if (!sorted) { fx_err(err, errcap, "out of memory"); goto fail; }
            for (int i = 0; i < ndeps; i++) sorted[i] = dep_paths[i];
            qsort(sorted, (size_t)ndeps, sizeof *sorted, pcmp);
        }
        if (buf_u32be(&b, (uint32_t)ndeps) != 0) { free(sorted); fx_err(err, errcap, "out of memory"); goto fail; }
        for (int i = 0; i < ndeps; i++)
            if (buf_str(&b, sorted[i], err, errcap) != 0) { free(sorted); goto fail; }
        free(sorted);
    }

    sha256_hex(b.d, b.len, hash_out);
    free(b.d);
    return 0;
fail:
    free(b.d);
    return -1;
}

/* Convenience wrapper: compute the clean source hash (hash-only walk) then
 * delegate to fx_derivation_hash_ex.  Callers that already computed the hash
 * (compute_paths, which must reuse it for fx_store_ensure_source) call the
 * _ex form directly. */
int fx_derivation_hash(const Package *p, char *const *dep_paths, int ndeps,
                       char hash_out[65], char *err, size_t errcap) {
    char src_hash[65];
    if (p->src.kind == SRC_PATH) {
        if (fx_content_hash_dir(p->src.path, src_hash, err, errcap) != 0) return -1;
        return fx_derivation_hash_ex(p, src_hash, dep_paths, ndeps,
                                     hash_out, err, errcap);
    }
    return fx_derivation_hash_ex(p, NULL, dep_paths, ndeps,
                                 hash_out, err, errcap);
}

void fx_store_path_of(const char *store_root, const char *hash,
                      const char *name, char *out, size_t cap) {
    snprintf(out, cap, "%s/%s-%s", store_root, hash, name);
}

int fx_derivation_store_path(const Package *p, char *const *dep_paths, int ndeps,
                             const char *store_root, char *path_out, size_t cap,
                             char *err, size_t errcap) {
    char hash[65];
    if (fx_derivation_hash(p, dep_paths, ndeps, hash, err, errcap) != 0) return -1;
    fx_store_path_of(store_root, hash, p->name, path_out, cap);
    return 0;
}
