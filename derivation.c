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

/* ─── File content hashing ─────────────────────────────────────────────── */

static int sha256_file(const char *path, char out[65], char *err, size_t errcap) {
    FILE *f = fopen(path, "rb");
    if (!f) return fx_err(err, errcap, "cannot open source file '%s': %s", path, strerror(errno));
    size_t cap = 1 << 16, len = 0;
    char *buf = malloc(cap);
    if (!buf) { fclose(f); return fx_err(err, errcap, "out of memory"); }
    for (;;) {
        if (len == cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); fclose(f); return fx_err(err, errcap, "out of memory"); }
            buf = nb;
        }
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) break;
    }
    if (ferror(f)) {
        free(buf); fclose(f);
        return fx_err(err, errcap, "read error on '%s'", path);
    }
    fclose(f);
    sha256_hex(buf, len, out);
    free(buf);
    return 0;
}

/* ─── content_hash_dir — Merkle hash of a source tree ────────────────────
 * Stream = for each direct child of `dir` (SORTED by name, strcmp):
 *     buf_str(child_name) + byte 'd'|'f' + buf_str(child content hash)
 * where a directory child's content hash is its own recursive stream hash
 * and a regular file child's is sha256 of its bytes.  The returned hash is
 * sha256 over the top-level stream.  Hidden files are CONTENT (only "."
 * and ".." are skipped); symlinks and special files are rejected loudly. */

typedef struct { char *name; char hash[65]; unsigned char type; } DirEnt;

static int dirent_cmp(const void *a, const void *b) {
    return strcmp(((const DirEnt *)a)->name, ((const DirEnt *)b)->name);
}

int fx_content_hash_dir(const char *dir, char hash_out[65], char *err, size_t errcap) {
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
        if (S_ISDIR(st.st_mode)) {
            ents[n].type = 'd';
            if (fx_content_hash_dir(child, ents[n].hash, err, errcap) != 0) { free(child); goto out; }
        } else if (S_ISREG(st.st_mode)) {
            ents[n].type = 'f';
            if (sha256_file(child, ents[n].hash, err, errcap) != 0) { free(child); goto out; }
        } else if (S_ISLNK(st.st_mode)) {
            /* A symlink is content: its TARGET (readlink bytes) is hashed,
             * type 'l'.  This keeps the store path a function of the actual
             * tree content — a symlink retarget changes the hash — while
             * accepting trees that legitimately contain symlinks (e.g. the
             * vendored ggml in datalog-dafsa).  The workdir copy (cp -a) and
             * the sandbox ro-bind both preserve symlinks, so the recipe can
             * follow them; a broken symlink (readlink succeeds, target
             * missing) is still hashed and copied faithfully. */
            char target[PATH_MAX];
            ssize_t tl = readlink(child, target, sizeof target - 1);
            if (tl < 0) {
                fx_err(err, errcap, "readlink '%s': %s", child, strerror(errno));
                free(child);
                goto out;
            }
            target[tl] = '\0';
            sha256_hex((const unsigned char *)target, (size_t)tl, ents[n].hash);
            ents[n].type = 'l';
        } else {
            fx_err(err, errcap, "unsupported special source entry '%s'", child);
            free(child);
            goto out;
        }
        free(child);
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

int fx_derivation_hash(const Package *p, char *const *dep_paths, int ndeps,
                       char hash_out[65], char *err, size_t errcap) {
    if (!p || !hash_out) return fx_err(err, errcap, "internal: null package/hash");
    if (ndeps < 0) return fx_err(err, errcap, "internal: negative dep count");

    Buf b = {0};
    char src_hash[65];

    /* (1) magic — versioned so a format change can never silently alias */
    if (buf_str(&b, "fxstore-drv-v1\n", err, errcap) != 0) goto fail;

    /* (2) name, (3) version */
    if (buf_str(&b, p->name, err, errcap) != 0) goto fail;
    if (buf_str(&b, p->version, err, errcap) != 0) goto fail;

    /* (4) src: 'P' + content-hash of the tree | 'F' + url + hash */
    if (p->src.kind == SRC_PATH) {
        if (buf_byte(&b, 'P') != 0) { fx_err(err, errcap, "out of memory"); goto fail; }
        if (fx_content_hash_dir(p->src.path, src_hash, err, errcap) != 0) goto fail;
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
