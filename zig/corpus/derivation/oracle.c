/* u2oracle.c — C oracle for the fxstore U2 Zig port goldens.
 * Links the REAL derivation.c + dhall-c sha256.c and prints the byte-exact
 * hashes the Zig port must reproduce. */
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include "fxstore.h"
#include "dhall.h"

#define P printf
#define CHECK(cond, what) do { if (!(cond)) { fprintf(stderr, "ORACLE FAIL: %s: %s\n", what, err); return 1; } } while (0)

int main(int argc, char **argv) {
    char err[512], hash[65], sp[4096];
    if (argc < 3) { fprintf(stderr, "usage: %s <tree> <copydst>\n", argv[0]); return 2; }
    const char *tree = argv[1], *copydst = argv[2];

    /* clean-tree hash, no per-pkg excludes */
    CHECK(fx_content_hash_dir(tree, NULL, 0, hash, err, sizeof err) == 0, "content_hash_dir");
    P("tree %s\n", hash);

    /* per-pkg exclude variants */
    char *ex1[] = { "docs/cache" };
    CHECK(fx_content_hash_dir(tree, ex1, 1, hash, err, sizeof err) == 0, "ex docs/cache");
    P("ex_docs_cache %s\n", hash);

    char *ex2[] = { "sub" };
    CHECK(fx_content_hash_dir(tree, ex2, 1, hash, err, sizeof err) == 0, "ex sub");
    P("ex_sub %s\n", hash);

    char *ex3[] = { "sub/nested.txt" };
    CHECK(fx_content_hash_dir(tree, ex3, 1, hash, err, sizeof err) == 0, "ex sub/nested.txt");
    P("ex_sub_nested %s\n", hash);

    char *ex4[] = { "", "docs/cache" };  /* empty entry is defense-skipped */
    CHECK(fx_content_hash_dir(tree, ex4, 2, hash, err, sizeof err) == 0, "ex empty+docs/cache");
    P("ex_empty_docs_cache %s\n", hash);

    char *ex5[] = { "doc" };  /* prefix boundary: must NOT exclude docs/ */
    CHECK(fx_content_hash_dir(tree, ex5, 1, hash, err, sizeof err) == 0, "ex doc");
    P("ex_doc %s\n", hash);

    /* empty dir hash */
    mkdir("/tmp/fxu2/empty", 0755);
    CHECK(fx_content_hash_dir("/tmp/fxu2/empty", NULL, 0, hash, err, sizeof err) == 0, "empty dir");
    P("empty_dir %s\n", hash);

    /* copy mode: dst dir must already exist; copy-hash must equal walk-hash */
    mkdir(copydst, 0755);
    char srccopy[65];
    memcpy(srccopy, hash, 65); /* not yet used */
    CHECK(fx_content_hash_dir(tree, NULL, 0, srccopy, err, sizeof err) == 0, "pre-copy walk");
    CHECK(fx_clean_tree(tree, copydst, NULL, 0, hash, err, sizeof err) == 0, "clean_tree copy");
    P("copy %s\n", hash);
    CHECK(fx_content_hash_dir(copydst, NULL, 0, hash, err, sizeof err) == 0, "re-hash copy");
    P("copyhash %s\n", hash);
    if (strcmp(srccopy, hash) != 0) { fprintf(stderr, "ORACLE: copy-hash != walk-hash!\n"); return 1; }

    /* copy mode WITH a per-pkg exclude */
    char copydst2[4096];
    snprintf(copydst2, sizeof copydst2, "%s2", copydst);
    mkdir(copydst2, 0755);
    CHECK(fx_clean_tree(tree, copydst2, ex1, 1, hash, err, sizeof err) == 0, "copy excl");
    P("copy_ex_docs_cache %s\n", hash);

    /* ── derivation goldens ─────────────────────────────────────────────── */
    const char *tree_hash = srccopy;

    Package a; memset(&a, 0, sizeof a);
    a.name = "hello"; a.version = "1.0";
    a.src.kind = SRC_PATH; a.src.path = "/src/hello";
    a.target = "hello";
    Action mk = { ACT_SHELL, .a = "make hello" };
    Action cp = { ACT_COPY, .a = "hello", .b = "bin/hello" };
    Action md = { ACT_MKDIR, .a = "bin" };
    Action rm = { ACT_RM, .a = "old" };
    Action tc = { ACT_TOUCH, .a = "stamp" };
    Action mv = { ACT_MOVE, .a = "a", .b = "b" };
    Action sl = { ACT_SYMLINK, .a = "target", .b = "link" };
    Action ch = { ACT_CHMOD, .a = "bin/hello", .b = "0755" };
    Action ec = { ACT_ECHO, .a = "hello world" };
    Action ev = { ACT_ENV, .a = "CC", .b = "cc" };
    char *av[] = { "./configure", "--prefix=/build" };
    Action rn = { ACT_RUN, .av = av, .nav = 2 };
    mk.next = &cp; cp.next = &md; md.next = &rm; rm.next = &tc; tc.next = &mv;
    mv.next = &sl; sl.next = &ch; ch.next = &ec; ec.next = &ev; ev.next = &rn;
    a.recipe = &mk;
    char *depsA[] = {
        "/fx/store/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff-zzz-dep",
        "/fx/store/0000000000000000000000000000000000000000000000000000000000000000-aaa-dep",
    };
    CHECK(fx_derivation_hash_ex(&a, tree_hash, depsA, 2, hash, err, sizeof err) == 0, "drvA");
    P("drvA %s\n", hash);
    fx_store_path_of("/fx/store", hash, a.name, sp, sizeof sp);
    P("spA %s\n", sp);

    /* dep-path sensitivity */
    char *depsA2[] = {
        "/fx/store/1111111111111111111111111111111111111111111111111111111111111111-zzz-dep",
        "/fx/store/0000000000000000000000000000000000000000000000000000000000000000-aaa-dep",
    };
    CHECK(fx_derivation_hash_ex(&a, tree_hash, depsA2, 2, hash, err, sizeof err) == 0, "drvA2");
    P("drvA2 %s\n", hash);

    /* fetch-src derivation */
    Package b; memset(&b, 0, sizeof b);
    b.name = "world"; b.version = "2.3.4";
    b.src.kind = SRC_FETCH;
    b.src.url = "https://example.com/world-2.3.4.tar.gz";
    b.src.hash = "f2ca1bb3c199e6c9eda0f4d1e7bb8b4b0f1b2a3c4d5e6f708192a3b4c5d6e7f8";
    b.target = "world"; b.recipe = NULL;
    char *depsB[] = { "/fx/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello" };
    CHECK(fx_derivation_hash_ex(&b, NULL, depsB, 1, hash, err, sizeof err) == 0, "drvB");
    P("drvB %s\n", hash);
    fx_store_path_of("/fx/store", hash, b.name, sp, sizeof sp);
    P("spB %s\n", sp);

    /* SRC_PATH without precomputed hash must be rejected */
    CHECK(fx_derivation_hash_ex(&a, NULL, depsA, 2, hash, err, sizeof err) != 0, "drvA no hash");
    P("drvA_nohash_err %s\n", err);

    /* special-file rejection */
    { char fifodir[] = "/tmp/fxu2/fifo";
      mkdir(fifodir, 0755);
      char fifopath[4096]; snprintf(fifopath, sizeof fifopath, "%s/pipe", fifodir);
      mkfifo(fifopath, 0644);
      int rc = fx_content_hash_dir(fifodir, NULL, 0, hash, err, sizeof err);
      P("fifo_rc %d\n", rc);
      P("fifo_err %s\n", err);
    }
    return 0;
}
