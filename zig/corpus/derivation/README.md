# fxstore U2 Zig-port goldens — byte-exact C reference values
#
# Produced by running the REAL C implementation (derivation.c + the vendored
# dhall-c sha256.c) against the fixture tree defined by build-tree.sh:
#
#   cd <fxstore repo root>
#   zig cc -std=gnu11 -O2 -I. -Ivendor/dhall-c/src \
#       zig/corpus/derivation/oracle.c derivation.c \
#       vendor/dhall-c/src/sha256.c -o /tmp/u2oracle
#   sh zig/corpus/derivation/build-tree.sh /tmp/fxu2/tree
#   mkdir -p /tmp/fxu2/copy
#   /tmp/u2oracle /tmp/fxu2/tree /tmp/fxu2/copy
#
# oracle.c reproduces the fixture tree semantics via build-tree.sh; the same
# tree is mirrored BYTE-FOR-BYTE in Zig by build_fixture_tree in
# zig/src/derivation.zig (the golden tests pin the values below, so any
# drift between the two builders fails loudly).
#
# Line semantics (see oracle.c):
#   tree                 fx_content_hash_dir(tree, no excludes)
#   ex_docs_cache        excludes = {"docs/cache"}
#   ex_sub               excludes = {"sub"}
#   ex_sub_nested        excludes = {"sub/nested.txt"}
#   ex_empty_docs_cache  excludes = {"", "docs/cache"} (empty entry skipped)
#   ex_doc               excludes = {"doc"} (prefix boundary: docs/ kept)
#   empty_dir            sha256 of the empty Merkle stream == sha256("")
#   copy                 fx_clean_tree(tree -> copy)   [== tree: by construction]
#   copyhash             re-hash of the materialized copy [== tree]
#   copy_ex_docs_cache   copy mode with excludes {"docs/cache"}
#   drvA                 fx_derivation_hash_ex(Package a, tree hash, 2 deps unsorted)
#   spA                  fx_store_path_of("/fx/store", drvA, "hello")
#   drvA2                same but first dep path changed (dep sensitivity)
#   drvB                 fetch-src Package b (url+hash serialized)
#   spB                  fx_store_path_of("/fx/store", drvB, "world")
#   drvA_nohash_err      SRC_PATH without a precomputed hash -> error text
#   fifo_rc / fifo_err   fifo in the tree -> loud rejection, exact message
#
# Package a/b field values are in oracle.c and mirrored in
# zig/src/derivation.zig (build_pkg_a + the world package literal).
