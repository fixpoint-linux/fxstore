-- m3/package-set.dhall — fixpoint-linux M3 self-hosting package set.
--
-- Specifies the org's self-hosting packages as fxstore derivations so the
-- system rebuilds itself from this one Dhall file.  Each package's src is its
-- WHOLE repo tree (vendored deps included); deps are LOGICAL build-order edges
-- that reflect the vendoring, so the datalog closure/topo-sort is meaningful
-- (the org thesis demonstrated) WITHOUT requiring Makefile/Dhakefile changes.
--
-- Recipe shape (same for every package): copy the ro-bound source tree into
-- the rw workdir via $FX_SRC (injected by build.c), then build with `make -B`
-- (force rebuild; never trust stale copied artifacts).  The built binary lands
-- in the workdir, which store.c renames into the store.
--
-- Usage:  cd fxstore/m3 && fxstore build --store /fx/store   (or any root)
--
-- NOTE: src paths are RELATIVE to this file (../../ = /home/arch/projects),
-- so the spec is relocatable alongside the sibling repo checkouts.
-- version values are placeholders — set each to its repo's git tag/commit
-- before finalizing.

let Action =
      < Shell : Text
      | Copy : { from : Text, to : Text }
      | Mkdir : Text
      | Rm : Text
      | Touch : Text
      | Move : { from : Text, to : Text }
      | Symlink : { from : Text, to : Text }
      | Chmod : { path : Text, mode : Text }
      | Echo : Text
      | Env : { key : Text, value : Text }
      | Run : { argv : List Text }
      >

let Src = < Path : Text | Fetch : { url : Text, hash : Text } >
let Build = { target : Text, recipe : List Action }
let Package = { name : Text, version : Text, src : Src, deps : List Text, build : Build }
let PackageSet = { packages : List Package }

in  { packages =
      [ { name = "dafsa", version = "0.1.0", src = < Path = "../../github/dafsa" >,
          deps = [] : List Text,
          build = { target = "dafsa",
                    recipe = [ < Shell = "cp -a \"$FX_SRC\"/. . && make -B dafsa" > ] } }
      , { name = "dhall-c", version = "0.1.0", src = < Path = "../../dhall-c" >,
          deps = [] : List Text,
          build = { target = "dhall.com",
                    recipe = [ < Shell = "cp -a \"$FX_SRC\"/. . && make -B dhall.com" > ] } }
      , { name = "datalog-dafsa", version = "0.1.0", src = < Path = "../../datalog-dafsa" >,
          deps = [ "dafsa" ],
          build = { target = "dl",
                    recipe = [ < Shell = "cp -a \"$FX_SRC\"/. . && make -B dl" > ] } }
      , { name = "dhake", version = "0.1.0", src = < Path = "../../dhake" >,
          deps = [ "dhall-c" ],
          build = { target = "dhake.com",
                    recipe =
                      [ < Shell = "cp -a \"$FX_SRC\"/. . && cosmocc -std=c11 -O2 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L -I vendor/dhall-c/src -o dhake.com src/dhake.c vendor/dhall-c/src/arena.c vendor/dhall-c/src/lexer.c vendor/dhall-c/src/parser.c vendor/dhall-c/src/ast.c vendor/dhall-c/src/normalize.c vendor/dhall-c/src/typecheck.c vendor/dhall-c/src/builtins.c vendor/dhall-c/src/serialize.c vendor/dhall-c/src/import.c vendor/dhall-c/src/bignum.c vendor/dhall-c/src/sha256.c vendor/dhall-c/src/ssrf.c vendor/dhall-c/src/http.c" > ] } }
      , { name = "compendium", version = "0.1.0", src = < Path = "../../compendium" >,
          deps = [ "dhall-c" ],
          build = { target = "dnsd.com",
                    recipe = [ < Shell = "cp -a \"$FX_SRC\"/. . && make -B dnsd.com" > ] } }
      , { name = "visage", version = "0.1.0", src = < Path = "../../visage" >,
          deps = [ "dhall-c", "datalog-dafsa" ],
          build = { target = "visage.com",
                    recipe = [ < Shell = "cp -a \"$FX_SRC\"/. . && make -B visage.com" > ] } }
      ] }
  : PackageSet
