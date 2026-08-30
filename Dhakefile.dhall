-- Dhakefile.dhall — build fxstore's native CLI and its docs site with dhake.
--
-- Native build (replaces the old Makefile):
--    ./dhake/dhake.com            # default target: the Zig port (zig-out/bin/fxstore)
--    ./dhake/dhake.com stage3     # build the palisade stage3 sandbox binary
--    ./dhake/dhake.com zig-test   # run the port's unit tests
--    ./dhake/dhake.com test       # run every test suite
--    ./dhake/dhake.com clean      # remove the native binaries
--
--   The CLI is the Zig port (root build.zig + zig/src): `zig` runs `zig build`
--   and bakes in the palisade stage3 sandbox binary (vendor/palisade
--   submodule).  Requires the Zig toolchain.  The C oracle sources were
--   removed (U2); the pre-built C binary ./fxstore, if present, is only the
--   frozen differential-harness reference (zig-diff).
--
-- Web build:
--    ./dhake/dhake.com dist/index.html   # the docs site (Elm + MFE + SSG)
--
--   The site is an Elm app (src/Main.elm) rendered against the shared
--   Fixpoint.* design package (the `design` submodule) plus the mfe-framework
--   (the `mfe-framework` submodule). The pipeline:
--     1. build mfe-framework (tsc) -> its dist JS
--     2. copy mfe-framework dist JS into vendor/@mfe/  (served here)
--     3. elm make src/Main.elm -> dist/elm.js
--     4. node scripts/ssg.mjs   -> dist/index.html  (SSG render of the docs MFE)

let Action =
      < Shell : Text
      | Copy : { from : Text, to : Text }
      | Mkdir : < Plain : Text | Parents : { path : Text, parents : Bool } >
      | Rm : < Plain : Text | Recursive : { path : Text, recursive : Bool } >
      | Touch : Text
      | Move : { from : Text, to : Text }
      | Symlink : { from : Text, to : Text }
      | Chmod : { path : Text, mode : Text }
      | Echo : Text
      | Env : { key : Text, value : Text }
      | Run : { argv : List Text }
      >

let Target = { deps : List Text, phony : Bool, recipe : List Action }

-- The palisade stage3 inner sandbox binary (seccomp/Landlock layer).  Built by
-- delegating to palisade's own Dhakefile (vendor/palisade/Dhakefile.dhall); the
-- target name is the output file so up-to-date tracking works across the
-- submodule boundary.
let stage3_path = "vendor/palisade/bin/stage3"

in  { targets =
        [ { mapKey = "vendor/palisade/bin/stage3"
          , mapValue =
              { deps =
                  [ "vendor/palisade/Dhakefile.dhall"
                  , "vendor/palisade/src/palisade/stage3.c"
                  , "vendor/palisade/src/palisade/cosmo/pledge-rattan.c"
                  ]
              , phony = False
              , recipe =
                  -- Run palisade's dhake in its own directory.  (dhake has no
                  -- -C; a Shell action starts in the buildfile's cwd, so cd
                  -- into the submodule and run its Dhakefile's stage3 target.)
                  [ < Shell = "cd vendor/palisade && ../../dhake/dhake.com bin/stage3" > ]
              }
          }
        , { mapKey = "stage3"
          , mapValue =
              { deps = [ "vendor/palisade/bin/stage3" ]
              , phony = True
              , recipe = [] : List Action
              }
          }
        -- ─── tests ──────────────────────────────────────────────────────────
        , { mapKey = "fxstore-golden"
          , mapValue = { deps = [ "fxstore" ], phony = True
                       , recipe = [ < Shell = "sh tests/fxstore_golden.sh ./fxstore" > ] }
          }
        , { mapKey = "fxstore-sandboxed"
          , mapValue = { deps = [ "fxstore" ], phony = True
                       , recipe = [ < Shell = "sh tests/fxstore_sandboxed.sh ./fxstore" > ] }
          }
        , { mapKey = "fxstore-m3"
          , mapValue = { deps = [ "fxstore" ], phony = True
                       , recipe = [ < Shell = "sh tests/fxstore_m3.sh ./fxstore" > ] }
          }
        , { mapKey = "fxstore-repro"
          , mapValue = { deps = [ "fxstore" ], phony = True
                       , recipe = [ < Shell = "sh tests/fxstore_repro.sh ./fxstore" > ] }
          }
        , { mapKey = "fxstore-excludes"
          , mapValue = { deps = [ "fxstore" ], phony = True
                       , recipe = [ < Shell = "sh tests/fxstore_excludes.sh ./fxstore" > ] }
          }
        , { mapKey = "fxstore-timeline"
          , mapValue = { deps = [ "fxstore" ], phony = True
                       , recipe = [ < Shell = "sh tests/fxstore_timeline.sh ./fxstore" > ] }
          }
        -- ─── Zig port ───────────────────────────────────────────────────────
        -- The Zig port (zig/src/*.zig + repo-root build.zig) builds the same
        -- `fxstore` CLI to zig-out/bin/fxstore.  `zig` builds it; `zig-test`
        -- runs the port's unit tests; `zig-diff` byte-compares the Zig binary
        -- against the C oracle over the shared corpus (the final gate).
        , { mapKey = "zig"
          , mapValue =
              { deps = [ "build.zig", "vendor/palisade/bin/stage3" ]
              , phony = True
              , recipe = [ < Shell = "zig build" > ]
              }
          }
        , { mapKey = "zig-test"
          , mapValue = { deps = [ "zig" ], phony = True
                       , recipe = [ < Shell = "zig build test" > ] }
          }
        , { mapKey = "zig-diff"
          , mapValue = { deps = [ "zig", "fxstore" ], phony = True
                       , recipe = [ < Shell = "sh zig/diff.sh" > ] }
          }

        , { mapKey = "test"
          , mapValue =
              { deps =
                  [ "fxstore-golden"
                  , "fxstore-sandboxed"
                  , "fxstore-m3"
                  , "fxstore-repro"
                  , "fxstore-excludes"
                  , "fxstore-timeline"
                  , "zig-test"
                  , "zig-diff"
                  ]
              , phony = True
              , recipe = [] : List Action
              }
          }

        -- ─── clean ──────────────────────────────────────────────────────────
        , { mapKey = "clean"
          , mapValue =
              { deps = [] : List Text
              , phony = True
              , recipe =
                  [ < Rm = "fxstore" >
                  , < Rm = "fxstore.aarch64.elf" >
                  , < Rm = "fxstore.com.dbg" >
                  , < Rm = "zig-out" >
                  , < Rm = ".zig-cache" >
                  ]
              }
          }

        -- ─── docs site ──────────────────────────────────────────────────────
        -- mfe-framework submodule source that, when touched, forces a rebuild.
        -- phony: its build is a plain `npm ci && npm run build` whose outputs
        -- live inside the submodule (packages/*/dist), not at a stable
        -- top-level path, so treat it as always-rebuild.
        , { mapKey = "mfe-framework"
          , mapValue =
              { deps = []
              , phony = True
              , recipe =
                  [ < Shell = "cd mfe-framework && npm ci && npm run build" >
                  ]
              }
          }
        , { mapKey = "vendor-mfe"
          , mapValue =
              { deps = [ "mfe-framework" ]
              , phony = True
              , recipe =
                  -- dhake's Rm/Mkdir are recursive now (opt-in flags): wipe and
                  -- recreate vendor/@mfe with parents, then copy the framework
                  -- dist JS in.
                  [ < Rm = { path = "vendor/@mfe", recursive = True } >
                  , < Mkdir = { path = "vendor/@mfe/core", parents = True } >
                  , < Mkdir = { path = "vendor/@mfe/framework", parents = True } >
                  , < Shell =
                        "cp mfe-framework/packages/core/dist/*.js vendor/@mfe/core/"
                    >
                  , < Shell =
                        "cp mfe-framework/packages/framework/dist/*.js vendor/@mfe/framework/"
                    >
                  ]
              }
          }
        , { mapKey = "dist/elm.js"
          , mapValue =
              { deps = [ "src/Main.elm", "elm.json", "design/src" ]
              , phony = False
              , recipe =
                  -- elm is a vendored ELF at node_modules/elm/bin/elm; npm's
                  -- script runner injects node_modules/.bin onto PATH, but a
                  -- plain dhake Shell action does not, so use the real path.
                  [ < Shell =
                        "node_modules/elm/bin/elm make src/Main.elm --output=dist/elm.js --optimize"
                    >
                  ]
              }
          }
        , { mapKey = "dist/index.html"
          , mapValue =
              { deps =
                  [ "dist/elm.js"
                  , "vendor-mfe"
                  , "shell/index.html"
                  , "scripts/ssg.mjs"
                  ]
              , phony = False
              , recipe = [ < Shell = "node scripts/ssg.mjs" > ]
              }
          }
        ]
      , default = "zig"
      }
