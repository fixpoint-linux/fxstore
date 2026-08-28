-- good.dhall — U1 happy-path fixture.  Ascriptions go on RECORD FIELD VALUES
-- only (this dhall-c grammar parses list elements at atom level, so
-- `[ x : T ]` is invalid; the `deps = [] : List Text` style is the house
-- shape).  Path src exercises realpath canonicalization, Fetch src, empty
-- deps, empty recipe, excludes on a Path pkg, empty excludes on a Fetch pkg,
-- and all 11 Action kinds in one recipe.
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
let Package =
      { name : Text
      , version : Text
      , src : Src
      , deps : List Text
      , excludes : List Text
      , build : Build
      }
in  { packages =
      [ { name = "hello"
        , version = "1.0"
        , src = < Path = "src-tree" > : Src
        , deps = [] : List Text
        , excludes = [ "build-out", "docs/cache" ] : List Text
        , build =
            { target = "hello"
            , recipe =
                [ < Shell = "make hello" >
                , < Copy = { from = "hello", to = "bin/hello" } >
                , < Mkdir = "share" >
                , < Rm = "hello.o" >
                , < Touch = "share/.keep" >
                , < Move = { from = "a", to = "b" } >
                , < Symlink = { from = "bin/hello", to = "h" } >
                , < Chmod = { path = "bin/hello", mode = "0755" } >
                , < Echo = "hi" >
                , < Env = { key = "CC", value = "cc" } >
                , < Run = { argv = [ "./configure", "--prefix=/build" ] } >
                ] : List Action
            }
        }
      , { name = "world"
        , version = "2.3.4"
        , src =
            < Fetch =
                { url = "https://example.com/world-2.3.4.tar.gz"
                , hash = "f2ca1bb3c199e6c9eda0f4d1e7bb8b4b0f1b2a3c4d5e6f708192a3b4c5d6e7f8"
                }
            > : Src
        , deps = [ "hello" ] : List Text
        , excludes = [] : List Text
        , build =
            { target = "world", recipe = [] : List Action }
        }
      ] : List Package
    }
