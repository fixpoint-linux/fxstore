-- excludes-trailing-slash.dhall — "build/" ends with '/' (entries are
-- prefix-matched against relative paths, which never carry a trailing '/').
{ packages =
      [ { name = "hello"
        , version = "1.0"
        , src = < Path = "src-tree" >
        , deps = []
        , excludes = [ "build/" ]
        , build = { target = "hello", recipe = [] }
        }
      ]
    }
