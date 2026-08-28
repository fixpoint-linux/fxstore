-- excludes-doubleslash.dhall — "a//b" is not a clean relative path.
{ packages =
      [ { name = "hello"
        , version = "1.0"
        , src = < Path = "src-tree" >
        , deps = []
        , excludes = [ "a//b" ]
        , build = { target = "hello", recipe = [] }
        }
      ]
    }
