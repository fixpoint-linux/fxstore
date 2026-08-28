-- excludes-dotdot.dhall — ".." is meaningless as a src-tree-relative prefix.
{ packages =
      [ { name = "hello"
        , version = "1.0"
        , src = < Path = "src-tree" >
        , deps = []
        , excludes = [ ".." ]
        , build = { target = "hello", recipe = [] }
        }
      ]
    }
