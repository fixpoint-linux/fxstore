-- excludes-dotslash.dhall — "./x" never matches a relative path within the
-- src tree.
{ packages =
      [ { name = "hello"
        , version = "1.0"
        , src = < Path = "src-tree" >
        , deps = []
        , excludes = [ "./x" ]
        , build = { target = "hello", recipe = [] }
        }
      ]
    }
