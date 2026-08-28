-- dup-name.dhall — two packages named 'hello': rejected (the name is the
-- store-path and dep-graph key).
{ packages =
      [ { name = "hello"
        , version = "1.0"
        , src = < Path = "src-tree" >
        , deps = []
        , build = { target = "hello", recipe = [] }
        }
      , { name = "hello"
        , version = "2.0"
        , src = < Path = "src-tree" >
        , deps = []
        , build = { target = "hello", recipe = [] }
        }
      ]
    }
