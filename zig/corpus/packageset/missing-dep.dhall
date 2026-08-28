-- missing-dep.dhall — 'world' depends on 'ghost', which is not in the set:
-- LOUD rejection (a wrong dep silently produces a wrong closure -> wrong
-- hash).
{ packages =
      [ { name = "hello"
        , version = "1.0"
        , src = < Path = "src-tree" >
        , deps = []
        , build = { target = "hello", recipe = [ < Shell = "true" > ] }
        }
      , { name = "world"
        , version = "2.0"
        , src = < Path = "src-tree" >
        , deps = [ "ghost" ]
        , build = { target = "world", recipe = [] }
        }
      ]
    }
