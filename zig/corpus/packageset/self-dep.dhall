-- self-dep.dhall — a package depending on itself: no finite store path.
{ packages =
      [ { name = "lonely"
        , version = "1.0"
        , src = < Path = "src-tree" >
        , deps = [ "lonely" ]
        , build = { target = "lonely", recipe = [] }
        }
      ]
    }
