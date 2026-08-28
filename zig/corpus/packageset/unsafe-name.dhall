-- unsafe-name.dhall — "../evil" could escape the store root (store dirs are
-- named "<hex64>-<name>"): need [A-Za-z0-9][A-Za-z0-9._+-]*.
{ packages =
      [ { name = "../evil"
        , version = "1.0"
        , src = < Path = "src-tree" >
        , deps = []
        , build = { target = "x", recipe = [] }
        }
      ]
    }
