-- no-excludes-field.dhall — a package-set WITHOUT the `excludes` field must
-- still load unchanged (backward compat: absent field => empty list).
{ packages =
      [ { name = "plain"
        , version = "3.1"
        , src = < Path = "src-tree" >
        , deps = []
        , build = { target = "plain", recipe = [ < Echo = "hi" > ] }
        }
      ]
    }
