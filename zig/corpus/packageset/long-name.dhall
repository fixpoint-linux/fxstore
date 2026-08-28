-- long-name.dhall — a 155-char INVALID name: the C error context is
-- snprintf'd into char where[160], so "package '<name>'" truncates to 159
-- bytes (a long name also loses the closing quote).
{ packages =
  [ { name = ".aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    , version = "1.0"
    , src = < Path = "src-tree" >
    , deps = []
    , build = { target = "x", recipe = [] }
    }
  ]
}
