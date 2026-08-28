-- excludes-abs.dhall — "/abs" can never match a relative path within the src
-- tree: silent acceptance would silently keep hashing what the author meant
-- to exclude.
{ packages =
      [ { name = "hello"
        , version = "1.0"
        , src = < Path = "src-tree" >
        , deps = []
        , excludes = [ "/abs" ]
        , build = { target = "hello", recipe = [] }
        }
      ]
    }
