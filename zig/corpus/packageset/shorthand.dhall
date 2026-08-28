-- shorthand.dhall — the dhake-style shorthand union literals with NO type
-- annotations: the recipe mixes < Shell = ... > and < Echo = ... >, which
-- infers as a list of two different SINGLETON unions, so infer_type fails.
-- The pipeline must print a warning to stderr and STILL produce the correct
-- table (the structural walk is the source of truth).
{ packages =
  [ { name = "mixed"
    , version = "0.1"
    , src = < Path = "src-tree" >
    , deps = []
    , build =
        { target = "mixed"
        , recipe = [ < Shell = "echo shell" >, < Echo = "echo text" > ]
        }
    }
  ]
}
