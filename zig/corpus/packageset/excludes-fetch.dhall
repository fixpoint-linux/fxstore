-- excludes-fetch.dhall — non-empty `excludes` on a Fetch src: they would be
-- silently ignored (a Fetch src is content-addressed by its own url+hash),
-- so reject loudly instead of letting the author think it took effect.
{ packages =
      [ { name = "world"
        , version = "2.0"
        , src = < Fetch = { url = "https://example.com/w.tar.gz", hash = "abcd" } >
        , deps = []
        , excludes = [ "junk" ]
        , build = { target = "world", recipe = [] }
        }
      ]
    }
