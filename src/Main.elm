module Main exposing (main)

{-| The fxstore documentation page as a plain `Browser.element` app.

This module renders the entire fxstore docs page — top nav, hero, and the
`#idea` / `#store` / `#usage` / `#features` / `#security` sections plus footer —
using the shared `Fixpoint.*` design package (`design/src` is a source-directory
in this application's `elm.json`).

The first child of the view is `Fixpoint.Style.stylesheet`, which emits the full
brand stylesheet as a single `<style>` node. Because the page is pre-rendered
under happy-dom by `scripts/ssg.mjs`, that `<style>` node is carried into the
static HTML — the styling ships with the page instead of living in a committed
stylesheet.

It is rendered at build time only: `scripts/ssg.mjs` loads the compiled bundle
under happy-dom and calls `Elm.Main.init({ node })` to pre-render the page to
static `dist/index.html`. There is no client-side interactivity (the model is
unit, the only message is `NoOp`).

The text/content is byte-faithful to the former committed `docs/index.html`
(now generated from this app).

-}

import Browser
import Fixpoint.Card
import Fixpoint.Code
import Fixpoint.Footer
import Fixpoint.Grid
import Fixpoint.Hero
import Fixpoint.Nav
import Fixpoint.Section
import Fixpoint.Style
import Html exposing (Html, a, b, div, em, p, span, text)
import Html.Attributes exposing (attribute, class, href)


main : Program () Model Msg
main =
    Browser.element
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        }



-- MODEL


type alias Model =
    ()


type Msg
    = NoOp


init : () -> ( Model, Cmd Msg )
init _ =
    ( (), Cmd.none )


update : Msg -> Model -> ( Model, Cmd Msg )
update _ model =
    ( model, Cmd.none )


subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.none



-- VIEW


view : Model -> Html Msg
view _ =
    div []
        [ Fixpoint.Style.stylesheet
        , navView
        , headerView
        , ideaSection
        , storeSection
        , usageSection
        , featuresSection
        , securitySection
        , footerView
        ]



-- Top nav (brand + anchor links)


navView : Html Msg
navView =
    Fixpoint.Nav.view
        { brand =
            span []
                [ span [ class "fx" ] [ text "fx" ]
                , text "://fxstore"
                ]
        , links =
            [ a [ class "home", href "https://fixpointlinux.org/", attribute "data-mfe-route" "/" ]
                [ text "fixpoint-linux" ]
            , Fixpoint.Nav.link "#idea" "idea"
            , Fixpoint.Nav.link "#store" "store"
            , Fixpoint.Nav.link "#usage" "usage"
            , Fixpoint.Nav.link "#features" "features"
            , Fixpoint.Nav.link "#security" "security"
            ]
        , extra = []
        }



-- Hero


headerView : Html Msg
headerView =
    Fixpoint.Hero.view
        { prompt =
            [ Fixpoint.Hero.hash
            , text " fxstore "
            , Fixpoint.Hero.dollar
            , text " fx build app --store /fx/store"
            , Fixpoint.Hero.blink
            ]
        , title =
            [ text "A "
            , Fixpoint.Hero.fx [ text "content-addressed" ]
            , text " build store."
            ]
        , tagline =
            [ text "Dhall package set · "
            , b [] [ text "least-fixed-point closure" ]
            , text " · `/fx/store/<hash>-<name>`."
            ]
        }



-- Section: #idea


ideaSection : Html Msg
ideaSection =
    Fixpoint.Section.view
        { id = "idea"
        , title = "The idea"
        , hint = "// packages are pure functions of their inputs"
        , children =
            [ p []
                [ Fixpoint.Code.inline "fxstore"
                , text " is the storage + build layer of "
                , a [ href "https://fixpointlinux.org/" ] [ text "fixpoint-linux" ]
                , text ". It reads a "
                , Fixpoint.Code.inline "package-set.dhall"
                , text ", computes the dependency closure as a "
                , b [] [ text "least fixed point" ]
                , text " with "
                , Fixpoint.Code.inline "datalog-dafsa"
                , text ", and gives every package a deterministic, content-addressed home in the store:"
                ]
            , Fixpoint.Code.block
                [ Fixpoint.Code.g "/fx/store"
                , text "/<"
                , Fixpoint.Code.g "sha256-of-input-closure"
                , text ">-<name>"
                ]
            , p []
                [ text "Because the store path is a hash of the package's "
                , em [] [ text "entire transitive dependency graph" ]
                , text ", a change anywhere upstream changes the path — the same inputs always produce the same artifact, and nothing is ever overwritten."
                ]
            ]
        }



-- Section: #store (pipeline)


storeSection : Html Msg
storeSection =
    Fixpoint.Section.view
        { id = "store"
        , title = "The pipeline"
        , hint = "// spec in Dhall · closure in Datalog · build with typed actions"
        , children =
            [ Fixpoint.Code.block
                [ Fixpoint.Code.k "package-set.dhall"
                , text "  "
                , Fixpoint.Code.c "# { packages : List Package }"
                , text "\n"
                , text "      "
                , Fixpoint.Code.g "→"
                , text "  dhall-c: parse / typecheck / normalize"
                , text "\n"
                , text "      "
                , Fixpoint.Code.g "→"
                , text "  datalog-dafsa: "
                , Fixpoint.Code.k "closure"
                , text " least-fixed-point + topo-order"
                , text "\n"
                , text "      "
                , Fixpoint.Code.g "→"
                , text "  sha256 of the canonical derivation  "
                , Fixpoint.Code.c "# /fx/store/<hex64>-<name>"
                , text "\n"
                , text "      "
                , Fixpoint.Code.g "→"
                , text "  typed recipe build (bwrap-sandboxed Shell / Run)"
                , text "\n"
                , text "      "
                , Fixpoint.Code.g "→"
                , text "  atomic rename + metadata-LAST transaction commit"
                , text "\n"
                , text "      "
                , Fixpoint.Code.g "→"
                , text "  "
                , Fixpoint.Code.k "gc <root>"
                , text " prunes unreachable artifacts"
                ]
            , p []
                [ text "Each stage is a pure function of the previous stage's typed output. The dependency-closure fixed point is computed by "
                , Fixpoint.Code.inline "datalog-dafsa"
                , text "'s native recursive rules:"
                ]
            , Fixpoint.Code.block
                [ Fixpoint.Code.k "closure"
                , text "(X) :- "
                , Fixpoint.Code.k "root"
                , text "(X)."
                , text "\n"
                , Fixpoint.Code.k "closure"
                , text "(Y) :- "
                , Fixpoint.Code.k "closure"
                , text "(X), "
                , Fixpoint.Code.k "dep"
                , text "(X, Y)."
                ]
            ]
        }



-- Section: #usage


usageSection : Html Msg
usageSection =
    Fixpoint.Section.view
        { id = "usage"
        , title = "Usage"
        , hint = "// init · build · query · gc"
        , children =
            [ Fixpoint.Code.block
                [ Fixpoint.Code.k "$"
                , text " "
                , Fixpoint.Code.g "fxstore init"
                , text " myproject               "
                , Fixpoint.Code.c "# scaffold a worked-example package-set.dhall"
                , text "\n"
                , Fixpoint.Code.k "$"
                , text " "
                , Fixpoint.Code.g "cd"
                , text " myproject"
                , text "\n"
                , Fixpoint.Code.k "$"
                , text " "
                , Fixpoint.Code.g "fxstore build app"
                , text " --store /fx/store  "
                , Fixpoint.Code.c "# build the closure of app (lib first), print paths"
                , text "\n"
                , Fixpoint.Code.k "$"
                , text " "
                , Fixpoint.Code.g "fxstore query app"
                , text " --store /fx/store  "
                , Fixpoint.Code.c "# print app's closure + store path"
                , text "\n"
                , Fixpoint.Code.k "$"
                , text " "
                , Fixpoint.Code.g "fxstore gc app"
                , text " --store /fx/store     "
                , Fixpoint.Code.c "# prune unreachable store dirs"
                ]
            , p []
                [ text "Dependencies are exported to each package's recipe as "
                , Fixpoint.Code.inline "FX_DEP_<NAME>"
                , text " environment variables. Build again after a source change and only the affected slice of the store rebuilds."
                ]
            ]
        }



-- Section: #features (6 cards)


featuresSection : Html Msg
featuresSection =
    Fixpoint.Section.view
        { id = "features"
        , title = "Features"
        , hint = "// content-addressed · reproducible · crash-consistent"
        , children =
            [ Fixpoint.Grid.grid
                [ Fixpoint.Card.view
                    { n = "01"
                    , title = "Content-addressed"
                    , body =
                        [ text "The store path is a sha256 of the full input closure — a change anywhere upstream changes the path."
                        ]
                    }
                , Fixpoint.Card.view
                    { n = "02"
                    , title = "Closure fixed point"
                    , body =
                        [ text "Transitive reachability is computed by datalog-dafsa's native recursive rules; cycles are rejected."
                        ]
                    }
                , Fixpoint.Card.view
                    { n = "03"
                    , title = "Crash-consistent"
                    , body =
                        [ text "Build into a temp dir, atomic rename, then metadata-LAST transaction commit — a crash leaves a reapable orphan, never dangling metadata."
                        ]
                    }
                , Fixpoint.Card.view
                    { n = "04"
                    , title = "Typed recipes"
                    , body =
                        [ text "Recipes are the same Dhall tagged-union "
                        , Fixpoint.Code.inline "Action"
                        , text " values that "
                        , a [ href "https://fixpointlinux.org/dhake/" ] [ text "dhake" ]
                        , text " executes."
                        ]
                    }
                , Fixpoint.Card.view
                    { n = "05"
                    , title = "Sandboxed exec"
                    , body =
                        [ Fixpoint.Code.inline "Shell"
                        , text " / "
                        , Fixpoint.Code.inline "Run"
                        , text " actions run under bwrap ("
                        , Fixpoint.Code.inline "--unshare-all"
                        , text ", network off) with a loud non-hermetic fallback."
                        ]
                    }
                , Fixpoint.Card.view
                    { n = "06"
                    , title = "Time travel, native"
                    , body =
                        [ text "Built on datalog-dafsa's versioned snapshots + as-of queries — a timeline / rollback layer slots straight on top."
                        ]
                    }
                ]
            ]
        }



-- Section: #security


securitySection : Html Msg
securitySection =
    Fixpoint.Section.view
        { id = "security"
        , title = "Security"
        , hint = "// trusted-author model · sandboxed exec"
        , children =
            [ p []
                [ text "The two "
                , em [] [ text "executing" ]
                , text " recipe actions ("
                , Fixpoint.Code.inline "Shell"
                , text ", "
                , Fixpoint.Code.inline "Run"
                , text ") run under "
                , a [ href "https://github.com/containers/bubblewrap" ] [ text "bwrap" ]
                , text " ("
                , Fixpoint.Code.inline "--unshare-all --die-with-parent"
                , text ", store + toolchain read-only-bound, network off). The pure-FS actions ("
                , Fixpoint.Code.inline "Copy"
                , text ", "
                , Fixpoint.Code.inline "Mkdir"
                , text ", …) run in-process under a trusted-author model — the package-set author is trusted, mirroring how "
                , a [ href "https://fixpointlinux.org/" ] [ text "fixpoint-linux" ]
                , text " treats its own spec."
                ]
            ]
        }



-- Footer


footerView : Html Msg
footerView =
    Fixpoint.Footer.view
        [ a [ href "https://github.com/fixpoint-linux/fxstore" ]
            [ text "github.com/fixpoint-linux/fxstore" ]
        , Fixpoint.Footer.sep
        , text "part of "
        , a [ href "https://fixpointlinux.org" ] [ text "fixpoint-linux" ]
        , Fixpoint.Footer.sep
        , text "MIT"
        ]
