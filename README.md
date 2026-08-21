# fxstore

A **content-addressed build store** for [fixpoint-linux](https://github.com/fixpoint-linux).

`fxstore` reads a Dhall package set, computes the dependency closure as a least
fixed point with `datalog-dafsa`, assigns every package a content-addressed
store path, builds each package's typed recipe into the store, and garbage
collects unreachable artifacts. It is the storage + build layer of a
Nix-like, but-specified-in-Dhall system.

```
/fx/store/<sha256-of-input-closure>-<name>
```

## Design

- **Spec in Dhall** — `package-set.dhall` defines `Package = { name, version,
  src, deps, build { target, recipe } }`, where `recipe` is the same typed
  `List Action` union that `dhake` executes.
- **Closure as a fixed point** — `datalog-dafsa` computes transitive
  reachability (`closure(X) :- root(X).` / `closure(Y) :- closure(X), dep(X,Y).`).
- **Content addressing** — a canonical, length-delimited serialization of the
  full input closure is sha256'd to form the store path; a change anywhere in a
  package's transitive dependency graph changes its path.
- **Crash-consistent store** — artifacts are built into a temp dir, atomically
  renamed to the final path, and *then* the metadata transaction commits
  (metadata-last: a crash leaves a reapable orphan dir, never dangling metadata).
- **Time travel, native** — `datalog-dafsa` versioned snapshots + as-of queries
  are available for timeline / rollback (future work).

See the [fixpoint-linux design](https://github.com/fixpoint-linux/fixpoint-linux/blob/main/DESIGN.md).

## Dependencies

Two git submodules (under `vendor/`), initialized via `git submodule update --init --recursive`:

- [`datalog-dafsa`](https://github.com/fixpoint-linux/datalog-dafsa) — the engine + vendored dafsa
- [`dhall-c`](https://github.com/fixpoint-linux/dhall-c) — the Dhall interpreter core

Requires the **cosmocc** toolchain.

## Build

```sh
make             # builds ./fxstore
make test        # runs the golden end-to-end test
make fxstore-golden
```

Override dependency paths with `make DATALOG=... DHALLC=...`.

## Usage

```sh
fxstore init [dir]                       # scaffold a project (worked-example package-set.dhall)
fxstore build [--store DIR] [<pkg>...]   # build the closure of <pkg>... (all when none),
                                         # print each store path
fxstore query <pkg> [--store DIR]        # print <pkg>'s closure names + store path
fxstore gc <root> [--store DIR]          # prune store dirs/facts unreachable from <root>
```

`build`/`query` load `package-set.dhall` from the current directory.

## Security / sandbox

The two *executing* recipe actions (`Shell`, `Run`) run under
[`bwrap`](https://github.com/containers/bubblewrap)
(`--unshare-all --die-with-parent`, store + toolchain ro-bound, network off).
If `bwrap` is absent, fxstore falls back to plain fork/exec with a **loud
non-hermetic warning**. The pure-FS actions (`Copy`, `Mkdir`, …) run in-process
under a trusted-author model in v1 (the package-set author is trusted).

## License

MIT.
