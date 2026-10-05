// main.zig — faithful Zig port of main.c (U6): the fxstore CLI entry point.
//
//   fxstore init [dir]                  scaffold a project (worked-example package-set.dhall)
//   fxstore build [--store DIR] [<pkg>...]  build the closure of <pkg>... (all when none)
//                                       into the store at DIR, print each store path
//   fxstore query <pkg> [--store DIR]   print <pkg>'s closure names + its store path
//   fxstore gc [<root>] [--retain N] [--store DIR]
//                                       prune store dirs/facts unreachable from <root>
//                                       (--retain N: keep the N most-recent snapshots)
//   fxstore timeline [--store DIR]      list every snapshot version, marking CURRENT
//   fxstore rollback [--hard] <v> [--store DIR]
//                                       roll the store back to snapshot version <v>
//                                       (default roll-forward; --hard repoints CURRENT)
//   fxstore what <target> [--as-of N] [--store DIR]
//                                       show the install fact managing <target>
//   fxstore why <pkg> [--as-of N] [--store DIR]
//                                       show why <pkg> is in the store
//   fxstore verify [<rootfs>] [--as-of N] [--store DIR]
//                                       reconcile <rootfs> against the recorded
//                                       install facts; report drift
//
// Glue over the five ported units: package-set walker (packageset.zig),
// canonical serializer + sha256 store path (derivation.zig), datalog closure
// fixpoint + topo-sort (closure.zig), store write + txn metadata + GC
// (store.zig), recipe executor + bwrap (build.zig).  build/query load
// "package-set.dhall" from the current working directory; relative <Path>
// sources are canonicalized against it at load time.
//
// Differences from C (mechanical only, never behavioral):
//   * `io: std.Io` threaded through the fs-touching calls (the C calls libc
//     directly); main() passes init.io, tests std.testing.io.
//   * printf/fprintf route through g_out_fd / g_err_fd (the store.zig /
//     build.zig house pattern) so tests capture output without desyncing the
//     zig test runner's fd-1 protocol pipe; usage() takes the target fd.
//   * malloc/realloc/free scratch becomes c_allocator allocs with the SAME
//     lifetimes (paths_free frees per-entry strings + the array); the
//     per-command cli_free/paths_free/fx_store_close/ps.deinit ordering of
//     the C is subsumed by defers (all leaf-first, like the C's teardown).
//   * Each module keeps its own ErrBuf type; a failure is relayed into this
//     file's ErrBuf verbatim (the C threads ONE err buffer through every
//     unit, so the printed message is the innermost module's fx_err text).
const std = @import("std");
const pkgs = @import("packageset");
const drv = @import("derivation");
const cl = @import("closure");
const st = @import("store");
const bld = @import("build");
const prov = @import("provenance");

const Package = pkgs.Package;
const PackageSet = pkgs.PackageSet;
const Io = std.Io;
const c_alloc = std.heap.c_allocator;

pub const DEFAULT_STORE_ROOT = "/fx/store";
pub const ERR_CAP = 2048;

pub const Error = error{FxCli};

// ─── printf plumbing (the store.zig/build.zig g_out_fd pattern) ─────────────

/// The zig test runner uses fd 1 as its --listen protocol pipe: tests
/// repoint these to capture files; production leaves the defaults.
pub var g_out_fd: c_int = 1;
pub var g_err_fd: c_int = 2;

fn out_print(comptime fmt: []const u8, args: anytype) void {
    var aw: Io.Writer.Allocating = .init(c_alloc);
    defer aw.deinit();
    aw.writer.print(fmt, args) catch return;
    const s = aw.written();
    _ = write(g_out_fd, s.ptr, s.len);
}

fn err_print(comptime fmt: []const u8, args: anytype) void {
    var aw: Io.Writer.Allocating = .init(c_alloc);
    defer aw.deinit();
    aw.writer.print(fmt, args) catch return;
    const s = aw.written();
    _ = write(g_err_fd, s.ptr, s.len);
}

// ─── libc surface (main.c includes) ──────────────────────────────────────────

const O_WRONLY: c_int = 0o1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;
const EEXIST: c_int = 17;

/// x86_64 glibc/musl `struct stat` — only st_mode is consumed (init).
/// MEASURED on x86_64-linux-gnu and x86_64-linux-musl: st_mode @24, 144 bytes.
/// (This is NOT the i386 layout — see CStatI386.  Nor the aarch64 one: there
/// st_mode is @16 in a 128-byte struct, measured by _Static_assert against the
/// aarch64 headers; no aarch64 build is run on this host, so CStat does not
/// cover it.)
const CStatX86_64 = extern struct {
    dev: u64,
    ino: u64,
    nlink: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    _pad0: i32,
    rdev: u64,
    size: i64,
    blksize: i64,
    blocks: i64,
    atim: [2]i64,
    mtim: [2]i64,
    ctim: [2]i64,
    _reserved: [3]u64,
};

/// i386 musl `struct stat` — st_mode @16, 144 bytes.
/// MEASURED empirically, not inferred: a C probe built with `zig cc -target
/// x86-linux-musl` prints offsetof(st_mode)==16 and stats a real 0644 file,
/// where the raw words show 0100644 landing at +16 (on x86_64 the same probe
/// shows it at +24).  musl's i386 layout is not the x86_64 one — the dev/ino/
/// rdev fields pack differently.  Only st_mode is consumed, so the rest is
/// kept as opaque padding; the total must stay `sizeof(struct stat)` or libc's
/// stat() would write past the struct.
const CStatI386 = extern struct {
    _head: [16]u8,
    mode: u32,
    _tail: [124]u8,
};

const CStat = if (@import("builtin").target.cpu.arch == .x86) CStatI386 else CStatX86_64;

comptime {
    const arch = @import("builtin").target.cpu.arch;
    const want_mode: usize = if (arch == .x86) 16 else 24;
    const want_size: usize = 144;
    if (@offsetOf(CStat, "mode") != want_mode)
        @compileError("struct stat st_mode offset changed for this target — re-measure it");
    if (@sizeOf(CStat) != want_size)
        @compileError("struct stat size changed for this target — re-measure it");
}

extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn write(fd: c_int, buf: [*]const u8, nbyte: usize) isize;
extern "c" fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern "c" fn stat(path: [*:0]const u8, st: *CStat) c_int;
extern "c" fn strerror(errnum: c_int) [*:0]const u8;
extern "c" fn strtol(nptr: [*:0]const u8, endptr: ?*[*:0]u8, base: c_int) c_long;
// The version parses below take values in 1..4294967295, which does not fit
// a 32-bit c_long: on i386 strtol saturates at LONG_MAX (2147483647, ERANGE)
// and would silently accept a clamped version.  strtoll returns 64 bits on
// every target, so the range check means the same thing everywhere.
extern "c" fn strtoll(nptr: [*:0]const u8, endptr: ?*[*:0]u8, base: c_int) c_longlong;

fn errno() c_int {
    return std.c._errno().*;
}

fn errstr() []const u8 {
    return std.mem.span(strerror(errno()));
}

// ─── usage (main.c:40-63, byte-exact) ────────────────────────────────────────

/// The exact help text (fprintf(out, ...) with the sole vararg being
/// DEFAULT_STORE_ROOT); written to `fd` (stdout or stderr in C).
pub fn usage(fd: c_int) void {
    var aw: Io.Writer.Allocating = .init(c_alloc);
    defer aw.deinit();
    aw.writer.print(
        "fxstore — content-addressed build store (M0/M1/M2 MVP)\n" ++
            "usage:\n" ++
            "  fxstore init [dir]                     scaffold a project dir\n" ++
            "  fxstore build [--store DIR] [<pkg>...]  build the closure of <pkg>...\n" ++
            "                                          (all packages when none), print store paths\n" ++
            "  fxstore query <pkg> [--store DIR]      print <pkg>'s closure names + store path\n" ++
            "  fxstore gc [<root>] [--retain N] [--store DIR]\n" ++
            "                                          prune store dirs/facts unreachable from <root>\n" ++
            "                                          (--retain N: keep N most-recent snapshots instead)\n" ++
            "  fxstore timeline [--store DIR]         list every snapshot version, marking CURRENT\n" ++
            "  fxstore rollback [--hard] <v> [--store DIR]\n" ++
            "                                          roll the store back to snapshot version <v>\n" ++
            "                                          (default roll-forward; --hard repoints CURRENT)\n" ++
            "  fxstore what <target> [--as-of N] [--store DIR]\n" ++
            "                                          show the install fact managing <target>\n" ++
            "                                          (the provenance proof tree)\n" ++
            "  fxstore why <pkg> [--as-of N] [--store DIR]\n" ++
            "                                          show why <pkg> is in the store (its closure,\n" ++
            "                                          provided targets, pulling roots)\n" ++
            "  fxstore verify [<rootfs>] [--as-of N] [--store DIR]\n" ++
            "                                          reconcile <rootfs> (default /) against the\n" ++
            "                                          recorded install facts; exit 1 on drift\n" ++
            "options:\n" ++
            "  --store DIR   store root (default: {s})\n" ++
            "  --retain N    (gc) keep the N most-recent snapshot versions, prune the rest\n" ++
            "  -n N          same as --retain N\n" ++
            "  --hard        (rollback) recovery-only: repoint CURRENT directly at <v>, no new version\n" ++
            "  --as-of N     (what/why/verify) read snapshot version N instead of the newest published\n" ++
            "                (a manual rollback does not re-publish — use --as-of to read the\n" ++
            "                rolled-back activation facts)\n" ++
            "  -h, --help    show this help\n" ++
            "build/query load \"package-set.dhall\" from the current directory.\n",
        .{DEFAULT_STORE_ROOT},
    ) catch return;
    const s = aw.written();
    _ = write(fd, s.ptr, s.len);
}

// ─── CLI arg parsing (main.c:65-134) ─────────────────────────────────────────

pub const CliArgs = struct {
    store_root: ?[]const u8 = null, // null when not given
    pos: [][]const u8 = &.{}, // positional args (borrowed pointers), c_alloc'd
    npos: usize = 0,
    hard: bool = false, // --hard (rollback)
    retain: u32 = 0, // --retain N / -n N (gc)
    has_retain: bool = false, // --retain was given
    as_of: u32 = 0, // --as-of N (what/why/verify)
    has_as_of: bool = false, // --as-of was given
};

/// Parse argv[start..].  Strips --store DIR / --store=DIR and -h/--help.
/// Returns 0 on success, 1 when -h/--help was shown (usage already printed),
/// -1 on a parse error (message already printed).
pub fn parse_args(argv: []const []const u8, start: usize, c: *CliArgs) i32 {
    c.* = .{};
    c.pos = c_alloc.alloc([]const u8, argv.len -| start) catch {
        err_print("fxstore: out of memory\n", .{});
        return -1;
    };
    var i: usize = start;
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (std.mem.eql(u8, a, "--store")) {
            if (i + 1 >= argv.len) {
                err_print("fxstore: --store requires a directory argument\n", .{});
                cli_free(c);
                return -1;
            }
            i += 1;
            c.store_root = argv[i];
        } else if (std.mem.startsWith(u8, a, "--store=")) {
            c.store_root = a[8..];
        } else if (std.mem.eql(u8, a, "--hard")) {
            c.hard = true;
        } else if (std.mem.eql(u8, a, "--retain") or std.mem.eql(u8, a, "-n")) {
            if (i + 1 >= argv.len) {
                err_print("fxstore: {s} requires a count argument\n", .{a});
                cli_free(c);
                return -1;
            }
            i += 1;
            if (!parse_retain(argv[i], c)) {
                cli_free(c);
                return -1;
            }
        } else if (std.mem.startsWith(u8, a, "--retain=")) {
            if (!parse_retain(a[9..], c)) {
                cli_free(c);
                return -1;
            }
        } else if (std.mem.eql(u8, a, "--as-of")) {
            if (i + 1 >= argv.len) {
                err_print("fxstore: --as-of requires a version argument\n", .{});
                cli_free(c);
                return -1;
            }
            i += 1;
            if (!parse_as_of(argv[i], c)) {
                cli_free(c);
                return -1;
            }
        } else if (std.mem.startsWith(u8, a, "--as-of=")) {
            if (!parse_as_of(a[8..], c)) {
                cli_free(c);
                return -1;
            }
        } else if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            usage(g_out_fd);
            cli_free(c);
            return 1;
        } else {
            c.pos[c.npos] = a;
            c.npos += 1;
        }
    }
    return 0;
}

/// The strtol-based --retain value validation (main.c:104-109): reject
/// trailing garbage, non-positive counts, and counts above 1000000.
fn parse_retain(val: []const u8, c: *CliArgs) bool {
    const zv = c_alloc.dupeZ(u8, val) catch {
        err_print("fxstore: out of memory\n", .{});
        return false;
    };
    defer c_alloc.free(zv);
    var end: [*:0]u8 = undefined;
    const n = strtol(zv.ptr, &end, 10);
    if (end[0] != 0 or n <= 0 or n > 1000000) {
        err_print("fxstore: invalid --retain count '{s}' (expected a positive integer)\n", .{val});
        return false;
    }
    c.retain = @intCast(n);
    c.has_retain = true;
    return true;
}

/// The --as-of counterpart of parse_retain (rollback's version validation):
/// reject trailing garbage, non-positive versions, and versions above
/// 4294967295 (the snapshot-version range).
fn parse_as_of(val: []const u8, c: *CliArgs) bool {
    const zv = c_alloc.dupeZ(u8, val) catch {
        err_print("fxstore: out of memory\n", .{});
        return false;
    };
    defer c_alloc.free(zv);
    var end: [*:0]u8 = undefined;
    const n = strtoll(zv.ptr, &end, 10);
    if (end[0] != 0 or n <= 0 or @as(u64, @intCast(n)) > 0xFFFFFFFF) {
        err_print("fxstore: invalid --as-of version '{s}' (expected an integer in 1..4294967295)\n", .{val});
        return false;
    }
    c.as_of = @intCast(n);
    c.has_as_of = true;
    return true;
}

pub fn cli_free(c: *CliArgs) void {
    if (c.pos.len > 0) c_alloc.free(c.pos);
    c.pos = &.{};
    c.npos = 0;
}

// ─── Store-path computation over the closure (main.c:136-242) ───────────────

pub const PathEntry = struct {
    p: ?*Package = null,
    path: ?[]u8 = null, // store path of p (c_alloc dupe)
    hash: ?[]u8 = null, // derivation sha256 (hex64)
    src_hash: ?[]u8 = null, // clean source hash (SRC_PATH), else null
};

pub fn path_of(es: []const PathEntry, name: []const u8) ?[]const u8 {
    for (es) |e| {
        const p = e.p orelse continue;
        if (std.mem.eql(u8, p.name, name)) return e.path;
    }
    return null;
}

/// paths_free (main.c:151-158): per-entry strings + the array.
pub fn paths_free(es: []PathEntry) void {
    for (es) |e| {
        if (e.path) |s| c_alloc.free(s);
        if (e.hash) |s| c_alloc.free(s);
        if (e.src_hash) |s| c_alloc.free(s);
    }
    if (es.len > 0) c_alloc.free(es);
}

/// Relay a module's ErrBuf text into ours (the C shares ONE err buffer).
fn relay(e: *ErrBuf, msg: []const u8) Error {
    return e.set("{s}", .{msg});
}

/// Compute the closure of roots (all packages when roots is empty) and the
/// store path of every package in deps-first topo order.  Each package's
/// hash embeds its direct deps' store paths (the Nix-style fixed point), so
/// the dep paths are tracked as we walk the topo order (main.c:164-242).
pub fn compute_paths(
    io: Io,
    ps: *const PackageSet,
    db: ?*cl.DlDb,
    roots: []const []const u8,
    store_root: []const u8,
    e: *ErrBuf,
) Error![]PathEntry {
    var cerr = cl.ErrBuf{};
    cl.fx_closure_compute(db, ps, roots, &cerr) catch return relay(e, cerr.slice());

    const names = cl.fx_closure_names(db, &cerr) catch return relay(e, cerr.slice());
    defer cl.free_names(names);

    const ord = cl.fx_topo_order(ps, names, &cerr) catch return relay(e, cerr.slice());
    defer cl.free_order(ord);

    const es = c_alloc.alloc(PathEntry, ord.len) catch return relay(e, "out of memory");
    errdefer paths_free(es);
    for (es) |*x| x.* = .{};

    for (ord, 0..) |p, i| {
        const dep_paths = c_alloc.alloc([]const u8, p.deps.len) catch
            return relay(e, "out of memory");
        defer c_alloc.free(dep_paths);

        for (p.deps, 0..) |dn, j| {
            const dp = path_of(es[0..i], dn) orelse {
                return e.set("internal: dep '{s}' of '{s}' not resolved (topo order broken)", .{ dn, p.name });
            };
            dep_paths[j] = dp;
        }
        {
            var h: [65]u8 = undefined;
            var path: [st.FX_PATH_MAX]u8 = undefined;
            // compute the CLEAN source hash ONCE (SRC_PATH only) and reuse it
            // for both the derivation hash and fx_store_ensure_source, so the
            // store path and the materialized src are provably the same
            // content (and the raw checkout is never walked twice)
            var derr = drv.ErrBuf{};
            var src_hash: ?[]const u8 = null;
            if (p.src.kind == .path) {
                var sh: [65]u8 = undefined;
                drv.fx_content_hash_dir(io, p.src.path orelse "", p.excludes, &sh, &derr) catch
                    return relay(e, derr.slice());
                es[i].src_hash = c_alloc.dupe(u8, sh[0..64]) catch
                    return relay(e, "out of memory");
                src_hash = es[i].src_hash.?;
            }
            drv.fx_derivation_hash_ex(p, src_hash, dep_paths, &h, &derr) catch
                return relay(e, derr.slice());
            const path_s = drv.fx_store_path_of(store_root, h[0..64], p.name, &path);
            es[i].p = p;
            es[i].hash = c_alloc.dupe(u8, h[0..64]) catch return relay(e, "out of memory");
            es[i].path = c_alloc.dupe(u8, path_s) catch return relay(e, "out of memory");
        }
    }
    return es;
}

// ─── build (main.c:246-338) ──────────────────────────────────────────────────

fn cmd_build(io: Io, argv: []const []const u8, start: usize) u8 {
    var c = CliArgs{};
    const pr = parse_args(argv, start, &c);
    if (pr != 0) return if (pr == 1) 0 else 2;
    defer cli_free(&c);
    const store_root = c.store_root orelse DEFAULT_STORE_ROOT;

    var ps: PackageSet = undefined;
    var perr = pkgs.ErrBuf{};
    pkgs.fx_packageset_load(&ps, "package-set.dhall", &perr) catch {
        err_print("fxstore: {s}\n", .{perr.slice()});
        return 1;
    };
    defer ps.deinit();

    var serr = st.ErrBuf{};
    const s = st.fx_store_open(io, store_root, &serr) catch {
        err_print("fxstore: {s}\n", .{serr.slice()});
        return 1;
    };
    defer st.fx_store_close(s);

    var e = ErrBuf{};
    const es = compute_paths(io, &ps, st.fx_store_db(s), c.pos[0..c.npos], store_root, &e) catch {
        err_print("fxstore: {s}\n", .{e.slice()});
        return 1;
    };
    defer paths_free(es);

    var rc: u8 = 0;
    for (es) |ent| {
        if (rc != 0) break;
        const p = ent.p.?;
        iter: {
            const dep_paths = c_alloc.alloc([]const u8, p.deps.len) catch {
                err_print("fxstore: out of memory\n", .{});
                rc = 1;
                break :iter;
            };
            defer c_alloc.free(dep_paths);

            var dep_ok = true;
            for (p.deps, 0..) |dn, j| {
                dep_paths[j] = path_of(es, dn) orelse {
                    err_print("fxstore: internal: dep '{s}' of '{s}' not resolved\n", .{ dn, p.name });
                    dep_ok = false;
                    rc = 1;
                    break;
                };
            }
            if (dep_ok) {
                // Materialize the CLEAN source into the store BEFORE building,
                // so the recipe reads (via FX_SRC) the same clean bytes the
                // store path was hashed from.  SRC_FETCH has no clean source.
                var src_path: [st.FX_PATH_MAX]u8 = undefined;
                var clean_src: ?[]const u8 = null;
                if (p.src.kind == .path) {
                    clean_src = st.fx_store_ensure_source(io, s, p, ent.src_hash.?, &src_path, &serr) catch {
                        err_print("fxstore: clean source {s} failed: {s}\n", .{ p.name, serr.slice() });
                        rc = 1;
                        break :iter;
                    };
                }
                out_print("fxstore: building {s}\n", .{p.name});
                if (st.fx_store_build(io, s, p, ent.hash.?, ent.path.?, clean_src, p.deps, dep_paths, &serr)) |_| {
                    out_print("fxstore: built {s}\n", .{ent.path.?});
                } else |_| {
                    err_print("fxstore: build {s} failed: {s}\n", .{ p.name, serr.slice() });
                    rc = 1;
                }
            }
        }
    }

    if (rc == 0) {
        st.fx_store_publish(s, &serr) catch {
            err_print("fxstore: {s}\n", .{serr.slice()});
            rc = 1;
        };
    }

    return rc;
}

// ─── query (main.c:340-413) ──────────────────────────────────────────────────

fn cmd_query(io: Io, argv: []const []const u8, start: usize) u8 {
    var c = CliArgs{};
    const pr = parse_args(argv, start, &c);
    if (pr != 0) return if (pr == 1) 0 else 2;
    defer cli_free(&c);
    if (c.npos != 1) {
        err_print("fxstore: query requires exactly one package name\n\n", .{});
        usage(g_err_fd);
        return 2;
    }
    const pkg = c.pos[0];
    const store_root = c.store_root orelse DEFAULT_STORE_ROOT;

    var ps: PackageSet = undefined;
    var perr = pkgs.ErrBuf{};
    pkgs.fx_packageset_load(&ps, "package-set.dhall", &perr) catch {
        err_print("fxstore: {s}\n", .{perr.slice()});
        return 1;
    };
    defer ps.deinit();

    var serr = st.ErrBuf{};
    const s = st.fx_store_open(io, store_root, &serr) catch {
        err_print("fxstore: {s}\n", .{serr.slice()});
        return 1;
    };
    defer st.fx_store_close(s);

    var e = ErrBuf{};
    const es = compute_paths(io, &ps, st.fx_store_db(s), &[_][]const u8{pkg}, store_root, &e) catch {
        err_print("fxstore: {s}\n", .{e.slice()});
        return 1;
    };
    defer paths_free(es);

    // closure names (the materialized fixpoint, read through the snapshot)
    var cerr = cl.ErrBuf{};
    const names = cl.fx_closure_names(st.fx_store_db(s), &cerr) catch {
        err_print("fxstore: {s}\n", .{cerr.slice()});
        return 1;
    };
    defer cl.free_names(names);
    out_print("fxstore: closure of '{s}' ({d} package(s)):\n", .{ pkg, names.len });
    for (names) |n| out_print("  {s}\n", .{n});

    const path = path_of(es, pkg) orelse {
        err_print("fxstore: no store path for '{s}'\n", .{pkg});
        return 1;
    };
    out_print("fxstore: store path: {s}\n", .{path});
    return 0;
}

// ─── gc (main.c:415-458) ─────────────────────────────────────────────────────

fn cmd_gc(io: Io, argv: []const []const u8, start: usize) u8 {
    var c = CliArgs{};
    const pr = parse_args(argv, start, &c);
    if (pr != 0) return if (pr == 1) 0 else 2;
    defer cli_free(&c);
    if (!c.has_retain and c.npos != 1) {
        err_print("fxstore: gc requires exactly one root package (or --retain N)\n\n", .{});
        usage(g_err_fd);
        return 2;
    }
    if (c.has_retain and c.npos > 1) {
        err_print("fxstore: gc accepts at most one root package\n\n", .{});
        usage(g_err_fd);
        return 2;
    }
    const store_root = c.store_root orelse DEFAULT_STORE_ROOT;

    var serr = st.ErrBuf{};
    const s = st.fx_store_open(io, store_root, &serr) catch {
        err_print("fxstore: {s}\n", .{serr.slice()});
        return 1;
    };
    defer st.fx_store_close(s);

    var rc: u8 = 0;
    if (c.has_retain) {
        // generation GC: prune to the N most-recent snapshot versions
        st.fx_store_gc_retain(io, s, c.retain, &serr) catch {
            err_print("fxstore: {s}\n", .{serr.slice()});
            rc = 1;
        };
    }
    if (rc == 0 and c.npos == 1) {
        // dir-level GC relative to a root (may follow --retain)
        st.fx_store_gc(io, s, c.pos[0], &serr) catch {
            err_print("fxstore: {s}\n", .{serr.slice()});
            rc = 1;
        };
    }
    return rc;
}

// ─── timeline (main.c:460-484) ───────────────────────────────────────────────

fn cmd_timeline(io: Io, argv: []const []const u8, start: usize) u8 {
    var c = CliArgs{};
    const pr = parse_args(argv, start, &c);
    if (pr != 0) return if (pr == 1) 0 else 2;
    defer cli_free(&c);
    if (c.npos != 0) {
        err_print("fxstore: timeline takes no arguments\n\n", .{});
        usage(g_err_fd);
        return 2;
    }
    const store_root = c.store_root orelse DEFAULT_STORE_ROOT;

    var serr = st.ErrBuf{};
    const s = st.fx_store_open(io, store_root, &serr) catch {
        err_print("fxstore: {s}\n", .{serr.slice()});
        return 1;
    };
    defer st.fx_store_close(s);

    st.fx_store_timeline(io, s, &serr) catch {
        err_print("fxstore: {s}\n", .{serr.slice()});
        return 1;
    };
    return 0;
}

// ─── rollback (main.c:486-518) ───────────────────────────────────────────────

fn cmd_rollback(io: Io, argv: []const []const u8, start: usize) u8 {
    var c = CliArgs{};
    const pr = parse_args(argv, start, &c);
    if (pr != 0) return if (pr == 1) 0 else 2;
    defer cli_free(&c);
    if (c.npos != 1) {
        err_print("fxstore: rollback requires exactly one version number\n\n", .{});
        usage(g_err_fd);
        return 2;
    }
    const vs = c.pos[0];
    const zv = c_alloc.dupeZ(u8, vs) catch {
        err_print("fxstore: out of memory\n", .{});
        return 2;
    };
    defer c_alloc.free(zv);
    var end: [*:0]u8 = undefined;
    const v = strtoll(zv.ptr, &end, 10);
    if (end[0] != 0 or v <= 0 or @as(u64, @intCast(v)) > 0xFFFFFFFF) {
        err_print("fxstore: invalid version '{s}' (expected an integer in 1..4294967295)\n", .{vs});
        return 2;
    }
    const store_root = c.store_root orelse DEFAULT_STORE_ROOT;

    var serr = st.ErrBuf{};
    const s = st.fx_store_open(io, store_root, &serr) catch {
        err_print("fxstore: {s}\n", .{serr.slice()});
        return 1;
    };
    defer st.fx_store_close(s);

    st.fx_store_rollback(s, @intCast(v), c.hard, &serr) catch {
        err_print("fxstore: {s}\n", .{serr.slice()});
        return 1;
    };
    return 0;
}

// ─── what/why/verify: the store-honest provenance debug view (the thin CLI
// ─── over provenance.zig; the engine owns every semantic) ───────────────────

/// The Version a --as-of flag selects (CURRENT = newest published when absent).
fn prov_version(c: *const CliArgs) prov.Version {
    return if (c.has_as_of) .{ .as_of = c.as_of } else .current;
}

/// Open the store for a read-only prov command (the cmd_query open idiom).
fn prov_open(io: Io, store_root: []const u8) ?*st.Store {
    var serr = st.ErrBuf{};
    const s = st.fx_store_open(io, store_root, &serr) catch {
        err_print("fxstore: {s}\n", .{serr.slice()});
        return null;
    };
    return s;
}

fn cmd_what(io: Io, argv: []const []const u8, start: usize) u8 {
    var c = CliArgs{};
    const pr = parse_args(argv, start, &c);
    if (pr != 0) return if (pr == 1) 0 else 2;
    defer cli_free(&c);
    if (c.npos != 1) {
        err_print("fxstore: what requires exactly one target path\n\n", .{});
        usage(g_err_fd);
        return 2;
    }
    const store_root = c.store_root orelse DEFAULT_STORE_ROOT;

    const s = prov_open(io, store_root) orelse return 1;
    defer st.fx_store_close(s);

    var e = prov.ProvErrBuf{};
    const r = prov.prov_what(st.fx_store_db(s), c.pos[0], prov_version(&c), &e) catch {
        err_print("fxstore: {s}\n", .{e.slice()});
        return 1;
    };
    defer prov.prov_free_what(r);

    var aw: Io.Writer.Allocating = .init(c_alloc);
    defer aw.deinit();
    prov.prov_render_what(&aw.writer, &r) catch return 1;
    const out = aw.written();
    _ = write(g_out_fd, out.ptr, out.len);
    return 0;
}

fn cmd_why(io: Io, argv: []const []const u8, start: usize) u8 {
    var c = CliArgs{};
    const pr = parse_args(argv, start, &c);
    if (pr != 0) return if (pr == 1) 0 else 2;
    defer cli_free(&c);
    if (c.npos != 1) {
        err_print("fxstore: why requires exactly one package name\n\n", .{});
        usage(g_err_fd);
        return 2;
    }
    const store_root = c.store_root orelse DEFAULT_STORE_ROOT;

    const s = prov_open(io, store_root) orelse return 1;
    defer st.fx_store_close(s);

    var e = prov.ProvErrBuf{};
    const r = prov.prov_why(st.fx_store_db(s), c.pos[0], prov_version(&c), &e) catch {
        err_print("fxstore: {s}\n", .{e.slice()});
        return 1;
    };
    defer prov.prov_free_why(r);

    var aw: Io.Writer.Allocating = .init(c_alloc);
    defer aw.deinit();
    prov.prov_render_why(&aw.writer, &r) catch return 1;
    const out = aw.written();
    _ = write(g_out_fd, out.ptr, out.len);
    return 0;
}

fn cmd_verify(io: Io, argv: []const []const u8, start: usize) u8 {
    var c = CliArgs{};
    const pr = parse_args(argv, start, &c);
    if (pr != 0) return if (pr == 1) 0 else 2;
    defer cli_free(&c);
    if (c.npos > 1) {
        err_print("fxstore: verify takes at most one rootfs path\n\n", .{});
        usage(g_err_fd);
        return 2;
    }
    const rootfs: []const u8 = if (c.npos == 1) c.pos[0] else "/";
    const store_root = c.store_root orelse DEFAULT_STORE_ROOT;

    const s = prov_open(io, store_root) orelse return 1;
    defer st.fx_store_close(s);

    // the drift strings are c_alloc-owned (prov_free_drifts); the list
    // STORAGE is ours (deinit(c_alloc)).
    var drifts: std.ArrayList(prov.Drift) = .empty;
    defer drifts.deinit(c_alloc);
    defer prov.prov_free_drifts(drifts.items);

    var e = prov.ProvErrBuf{};
    prov.prov_verify(io, st.fx_store_db(s), rootfs, store_root, prov_version(&c), &e, &drifts) catch {
        err_print("fxstore: {s}\n", .{e.slice()});
        return 1;
    };

    out_print("fxstore: verify {s} against store {s}: {d} drift(s)\n", .{ rootfs, store_root, drifts.items.len });
    for (drifts.items) |dr|
        out_print("{s}: {s}: {s}\n", .{ dr.target, @tagName(dr.kind), dr.detail });
    if (drifts.items.len > 0) return 1;
    out_print("fxstore: verify OK\n", .{});
    return 0;
}

// ─── init: scaffold a worked-example project (main.c:520-624) ───────────────

/// mkdir_if_missing (main.c:522-527): mkdir(0755); EEXIST + is-dir is OK.
fn mkdir_if_missing(dir: []const u8) bool {
    const z = c_alloc.dupeZ(u8, dir) catch return false;
    defer c_alloc.free(z);
    if (mkdir(z.ptr, 0o755) == 0) return true;
    var stt: CStat = undefined;
    if (errno() == EEXIST and stat(z.ptr, &stt) == 0 and (stt.mode & 0o170000) == 0o040000)
        return true;
    return false;
}

/// write_file (main.c:529-538): fopen "w" + fputs + fclose with the exact
/// errno messages.
fn write_file(path: []const u8, content: []const u8, e: *ErrBuf) Error!void {
    const z = c_alloc.dupeZ(u8, path) catch return relay(e, "out of memory");
    defer c_alloc.free(z);
    const fd = open(z.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o666);
    if (fd < 0) return e.set("cannot create '{s}': {s}", .{ path, errstr() });
    var off: usize = 0;
    while (off < content.len) {
        const n = write(fd, content.ptr + off, content.len - off);
        if (n <= 0) {
            _ = close(fd);
            return e.set("cannot write '{s}': {s}", .{ path, errstr() });
        }
        off += @intCast(n);
    }
    if (close(fd) != 0) return e.set("cannot write '{s}': {s}", .{ path, errstr() });
}

/// TEMPLATE_PACKAGE_SET (main.c:540-568), byte-exact; the scaffolded
/// package-set.dhall must load via fx_packageset_load (unit-tested).
pub const TEMPLATE_PACKAGE_SET =
    "-- fxstore worked-example package set (lib -> app)\n" ++
    "--\n" ++
    "--   Src     = < Path : Text | Fetch : { url : Text, hash : Text } >\n" ++
    "--   Build   = { target : Text, recipe : List Action }\n" ++
    "--   Package = { name : Text, version : Text, src : Src, deps : List Text, build : Build }\n" ++
    "--   body    = { packages : List Package } : PackageSet\n" ++
    "--\n" ++
    "-- Relative < Path = ... > sources are resolved against this file's\n" ++
    "-- directory at load time.  Recipes are self-contained (pure-filesystem\n" ++
    "-- actions run in-process; Shell/Run run under bwrap).\n" ++
    "let Action = < Shell : Text | Copy : { from : Text, to : Text } | Mkdir : Text | Rm : Text | Touch : Text | Move : { from : Text, to : Text } | Symlink : { from : Text, to : Text } | Chmod : { path : Text, mode : Text } | Echo : Text | Env : { key : Text, value : Text } | Run : { argv : List Text } >\n" ++
    "let Src = < Path : Text | Fetch : { url : Text, hash : Text } >\n" ++
    "let Build = { target : Text, recipe : List Action }\n" ++
    "let Package = { name : Text, version : Text, src : Src, deps : List Text, build : Build }\n" ++
    "let PackageSet = { packages : List Package }\n" ++
    "in { packages =\n" ++
    "     [ { name = \"lib\",\n" ++
    "         version = \"1.0.0\",\n" ++
    "         src = < Path = \"src/lib\" >,\n" ++
    "         deps = [] : List Text,\n" ++
    "         build = { target = \"lib\",\n" ++
    "                   recipe = [ < Touch = \"lib.txt\" >, < Echo = \"built lib\" > ] } },\n" ++
    "       { name = \"app\",\n" ++
    "         version = \"1.0.0\",\n" ++
    "         src = < Path = \"src/app\" >,\n" ++
    "         deps = [ \"lib\" ],\n" ++
    "         build = { target = \"app\",\n" ++
    "                   recipe = [ < Touch = \"app.txt\" >, < Echo = \"built app\" > ] } } ] } : PackageSet\n";

fn cmd_init(argv: []const []const u8, start: usize) u8 {
    const dir: []const u8 = if (start < argv.len) argv[start] else ".";
    var e = ErrBuf{};

    var ps_path: []const u8 = undefined;
    var src_dir: []const u8 = undefined;
    var lib_dir: []const u8 = undefined;
    var app_dir: []const u8 = undefined;
    var lib_file: []const u8 = undefined;
    var app_file: []const u8 = undefined;

    if (std.mem.eql(u8, dir, ".")) {
        ps_path = "package-set.dhall";
        src_dir = "src";
        lib_dir = "src/lib";
        app_dir = "src/app";
        lib_file = "src/lib/hello.txt";
        app_file = "src/app/hello.txt";
    } else {
        var bufs: [6][st.FX_PATH_MAX]u8 = undefined;
        ps_path = std.fmt.bufPrint(&bufs[0], "{s}/package-set.dhall", .{dir}) catch {
            err_print("fxstore: project path too long\n", .{});
            return 1;
        };
        src_dir = std.fmt.bufPrint(&bufs[1], "{s}/src", .{dir}) catch {
            err_print("fxstore: project path too long\n", .{});
            return 1;
        };
        lib_dir = std.fmt.bufPrint(&bufs[2], "{s}/src/lib", .{dir}) catch {
            err_print("fxstore: project path too long\n", .{});
            return 1;
        };
        app_dir = std.fmt.bufPrint(&bufs[3], "{s}/src/app", .{dir}) catch {
            err_print("fxstore: project path too long\n", .{});
            return 1;
        };
        lib_file = std.fmt.bufPrint(&bufs[4], "{s}/src/lib/hello.txt", .{dir}) catch {
            err_print("fxstore: project path too long\n", .{});
            return 1;
        };
        app_file = std.fmt.bufPrint(&bufs[5], "{s}/src/app/hello.txt", .{dir}) catch {
            err_print("fxstore: project path too long\n", .{});
            return 1;
        };
    }

    if (!mkdir_if_missing(dir)) {
        err_print("fxstore: cannot create project dir '{s}': {s}\n", .{ dir, errstr() });
        return 1;
    }
    if (!mkdir_if_missing(src_dir)) {
        err_print("fxstore: cannot create source dir '{s}': {s}\n", .{ src_dir, errstr() });
        return 1;
    }
    if (!mkdir_if_missing(lib_dir) or !mkdir_if_missing(app_dir)) {
        err_print("fxstore: cannot create source dirs: {s}\n", .{errstr()});
        return 1;
    }
    write_file(ps_path, TEMPLATE_PACKAGE_SET, &e) catch {
        err_print("fxstore: {s}\n", .{e.slice()});
        return 1;
    };
    write_file(lib_file, "hello from lib\n", &e) catch {
        err_print("fxstore: {s}\n", .{e.slice()});
        return 1;
    };
    write_file(app_file, "hello from app\n", &e) catch {
        err_print("fxstore: {s}\n", .{e.slice()});
        return 1;
    };

    out_print("fxstore: initialized project in '{s}'\n", .{dir});
    out_print("  {s}\n", .{ps_path});
    out_print("  {s}/  (lib source tree)\n", .{lib_dir});
    out_print("  {s}/  (app source tree)\n", .{app_dir});
    out_print("  e.g.  cd '{s}' && fxstore build --store /tmp/store app\n", .{dir});
    return 0;
}

// ─── main (main.c:628-653) ───────────────────────────────────────────────────

pub fn main(init: std.process.Init) !void {
    const alloc = init.arena.allocator();
    const args0 = try init.minimal.args.toSlice(alloc);
    const args = try alloc.alloc([]const u8, args0.len);
    for (args0, 0..) |a, i| args[i] = a;

    const cmd: ?[]const u8 = if (args.len > 1) args[1] else null;

    // Resolve the stage3 sandbox binary path ONCE, before any package-set
    // is loaded — recipes can set arbitrary env vars via the Env action,
    // and the FXSTORE_STAGE3 override must be settled before they run.
    bld.fx_stage3_resolve();
    bld.fx_bwrap_resolve(); // lock the bwrap path before recipes run
    bld.fx_cosmo_resolve(); // lock the cosmocc toolchain tree before recipes run

    if (cmd == null or std.mem.eql(u8, cmd.?, "-h") or std.mem.eql(u8, cmd.?, "--help")) {
        usage(if (cmd != null) g_out_fd else g_err_fd);
        std.process.exit(if (cmd != null) 0 else 2);
    }

    const io = init.io;
    var rc: u8 = 2;
    if (std.mem.eql(u8, cmd.?, "init")) {
        rc = cmd_init(args, 2);
    } else if (std.mem.eql(u8, cmd.?, "build")) {
        rc = cmd_build(io, args, 2);
    } else if (std.mem.eql(u8, cmd.?, "query")) {
        rc = cmd_query(io, args, 2);
    } else if (std.mem.eql(u8, cmd.?, "gc")) {
        rc = cmd_gc(io, args, 2);
    } else if (std.mem.eql(u8, cmd.?, "timeline")) {
        rc = cmd_timeline(io, args, 2);
    } else if (std.mem.eql(u8, cmd.?, "rollback")) {
        rc = cmd_rollback(io, args, 2);
    } else if (std.mem.eql(u8, cmd.?, "what")) {
        rc = cmd_what(io, args, 2);
    } else if (std.mem.eql(u8, cmd.?, "why")) {
        rc = cmd_why(io, args, 2);
    } else if (std.mem.eql(u8, cmd.?, "verify")) {
        rc = cmd_verify(io, args, 2);
    } else {
        err_print("fxstore: unknown command '{s}'\n\n", .{cmd.?});
        usage(g_err_fd);
    }
    std.process.exit(rc);
}

// ─── ErrBuf (the fx_err helper; each module's text relays in verbatim) ──────

pub const err_cap_default = ERR_CAP;

pub const ErrBuf = struct {
    buf: [err_cap_default]u8 = undefined,
    len: usize = 0,

    pub fn set(self: *ErrBuf, comptime fmt: []const u8, args: anytype) error{FxCli} {
        var aw: Io.Writer.Allocating = .init(c_alloc);
        defer aw.deinit();
        aw.writer.print(fmt, args) catch unreachable;
        const s = aw.written();
        const n = @min(s.len, self.buf.len - 1);
        @memcpy(self.buf[0..n], s[0..n]);
        self.buf[n] = 0;
        self.len = n;
        return error.FxCli;
    }

    pub fn slice(self: *const ErrBuf) []const u8 {
        return self.buf[0..self.len];
    }
};

// ─── unit tests (pure parts; NEVER write fd 1 from tests) ───────────────────

const testing = std.testing;

fn tio() Io {
    return std.testing.io;
}

/// The store.zig Capture pattern: repoint this file's out/err fds to temp
/// files, hand back their bytes, restore.  Idempotent restore (closing a
/// closed fd is EBADF -> Threaded Io panic -> --listen=- deadlock).
const Capture = struct {
    saved_out: c_int,
    saved_err: c_int,
    out_file: Io.File,
    err_file: Io.File,
    out_path: [:0]const u8,
    err_path: [:0]const u8,

    fn begin(out_path: [:0]const u8, err_path: [:0]const u8) !Capture {
        const of = try Io.Dir.cwd().createFile(tio(), out_path, .{ .truncate = true });
        errdefer of.close(tio());
        const ef = try Io.Dir.cwd().createFile(tio(), err_path, .{ .truncate = true });
        return .{
            .saved_out = g_out_fd,
            .saved_err = g_err_fd,
            .out_file = of,
            .err_file = ef,
            .out_path = out_path,
            .err_path = err_path,
        };
    }

    fn redirect(self: *Capture) void {
        g_out_fd = self.out_file.handle;
        g_err_fd = self.err_file.handle;
    }

    fn restore(self: *Capture) void {
        g_out_fd = self.saved_out;
        g_err_fd = self.saved_err;
        if (self.out_file.handle >= 0) {
            self.out_file.close(tio());
            self.err_file.close(tio());
            self.out_file.handle = -1;
        }
    }

    fn end(self: *Capture) ![]u8 {
        self.restore();
        const bytes = try Io.Dir.cwd().readFileAlloc(tio(), self.out_path, testing.allocator, .limited(1 << 20));
        Io.Dir.cwd().deleteTree(tio(), self.out_path) catch {};
        return bytes;
    }

    fn end_err(self: *Capture) ![]u8 {
        self.restore();
        const bytes = try Io.Dir.cwd().readFileAlloc(tio(), self.err_path, testing.allocator, .limited(1 << 20));
        Io.Dir.cwd().deleteTree(tio(), self.err_path) catch {};
        return bytes;
    }
};

test "usage text is byte-exact vs the extracted main.c golden" {
    var cap = try Capture.begin("/tmp/fx-u6-usage-out", "/tmp/fx-u6-usage-err");
    cap.redirect();
    usage(g_out_fd);
    const out = try cap.end();
    defer testing.allocator.free(out);
    const err_bytes = try cap.end_err();
    defer testing.allocator.free(err_bytes);
    try testing.expectEqual(@as(usize, 0), err_bytes.len);
    const golden = try Io.Dir.cwd().readFileAlloc(tio(), "zig/corpus/cli/usage_golden.txt", testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(golden);
    try testing.expectEqualStrings(golden, out);
}

test "parse_args: --store DIR, --store=DIR, positionals, --hard" {
    var c = CliArgs{};
    const rc = parse_args(&.{ "build", "--store", "/tmp/s", "--hard", "app", "lib" }, 1, &c);
    try testing.expectEqual(@as(i32, 0), rc);
    defer cli_free(&c);
    try testing.expectEqualStrings("/tmp/s", c.store_root.?);
    try testing.expect(c.hard);
    try testing.expect(!c.has_retain);
    try testing.expectEqual(@as(usize, 2), c.npos);
    try testing.expectEqualStrings("app", c.pos[0]);
    try testing.expectEqualStrings("lib", c.pos[1]);
}

test "parse_args: --retain N / -n N / --retain= forms" {
    var c = CliArgs{};
    try testing.expectEqual(@as(i32, 0), parse_args(&.{ "gc", "--retain", "7" }, 1, &c));
    defer cli_free(&c);
    try testing.expect(c.has_retain);
    try testing.expectEqual(@as(u32, 7), c.retain);

    var c2 = CliArgs{};
    try testing.expectEqual(@as(i32, 0), parse_args(&.{ "gc", "-n", "42", "root" }, 1, &c2));
    defer cli_free(&c2);
    try testing.expect(c2.has_retain);
    try testing.expectEqual(@as(u32, 42), c2.retain);
    try testing.expectEqual(@as(usize, 1), c2.npos);

    var c3 = CliArgs{};
    try testing.expectEqual(@as(i32, 0), parse_args(&.{ "gc", "--retain=9" }, 1, &c3));
    defer cli_free(&c3);
    try testing.expect(c3.has_retain);
    try testing.expectEqual(@as(u32, 9), c3.retain);
}

test "parse_args: missing --store value -> -1 + exact stderr" {
    var cap = try Capture.begin("/tmp/fx-u6-pa-out", "/tmp/fx-u6-pa-err");
    cap.redirect();
    var c = CliArgs{};
    const rc = parse_args(&.{ "build", "--store" }, 1, &c);
    const out_bytes = try cap.end();
    defer testing.allocator.free(out_bytes);
    const err_bytes = try cap.end_err();
    defer testing.allocator.free(err_bytes);
    try testing.expectEqual(@as(i32, -1), rc);
    try testing.expectEqualStrings(
        "fxstore: --store requires a directory argument\n",
        err_bytes,
    );
}

test "parse_args: missing --retain/-n value -> -1 + exact stderr (flag echoed)" {
    var cap = try Capture.begin("/tmp/fx-u6-pr-out", "/tmp/fx-u6-pr-err");
    cap.redirect();
    var c = CliArgs{};
    const rc = parse_args(&.{ "gc", "-n" }, 1, &c);
    const out_bytes = try cap.end();
    defer testing.allocator.free(out_bytes);
    const err_bytes = try cap.end_err();
    defer testing.allocator.free(err_bytes);
    try testing.expectEqual(@as(i32, -1), rc);
    try testing.expectEqualStrings(
        "fxstore: -n requires a count argument\n",
        err_bytes,
    );

    var cap2 = try Capture.begin("/tmp/fx-u6-pr2-out", "/tmp/fx-u6-pr2-err");
    cap2.redirect();
    var c2 = CliArgs{};
    const rc2 = parse_args(&.{ "gc", "--retain" }, 1, &c2);
    const out2 = try cap2.end();
    defer testing.allocator.free(out2);
    const err2 = try cap2.end_err();
    defer testing.allocator.free(err2);
    try testing.expectEqual(@as(i32, -1), rc2);
    try testing.expectEqualStrings(
        "fxstore: --retain requires a count argument\n",
        err2,
    );
}

test "parse_args: invalid retain values -> -1 + exact stderr" {
    const bad = [_][]const u8{ "abc", "0", "-3", "1000001", "12x", "" };
    for (bad) |v| {
        var cap = try Capture.begin("/tmp/fx-u6-prb-out", "/tmp/fx-u6-prb-err");
        cap.redirect();
        var c = CliArgs{};
        const rc = parse_args(&.{ "gc", "--retain", v }, 1, &c);
        const out_bytes = try cap.end();
        defer testing.allocator.free(out_bytes);
        const err_bytes = try cap.end_err();
        defer testing.allocator.free(err_bytes);
        try testing.expectEqual(@as(i32, -1), rc);
        const want = try std.fmt.allocPrint(testing.allocator, "fxstore: invalid --retain count '{s}' (expected a positive integer)\n", .{v});
        defer testing.allocator.free(want);
        try testing.expectEqualStrings(want, err_bytes);

        // the = form takes the same path with the same message
        var cap2 = try Capture.begin("/tmp/fx-u6-prb2-out", "/tmp/fx-u6-prb2-err");
        cap2.redirect();
        const joined = try std.fmt.allocPrint(testing.allocator, "--retain={s}", .{v});
        defer testing.allocator.free(joined);
        var c2 = CliArgs{};
        try testing.expectEqual(@as(i32, -1), parse_args(&.{ "gc", joined }, 1, &c2));
        const out2 = try cap2.end();
        defer testing.allocator.free(out2);
        const err2 = try cap2.end_err();
        defer testing.allocator.free(err2);
        try testing.expectEqualStrings(want, err2);
    }
    // boundary: 1 and 1000000 are accepted
    var c = CliArgs{};
    try testing.expectEqual(@as(i32, 0), parse_args(&.{ "gc", "--retain", "1000000" }, 1, &c));
    cli_free(&c);
    var c2 = CliArgs{};
    try testing.expectEqual(@as(i32, 0), parse_args(&.{ "gc", "--retain", "1" }, 1, &c2));
    cli_free(&c2);
}

test "parse_args: --as-of N / --as-of= forms (what/why/verify)" {
    var c = CliArgs{};
    const rc = parse_args(&.{ "what", "--as-of", "7", "/bin/hello" }, 1, &c);
    try testing.expectEqual(@as(i32, 0), rc);
    defer cli_free(&c);
    try testing.expect(c.has_as_of);
    try testing.expectEqual(@as(u32, 7), c.as_of);
    try testing.expectEqual(@as(usize, 1), c.npos);
    try testing.expectEqualStrings("/bin/hello", c.pos[0]);

    var c2 = CliArgs{};
    try testing.expectEqual(@as(i32, 0), parse_args(&.{ "why", "--as-of=42", "hello" }, 1, &c2));
    defer cli_free(&c2);
    try testing.expect(c2.has_as_of);
    try testing.expectEqual(@as(u32, 42), c2.as_of);

    // the boundary values behave like rollback's version parse
    var c3 = CliArgs{};
    try testing.expectEqual(@as(i32, 0), parse_args(&.{ "verify", "--as-of=4294967295" }, 1, &c3));
    cli_free(&c3);
}

test "parse_args: --as-of errors -> -1 + exact stderr" {
    // missing value
    {
        var cap = try Capture.begin("/tmp/fx-u9-ao-out", "/tmp/fx-u9-ao-err");
        cap.redirect();
        var c = CliArgs{};
        const rc = parse_args(&.{ "what", "--as-of" }, 1, &c);
        const out_bytes = try cap.end();
        defer testing.allocator.free(out_bytes);
        const err_bytes = try cap.end_err();
        defer testing.allocator.free(err_bytes);
        try testing.expectEqual(@as(i32, -1), rc);
        try testing.expectEqualStrings(
            "fxstore: --as-of requires a version argument\n",
            err_bytes,
        );
    }
    // invalid values (trailing garbage, zero, negative, out of range)
    const bad = [_][]const u8{ "abc", "0", "-3", "4294967296", "12x", "" };
    for (bad) |v| {
        var cap = try Capture.begin("/tmp/fx-u9-aob-out", "/tmp/fx-u9-aob-err");
        cap.redirect();
        var c = CliArgs{};
        const rc = parse_args(&.{ "why", "--as-of", v, "hello" }, 1, &c);
        const out_bytes = try cap.end();
        defer testing.allocator.free(out_bytes);
        const err_bytes = try cap.end_err();
        defer testing.allocator.free(err_bytes);
        try testing.expectEqual(@as(i32, -1), rc);
        const want = try std.fmt.allocPrint(testing.allocator, "fxstore: invalid --as-of version '{s}' (expected an integer in 1..4294967295)\n", .{v});
        defer testing.allocator.free(want);
        try testing.expectEqualStrings(want, err_bytes);
    }
}

test "parse_args: -h/--help -> 1 with usage on stdout, positionals collected" {
    var cap = try Capture.begin("/tmp/fx-u6-ph-out", "/tmp/fx-u6-ph-err");
    cap.redirect();
    var c = CliArgs{};
    const rc = parse_args(&.{ "build", "-h" }, 1, &c);
    const out = try cap.end();
    defer testing.allocator.free(out);
    const err_bytes = try cap.end_err();
    defer testing.allocator.free(err_bytes);
    try testing.expectEqual(@as(i32, 1), rc);
    const golden = try Io.Dir.cwd().readFileAlloc(tio(), "zig/corpus/cli/usage_golden.txt", testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(golden);
    try testing.expectEqualStrings(golden, out);

    var cap2 = try Capture.begin("/tmp/fx-u6-ph2-out", "/tmp/fx-u6-ph2-err");
    cap2.redirect();
    var c2 = CliArgs{};
    try testing.expectEqual(@as(i32, 1), parse_args(&.{"--help"}, 0, &c2));
    const out2 = try cap2.end();
    defer testing.allocator.free(out2);
    const err2 = try cap2.end_err();
    defer testing.allocator.free(err2);
    try testing.expectEqual(@as(usize, 0), err2.len);
}

test "cmd_rollback: invalid versions -> 2 + exact stderr, before any store open" {
    const bad = [_][]const u8{ "abc", "0", "-3", "4294967296", "12x", "" };
    for (bad) |v| {
        var cap = try Capture.begin("/tmp/fx-u6-rb-out", "/tmp/fx-u6-rb-err");
        cap.redirect();
        try testing.expectEqual(@as(u8, 2), cmd_rollback(tio(), &.{ "fxstore", "rollback", v }, 2));
        const out_bytes = try cap.end();
        defer testing.allocator.free(out_bytes);
        const err_bytes = try cap.end_err();
        defer testing.allocator.free(err_bytes);
        const want = try std.fmt.allocPrint(testing.allocator, "fxstore: invalid version '{s}' (expected an integer in 1..4294967295)\n", .{v});
        defer testing.allocator.free(want);
        try testing.expectEqualStrings(want, err_bytes);
    }
    var cap_n = try Capture.begin("/tmp/fx-u6-rb2-out", "/tmp/fx-u6-rb2-err");
    cap_n.redirect();
    try testing.expectEqual(@as(u8, 2), cmd_rollback(tio(), &.{ "fxstore", "rollback" }, 2));
    const out_n = try cap_n.end();
    defer testing.allocator.free(out_n);
    const err_n = try cap_n.end_err();
    defer testing.allocator.free(err_n);
    try testing.expect(std.mem.startsWith(
        u8,
        err_n,
        "fxstore: rollback requires exactly one version number\n\n",
    ));
    try testing.expect(err_n.len > "fxstore: rollback requires exactly one version number\n\n".len); // + usage
}

test "TEMPLATE_PACKAGE_SET round-trips through fx_packageset_load" {
    const io = tio();
    var rnd: [8]u8 = undefined;
    io.random(&rnd);
    var root_buf: [64]u8 = undefined;
    var path_buf: [96]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, "/tmp/fx-u6-tpl-{x}", .{&rnd});
    defer Io.Dir.cwd().deleteTree(io, root) catch {};

    try Io.Dir.cwd().createDirPath(io, root);
    try Io.Dir.cwd().createDirPath(io, try std.fmt.bufPrint(&path_buf, "{s}/src/lib", .{root}));
    try Io.Dir.cwd().createDirPath(io, try std.fmt.bufPrint(&path_buf, "{s}/src/app", .{root}));

    const ps_path = try std.fmt.allocPrintSentinel(testing.allocator, "{s}/package-set.dhall", .{root}, 0);
    defer testing.allocator.free(ps_path);
    {
        const f = try Io.Dir.cwd().createFile(io, ps_path, .{ .truncate = true });
        defer f.close(io);
        var w: Io.Writer.Allocating = .init(testing.allocator);
        defer w.deinit();
        try w.writer.writeAll(TEMPLATE_PACKAGE_SET);
        const s = w.written();
        try f.writeStreamingAll(io, s);
    }

    // the house shape the dhall core parses (ascriptions on field VALUES only)
    try testing.expect(std.mem.indexOf(u8, TEMPLATE_PACKAGE_SET, "deps = [] : List Text") != null);

    var pset: PackageSet = undefined;
    var perr = pkgs.ErrBuf{};
    try pkgs.fx_packageset_load(&pset, ps_path, &perr);
    defer pset.deinit();

    try testing.expectEqual(@as(usize, 2), pset.count);
    const lib = pset.find("lib") orelse return error.TestUnexpectedResult;
    const app = pset.find("app") orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("1.0.0", lib.version);
    try testing.expectEqualStrings("1.0.0", app.version);
    // packageset canonicalizes relative Path sources against the file's dir
    const lib_src = try std.fmt.allocPrint(testing.allocator, "{s}/src/lib", .{root});
    defer testing.allocator.free(lib_src);
    const app_src = try std.fmt.allocPrint(testing.allocator, "{s}/src/app", .{root});
    defer testing.allocator.free(app_src);
    try testing.expectEqual(pkgs.SrcKind.path, lib.src.kind);
    try testing.expectEqualStrings(lib_src, lib.src.path.?);
    try testing.expectEqualStrings(app_src, app.src.path.?);
    try testing.expectEqual(@as(usize, 0), lib.deps.len);
    try testing.expectEqual(@as(usize, 1), app.deps.len);
    try testing.expectEqualStrings("lib", app.deps[0]);
    try testing.expectEqualStrings("lib", lib.target);
    try testing.expectEqualStrings("app", app.target);

    // recipe: [ Touch "lib.txt", Echo "built lib" ] in order
    var n: usize = 0;
    var kinds: [4]pkgs.ActionKind = undefined;
    var act = lib.recipe;
    while (act) |a| : (act = a.next) {
        kinds[n] = a.kind;
        n += 1;
    }
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqual(pkgs.ActionKind.touch, kinds[0]);
    try testing.expectEqual(pkgs.ActionKind.echo, kinds[1]);
    try testing.expectEqualStrings("lib.txt", lib.recipe.?.a.?);
    try testing.expectEqualStrings("built lib", lib.recipe.?.next.?.a.?);
}

test "cmd_init scaffolds a loadable project with the exact stdout lines" {
    const io = tio();
    var rnd: [8]u8 = undefined;
    io.random(&rnd);
    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, "/tmp/fx-u6-init-{x}", .{&rnd});
    defer Io.Dir.cwd().deleteTree(io, root) catch {};

    var cap = try Capture.begin("/tmp/fx-u6-init-out", "/tmp/fx-u6-init-err");
    cap.redirect();
    const rc = cmd_init(&.{ "fxstore", "init", root }, 2);
    try testing.expectEqual(@as(u8, 0), rc);
    const want_out =
        try std.fmt.allocPrint(testing.allocator, "fxstore: initialized project in '{s}'\n" ++
        "  {s}/package-set.dhall\n" ++
        "  {s}/src/lib/  (lib source tree)\n" ++
        "  {s}/src/app/  (app source tree)\n" ++
        "  e.g.  cd '{s}' && fxstore build --store /tmp/store app\n", .{ root, root, root, root, root });
    defer testing.allocator.free(want_out);
    const out1 = try cap.end();
    defer testing.allocator.free(out1);
    try testing.expectEqualStrings(want_out, out1);
    const err1 = try cap.end_err();
    defer testing.allocator.free(err1);
    try testing.expectEqual(@as(usize, 0), err1.len);

    // scaffold contents: the template + the two hello files
    const ps_path = try std.fmt.allocPrintSentinel(testing.allocator, "{s}/package-set.dhall", .{root}, 0);
    defer testing.allocator.free(ps_path);
    const ps_bytes = try Io.Dir.cwd().readFileAlloc(io, ps_path, testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(ps_bytes);
    try testing.expectEqualStrings(TEMPLATE_PACKAGE_SET, ps_bytes);
    const lib_path = try std.fmt.allocPrintSentinel(testing.allocator, "{s}/src/lib/hello.txt", .{root}, 0);
    defer testing.allocator.free(lib_path);
    const lib_bytes = try Io.Dir.cwd().readFileAlloc(io, lib_path, testing.allocator, .limited(4096));
    defer testing.allocator.free(lib_bytes);
    try testing.expectEqualStrings("hello from lib\n", lib_bytes);
    const app_path = try std.fmt.allocPrintSentinel(testing.allocator, "{s}/src/app/hello.txt", .{root}, 0);
    defer testing.allocator.free(app_path);
    const app_bytes = try Io.Dir.cwd().readFileAlloc(io, app_path, testing.allocator, .limited(4096));
    defer testing.allocator.free(app_bytes);
    try testing.expectEqualStrings("hello from app\n", app_bytes);

    // re-init over the existing dir is idempotent (mkdir EEXIST + is-dir)
    var cap2 = try Capture.begin("/tmp/fx-u6-init2-out", "/tmp/fx-u6-init2-err");
    cap2.redirect();
    try testing.expectEqual(@as(u8, 0), cmd_init(&.{ "fxstore", "init", root }, 2));
    const out2 = try cap2.end();
    defer testing.allocator.free(out2);
    const err2 = try cap2.end_err();
    defer testing.allocator.free(err2);
    try testing.expectEqual(@as(usize, 0), err2.len);
}

test "cmd_init: rejects unwritable project dir with the exact stderr" {
    var cap = try Capture.begin("/tmp/fx-u6-initx-out", "/tmp/fx-u6-initx-err");
    cap.redirect();
    // a FILE cannot become a directory (EEXIST + not-dir)
    const notadir = try Io.Dir.cwd().createFile(tio(), "/tmp/fx-u6-notadir", .{ .truncate = true });
    notadir.close(tio());
    defer Io.Dir.cwd().deleteTree(tio(), "/tmp/fx-u6-notadir") catch {};
    try testing.expectEqual(@as(u8, 1), cmd_init(&.{ "fxstore", "init", "/tmp/fx-u6-notadir" }, 2));
    const out_bytes = try cap.end();
    defer testing.allocator.free(out_bytes);
    const err_bytes = try cap.end_err();
    defer testing.allocator.free(err_bytes);
    try testing.expectEqualStrings(
        "fxstore: cannot create project dir '/tmp/fx-u6-notadir': File exists\n",
        err_bytes,
    );
}
