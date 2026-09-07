// provenance.zig — the Lens-2 provenance QUERY ENGINE (plan unit U2): the
// read side of the snapshot-versioned activation facts fx-activate writes
// (fx-init activate.zig, U1):
//
//     install(target, origin, mode, genhash) a4
//         target   = rootfs-absolute (/etc/{p}, /bin/{name})
//         origin   = STORE-RELATIVE ('{genhash}-system-generation/etc/{p}'
//                    for the etc Copies, '{hash}-{pkg}' for the bin
//                    symlinks), resolved against the store root at QUERY
//                    time (the relocation principle — mirrors svc_bin).
//         mode     = RAW u32 column (0o644 etc files, 0 symlinks) so
//                    reconcile can compare st_mode & 0o7777 directly.
//         genhash  = 64-hex activation generation.
//     provides(pkg, store_dir) a2 — the store-dir -> pkg-name mapping.
//
// READ-ONLY by construction: every reader goes through dl_query_version
// (as-of), a relation ABSENT from an old snapshot reads as EMPTY (the
// store.zig version_bag allow_absent idiom — install/provides postdate the
// store's own snapshots), and nothing here declares, add_fact's, deletes,
// or publishes.  The why-fixpoint (closure-from-pkg, "which roots pull
// this") is a BFS over the dep tuples AS-OF the version — the live
// materialized `closure` relation is never touched (it is the union over
// ALL roots and cannot answer per-root reachability anyway).
//
// Memory contract (the fx_closure_names/free_names idiom, closure.zig:
// 330-351): each query runs on a private arena for scratch; strings that
// ESCAPE (WhatResult/WhyResult fields) are c_allocator-owned and freed by
// prov_free_what / prov_free_why.  Drifts appended by prov_verify are
// c_allocator-owned too (target + detail + the list storage) — free them
// with prov_free_drifts.
//
// This module imports ONLY std + closure/store/packageset/derivation; it
// must never import main.zig (which has its own main) or write any
// relation (fx-core's fx-what/fx-why and fxstore's what/why/verify
// subcommands are thin surfaces over exactly these entry points).
const std = @import("std");
const cl = @import("closure");
const st = @import("store");
const pkgs = @import("packageset");
const drv = @import("derivation");

const DlDb = cl.DlDb;
const Io = std.Io;
const c_alloc = std.heap.c_allocator;

pub const ProvError = error{FxProv};

pub const err_cap_default = 2048;

/// The fx_err helper as a context struct (the closure.zig/store.zig ErrBuf
/// pattern): every failure path calls set and returns error.FxProv.
pub const ProvErrBuf = struct {
    buf: [err_cap_default]u8 = undefined,
    len: usize = 0,

    pub fn set(self: *ProvErrBuf, comptime fmt: []const u8, args: anytype) error{FxProv} {
        var aw: Io.Writer.Allocating = .init(c_alloc);
        defer aw.deinit();
        aw.writer.print(fmt, args) catch unreachable;
        const s = aw.written();
        const n = @min(s.len, self.buf.len - 1);
        @memcpy(self.buf[0..n], s[0..n]);
        self.buf[n] = 0;
        self.len = n;
        return error.FxProv;
    }

    pub fn slice(self: *const ProvErrBuf) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Which snapshot a query reads.  `.current` resolves to the NEWEST
/// PUBLISHED snapshot in the db (the fx_store_current_version fallback when
/// the CURRENT file is unreadable — the engine has no io/store handle to
/// read the pointer file; after a `rollback --hard` repoints CURRENT at an
/// older version the caller can pass `.as_of` explicitly).
pub const Version = union(enum) {
    current,
    as_of: u32,
};

/// The answer to "what owns this rootfs path": the install fact, the
/// package whose store dir the origin resolves into, and the roots whose
/// dep-closure reaches that package.  All strings c_allocator-owned; free
/// with prov_free_what.
pub const WhatResult = struct {
    target: []const u8,
    origin: []const u8,
    mode: u32,
    genhash: []const u8,
    pkg: ?[]const u8,
    /// Roots whose dep-closure reaches pkg (lexicographic; pkg itself
    /// counts when it is a root — closure(X) contains X).
    pullers: [][]const u8,
};

/// The answer to "why is this package in the store": its store dir, the
/// closure-from-pkg in deps-first topo order (pkg LAST, the fx_topo_order
/// contract), the install targets whose origin IS its store dir (bin
/// symlinks — etc-file origins are generation-relative and belong to the
/// activation, not to a single package), and the pulling roots.  Free with
/// prov_free_why.
pub const WhyResult = struct {
    pkg: []const u8,
    store_dir: []const u8,
    deps: [][]const u8,
    provides_targets: [][]const u8,
    pulled_by: [][]const u8,
};

/// One rootfs/store divergence found by prov_verify.  target + detail are
/// c_allocator-owned; free the appended slice with prov_free_drifts.
pub const DriftKind = enum { missing, hash, mode, link_target, unmanaged };

pub const Drift = struct {
    target: []const u8,
    kind: DriftKind,
    detail: []const u8,
};

// ─── as-of fact readers (the store.zig RawBag/version_bag idiom) ───────────

/// Raw sym-id fact bag over dl_query_version; tuples resolve against the
/// live db's shared/persisted interner.  Allocations live in the caller's
/// per-call arena.
const RelBag = struct {
    a: std.mem.Allocator,
    tuples: std.ArrayList(u32) = .empty, // arity * n values
    n: usize = 0,
    arity: u8 = 0,
    oom: bool = false,
};

fn relbag_cb(cols: [*]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    const bag: *RelBag = @ptrCast(@alignCast(user.?));
    bag.arity = arity;
    bag.tuples.appendSlice(bag.a, cols[0..arity]) catch {
        bag.oom = true;
        return 1; // OOM: stop enumeration
    };
    bag.n += 1;
    return 0;
}

/// Read all facts of `rel` as-of `version`.  A relation ABSENT from that
/// version (dl_query_version returns -1; old snapshots predate
/// install/provides) is EMPTY, not an error — store.zig:890-912.
fn read_rel(a: std.mem.Allocator, db: *DlDb, version: u32, rel: [*:0]const u8, e: *ProvErrBuf) ProvError!RelBag {
    var bag = RelBag{ .a = a };
    const n = st.dl_query_version(db, version, rel, relbag_cb, &bag);
    if (bag.oom) return e.set("out of memory reading '{s}'", .{std.mem.span(rel)});
    if (n < 0) return bag; // absent in that version -> empty
    return bag;
}

/// The tuples of a non-empty bag as an [n]arity slice-of-columns accessor
/// guard: the schema is fixed (install a4, provides/dep a2, root a1), so a
/// mismatching arity means a corrupted/foreign db — refuse loudly rather
/// than misindexing the flat buffer.
fn check_arity(bag: *const RelBag, want: u8, rel: [*:0]const u8, e: *ProvErrBuf) ProvError!void {
    if (bag.n > 0 and bag.arity != want)
        return e.set("relation '{s}' has arity {d}, expected {d}", .{ std.mem.span(rel), bag.arity, want });
}

/// Resolve an interned sym_id to a name duped into the arena.
fn sym_name(a: std.mem.Allocator, db: *DlDb, sym: u32, e: *ProvErrBuf) ProvError![]const u8 {
    const s = cl.dl_intern_str_of(db, sym) orelse
        return e.set("internal: cannot resolve symbol {d}", .{sym});
    return a.dupe(u8, std.mem.span(s)) catch e.set("out of memory", .{});
}

/// Resolve `v` against the published snapshot list: `.current` = the newest
/// published version; an `.as_of` version that was never published (or was
/// pruned by gc --retain) is a hard error — dl_query_version alone cannot
/// distinguish "absent relation" from "nonexistent version" (both -1).
fn resolve_version(a: std.mem.Allocator, db: *DlDb, v: Version, e: *ProvErrBuf, out: *u32) ProvError!void {
    const total = st.dl_snapshot_versions(db, null, 0);
    if (total <= 0)
        return e.set("no published snapshot in the store db — run a build first", .{});
    const vers = a.alloc(u32, @intCast(total)) catch return e.set("out of memory", .{});
    _ = st.dl_snapshot_versions(db, vers.ptr, @intCast(total));
    const want: u32 = switch (v) {
        .current => vers[vers.len - 1],
        .as_of => |n| n,
    };
    for (vers) |x| {
        if (x == want) {
            out.* = want;
            return;
        }
    }
    return e.set("no such version {d} (have {d} version(s))", .{ want, total });
}

// ─── dep-graph reachability as-of a version (BFS, never the live closure) ──

const Edge = struct { from: []const u8, to: []const u8 };

fn read_edges(a: std.mem.Allocator, db: *DlDb, version: u32, e: *ProvErrBuf) ProvError![]Edge {
    var bag = try read_rel(a, db, version, "dep", e);
    try check_arity(&bag, 2, "dep", e);
    const edges = a.alloc(Edge, bag.n) catch return e.set("out of memory", .{});
    for (0..bag.n) |i| {
        const t = bag.tuples.items[i * 2 ..][0..2];
        edges[i] = .{
            .from = try sym_name(a, db, t[0], e),
            .to = try sym_name(a, db, t[1], e),
        };
    }
    return edges;
}

fn in_names(list: []const []const u8, name: []const u8) bool {
    for (list) |x| {
        if (std.mem.eql(u8, x, name)) return true;
    }
    return false;
}

fn name_lt(_: void, x: []const u8, y: []const u8) bool {
    return std.mem.order(u8, x, y) == .lt;
}

/// Roots whose dep-closure reaches `pkg_name`, as-of `version`: a BACKWARD
/// BFS over the dep tuples (edges n -> m where m already reaches pkg seed
/// the reachable set with n), then intersect with the `root` relation of
/// the same version.  Lexicographically sorted, arena-owned.  The live
/// materialized closure relation is never read or mutated.
fn collect_pullers(a: std.mem.Allocator, db: *DlDb, version: u32, pkg_name: []const u8, e: *ProvErrBuf) ProvError![][]const u8 {
    const edges = try read_edges(a, db, version, e);
    var root_bag = try read_rel(a, db, version, "root", e);
    try check_arity(&root_bag, 1, "root", e);

    // backward-reachable set: nodes from which pkg_name is reachable.
    var reach: std.ArrayList([]const u8) = .empty;
    reach.append(a, pkg_name) catch return e.set("out of memory", .{});
    var i: usize = 0;
    while (i < reach.items.len) : (i += 1) {
        const cur = reach.items[i];
        for (edges) |ed| {
            if (!std.mem.eql(u8, ed.to, cur)) continue;
            if (in_names(reach.items, ed.from)) continue;
            reach.append(a, ed.from) catch return e.set("out of memory", .{});
        }
    }

    var out: std.ArrayList([]const u8) = .empty;
    for (0..root_bag.n) |r| {
        const name = try sym_name(a, db, root_bag.tuples.items[r], e);
        if (in_names(reach.items, name))
            out.append(a, name) catch return e.set("out of memory", .{});
    }
    const pullers = out.toOwnedSlice(a) catch return e.set("out of memory", .{});
    std.mem.sort([]const u8, pullers, {}, name_lt);
    return pullers;
}

const Frame = struct { name: []const u8, ei: usize };

/// The closure-from-pkg as-of `version` in deps-first TOPO order (pkg LAST
/// — the fx_topo_order contract), by iterative DFS post-order over the dep
/// tuples.  Cycles are rejected with the house error (a snapshot whose dep
/// graph cycles could never have produced a finite store path).  Arena-
/// owned; deps-first means every element follows its dependencies.
fn collect_deps_topo(a: std.mem.Allocator, db: *DlDb, version: u32, pkg_name: []const u8, e: *ProvErrBuf) ProvError![][]const u8 {
    const edges = try read_edges(a, db, version, e);

    var stack: std.ArrayList(Frame) = .empty; // on-stack == visiting
    var done: std.ArrayList([]const u8) = .empty;
    var order: std.ArrayList([]const u8) = .empty;

    stack.append(a, .{ .name = pkg_name, .ei = 0 }) catch return e.set("out of memory", .{});
    while (stack.items.len > 0) {
        // NOTE: `top` is re-fetched every iteration — stack.append below
        // may reallocate and invalidate a cached pointer.
        var descended = false;
        {
            const idx0 = stack.items[stack.items.len - 1].ei;
            var i = idx0;
            while (i < edges.len) : (i += 1) {
                const ed = edges[i];
                if (!std.mem.eql(u8, ed.from, stack.items[stack.items.len - 1].name)) continue;
                if (in_names(done.items, ed.to)) continue;
                var on_stack = false;
                for (stack.items) |fr| {
                    if (std.mem.eql(u8, fr.name, ed.to)) {
                        on_stack = true;
                        break;
                    }
                }
                if (on_stack)
                    return e.set(
                        "dependency cycle detected involving '{s}' " ++
                            "(cyclic deps have no finite store path)",
                        .{ed.to},
                    );
                stack.items[stack.items.len - 1].ei = i + 1;
                stack.append(a, .{ .name = ed.to, .ei = 0 }) catch return e.set("out of memory", .{});
                descended = true;
                break;
            }
            if (!descended) stack.items[stack.items.len - 1].ei = i;
        }
        if (!descended) {
            const name = stack.items[stack.items.len - 1].name;
            order.append(a, name) catch return e.set("out of memory", .{});
            done.append(a, name) catch return e.set("out of memory", .{});
            _ = stack.pop();
        }
    }
    return order.toOwnedSlice(a) catch return e.set("out of memory", .{});
}

// ─── escaping-string helpers (the caller-frees contract) ───────────────────

fn dupe_str(s: []const u8, e: *ProvErrBuf) ProvError![]const u8 {
    return c_alloc.dupe(u8, s) catch e.set("out of memory", .{});
}

/// dupe each string + the array (free_names' per-item contract); on OOM
/// everything allocated so far is freed.
fn dupe_list(items: []const []const u8, e: *ProvErrBuf) ProvError![][]const u8 {
    const out = c_alloc.alloc([]const u8, items.len) catch return e.set("out of memory", .{});
    var n: usize = 0;
    errdefer {
        for (out[0..n]) |s| c_alloc.free(s);
        c_alloc.free(out);
    }
    for (items) |s| {
        out[n] = try dupe_str(s, e);
        n += 1;
    }
    return out;
}

// ─── prov_what ─────────────────────────────────────────────────────────────

/// Which install fact manages `target` (rootfs-absolute), as-of `v`; the
/// result's pkg is the package whose store dir the origin resolves into
/// (null when the origin is generation-relative or the snapshot predates
/// provides), and pullers are the roots whose dep-closure reaches pkg.
pub fn prov_what(db: ?*DlDb, target: []const u8, v: Version, e: *ProvErrBuf) ProvError!WhatResult {
    const d = db orelse return e.set("internal: null db", .{});

    var arena = std.heap.ArenaAllocator.init(c_alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var ver: u32 = 0;
    try resolve_version(a, d, v, e, &ver);

    // install(target, origin, mode, genhash) as-of ver; absent-as-empty.
    var bag = try read_rel(a, d, ver, "install", e);
    try check_arity(&bag, 4, "install", e);
    var origin: []const u8 = "";
    var mode: u32 = 0;
    var genhash: []const u8 = "";
    var found = false;
    for (0..bag.n) |i| {
        const t = bag.tuples.items[i * 4 ..][0..4];
        const tgt = try sym_name(a, d, t[0], e);
        if (!std.mem.eql(u8, tgt, target)) continue;
        origin = try sym_name(a, d, t[1], e);
        mode = t[2]; // raw u32 column, never interned
        genhash = try sym_name(a, d, t[3], e);
        found = true;
        break; // one install per target per snapshot (activation clears)
    }
    if (!found)
        return e.set(
            "target '{s}' is unmanaged (no install fact as-of version {d})",
            .{ target, ver },
        );

    // pkg: the provides fact whose store_dir is origin's FIRST path
    // segment ('{hash}-{pkg}' for bin links; '{genhash}-system-generation'
    // for etc copies, which no package provides -> null).
    const seg = if (std.mem.indexOfScalar(u8, origin, '/')) |slash| origin[0..slash] else origin;
    var pkg: ?[]const u8 = null;
    var pullers: [][]const u8 = &.{};
    if (seg.len > 0) {
        var pbag = try read_rel(a, d, ver, "provides", e);
        try check_arity(&pbag, 2, "provides", e);
        for (0..pbag.n) |i| {
            const t = pbag.tuples.items[i * 2 ..][0..2];
            const dir = try sym_name(a, d, t[1], e);
            if (!std.mem.eql(u8, dir, seg)) continue;
            pkg = try sym_name(a, d, t[0], e);
            pullers = try collect_pullers(a, d, ver, pkg.?, e);
            break;
        }
    }

    // escaping strings: c_allocator-owned, freed by prov_free_what.
    const out_target = try dupe_str(target, e);
    errdefer c_alloc.free(out_target);
    const out_origin = try dupe_str(origin, e);
    errdefer c_alloc.free(out_origin);
    const out_genhash = try dupe_str(genhash, e);
    errdefer c_alloc.free(out_genhash);
    var out_pkg: ?[]const u8 = null;
    errdefer if (out_pkg) |p| c_alloc.free(p);
    if (pkg) |p| out_pkg = try dupe_str(p, e);
    const out_pullers = try dupe_list(pullers, e);

    return .{
        .target = out_target,
        .origin = out_origin,
        .mode = mode,
        .genhash = out_genhash,
        .pkg = out_pkg,
        .pullers = out_pullers,
    };
}

/// Caller-frees contract of prov_what (each string + each array).
pub fn prov_free_what(r: WhatResult) void {
    c_alloc.free(r.target);
    c_alloc.free(r.origin);
    c_alloc.free(r.genhash);
    if (r.pkg) |p| c_alloc.free(p);
    for (r.pullers) |s| c_alloc.free(s);
    c_alloc.free(r.pullers);
}

// ─── prov_why ──────────────────────────────────────────────────────────────

/// Why `pkg` is in the store as-of `v`: its store dir, its dependency
/// closure in deps-first topo order, the rootfs paths installed from it,
/// and the roots that pull it in.
pub fn prov_why(db: ?*DlDb, pkg: []const u8, v: Version, e: *ProvErrBuf) ProvError!WhyResult {
    const d = db orelse return e.set("internal: null db", .{});

    var arena = std.heap.ArenaAllocator.init(c_alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var ver: u32 = 0;
    try resolve_version(a, d, v, e, &ver);

    // provides(pkg, store_dir) as-of ver; absent-as-empty reads as "no
    // provides fact" (clean error below), never a snapshot error.
    var pbag = try read_rel(a, d, ver, "provides", e);
    try check_arity(&pbag, 2, "provides", e);
    var store_dir: []const u8 = "";
    var found = false;
    for (0..pbag.n) |i| {
        const t = pbag.tuples.items[i * 2 ..][0..2];
        const name = try sym_name(a, d, t[0], e);
        if (!std.mem.eql(u8, name, pkg)) continue;
        store_dir = try sym_name(a, d, t[1], e);
        found = true;
        break;
    }
    if (!found)
        return e.set(
            "package '{s}' has no provides fact as-of version {d} " ++
                "(unknown package or snapshot predates provenance)",
            .{ pkg, ver },
        );

    // closure-from-pkg (deps-first topo) + install targets from this dir +
    // pulling roots, all as-of the same version.
    const deps = try collect_deps_topo(a, d, ver, pkg, e);
    const pulled_by = try collect_pullers(a, d, ver, pkg, e);

    var targets: std.ArrayList([]const u8) = .empty;
    var ibag = try read_rel(a, d, ver, "install", e);
    try check_arity(&ibag, 4, "install", e);
    for (0..ibag.n) |i| {
        const t = ibag.tuples.items[i * 4 ..][0..4];
        const origin = try sym_name(a, d, t[1], e);
        if (!std.mem.eql(u8, origin, store_dir)) continue;
        targets.append(a, try sym_name(a, d, t[0], e)) catch
            return e.set("out of memory", .{});
    }
    const provides_targets = targets.toOwnedSlice(a) catch return e.set("out of memory", .{});
    std.mem.sort([]const u8, provides_targets, {}, name_lt);

    // escaping strings: c_allocator-owned, freed by prov_free_why.
    const out_pkg = try dupe_str(pkg, e);
    errdefer c_alloc.free(out_pkg);
    const out_dir = try dupe_str(store_dir, e);
    errdefer c_alloc.free(out_dir);
    const out_deps = try dupe_list(deps, e);
    errdefer {
        for (out_deps) |s| c_alloc.free(s);
        c_alloc.free(out_deps);
    }
    const out_targets = try dupe_list(provides_targets, e);
    errdefer {
        for (out_targets) |s| c_alloc.free(s);
        c_alloc.free(out_targets);
    }
    const out_pulled = try dupe_list(pulled_by, e);

    return .{
        .pkg = out_pkg,
        .store_dir = out_dir,
        .deps = out_deps,
        .provides_targets = out_targets,
        .pulled_by = out_pulled,
    };
}

/// Caller-frees contract of prov_why (each string + each array).
pub fn prov_free_why(r: WhyResult) void {
    c_alloc.free(r.pkg);
    c_alloc.free(r.store_dir);
    for (r.deps) |s| c_alloc.free(s);
    c_alloc.free(r.deps);
    for (r.provides_targets) |s| c_alloc.free(s);
    c_alloc.free(r.provides_targets);
    for (r.pulled_by) |s| c_alloc.free(s);
    c_alloc.free(r.pulled_by);
}

// ─── proof-tree renderers ──────────────────────────────────────────────────

/// Indented proof tree for a what-answer:
///
///     /bin/hello
///       <- origin <hash>-hello (mode 0o0, generation <genhash>)
///         <- package hello
///           <- pulled by root 'world'
///
/// The writer is anytype (CLI stdout, a buffer in tests); errors propagate.
pub fn prov_render_what(w: anytype, r: *const WhatResult) !void {
    try w.print("{s}\n", .{r.target});
    try w.print("  <- origin {s} (mode 0o{o}, generation {s})\n", .{ r.origin, r.mode, r.genhash });
    if (r.pkg) |p| {
        try w.print("    <- package {s}\n", .{p});
        if (r.pullers.len == 0) {
            try w.print("      <- pulled by (no recorded root)\n", .{});
        } else for (r.pullers) |root| {
            try w.print("      <- pulled by root '{s}'\n", .{root});
        }
    } else {
        try w.print("    <- package unknown (origin's store dir has no provides fact)\n", .{});
    }
}

/// Indented proof tree for a why-answer (deps-first closure, provided
/// targets, pulling roots):
///
///     package world
///       <- store dir <hash>-world
///       <- closure-from-pkg (deps-first topo order):
///         hello
///         world
///       <- provides targets:
///         /bin/world
///       <- pulled by roots:
///         world
pub fn prov_render_why(w: anytype, r: *const WhyResult) !void {
    try w.print("package {s}\n", .{r.pkg});
    try w.print("  <- store dir {s}\n", .{r.store_dir});
    try w.print("  <- closure-from-pkg (deps-first topo order):\n", .{});
    if (r.deps.len == 0) {
        try w.print("    (none)\n", .{});
    } else for (r.deps) |dep| {
        try w.print("    {s}\n", .{dep});
    }
    try w.print("  <- provides targets:\n", .{});
    if (r.provides_targets.len == 0) {
        try w.print("    (none)\n", .{});
    } else for (r.provides_targets) |t| {
        try w.print("    {s}\n", .{t});
    }
    try w.print("  <- pulled by roots:\n", .{});
    if (r.pulled_by.len == 0) {
        try w.print("    (none)\n", .{});
    } else for (r.pulled_by) |root| {
        try w.print("    {s}\n", .{root});
    }
}

// ─── prov_verify ───────────────────────────────────────────────────────────

fn add_drift(out: *std.ArrayList(Drift), target: []const u8, kind: DriftKind, detail: []const u8, e: *ProvErrBuf) ProvError!void {
    const t = c_alloc.dupe(u8, target) catch return e.set("out of memory", .{});
    errdefer c_alloc.free(t);
    const d = c_alloc.dupe(u8, detail) catch return e.set("out of memory", .{});
    out.append(c_alloc, .{ .target = t, .kind = kind, .detail = d }) catch {
        c_alloc.free(d);
        return e.set("out of memory", .{});
    };
}

/// Compare the rootfs against the install facts as-of `v` and append one
/// Drift per divergence to `out` (c_allocator-owned — free with
/// prov_free_drifts).  Per install fact: the target must exist, be the
/// recorded KIND (mode 0 = symlink to {store_root}/{origin}, else a
/// regular file) and carry the recorded mode bits.  Then every entry in
/// the install targets' parent dirs (/etc, /bin, ...) that no install fact
/// records is unmanaged drift.  The `hash` kind (etc-file content vs the
/// store copy) is the U5 reconcile extension.  A snapshot predating the
/// install relation reads as empty: verify then reports nothing (no
/// knowledge, no drift), never an error.
pub fn prov_verify(
    io: Io,
    db: ?*DlDb,
    rootfs: []const u8,
    store_root: []const u8,
    v: Version,
    e: *ProvErrBuf,
    out: *std.ArrayList(Drift),
) ProvError!void {
    const d = db orelse return e.set("internal: null db", .{});

    var arena = std.heap.ArenaAllocator.init(c_alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var ver: u32 = 0;
    try resolve_version(a, d, v, e, &ver);

    // normalize rootfs/store_root: strip trailing slashes (but keep a bare
    // "/") — the fx_store_open root normalization.
    var rf = rootfs;
    while (rf.len > 1 and rf[rf.len - 1] == '/') rf = rf[0 .. rf.len - 1];
    var sr = store_root;
    while (sr.len > 1 and sr[sr.len - 1] == '/') sr = sr[0 .. sr.len - 1];

    var bag = try read_rel(a, d, ver, "install", e);
    try check_arity(&bag, 4, "install", e);

    // pass 1: per-fact lstat + kind/mode/link-target comparison.
    var targets: std.ArrayList([]const u8) = .empty;
    for (0..bag.n) |i| {
        const t = bag.tuples.items[i * 4 ..][0..4];
        const target = try sym_name(a, d, t[0], e);
        const origin = try sym_name(a, d, t[1], e);
        const mode: u32 = t[2];
        targets.append(a, target) catch return e.set("out of memory", .{});

        var pb: [2 * st.FX_PATH_MAX]u8 = undefined;
        const full = std.fmt.bufPrint(&pb, "{s}{s}", .{ rf, target }) catch
            return e.set("rootfs path too long: {s}{s}", .{ rf, target });
        const fst = Io.Dir.cwd().statFile(io, full, .{ .follow_symlinks = false }) catch |err| {
            if (err != error.FileNotFound)
                return e.set("cannot stat '{s}': {s}", .{ full, @errorName(err) });
            var tb: [2 * st.FX_PATH_MAX]u8 = undefined;
            const det = std.fmt.bufPrint(&tb, "target does not exist (expected {s} from origin {s})", .{
                if (mode == 0) "a symlink" else "a regular file",
                origin,
            }) catch "target does not exist";
            try add_drift(out, target, .missing, det, e);
            continue;
        };

        if (mode == 0) {
            // symlink expected: target must point at {store_root}/{origin}.
            var eb: [2 * st.FX_PATH_MAX]u8 = undefined;
            const want = std.fmt.bufPrint(&eb, "{s}/{s}", .{ sr, origin }) catch
                return e.set("store path too long: {s}/{s}", .{ sr, origin });
            if (fst.kind != .sym_link) {
                var tb: [2 * st.FX_PATH_MAX]u8 = undefined;
                const det = std.fmt.bufPrint(&tb, "not a symlink (install fact records mode 0; expected target '{s}')", .{want}) catch "not a symlink";
                try add_drift(out, target, .link_target, det, e);
                continue;
            }
            var lb: [st.FX_PATH_MAX]u8 = undefined;
            const n = Io.Dir.cwd().readLink(io, full, &lb) catch {
                var tb: [2 * st.FX_PATH_MAX]u8 = undefined;
                const det = std.fmt.bufPrint(&tb, "cannot read link (expected target '{s}')", .{want}) catch "cannot read link";
                try add_drift(out, target, .link_target, det, e);
                continue;
            };
            if (!std.mem.eql(u8, lb[0..n], want)) {
                var tb: [2 * st.FX_PATH_MAX]u8 = undefined;
                const det = std.fmt.bufPrint(&tb, "symlink points at '{s}' != store path '{s}'", .{ lb[0..n], want }) catch "symlink target mismatch";
                try add_drift(out, target, .link_target, det, e);
            }
        } else {
            // regular file expected: kind first, then the mode bits.
            if (fst.kind == .sym_link) {
                var tb: [2 * st.FX_PATH_MAX]u8 = undefined;
                const det = std.fmt.bufPrint(&tb, "is a symlink but install fact records a regular file (mode 0o{o})", .{mode}) catch "unexpected symlink";
                try add_drift(out, target, .link_target, det, e);
                continue;
            }
            const actual: u32 = @intFromEnum(fst.permissions) & 0o7777;
            if (actual != mode) {
                var tb: [2 * st.FX_PATH_MAX]u8 = undefined;
                const det = std.fmt.bufPrint(&tb, "mode 0o{o} != recorded 0o{o}", .{ actual, mode }) catch "mode mismatch";
                try add_drift(out, target, .mode, det, e);
            }
        }
    }

    // pass 2: unmanaged scan — walk the (deduped) parent dirs of the
    // install targets; every non-directory entry no install fact records
    // is drift.  No install facts (or a snapshot predating them) -> no
    // scan: absence of knowledge is not drift.
    var parents: std.ArrayList([]const u8) = .empty;
    for (targets.items) |target| {
        const dir = if (std.mem.lastIndexOfScalar(u8, target, '/')) |slash| target[0..slash] else continue;
        if (in_names(parents.items, dir)) continue;
        parents.append(a, dir) catch return e.set("out of memory", .{});
    }
    for (parents.items) |dir| {
        var pb2: [2 * st.FX_PATH_MAX]u8 = undefined;
        const full_dir = std.fmt.bufPrint(&pb2, "{s}{s}", .{ rf, dir }) catch continue;
        var dirh = Io.Dir.cwd().openDir(io, full_dir, .{ .iterate = true }) catch continue;
        defer dirh.close(io);
        var it = dirh.iterate();
        while (it.next(io) catch null) |ent| {
            if (ent.kind == .directory) continue;
            var cb: [2 * st.FX_PATH_MAX]u8 = undefined;
            const child = std.fmt.bufPrint(&cb, "{s}/{s}", .{ dir, ent.name }) catch continue;
            if (in_names(targets.items, child)) continue;
            var tb: [2 * st.FX_PATH_MAX]u8 = undefined;
            const det = std.fmt.bufPrint(&tb, "present under {s} but no install fact records it (as-of version {d})", .{ dir, ver }) catch "unmanaged";
            try add_drift(out, child, .unmanaged, det, e);
        }
    }
}

/// Caller-frees contract of prov_verify's appended drifts (each target +
/// detail + the list storage).  The pinned API has no drift free fn; this
/// mirrors prov_free_what/why so callers never leak.
pub fn prov_free_drifts(drifts: []Drift) void {
    for (drifts) |dr| {
        c_alloc.free(dr.target);
        c_alloc.free(dr.detail);
    }
}

// ─── unit tests (live dbs on per-test temp dirs, run sequentially — the
// closure.zig/store.zig test discipline: dl_open holds a process-lifetime
// fcntl single-writer lock, so each test owns its OWN dir and closes +
// deletes it before ending) ─────────────────────────────────────────────────

const testing = std.testing;

fn tio() Io {
    return std.testing.io;
}

fn temp_db_dir(buf: *[64:0]u8) ![:0]u8 {
    var seed: [4]u8 = undefined;
    tio().random(&seed);
    return std.fmt.bufPrintZ(buf, "/tmp/fx-prov-db-{x:0>8}", .{std.mem.readInt(u32, &seed, .little)});
}

fn temp_dir(buf: *[64:0]u8, tag: []const u8) ![:0]u8 {
    var seed: [4]u8 = undefined;
    tio().random(&seed);
    return std.fmt.bufPrintZ(buf, "/tmp/fx-prov-{s}-{x:0>8}", .{ tag, std.mem.readInt(u32, &seed, .little) });
}

// fixture store-dir hashes (64 hex chars each — opaque to the engine)
const ha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const hb = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const gen = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

/// Intern a Zig slice for a fixture fact (0 on OOM — checked by callers).
fn zify(buf: []u8, s: []const u8) [:0]u8 {
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return buf[0..s.len :0];
}

/// The activation txn exactly as fx-activate writes it (U1,
/// activate.zig:1051-1093): declare, txn add of install(4)/provides(2)
/// facts, commit, publish — creating a NEW snapshot version.
fn activate(db: *DlDb) !void {
    if (cl.dl_declare_relation(db, "install", 4) != 0) return error.DlDeclare;
    if (cl.dl_declare_relation(db, "provides", 2) != 0) return error.DlDeclare;
    if (st.dl_txn_begin(db) != 0) return error.DlTxn;
    errdefer _ = st.dl_txn_rollback(db);

    const F = struct {
        fn install(d: *DlDb, target: [:0]const u8, origin: [:0]const u8, mode: u32, gh: [:0]const u8) !void {
            const cols = [4]u32{
                cl.dl_intern_str(d, target.ptr),
                cl.dl_intern_str(d, origin.ptr),
                mode, // raw u32 column, never interned
                cl.dl_intern_str(d, gh.ptr),
            };
            if (st.dl_txn_add_fact(d, "install", &cols, 4) != 0) return error.DlFact;
        }
        fn provides(d: *DlDb, pkg: [:0]const u8, dir: [:0]const u8) !void {
            const cols = [2]u32{ cl.dl_intern_str(d, pkg.ptr), cl.dl_intern_str(d, dir.ptr) };
            if (st.dl_txn_add_fact(d, "provides", &cols, 2) != 0) return error.DlFact;
        }
    };

    var b1: [128:0]u8 = undefined;
    var b2: [128:0]u8 = undefined;
    var b3: [128:0]u8 = undefined;
    var b4: [128:0]u8 = undefined;
    var b5: [128:0]u8 = undefined;
    var b6: [128:0]u8 = undefined;

    try F.install(db, zify(&b1, "/bin/hello"), zify(&b2, ha ++ "-hello"), 0, gen);
    try F.install(db, zify(&b3, "/bin/world"), zify(&b4, hb ++ "-world"), 0, gen);
    try F.install(db, "/etc/motd", zify(&b4, gen ++ "-system-generation/etc/motd"), 0o644, gen);
    try F.install(db, "/etc/hosts", zify(&b2, gen ++ "-system-generation/etc/hosts"), 0o644, gen);
    try F.provides(db, "hello", zify(&b5, ha ++ "-hello"));
    try F.provides(db, "world", zify(&b6, hb ++ "-world"));

    if (st.dl_txn_commit(db) != 0) return error.DlTxn;
    if (cl.dl_publish_snapshot(db) != 0) return error.DlPublish;
}

test "prov_what: current + as-of, pkg resolution, pullers, error paths" {
    var dir_buf: [64:0]u8 = undefined;
    const dir = try temp_db_dir(&dir_buf);
    const db = cl.dl_open(dir.ptr) orelse return error.DlOpenFailed;
    defer {
        cl.dl_close(db);
        Io.Dir.cwd().deleteTree(tio(), dir) catch {};
    }
    var pe = pkgs.ErrBuf{};
    var pset: pkgs.PackageSet = undefined;
    try pkgs.fx_packageset_load(&pset, "zig/corpus/packageset/good.dhall", &pe);
    defer pset.deinit();
    var ce = cl.ErrBuf{};
    try cl.fx_closure_compute(db, &pset, &.{}, &ce); // v1: old snapshot
    try activate(db); // v2: CURRENT

    var e = ProvErrBuf{};

    // null db
    try testing.expectError(error.FxProv, prov_what(null, "/bin/hello", .current, &e));
    try testing.expectEqualStrings("internal: null db", e.slice());

    // bin symlink: origin IS the pkg store dir -> pkg + pullers
    const r = try prov_what(db, "/bin/hello", .current, &e);
    defer prov_free_what(r);
    try testing.expectEqualStrings("/bin/hello", r.target);
    try testing.expectEqualStrings(ha ++ "-hello", r.origin);
    try testing.expectEqual(@as(u32, 0), r.mode);
    try testing.expectEqualStrings(gen, r.genhash);
    try testing.expectEqualStrings("hello", r.pkg.?);
    try testing.expectEqual(@as(usize, 2), r.pullers.len); // hello pulls itself
    try testing.expectEqualStrings("hello", r.pullers[0]); // lexicographic
    try testing.expectEqualStrings("world", r.pullers[1]);

    // etc copy: origin is generation-relative -> no pkg, no pullers
    const r2 = try prov_what(db, "/etc/motd", .current, &e);
    defer prov_free_what(r2);
    try testing.expectEqualStrings(gen ++ "-system-generation/etc/motd", r2.origin);
    try testing.expectEqual(@as(u32, 0o644), r2.mode);
    try testing.expect(r2.pkg == null);
    try testing.expectEqual(@as(usize, 0), r2.pullers.len);

    // explicit as-of == current gives the same answer
    const r3 = try prov_what(db, "/bin/hello", .{ .as_of = 2 }, &e);
    defer prov_free_what(r3);
    try testing.expectEqualStrings("hello", r3.pkg.?);

    // OLD snapshot (v1) predates install/provides: absent-as-empty reads
    // as "unmanaged", NOT as a snapshot error (the R2 pin).
    e = .{};
    try testing.expectError(error.FxProv, prov_what(db, "/bin/hello", .{ .as_of = 1 }, &e));
    try testing.expectEqualStrings("target '/bin/hello' is unmanaged (no install fact as-of version 1)", e.slice());

    // unknown target on the current snapshot
    e = .{};
    try testing.expectError(error.FxProv, prov_what(db, "/bin/rogue", .current, &e));
    try testing.expectEqualStrings("target '/bin/rogue' is unmanaged (no install fact as-of version 2)", e.slice());

    // never-published version
    e = .{};
    try testing.expectError(error.FxProv, prov_what(db, "/bin/hello", .{ .as_of = 99 }, &e));
    try testing.expectEqualStrings("no such version 99 (have 2 version(s))", e.slice());
}

test "prov_why: topo closure-from-pkg, provides targets, pulled_by" {
    var dir_buf: [64:0]u8 = undefined;
    const dir = try temp_db_dir(&dir_buf);
    const db = cl.dl_open(dir.ptr) orelse return error.DlOpenFailed;
    defer {
        cl.dl_close(db);
        Io.Dir.cwd().deleteTree(tio(), dir) catch {};
    }
    var pe = pkgs.ErrBuf{};
    var pset: pkgs.PackageSet = undefined;
    try pkgs.fx_packageset_load(&pset, "zig/corpus/packageset/good.dhall", &pe);
    defer pset.deinit();
    var ce = cl.ErrBuf{};
    try cl.fx_closure_compute(db, &pset, &.{}, &ce); // v1: old snapshot
    try activate(db); // v2: CURRENT

    var e = ProvErrBuf{};

    try testing.expectError(error.FxProv, prov_why(null, "hello", .current, &e));
    try testing.expectEqualStrings("internal: null db", e.slice());

    // hello: no deps -> closure-from-pkg is itself; both roots pull it
    const r = try prov_why(db, "hello", .current, &e);
    defer prov_free_why(r);
    try testing.expectEqualStrings("hello", r.pkg);
    try testing.expectEqualStrings(ha ++ "-hello", r.store_dir);
    try testing.expectEqual(@as(usize, 1), r.deps.len);
    try testing.expectEqualStrings("hello", r.deps[0]);
    try testing.expectEqual(@as(usize, 1), r.provides_targets.len);
    try testing.expectEqualStrings("/bin/hello", r.provides_targets[0]);
    try testing.expectEqual(@as(usize, 2), r.pulled_by.len);
    try testing.expectEqualStrings("hello", r.pulled_by[0]);
    try testing.expectEqualStrings("world", r.pulled_by[1]);

    // world: deps-first topo = [hello, world]; only world pulls world
    const r2 = try prov_why(db, "world", .current, &e);
    defer prov_free_why(r2);
    try testing.expectEqual(@as(usize, 2), r2.deps.len);
    try testing.expectEqualStrings("hello", r2.deps[0]); // deps first
    try testing.expectEqualStrings("world", r2.deps[1]); // pkg last
    try testing.expectEqualStrings("/bin/world", r2.provides_targets[0]);
    try testing.expectEqual(@as(usize, 1), r2.pulled_by.len);
    try testing.expectEqualStrings("world", r2.pulled_by[0]);

    // OLD snapshot (v1) predates provides: clean semantic error, absent-
    // as-empty (the R2 pin).
    e = .{};
    try testing.expectError(error.FxProv, prov_why(db, "hello", .{ .as_of = 1 }, &e));
    try testing.expectEqualStrings(
        "package 'hello' has no provides fact as-of version 1 (unknown package or snapshot predates provenance)",
        e.slice(),
    );

    // unknown package on the current snapshot
    e = .{};
    try testing.expectError(error.FxProv, prov_why(db, "ghost", .current, &e));
    try testing.expectEqualStrings(
        "package 'ghost' has no provides fact as-of version 2 (unknown package or snapshot predates provenance)",
        e.slice(),
    );
}

test "prov_why rejects a cyclic dep graph with the topo error" {
    var dir_buf: [64:0]u8 = undefined;
    const dir = try temp_db_dir(&dir_buf);
    const db = cl.dl_open(dir.ptr) orelse return error.DlOpenFailed;
    defer {
        cl.dl_close(db);
        Io.Dir.cwd().deleteTree(tio(), dir) catch {};
    }

    // hand-built cyclic EDB (the fixpoint tolerates it; the store pipeline
    // never could — fx_topo_order would have rejected the build)
    const sa = cl.dl_intern_str(db, "a");
    const sb = cl.dl_intern_str(db, "b");
    var ce = cl.ErrBuf{};
    try cl.fx_closure_rebuild(db, &.{ sa, sb }, &.{ sa, sb, sb, sa }, &.{sa}, &ce); // v1
    try activate(db); // v2

    // provides for 'a' on a THIRD version so the cycle is reachable
    if (st.dl_txn_begin(db) != 0) return error.DlTxn;
    var dir_a: [80:0]u8 = undefined;
    const store_dir_a = try std.fmt.bufPrintZ(&dir_a, "{s}-a", .{ha});
    const cols = [2]u32{ cl.dl_intern_str(db, "a"), cl.dl_intern_str(db, store_dir_a.ptr) };
    if (st.dl_txn_add_fact(db, "provides", &cols, 2) != 0) return error.DlFact;
    if (st.dl_txn_commit(db) != 0) return error.DlTxn;
    if (cl.dl_publish_snapshot(db) != 0) return error.DlPublish; // v3

    var e = ProvErrBuf{};
    try testing.expectError(error.FxProv, prov_why(db, "a", .current, &e));
    try testing.expectEqualStrings(
        "dependency cycle detected involving 'a' (cyclic deps have no finite store path)",
        e.slice(),
    );
}

test "prov_render_what / prov_render_why: indented proof trees" {
    var dir_buf: [64:0]u8 = undefined;
    const dir = try temp_db_dir(&dir_buf);
    const db = cl.dl_open(dir.ptr) orelse return error.DlOpenFailed;
    defer {
        cl.dl_close(db);
        Io.Dir.cwd().deleteTree(tio(), dir) catch {};
    }
    var pe = pkgs.ErrBuf{};
    var pset: pkgs.PackageSet = undefined;
    try pkgs.fx_packageset_load(&pset, "zig/corpus/packageset/good.dhall", &pe);
    defer pset.deinit();
    var ce = cl.ErrBuf{};
    try cl.fx_closure_compute(db, &pset, &.{}, &ce);
    try activate(db);

    var e = ProvErrBuf{};
    const r = try prov_what(db, "/bin/hello", .current, &e);
    defer prov_free_what(r);
    var aw: Io.Writer.Allocating = .init(c_alloc);
    defer aw.deinit();
    try prov_render_what(&aw.writer, &r);
    const want_what =
        "/bin/hello\n" ++
        "  <- origin " ++ ha ++ "-hello (mode 0o0, generation " ++ gen ++ ")\n" ++
        "    <- package hello\n" ++
        "      <- pulled by root 'hello'\n" ++
        "      <- pulled by root 'world'\n";
    try testing.expectEqualStrings(want_what, aw.written());

    var aw2: Io.Writer.Allocating = .init(c_alloc);
    defer aw2.deinit();
    const r2 = try prov_what(db, "/etc/motd", .current, &e);
    defer prov_free_what(r2);
    try prov_render_what(&aw2.writer, &r2);
    const want_what2 =
        "/etc/motd\n" ++
        "  <- origin " ++ gen ++ "-system-generation/etc/motd (mode 0o644, generation " ++ gen ++ ")\n" ++
        "    <- package unknown (origin's store dir has no provides fact)\n";
    try testing.expectEqualStrings(want_what2, aw2.written());

    var aw3: Io.Writer.Allocating = .init(c_alloc);
    defer aw3.deinit();
    const r3 = try prov_why(db, "world", .current, &e);
    defer prov_free_why(r3);
    try prov_render_why(&aw3.writer, &r3);
    const want_why =
        "package world\n" ++
        "  <- store dir " ++ hb ++ "-world\n" ++
        "  <- closure-from-pkg (deps-first topo order):\n" ++
        "    hello\n" ++
        "    world\n" ++
        "  <- provides targets:\n" ++
        "    /bin/world\n" ++
        "  <- pulled by roots:\n" ++
        "    world\n";
    try testing.expectEqualStrings(want_why, aw3.written());
}

test "prov_verify: drift taxonomy + clean rootfs + old-snapshot absent-as-empty" {
    const io = tio();
    var dir_buf: [64:0]u8 = undefined;
    const dir = try temp_db_dir(&dir_buf);
    const db = cl.dl_open(dir.ptr) orelse return error.DlOpenFailed;
    defer {
        cl.dl_close(db);
        Io.Dir.cwd().deleteTree(tio(), dir) catch {};
    }
    var pe = pkgs.ErrBuf{};
    var pset: pkgs.PackageSet = undefined;
    try pkgs.fx_packageset_load(&pset, "zig/corpus/packageset/good.dhall", &pe);
    defer pset.deinit();
    var ce = cl.ErrBuf{};
    try cl.fx_closure_compute(db, &pset, &.{}, &ce); // v1: old snapshot
    try activate(db); // v2: CURRENT

    var drifts: std.ArrayList(Drift) = .empty;
    defer drifts.deinit(c_alloc);
    defer prov_free_drifts(drifts.items);

    var e = ProvErrBuf{};
    try testing.expectError(error.FxProv, prov_verify(io, null, "/", "/", .current, &e, &drifts));
    try testing.expectEqualStrings("internal: null db", e.slice());

    // a fake store (dirs the symlinks point into) + a rootfs
    var sr_buf: [64:0]u8 = undefined;
    const store = try temp_dir(&sr_buf, "store");
    defer Io.Dir.cwd().deleteTree(io, store) catch {};
    var hb1: [160:0]u8 = undefined;
    var hb2: [160:0]u8 = undefined;
    const dir_hello = try std.fmt.bufPrintZ(&hb1, "{s}/{s}-hello", .{ store, ha });
    const dir_world = try std.fmt.bufPrintZ(&hb2, "{s}/{s}-world", .{ store, hb });
    try Io.Dir.cwd().createDirPath(io, dir_hello);
    try Io.Dir.cwd().createDirPath(io, dir_world);

    var rf_buf: [64:0]u8 = undefined;
    const rootfs = try temp_dir(&rf_buf, "rootfs");
    defer Io.Dir.cwd().deleteTree(io, rootfs) catch {};
    var p1: [160:0]u8 = undefined;
    var p2: [160:0]u8 = undefined;
    const bin_dir = try std.fmt.bufPrintZ(&p1, "{s}/bin", .{rootfs});
    const etc_dir = try std.fmt.bufPrintZ(&p2, "{s}/etc", .{rootfs});
    try Io.Dir.cwd().createDirPath(io, bin_dir);
    try Io.Dir.cwd().createDirPath(io, etc_dir);

    // clean baseline first: every recorded target exactly as installed
    var l1: [128:0]u8 = undefined;
    var l2: [128:0]u8 = undefined;
    const link_hello = try std.fmt.bufPrintZ(&l1, "{s}/bin/hello", .{rootfs});
    const link_world = try std.fmt.bufPrintZ(&l2, "{s}/bin/world", .{rootfs});
    try Io.Dir.cwd().symLink(io, dir_hello, link_hello, .{});
    try Io.Dir.cwd().symLink(io, dir_world, link_world, .{});
    var f1: [128:0]u8 = undefined;
    var f2: [128:0]u8 = undefined;
    const motd = try std.fmt.bufPrintZ(&f1, "{s}/etc/motd", .{rootfs});
    const hosts = try std.fmt.bufPrintZ(&f2, "{s}/etc/hosts", .{rootfs});
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = motd, .data = "fx\n" });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = hosts, .data = "localhost\n" });
    // writeFile's default mode is umask-dependent (0o640 here) — the
    // activation records 0o644, so set it explicitly like emitBuildfile's
    // Chmod does.
    try Io.Dir.cwd().setFilePermissions(io, motd, Io.File.Permissions.fromMode(0o644), .{});
    try Io.Dir.cwd().setFilePermissions(io, hosts, Io.File.Permissions.fromMode(0o644), .{});

    try prov_verify(io, db, rootfs, store, .current, &e, &drifts);
    try testing.expectEqual(@as(usize, 0), drifts.items.len);

    // OLD snapshot: no install facts -> no drift, NO error (the R2 pin)
    try prov_verify(io, db, rootfs, store, .{ .as_of = 1 }, &e, &drifts);
    try testing.expectEqual(@as(usize, 0), drifts.items.len);

    // tamper: missing /etc/hosts, wrong mode on /etc/motd, repointed
    // /bin/world, and two unmanaged strays
    Io.Dir.cwd().deleteFile(io, hosts) catch {};
    Io.Dir.cwd().setFilePermissions(io, motd, Io.File.Permissions.fromMode(0o777), .{}) catch {};
    Io.Dir.cwd().deleteFile(io, link_world) catch {};
    try Io.Dir.cwd().symLink(io, "/nowhere", link_world, .{});
    var f3: [128:0]u8 = undefined;
    var f4: [128:0]u8 = undefined;
    const rogue = try std.fmt.bufPrintZ(&f3, "{s}/bin/rogue", .{rootfs});
    const stray = try std.fmt.bufPrintZ(&f4, "{s}/etc/stray", .{rootfs});
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = rogue, .data = "x" });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = stray, .data = "y" });

    try prov_verify(io, db, rootfs, store, .current, &e, &drifts);
    try testing.expectEqual(@as(usize, 5), drifts.items.len);

    var seen_missing: usize = 0;
    var seen_mode: usize = 0;
    var seen_link: usize = 0;
    var seen_unmanaged: usize = 0;
    for (drifts.items) |dr| {
        switch (dr.kind) {
            .missing => {
                seen_missing += 1;
                try testing.expectEqualStrings("/etc/hosts", dr.target);
                try testing.expect(std.mem.indexOf(u8, dr.detail, "does not exist") != null);
            },
            .mode => {
                seen_mode += 1;
                try testing.expectEqualStrings("/etc/motd", dr.target);
                try testing.expectEqualStrings("mode 0o777 != recorded 0o644", dr.detail);
            },
            .link_target => {
                seen_link += 1;
                try testing.expectEqualStrings("/bin/world", dr.target);
                try testing.expect(std.mem.indexOf(u8, dr.detail, "'/nowhere'") != null);
            },
            .unmanaged => {
                seen_unmanaged += 1;
                try testing.expect(std.mem.eql(u8, dr.target, "/bin/rogue") or
                    std.mem.eql(u8, dr.target, "/etc/stray"));
            },
            .hash => return error.UnexpectedHashDrift, // U5's extension
        }
    }
    try testing.expectEqual(@as(usize, 1), seen_missing);
    try testing.expectEqual(@as(usize, 1), seen_mode);
    try testing.expectEqual(@as(usize, 1), seen_link);
    try testing.expectEqual(@as(usize, 2), seen_unmanaged);

    // never-published version
    e = .{};
    try testing.expectError(error.FxProv, prov_verify(io, db, rootfs, store, .{ .as_of = 99 }, &e, &drifts));
    try testing.expectEqualStrings("no such version 99 (have 2 version(s))", e.slice());
}

test "prov_what/prov_why on a db with no published snapshot" {
    var dir_buf: [64:0]u8 = undefined;
    const dir = try temp_db_dir(&dir_buf);
    const db = cl.dl_open(dir.ptr) orelse return error.DlOpenFailed;
    defer {
        cl.dl_close(db);
        Io.Dir.cwd().deleteTree(tio(), dir) catch {};
    }
    var e = ProvErrBuf{};
    try testing.expectError(error.FxProv, prov_what(db, "/bin/hello", .current, &e));
    try testing.expectEqualStrings("no published snapshot in the store db — run a build first", e.slice());
    e = .{};
    try testing.expectError(error.FxProv, prov_why(db, "hello", .current, &e));
    try testing.expectEqualStrings("no published snapshot in the store db — run a build first", e.slice());
}
