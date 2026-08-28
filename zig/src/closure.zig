// closure.zig — faithful Zig port of closure.c (U3): the datalog closure
// fixpoint plus the C-side topo-sort.
//
// NAME-LEVEL transitive reachability is computed by the engine as the least
// fixed point of the 2-rule program (FX_CLOSURE_RULES below):
//
//     closure(X) :- root(X).
//     closure(Y) :- closure(X), dep(X,Y).
//
// The engine STAYS C (vendor/datalog-dafsa, linked as the fxengine static
// lib in build.zig) — this module only ports the wrapper logic, calling it
// through the dl_* externs below (the fx-init log.zig / activate.zig FFI
// pattern).  The content-addressed store-path hash is computed SEPARATELY in
// derivation.zig and must never be forced into Datalog.
//
// Per-run EDB contract (closure.c header): pkg(name) dep(from,to) root(name)
// are rebuilt from the current package set on every fx_closure_compute;
// stale facts (and previously materialized closure tuples) are enumerated
// and deleted first — the fixpoint engine is monotone, so without the clear
// a package removed from the set would linger in closure.  `closure` is an
// IDB relation auto-declared by the rules: NEVER pre-declare it or add_fact
// it (that breaks the engine's fixpoint treatment).
//
// Differences from C (mechanical only, never behavioral):
//   * malloc/realloc/free scratch (FactBag/NameBag growth, per-call tuples)
//     becomes a per-call ArenaAllocator + ArrayList over c_allocator; memory
//     that escapes (fx_closure_names / fx_topo_order results) is
//     c_allocator-owned with free_names / free_order mirroring the C's
//     "caller frees" contract.
//   * The defensive null/negative checks the C does on its out-params are
//     dropped where Zig's type system already makes them impossible (null
//     ps/out, negative counts).  The null-db checks stay: db is ?*DlDb and
//     the C rejects a null db with the same "internal: null ..." strings.
//   * An OOM inside the clear_relation callback aborts with an error; the C
//     callback only stops the enumeration, and its caller would then delete
//     a PARTIAL bag (a latent C bug not reproduced).
//
// TEST DISCIPLINE: dl_open holds a process-lifetime fcntl F_SETLK
// single-writer lock — every closure test below opens its OWN temp db dir
// and closes + deletes it before ending, and the tests run sequentially
// (the zig test runner is single-threaded).
const std = @import("std");
const pkgs = @import("packageset");

const Package = pkgs.Package;
const PackageSet = pkgs.PackageSet;

const Io = std.Io;
const c_alloc = std.heap.c_allocator;

pub const Error = error{FxClosure};

pub const err_cap_default = 2048;

/// The fx_err helper (fxstore.h) as a context struct: the C threads
/// `char *err, size_t errcap` through every entry point and signals failure
/// by return value; here every failure path calls ErrBuf.set (with the
/// verbatim closure.c format string) and returns error.FxClosure.
pub const ErrBuf = struct {
    buf: [err_cap_default]u8 = undefined,
    len: usize = 0,

    pub fn set(self: *ErrBuf, comptime fmt: []const u8, args: anytype) error{FxClosure} {
        var aw: std.Io.Writer.Allocating = .init(c_alloc);
        defer aw.deinit();
        aw.writer.print(fmt, args) catch unreachable;
        const s = aw.written();
        const n = @min(s.len, self.buf.len - 1);
        @memcpy(self.buf[0..n], s[0..n]);
        self.buf[n] = 0;
        self.len = n;
        return error.FxClosure;
    }

    pub fn slice(self: *const ErrBuf) []const u8 {
        return self.buf[0..self.len];
    }
};

// ─── engine C API (vendor/datalog-dafsa, dl.h — AUTHORITATIVE signatures) ──

pub const DlDb = opaque {};
pub const DlIter = opaque {};

/// dl.h dl_tuple_cb: return non-zero to stop enumeration early.
const dl_tuple_cb = *const fn (cols: [*]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int;

pub extern fn dl_open(dir: [*:0]const u8) ?*DlDb; // creates the dir
pub extern fn dl_close(db: ?*DlDb) void;
pub extern fn dl_declare_relation(db: *DlDb, name: [*:0]const u8, arity: u8) c_int;
pub extern fn dl_add_fact(db: *DlDb, rel: [*:0]const u8, cols: [*]const u32, arity: u8) c_int;
pub extern fn dl_delete_fact(db: *DlDb, rel: [*:0]const u8, cols: [*]const u32, arity: u8) c_int;
pub extern fn dl_count(db: *DlDb, rel: [*:0]const u8) u64; // maxInt(u64) = unknown rel
pub extern fn dl_load_rules(db: *DlDb, source: [*:0]const u8) c_int;
pub extern fn dl_compile(db: *DlDb) c_int;
pub extern fn dl_publish_snapshot(db: *DlDb) c_int;
pub extern fn dl_query(db: *DlDb, goal_rel: [*:0]const u8, cb: dl_tuple_cb, user: ?*anyopaque) c_long;
/// 1-based sym_id; 0 on OOM (the C's !sym check).
pub extern fn dl_intern_str(db: *DlDb, str: [*:0]const u8) u32;
pub extern fn dl_intern_str_of(db: *DlDb, sym_id: u32) ?[*:0]const u8;
pub extern fn dl_iter_open(db: *DlDb, rel: [*:0]const u8, leading: ?[*]const u32, k: u8) ?*DlIter;
pub extern fn dl_iter_arity(it: *const DlIter) u8;
pub extern fn dl_iter_next(it: *DlIter, cols_out: [*]u32) c_int;
pub extern fn dl_iter_close(it: ?*DlIter) void;

// ─── constants (fxstore.h:177-205) ─────────────────────────────────────────

/// The datalog DB directory inside a store: <root>/.db (FX_DB_SUBDIR).
pub const FX_DB_SUBDIR = ".db";

/// The closure program: the least fixed point of
///   closure(X) :- root(X).  closure(Y) :- closure(X), dep(X,Y).
/// (`closure` is auto-declared as IDB by these rules when loaded.)
pub const FX_CLOSURE_RULES = "closure(X):-root(X).\nclosure(Y):-closure(X),dep(X,Y).\n";

// ─── interning helper ──────────────────────────────────────────────────────

/// dl_intern_str for a Zig string slice (NUL-terminated into scratch `a`);
/// null on OOM — both the dupeZ failure and the C's 0 return.
fn intern(db: *DlDb, a: std.mem.Allocator, s: []const u8) ?u32 {
    const z = a.dupeZ(u8, s) catch return null;
    const sym = dl_intern_str(db, z.ptr);
    return if (sym == 0) null else sym;
}

// ─── Stale-fact clearing (closure.c:41-81) ─────────────────────────────────

const FactBag = struct {
    tuples: std.ArrayList(u32) = .empty, // arity * count values
    n: usize = 0, // tuple count
    arity: u8 = 0, // fixed-arity relation: constant
    oom: bool = false,
};

fn bag_cb(cols: [*]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    const bag: *FactBag = @ptrCast(@alignCast(user.?));
    bag.arity = arity;
    bag.tuples.appendSlice(c_alloc, cols[0..arity]) catch {
        bag.oom = true;
        return 1; // OOM: stop enumeration
    };
    bag.n += 1;
    return 0;
}

/// Enumerate all facts of `rel` via dl_query and delete each durably.
/// Unknown relations (first run, closure not yet auto-declared) are a no-op:
/// dl_count returns UINT64_MAX for an unknown relation.
fn clear_relation(db: *DlDb, rel: [*:0]const u8, e: *ErrBuf) Error!void {
    if (dl_count(db, rel) == std.math.maxInt(u64)) return; // not declared yet

    var bag: FactBag = .{};
    defer bag.tuples.deinit(c_alloc);
    const n = dl_query(db, rel, bag_cb, &bag);
    if (n < 0 or bag.oom)
        return e.set("cannot enumerate '{s}' for clearing", .{std.mem.span(rel)});
    for (0..bag.n) |i| {
        const tuple = bag.tuples.items[i * bag.arity ..][0..bag.arity].ptr;
        if (dl_delete_fact(db, rel, tuple, bag.arity) < 0)
            return e.set("cannot delete stale fact from '{s}'", .{std.mem.span(rel)});
    }
}

// ─── fx_closure_rebuild — re-derive the fixpoint over given facts ──────────

/// Rebuild the closure fixpoint over the GIVEN fact tuples (already-interned
/// sym_ids): declares pkg/dep/root idempotently, clears stale
/// pkg/dep/root/closure facts, adds the given tuples, then loads + compiles
/// FX_CLOSURE_RULES and publishes a snapshot.  `pkg`/`root` are arity-1
/// (one sym each), `dep` is arity-2 PAIRS (len 2*ndep, dep[i*2]=from,
/// dep[i*2+1]=to).  CRITICAL: `closure` is an IDB relation auto-declared by
/// the rules — never pre-declared or add_fact'd here.
pub fn fx_closure_rebuild(
    db: ?*DlDb,
    pkg: []const u32,
    dep: []const u32,
    root: []const u32,
    e: *ErrBuf,
) Error!void {
    const d = db orelse return e.set("internal: null db", .{});

    // EDB declarations (idempotent).  closure is auto-declared by the rules.
    if (dl_declare_relation(d, "pkg", 1) != 0)
        return e.set("cannot declare relation 'pkg'", .{});
    if (dl_declare_relation(d, "dep", 2) != 0)
        return e.set("cannot declare relation 'dep'", .{});
    if (dl_declare_relation(d, "root", 1) != 0)
        return e.set("cannot declare relation 'root'", .{});

    // Rebuild the per-run EDB: clear stale facts (a previous run / a
    // previous version's EDB), including previously materialized closure.
    try clear_relation(d, "pkg", e);
    try clear_relation(d, "dep", e);
    try clear_relation(d, "root", e);
    try clear_relation(d, "closure", e);

    // Fresh EDB from the given tuples (already-interned sym_ids).
    for (pkg) |sym| {
        const one = [1]u32{sym};
        if (dl_add_fact(d, "pkg", &one, 1) < 0)
            return e.set("cannot add pkg fact", .{});
    }
    for (0..dep.len / 2) |i| {
        if (dl_add_fact(d, "dep", dep[i * 2 ..][0..2].ptr, 2) < 0)
            return e.set("cannot add dep fact", .{});
    }
    for (root) |sym| {
        const one = [1]u32{sym};
        if (dl_add_fact(d, "root", &one, 1) < 0)
            return e.set("cannot add root fact", .{});
    }

    // The closure program + compile (materializes closure in-place).
    if (dl_load_rules(d, FX_CLOSURE_RULES) != 0)
        return e.set("cannot load closure rules", .{});
    if (dl_compile(d) != 0)
        return e.set("cannot compile closure rules", .{});

    // Publish so query/gc read a stable mmap view of the fixpoint.
    if (dl_publish_snapshot(d) != 0)
        return e.set("cannot publish closure snapshot", .{});
}

// ─── fx_closure_compute (closure.c:135-201) ────────────────────────────────

/// Compute the closure fixpoint over the persisted DB: clear stale per-run
/// EDB, load fresh facts from the package set (interned syms), roots = the
/// requested names (every package when `roots` is empty; every root must
/// exist), load + compile the 2-rule program, publish a snapshot.
pub fn fx_closure_compute(
    db: ?*DlDb,
    pset: *const PackageSet,
    roots: []const []const u8,
    e: *ErrBuf,
) Error!void {
    const d = db orelse return e.set("internal: null db/package-set", .{});

    // First pass: sizes for the fact arrays (pkg arity1, dep arity2 pairs,
    // root arity1).
    var npkg: usize = 0;
    var ndep: usize = 0;
    var p = pset.head;
    while (p) |pkg| : (p = pkg.next) {
        npkg += 1;
        ndep += pkg.deps.len;
    }
    const nroot = if (roots.len > 0) roots.len else pset.count;

    var arena = std.heap.ArenaAllocator.init(c_alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const pkg = a.alloc(u32, npkg) catch return e.set("out of memory", .{});
    const dep = a.alloc(u32, ndep * 2) catch return e.set("out of memory", .{});
    const root = a.alloc(u32, nroot) catch return e.set("out of memory", .{});

    // Fill pkg + dep from the current package set (interned syms).
    var ip: usize = 0;
    var id: usize = 0;
    p = pset.head;
    while (p) |pkg_p| : (p = pkg_p.next) {
        const sym = intern(d, a, pkg_p.name) orelse
            return e.set("out of memory interning package name", .{});
        pkg[ip] = sym;
        ip += 1;
        for (pkg_p.deps) |dep_name| {
            const to = intern(d, a, dep_name) orelse
                return e.set("out of memory interning package name", .{});
            dep[id * 2] = sym;
            dep[id * 2 + 1] = to;
            id += 1;
        }
    }

    // Roots: the requested build targets, or every package when none.
    var ir: usize = 0;
    if (roots.len > 0) {
        for (roots) |r| {
            if (pset.find(r) == null)
                return e.set("unknown package '{s}' (not in the package set)", .{r});
            const sym = intern(d, a, r) orelse
                return e.set("out of memory interning package name", .{});
            root[ir] = sym;
            ir += 1;
        }
    } else {
        p = pset.head;
        while (p) |pkg_p| : (p = pkg_p.next) {
            const sym = intern(d, a, pkg_p.name) orelse
                return e.set("out of memory interning package name", .{});
            root[ir] = sym;
            ir += 1;
        }
    }

    return fx_closure_rebuild(d, pkg[0..ip], dep[0 .. id * 2], root[0..ir], e);
}

// ─── fx_closure_names (closure.c:203-242) ──────────────────────────────────

const NameBag = struct {
    db: *DlDb,
    names: std.ArrayList([]const u8) = .empty,
    oom: bool = false,
};

fn name_cb(cols: [*]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    _ = arity; // closure is arity 1
    const nb: *NameBag = @ptrCast(@alignCast(user.?));
    const s = dl_intern_str_of(nb.db, cols[0]) orelse {
        nb.oom = true;
        return 1;
    };
    const dup = c_alloc.dupe(u8, std.mem.span(s)) catch {
        nb.oom = true;
        return 1;
    };
    nb.names.append(c_alloc, dup) catch {
        c_alloc.free(dup);
        nb.oom = true;
        return 1;
    };
    return 0;
}

/// Collect the materialized closure names (dl_query on `closure`, resolving
/// sym_ids via the interner).  The strdup-equivalent: the result is
/// c_allocator-owned — free it with free_names (the C's "caller frees each
/// string and the array").
pub fn fx_closure_names(db: ?*DlDb, e: *ErrBuf) Error![][]const u8 {
    const d = db orelse return e.set("internal: null args", .{});
    var nb = NameBag{ .db = d };
    const n = dl_query(d, "closure", name_cb, &nb);
    if (n < 0 or nb.oom) {
        free_names(nb.names.items);
        nb.names.deinit(c_alloc);
        return e.set("closure query failed{s}", .{if (nb.oom) " (out of memory)" else ""});
    }
    const out = nb.names.toOwnedSlice(c_alloc) catch {
        free_names(nb.names.items);
        nb.names.deinit(c_alloc);
        return e.set("out of memory", .{});
    };
    return out;
}

/// Caller-frees contract of fx_closure_names: each string + the array.
pub fn free_names(names: [][]const u8) void {
    for (names) |s| c_alloc.free(s);
    c_alloc.free(names);
}

// ─── fx_topo_order — deps-first order + cycle rejection (dhake pattern) ────

/// state flags: 0 unvisited, 1 visiting, 2 done (closure.c TNode).
const TNode = struct {
    p: *Package,
    state: u8,
};

fn tnode_of(nodes: []TNode, p: *const Package) ?*TNode {
    for (nodes) |*nd| {
        if (nd.p == p) return nd;
    }
    return null;
}

const Frame = struct {
    t: *TNode,
    i: usize,
};

/// Topo-sort `names` (a subset of the package set, typically the closure) so
/// every package follows its deps; reject cycles ("no finite store path")
/// and deps outside the given name set.  Returns a c_allocator-owned array
/// of *Package (deps-first, post-order); free the array only, with
/// free_order.  Duplicate names in the input are harmless: dedup by state.
pub fn fx_topo_order(
    pset: *const PackageSet,
    names: []const []const u8,
    e: *ErrBuf,
) Error![]*Package {
    const n = names.len;
    if (n == 0) return &[_]*Package{};

    const nodes = c_alloc.alloc(TNode, n) catch return e.set("out of memory", .{});
    defer c_alloc.free(nodes);
    const order = c_alloc.alloc(*Package, n) catch return e.set("out of memory", .{});
    errdefer c_alloc.free(order);

    for (names, 0..) |name, i| {
        const p = pset.find(name) orelse
            return e.set("closure contains '{s}' which is not in the package set", .{name});
        nodes[i] = .{ .p = p, .state = 0 };
    }

    const stk = c_alloc.alloc(Frame, n) catch return e.set("out of memory", .{});
    defer c_alloc.free(stk);

    var nn: usize = 0;
    for (0..n) |r| {
        if (nodes[r].state != 0) continue;
        var top: usize = 0;
        stk[top] = .{ .t = &nodes[r], .i = 0 };
        top += 1;
        nodes[r].state = 1;
        while (top > 0) {
            const f = &stk[top - 1];
            const cur = f.t.p;
            if (f.i < cur.deps.len) {
                const dep_name = cur.deps[f.i];
                f.i += 1;
                const dp = pset.find(dep_name);
                const dn = if (dp) |d| tnode_of(nodes, d) else null;
                const dn_node = dn orelse
                    return e.set(
                        "package '{s}' depends on '{s}' which is not in the closure " ++
                            "(incomplete closure — engine bug or stale EDB)",
                        .{ cur.name, dep_name },
                    );
                if (dn_node.state == 1)
                    return e.set(
                        "dependency cycle detected involving '{s}' " ++
                            "(cyclic deps have no finite store path)",
                        .{dn_node.p.name},
                    );
                if (dn_node.state == 0) {
                    dn_node.state = 1;
                    stk[top] = .{ .t = dn_node, .i = 0 };
                    top += 1;
                }
            } else {
                f.t.state = 2;
                order[nn] = f.t.p; // deps-first (post-order)
                nn += 1;
                top -= 1;
            }
        }
    }

    // Each package is emitted exactly once (the visiting/done state
    // machine), so nn <= n.  A duplicated name in `names` is harmless: it
    // only adds an extra DFS root over already-done nodes.
    return order[0..nn];
}

/// Caller-frees contract of fx_topo_order: the array only (the Package*
/// point into the package set).
pub fn free_order(order: []*Package) void {
    c_alloc.free(order);
}

// ─── unit tests (live dbs on per-test temp dirs, run sequentially) ─────────

const testing = std.testing;

/// std.testing.io is runtime-valued (it borrows the runner's Io.Threaded),
/// so it must be fetched inside a function scope.
fn tio() Io {
    return std.testing.io;
}

/// A unique temp db dir per test: dl_open holds a process-lifetime fcntl
/// F_SETLK single-writer lock, so each test owns its OWN dir and closes +
/// deletes it before ending (never two dbs live at once).
fn temp_db_dir(buf: *[64:0]u8) ![:0]u8 {
    var seed: [4]u8 = undefined;
    tio().random(&seed);
    return std.fmt.bufPrintZ(buf, "/tmp/fx-u3-db-{x:0>8}", .{std.mem.readInt(u32, &seed, .little)});
}

fn load_good(e: *pkgs.ErrBuf) pkgs.LoadError!PackageSet {
    var pset: PackageSet = undefined;
    try pkgs.fx_packageset_load(&pset, "zig/corpus/packageset/good.dhall", e);
    return pset;
}

fn name_lt(_: void, x: []const u8, y: []const u8) bool {
    return std.mem.order(u8, x, y) == .lt;
}

/// The engine enumerates closure in sym-id order, so compare AS A SET.
fn expect_same_names(want: []const []const u8, got: []const []const u8) !void {
    try testing.expectEqual(want.len, got.len);
    const sorted = try testing.allocator.dupe([]const u8, got);
    defer testing.allocator.free(sorted);
    std.mem.sort([]const u8, sorted, {}, name_lt);
    for (want, sorted) |w, g| try testing.expectEqualStrings(w, g);
}

test "fx_closure_compute roots={} -> whole set is the closure (U1 corpus)" {
    var pe = pkgs.ErrBuf{};
    var pset = try load_good(&pe); // hello (no deps), world (deps [hello])
    defer pset.deinit();

    var dir_buf: [64:0]u8 = undefined;
    const dir = try temp_db_dir(&dir_buf);
    const db = dl_open(dir.ptr) orelse return error.DlOpenFailed;
    defer {
        dl_close(db);
        Io.Dir.cwd().deleteTree(tio(), dir) catch {};
    }

    var e = ErrBuf{};
    try fx_closure_compute(db, &pset, &.{}, &e);
    const names = try fx_closure_names(db, &e);
    defer free_names(names);
    try expect_same_names(&.{ "hello", "world" }, names);
}

test "fx_closure_compute roots={world|hello} -> transitive deps; unknown root rejected" {
    var pe = pkgs.ErrBuf{};
    var pset = try load_good(&pe);
    defer pset.deinit();

    var dir_buf: [64:0]u8 = undefined;
    const dir = try temp_db_dir(&dir_buf);
    const db = dl_open(dir.ptr) orelse return error.DlOpenFailed;
    defer {
        dl_close(db);
        Io.Dir.cwd().deleteTree(tio(), dir) catch {};
    }

    var e = ErrBuf{};

    // world depends on hello: the closure of {world} is {hello, world}
    try fx_closure_compute(db, &pset, &.{"world"}, &e);
    const names = try fx_closure_names(db, &e);
    defer free_names(names);
    try expect_same_names(&.{ "hello", "world" }, names);

    // hello has no deps: the closure of {hello} is {hello} alone
    try fx_closure_compute(db, &pset, &.{"hello"}, &e);
    const names2 = try fx_closure_names(db, &e);
    defer free_names(names2);
    try expect_same_names(&.{"hello"}, names2);

    // and the topo order over that closure is the build order
    const order = try fx_topo_order(&pset, names2, &e);
    defer free_order(order);
    try testing.expectEqual(@as(usize, 1), order.len);
    try testing.expectEqualStrings("hello", order[0].name);

    // every root must exist in the package set
    try testing.expectError(error.FxClosure, fx_closure_compute(db, &pset, &.{"ghost"}, &e));
    try testing.expectEqualStrings("unknown package 'ghost' (not in the package set)", e.slice());
}

test "fx_closure_rebuild hand-built tuples on a fresh db" {
    var dir_buf: [64:0]u8 = undefined;
    const dir = try temp_db_dir(&dir_buf);
    const db = dl_open(dir.ptr) orelse return error.DlOpenFailed;
    defer {
        dl_close(db);
        Io.Dir.cwd().deleteTree(tio(), dir) catch {};
    }

    const sa = dl_intern_str(db, "a");
    const sb = dl_intern_str(db, "b");
    const sc = dl_intern_str(db, "c");
    try testing.expect(sa != 0 and sb != 0 and sc != 0);

    var e = ErrBuf{};
    // pkg={a,b,c} dep={(a,b)} root={a} -> closure={a,b}
    try fx_closure_rebuild(db, &.{ sa, sb, sc }, &.{ sa, sb }, &.{sa}, &e);
    const names = try fx_closure_names(db, &e);
    defer free_names(names);
    try expect_same_names(&.{ "a", "b" }, names);

    // the engine is monotone: rebuilding with root={c} and no deps must
    // CLEAR the stale a,b tuples (clear_relation) or they would linger
    try fx_closure_rebuild(db, &.{ sa, sb, sc }, &.{}, &.{sc}, &e);
    const names2 = try fx_closure_names(db, &e);
    defer free_names(names2);
    try expect_same_names(&.{"c"}, names2);
}

test "compute then rebuild: stale closure from the previous run is cleared" {
    var pe = pkgs.ErrBuf{};
    var pset = try load_good(&pe);
    defer pset.deinit();

    var dir_buf: [64:0]u8 = undefined;
    const dir = try temp_db_dir(&dir_buf);
    const db = dl_open(dir.ptr) orelse return error.DlOpenFailed;
    defer {
        dl_close(db);
        Io.Dir.cwd().deleteTree(tio(), dir) catch {};
    }

    var e = ErrBuf{};
    try fx_closure_compute(db, &pset, &.{}, &e); // closure = {hello, world}
    const shello = dl_intern_str(db, "hello");
    try testing.expect(shello != 0);

    // shrink to just hello: a removed package must not linger in closure
    try fx_closure_rebuild(db, &.{shello}, &.{}, &.{shello}, &e);
    const names = try fx_closure_names(db, &e);
    defer free_names(names);
    try expect_same_names(&.{"hello"}, names);
}

// ─── fx_topo_order fixtures (hand-built package sets, no db needed) ────────

fn test_pkg(name: []const u8, deps: []const []const u8) Package {
    return .{ .name = name, .version = "1", .target = name, .deps = deps };
}

fn link(pset: *PackageSet, table: []Package) void {
    for (table[0 .. table.len - 1], 0..) |*p, i| p.next = &table[i + 1];
    pset.head = &table[0];
    pset.count = table.len;
}

test "fx_topo_order: chain and diamond are deps-first" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();

    var e = ErrBuf{};

    // chain a -> b -> c
    var chain = [_]Package{
        test_pkg("a", &.{"b"}),
        test_pkg("b", &.{"c"}),
        test_pkg("c", &.{}),
    };
    var chain_set: PackageSet = .{ .arena = arena_inst };
    link(&chain_set, &chain);

    const order = try fx_topo_order(&chain_set, &.{ "a", "b", "c" }, &e);
    defer free_order(order);
    try testing.expectEqual(@as(usize, 3), order.len);
    try testing.expectEqualStrings("c", order[0].name); // deps-first
    try testing.expectEqualStrings("b", order[1].name);
    try testing.expectEqualStrings("a", order[2].name);

    // diamond d -> {b,c} -> a
    var diamond = [_]Package{
        test_pkg("a", &.{}),
        test_pkg("b", &.{"a"}),
        test_pkg("c", &.{"a"}),
        test_pkg("d", &.{ "b", "c" }),
    };
    var diamond_set: PackageSet = .{ .arena = arena_inst };
    link(&diamond_set, &diamond);

    const order2 = try fx_topo_order(&diamond_set, &.{ "a", "b", "c", "d" }, &e);
    defer free_order(order2);
    try testing.expectEqual(@as(usize, 4), order2.len);
    try testing.expectEqualStrings("a", order2[0].name);
    try testing.expectEqualStrings("d", order2[3].name);
}

test "fx_topo_order: cycles, deps outside closure, unknown names, dups" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var e = ErrBuf{};

    // self-dep
    var solo = [_]Package{test_pkg("x", &.{"x"})};
    var solo_set: PackageSet = .{ .arena = arena_inst };
    link(&solo_set, &solo);
    try testing.expectError(error.FxClosure, fx_topo_order(&solo_set, &.{"x"}, &e));
    try testing.expectEqualStrings(
        "dependency cycle detected involving 'x' (cyclic deps have no finite store path)",
        e.slice(),
    );

    // a -> b -> a
    var loop = [_]Package{
        test_pkg("a", &.{"b"}),
        test_pkg("b", &.{"a"}),
    };
    var loop_set: PackageSet = .{ .arena = arena_inst };
    link(&loop_set, &loop);
    e = .{};
    try testing.expectError(error.FxClosure, fx_topo_order(&loop_set, &.{ "a", "b" }, &e));
    try testing.expectEqualStrings(
        "dependency cycle detected involving 'a' (cyclic deps have no finite store path)",
        e.slice(),
    );

    // dep outside the closure name set (b exists in the set but not in names)
    var chain = [_]Package{
        test_pkg("a", &.{"b"}),
        test_pkg("b", &.{}),
    };
    var chain_set: PackageSet = .{ .arena = arena_inst };
    link(&chain_set, &chain);
    e = .{};
    try testing.expectError(error.FxClosure, fx_topo_order(&chain_set, &.{"a"}, &e));
    try testing.expectEqualStrings(
        "package 'a' depends on 'b' which is not in the closure (incomplete closure — engine bug or stale EDB)",
        e.slice(),
    );

    // a closure name that is not in the package set at all
    e = .{};
    try testing.expectError(error.FxClosure, fx_topo_order(&chain_set, &.{"ghost"}, &e));
    try testing.expectEqualStrings(
        "closure contains 'ghost' which is not in the package set",
        e.slice(),
    );

    // empty name list -> empty order
    const none = try fx_topo_order(&chain_set, &.{}, &e);
    try testing.expectEqual(@as(usize, 0), none.len);

    // duplicate names: the C keeps per-INDEX TNodes (state is per node, and
    // tnode_of returns the FIRST match), so a duplicated name adds an extra
    // DFS root and is emitted once per occurrence — nn <= n, never a crash.
    // (The real pipeline can't produce dups: closure is a set.)
    e = .{};
    const dup = try fx_topo_order(&chain_set, &.{ "b", "b", "a", "a" }, &e);
    defer free_order(dup);
    try testing.expectEqual(@as(usize, 4), dup.len);
    try testing.expectEqualStrings("b", dup[0].name);
    try testing.expectEqualStrings("b", dup[1].name);
    try testing.expectEqualStrings("a", dup[2].name);
    try testing.expectEqualStrings("a", dup[3].name);
}
