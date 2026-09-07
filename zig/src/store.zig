// store.zig — faithful Zig port of store.c (U4): the content store layout,
// atomic install with METADATA-LAST commit, pinned-snapshot GC, and the
// timeline/rollback over datalog-dafsa's snapshot time-travel.
//
// CRASH-CONSISTENCY INVARIANT (store.c header, preserved exactly):
//   build = recipe into <root>.build/<hash>-<name>-<pid> (scratch OUTSIDE
//   the store, same fs by the st_dev check at open) -> atomic rename() into
//   <root>/<hash>-<name> -> ONLY THEN the metadata txn (one WAL append +
//   one fsync is THE atomic commit point).  A crash before the commit
//   leaves a reapable orphan dir, never dangling metadata; a crash between
//   the rename and the commit is repaired by the next build of the same
//   derivation (adoption — content addressing makes the rebuild identical).
//   GC deletes METADATA FIRST (one atomic txn per unreachable fact), THEN
//   the dirs, reading from a PINNED snapshot so a concurrent build that
//   publishes newer versions can never race the sweep.
//
// The engine STAYS C (the dl_* externs; dl_open/close/declare/intern/query
// are closure.zig's block, the txn + snapshot-time-travel surface below is
// store.c-specific).  C source order and every fx_err string are preserved;
// the printf lines are matched byte-identically by the tests (the C test
// suite greps them).
//
// Differences from C (mechanical only, never behavioral):
//   * `io: std.Io` threaded through the fs-touching entry points (the C
//     calls libc directly); tests pass std.testing.io.
//   * malloc/realloc/free scratch (PairBag/RawBag/live-set) becomes one
//     arena per call over c_allocator; an OOM inside a bag callback aborts
//     loudly instead of leaving a partial bag.
//   * printf/fprintf lines route through g_out_fd / g_err_fd (default 1/2,
//     the U5 build.zig pattern) so tests can capture them without
//     desyncing the zig test runner's fd-1 protocol pipe.
//   * The C's null-pointer checks stay where a Zig optional can actually
//     be null (the store handle, the package); impossible null checks on
//     slices are dropped.
const std = @import("std");
const cl = @import("closure");
const drv = @import("derivation");
const bld = @import("build");
const pkgs = @import("packageset");

const Package = pkgs.Package;
const DlDb = cl.DlDb;

const Io = std.Io;
const c_alloc = std.heap.c_allocator;

pub const Error = error{FxStore};

pub const err_cap_default = 2048;

/// The fx_err helper (fxstore.h) as a context struct: the C threads
/// `char *err, size_t errcap` through every entry point and signals failure
/// by return value; here every failure path calls ErrBuf.set (with the
/// verbatim store.c format string) and returns error.FxStore.
pub const ErrBuf = struct {
    buf: [err_cap_default]u8 = undefined,
    len: usize = 0,

    pub fn set(self: *ErrBuf, comptime fmt: []const u8, args: anytype) error{FxStore} {
        var aw: Io.Writer.Allocating = .init(c_alloc);
        defer aw.deinit();
        aw.writer.print(fmt, args) catch unreachable;
        const s = aw.written();
        const n = @min(s.len, self.buf.len - 1);
        @memcpy(self.buf[0..n], s[0..n]);
        self.buf[n] = 0;
        self.len = n;
        return error.FxStore;
    }

    pub fn slice(self: *const ErrBuf) []const u8 {
        return self.buf[0..self.len];
    }
};

// ─── engine C API (dl.h — AUTHORITATIVE signatures) ────────────────────────

/// dl.h dl_tuple_cb: return non-zero to stop enumeration early.
const dl_tuple_cb = *const fn (cols: [*]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int;
const dl_relation_cb = *const fn (name: [*:0]const u8, arity: u8, idb: c_int, user: ?*anyopaque) callconv(.c) c_int;

pub extern fn dl_lookup(db: *DlDb, rel: [*:0]const u8, cols: [*]const u32, arity: u8) c_int;
pub extern fn dl_txn_begin(db: *DlDb) c_int;
pub extern fn dl_txn_add_fact(db: *DlDb, rel: [*:0]const u8, cols: [*]const u32, arity: u8) c_int;
pub extern fn dl_txn_delete_fact(db: *DlDb, rel: [*:0]const u8, cols: [*]const u32, arity: u8) c_int;
pub extern fn dl_txn_commit(db: *DlDb) c_int;
pub extern fn dl_txn_rollback(db: *DlDb) c_int;
pub extern fn dl_snapshot_versions(db: *const DlDb, out: ?[*]u32, cap: usize) c_long;
pub extern fn dl_query_version(db: *DlDb, version: u32, goal_rel: [*:0]const u8, cb: dl_tuple_cb, user: ?*anyopaque) c_long;
/// The one LIVE-state reader (dl.h CAVEAT: dl_query/dl_iter prefer the
/// published snapshot; dl_prefix always reads the WAL-replayed relation).
pub extern fn dl_prefix(db: *const DlDb, rel: [*:0]const u8, leading: ?[*]const u32, k: u8, cb: dl_tuple_cb, user: ?*anyopaque) c_long;
pub extern fn dl_snapshot_relations(db: *DlDb, version: u32, cb: dl_relation_cb, user: ?*anyopaque) c_long;
pub extern fn dl_set_snapshot_retain(db: *DlDb, n: c_uint) c_int;

// ─── constants + libc surface (fxstore.h:182-197; the build.zig externs) ───

pub const FX_PATH_MAX = 4096;
/// The datalog DB directory inside a store (closure.zig's constant).
pub const FX_DB_SUBDIR = cl.FX_DB_SUBDIR; // ".db"
/// Build scratch area: a SIBLING directory of the store root, never inside.
pub const FX_BUILD_SUFFIX = ".build";
/// Legacy scratch area of pre-sibling stores; still swept by gc.
pub const FX_TMP_SUBDIR = ".tmp";

const O_RDONLY: c_int = 0o0;
const O_WRONLY: c_int = 0o1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;
const EEXIST: c_int = 17;
const ENOTEMPTY: c_int = 39;
const ESRCH: c_int = 3;

/// glibc x86_64/aarch64 `struct stat` — only st_dev is consumed (open).
const CStat = extern struct {
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

extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn write(fd: c_int, buf: [*]const u8, nbyte: usize) isize;
extern "c" fn fsync(fd: c_int) c_int;
extern "c" fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern "c" fn rename(oldp: [*:0]const u8, newp: [*:0]const u8) c_int;
extern "c" fn unlink(path: [*:0]const u8) c_int;
extern "c" fn rmdir(path: [*:0]const u8) c_int;
extern "c" fn chmod(path: [*:0]const u8, mode: c_uint) c_int;
extern "c" fn kill(pid: c_int, sig: c_int) c_int;
extern "c" fn getpid() c_int;
extern "c" fn strerror(errnum: c_int) [*:0]const u8;
extern "c" fn stat(path: [*:0]const u8, st: *CStat) c_int;

fn errno() c_int {
    return std.c._errno().*;
}

fn errstr_e(errnum: c_int) []const u8 {
    return std.mem.span(strerror(errnum));
}

// ─── printf plumbing (the build.zig g_out_fd pattern) ──────────────────────

/// The zig test runner uses fd 1 as its --listen protocol pipe: tests
/// repoint this to a capture file; production leaves the defaults.
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

// ─── Small filesystem helpers (store.c:58-101) ─────────────────────────────

fn is_dir(io: Io, path: []const u8) bool {
    const st = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = true }) catch return false;
    return st.kind == .directory;
}

/// Recursive delete; does NOT follow symlinks: lstat each entry and recurse
/// only into real directories, so a symlink child (even one pointing at a
/// directory outside the store) is unlinked, never traversed.
fn rm_rf(io: Io, path: []const u8) void {
    const root = Io.Dir.cwd();
    const st = root.statFile(io, path, .{ .follow_symlinks = false }) catch return; // gone
    var zp: [4 * FX_PATH_MAX:0]u8 = undefined;
    if (st.kind == .directory) {
        // clean-copy artifacts mirror SOURCE modes, so they may contain
        // non-writable dirs; make this dir owner-writable (best-effort) so
        // the removals below can succeed.
        if (std.fmt.bufPrintZ(&zp, "{s}", .{path})) |z| {
            _ = chmod(z.ptr, 0o700);
        } else |_| {}
        if (root.openDir(io, path, .{ .iterate = true })) |d| {
            defer d.close(io);
            var it = d.iterate();
            while (it.next(io) catch null) |entry| {
                if (std.mem.eql(u8, entry.name, ".") or std.mem.eql(u8, entry.name, "..")) continue;
                var cb: [4 * FX_PATH_MAX]u8 = undefined;
                const child = std.fmt.bufPrint(&cb, "{s}/{s}", .{ path, entry.name }) catch continue;
                rm_rf(io, child);
            }
        } else |_| {}
    }
    const z = std.fmt.bufPrintZ(&zp, "{s}", .{path}) catch return;
    // remove(path): rmdir for real dirs, unlink for files/links
    if (st.kind == .directory) {
        _ = rmdir(z.ptr);
    } else {
        _ = unlink(z.ptr);
    }
}

/// Best-effort fsync of a directory (durability of a rename before the
/// metadata commit).  Failures are non-fatal: the metadata txn remains the
/// atomic commit point.
fn fsync_dir_best_effort(path: []const u8) void {
    var zb: [4 * FX_PATH_MAX:0]u8 = undefined;
    const z = std.fmt.bufPrintZ(&zb, "{s}", .{path}) catch return;
    const fd = open(z.ptr, O_RDONLY, 0);
    if (fd < 0) return;
    _ = fsync(fd);
    _ = close(fd);
}

// ─── Open / close (store.c:105-212) ────────────────────────────────────────

pub const Store = struct {
    root_buf: [FX_PATH_MAX]u8 = undefined,
    root_len: usize = 0,
    build_buf: [FX_PATH_MAX:0]u8 = undefined,
    build_len: usize = 0,
    db: *DlDb,

    /// The store root, no trailing '/'.
    pub fn root(self: *const Store) []const u8 {
        return self.root_buf[0..self.root_len];
    }

    /// The <root>.build scratch sibling, no trailing '/'.
    pub fn build(self: *const Store) []const u8 {
        return self.build_buf[0..self.build_len];
    }
};

/// Open (create if needed) a store at `root`: root/, the build scratch dir
/// <root>.build/ (a sibling on the SAME filesystem — the atomic install
/// rename(2)s between them and cannot cross filesystems), and the metadata
/// DB at root/.db (dl_open).
pub fn fx_store_open(io: Io, root: []const u8, e: *ErrBuf) Error!*Store {
    if (root.len == 0)
        return e.set("store root must be non-empty", .{});

    const s = c_alloc.create(Store) catch return e.set("out of memory", .{});
    errdefer c_alloc.destroy(s);

    // normalize: strip trailing slashes (but keep a bare "/")
    var n = root.len;
    while (n > 1 and root[n - 1] == '/') n -= 1;
    if (n >= FX_PATH_MAX)
        return e.set("store root too long", .{});
    @memcpy(s.root_buf[0..n], root[0..n]);
    s.root_len = n;
    const rt = s.root();

    var zr: [FX_PATH_MAX:0]u8 = undefined;
    const rz = std.fmt.bufPrintZ(&zr, "{s}", .{rt}) catch
        return e.set("store root too long", .{});

    if (mkdir(rz.ptr, 0o755) != 0) {
        const en = errno();
        if (en != EEXIST)
            return e.set("cannot create store root '{s}': {s}", .{ rt, errstr_e(en) });
    }
    if (!is_dir(io, rt))
        return e.set("store root '{s}' is not a directory", .{rt});

    var dbp_buf: [FX_PATH_MAX:0]u8 = undefined;
    const bz = std.fmt.bufPrintZ(&s.build_buf, "{s}{s}", .{ rt, FX_BUILD_SUFFIX }) catch
        return e.set("store path too long", .{});
    s.build_len = bz.len;
    const dbp = std.fmt.bufPrintZ(&dbp_buf, "{s}/{s}", .{ rt, FX_DB_SUBDIR }) catch
        return e.set("store path too long", .{});

    // Build scratch area: a SIBLING of the store root, never inside it —
    // run_sandboxed ro-binds the whole store, so a rw workdir nested under
    // it could not be mounted inside the bwrap sandbox.  It must sit on the
    // SAME filesystem as the store root (rename(2) is same-fs only); a root
    // that is itself a mount point puts the sibling on the parent fs — the
    // one layout this rejects, loudly at open instead of mid-build.
    if (mkdir(bz.ptr, 0o755) != 0) {
        const en = errno();
        if (en != EEXIST)
            return e.set("cannot create build dir '{s}': {s}", .{ s.build(), errstr_e(en) });
    }
    if (!is_dir(io, s.build()))
        return e.set("build dir '{s}' is not a directory", .{s.build()});

    var st_root: CStat = undefined;
    var st_build: CStat = undefined;
    if (stat(rz.ptr, &st_root) != 0 or stat(bz.ptr, &st_build) != 0) {
        const en = errno();
        return e.set("cannot stat store root / build dir: {s}", .{errstr_e(en)});
    }
    if (st_root.dev != st_build.dev)
        return e.set("build dir '{s}' is on a different filesystem than the store " ++
            "root '{s}': the atomic install rename(2)s between them and " ++
            "cannot cross filesystems; use a store root that is a plain " ++
            "directory on the target filesystem", .{ s.build(), rt });

    s.db = cl.dl_open(dbp.ptr) orelse
        return e.set("cannot open store metadata db '{s}'", .{dbp});

    // the durable store index (idempotent declare)
    if (cl.dl_declare_relation(s.db, "store", 2) != 0) {
        cl.dl_close(s.db);
        return e.set("cannot declare relation 'store'", .{});
    }
    // the clean-source artifact index (idempotent declare)
    if (cl.dl_declare_relation(s.db, "srcstore", 2) != 0) {
        cl.dl_close(s.db);
        return e.set("cannot declare relation 'srcstore'", .{});
    }
    return s;
}

/// NULL-safe; closes the DB and frees the handle.
pub fn fx_store_close(s: ?*Store) void {
    const st = s orelse return;
    cl.dl_close(st.db);
    c_alloc.destroy(st);
}

pub fn fx_store_db(s: ?*Store) ?*DlDb {
    return if (s) |st| st.db else null;
}

pub fn fx_store_root(s: ?*const Store) []const u8 {
    return if (s) |st| st.root() else "";
}

pub fn fx_store_publish(s: ?*Store, e: *ErrBuf) Error!void {
    const st = s orelse return e.set("internal: null store", .{});
    if (cl.dl_publish_snapshot(st.db) != 0)
        return e.set("cannot publish store metadata snapshot", .{});
}

// ─── Metadata commit (the LAST step of a build, store.c:218-255) ───────────

/// Commit `rel`(hash,name) as one atomic txn (one WAL append + one fsync).
/// Idempotent: an already-committed fact is a no-op.  commit_store_fact /
/// commit_srcstore_fact are this with the relation's exact error strings.
fn commit_pair_fact(
    s: *Store,
    rel: [*:0]const u8,
    hash: []const u8,
    name: []const u8,
    comptime oom_msg: []const u8,
    comptime fail_fmt: []const u8,
    e: *ErrBuf,
) Error!void {
    var arena = std.heap.ArenaAllocator.init(c_alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const cols = blk: {
        const hz = a.dupeZ(u8, hash) catch break :blk null;
        const c0 = cl.dl_intern_str(s.db, hz.ptr);
        const nz = a.dupeZ(u8, name) catch break :blk null;
        const c1 = cl.dl_intern_str(s.db, nz.ptr);
        if (c0 == 0 or c1 == 0) break :blk null;
        break :blk [2]u32{ c0, c1 };
    } orelse return e.set(oom_msg, .{});

    if (dl_lookup(s.db, rel, &cols, 2) != 0)
        return; // already committed

    if (dl_txn_begin(s.db) != 0)
        return e.set("txn begin failed (another txn open?)", .{});
    if (dl_txn_add_fact(s.db, rel, &cols, 2) != 0 or dl_txn_commit(s.db) != 0) {
        _ = dl_txn_rollback(s.db);
        return e.set(fail_fmt, .{ hash, name });
    }
}

fn commit_store_fact(s: *Store, hash: []const u8, name: []const u8, e: *ErrBuf) Error!void {
    return commit_pair_fact(
        s,
        "store",
        hash,
        name,
        "out of memory interning store fact",
        "metadata commit failed for '{s}-{s}' (dir is an orphan; gc will reap it)",
        e,
    );
}

fn commit_srcstore_fact(s: *Store, hash: []const u8, name: []const u8, e: *ErrBuf) Error!void {
    return commit_pair_fact(
        s,
        "srcstore",
        hash,
        name,
        "out of memory interning srcstore fact",
        "metadata commit failed for srcstore '{s}-{s}' (dir is an orphan; gc will reap it)",
        e,
    );
}

// ─── fx_store_build (store.c:259-312) ──────────────────────────────────────

/// Build ONE package into the store (deps already built; their store paths
/// are dep_paths, parallel to dep_names):
///   1. run the recipe into <root>.build/<hash>-<name>-<pid>
///   2. atomically rename() the temp dir to final_path
///   3. ONLY THEN commit the metadata txn: store(hash,name)
/// If final_path already exists the build is ADOPTED and only the missing
/// metadata fact is committed.
pub fn fx_store_build(
    io: Io,
    s: ?*Store,
    p: ?*const Package,
    hash: []const u8,
    final_path: []const u8,
    src_path: ?[]const u8,
    dep_names: []const []const u8,
    dep_paths: []const []const u8,
    e: *ErrBuf,
) Error!void {
    const st = s orelse return e.set("internal: null args to fx_store_build", .{});
    const pkg = p orelse return e.set("internal: null args to fx_store_build", .{});

    // idempotent adoption: a previous run (or a crashed run repaired by a
    // rerun) already installed this exact content — just ensure metadata
    if (is_dir(io, final_path))
        return commit_store_fact(st, hash, pkg.name, e);

    const base = if (std.mem.lastIndexOfScalar(u8, final_path, '/')) |i|
        final_path[i + 1 ..]
    else
        final_path;

    var zt: [FX_PATH_MAX:0]u8 = undefined;
    const tmp = std.fmt.bufPrintZ(&zt, "{s}/{s}-{d}", .{ st.build(), base, getpid() }) catch
        return e.set("temp build path too long", .{});

    if (is_dir(io, tmp)) rm_rf(io, tmp); // stale same-pid leftover
    if (mkdir(tmp.ptr, 0o755) != 0) {
        const en = errno();
        return e.set("cannot create temp dir '{s}': {s}", .{ tmp, errstr_e(en) });
    }

    var be = bld.ErrBuf{};
    const rc = bld.fx_build_recipe(pkg, tmp, dep_names, dep_paths, st.root(), src_path, &be) catch {
        defer rm_rf(io, tmp); // the C threads the SAME err buffer through
        return e.set("{s}", .{be.slice()});
    };
    if (rc != 0) {
        defer rm_rf(io, tmp);
        if (be.len == 0)
            return e.set("recipe action failed with exit code {d}", .{rc});
        return e.set("{s}", .{be.slice()});
    }

    // ATOMIC INSTALL: rename temp -> final.  EEXIST/ENOTEMPTY means a
    // concurrent build installed the same content — adopt theirs.
    var zf: [4 * FX_PATH_MAX:0]u8 = undefined;
    const fz = std.fmt.bufPrintZ(&zf, "{s}", .{final_path}) catch {
        rm_rf(io, tmp);
        return e.set("cannot install '{s}': {s}", .{ final_path, errstr_e(0) });
    };
    if (rename(tmp.ptr, fz.ptr) != 0) {
        const en = errno();
        if ((en == EEXIST or en == ENOTEMPTY) and is_dir(io, final_path)) {
            rm_rf(io, tmp);
            return commit_store_fact(st, hash, pkg.name, e);
        }
        defer rm_rf(io, tmp);
        return e.set("cannot install '{s}': {s}", .{ final_path, errstr_e(en) });
    }

    // durability of the rename before the metadata commit (best-effort)
    fsync_dir_best_effort(st.root());

    // METADATA LAST: the single atomic commit point.  A crash before this
    // leaves the installed dir as a reapable orphan — never the reverse.
    return commit_store_fact(st, hash, pkg.name, e);
}

// ─── fx_store_ensure_source (store.c:316-381) ──────────────────────────────

/// Materialize the CLEAN source tree of a SRC_PATH package into the store as
/// a content-addressed artifact "<root>/<src_hash>-<name>-src" and commit
/// the srcstore(src_hash,name) fact — the SAME build-tmp + atomic-rename +
/// metadata-LAST pattern as fx_store_build, FAILING LOUDLY (TOCTOU guard) if
/// the streamed copy's hash differs from src_hash.  Existing artifacts are
/// ADOPTED.  Returns the artifact path (a slice of src_path_out).
pub fn fx_store_ensure_source(
    io: Io,
    s: ?*Store,
    p: ?*const Package,
    src_hash: []const u8,
    src_path_out: []u8,
    e: *ErrBuf,
) Error![]const u8 {
    const st = s orelse return e.set("internal: null args to fx_store_ensure_source", .{});
    const pkg = p orelse return e.set("internal: null args to fx_store_ensure_source", .{});
    if (pkg.src.kind != .path)
        return e.set("internal: ensure_source on a non-Path source", .{});

    // content-addressed clean-source artifact, in the STORE
    const artifact = std.fmt.bufPrint(src_path_out, "{s}/{s}-{s}-src", .{ st.root(), src_hash, pkg.name }) catch
        return e.set("clean source path too long", .{});

    // idempotent adoption: the artifact already exists — ensure metadata
    if (is_dir(io, artifact)) {
        try commit_srcstore_fact(st, src_hash, pkg.name, e);
        return artifact;
    }

    // materialize into the SAME build scratch area as fx_store_build (a
    // sibling of the store on the same filesystem, so the rename is atomic)
    var zt: [FX_PATH_MAX:0]u8 = undefined;
    const tmp = std.fmt.bufPrintZ(&zt, "{s}/{s}-{s}-src-{d}", .{ st.build(), src_hash, pkg.name, getpid() }) catch
        return e.set("temp clean-source path too long", .{});

    if (is_dir(io, tmp)) rm_rf(io, tmp); // stale same-pid leftover
    if (mkdir(tmp.ptr, 0o755) != 0) {
        const en = errno();
        return e.set("cannot create temp src dir '{s}': {s}", .{ tmp, errstr_e(en) });
    }

    // copy + hash in ONE walk; the streamed hash MUST equal the precomputed
    // src_hash, else the source changed between compute_paths and build
    // (TOCTOU) — fail loudly rather than build from different bytes
    var actual: [65]u8 = undefined;
    var de = drv.ErrBuf{};
    const src_dir = pkg.src.path orelse "";
    drv.fx_clean_tree(io, src_dir, tmp, pkg.excludes, &actual, &de) catch {
        defer rm_rf(io, tmp);
        return e.set("{s}", .{de.slice()});
    };
    if (!std.mem.eql(u8, actual[0..64], src_hash)) {
        defer rm_rf(io, tmp);
        const want = src_hash[0..@min(src_hash.len, 16)];
        return e.set(
            "source '{s}' changed between path computation and build " ++
                "(expected clean hash {s}..., got {s}...); " ++
                "re-run fxstore build",
            .{ src_dir, want, actual[0..16] },
        );
    }

    // ATOMIC INSTALL: rename temp -> artifact.  EEXIST/ENOTEMPTY means a
    // concurrent build materialized the same content — adopt theirs.
    var zf: [4 * FX_PATH_MAX:0]u8 = undefined;
    const fz = std.fmt.bufPrintZ(&zf, "{s}", .{artifact}) catch {
        rm_rf(io, tmp);
        return e.set("cannot install clean source '{s}': {s}", .{ artifact, errstr_e(0) });
    };
    if (rename(tmp.ptr, fz.ptr) != 0) {
        const en = errno();
        if ((en == EEXIST or en == ENOTEMPTY) and is_dir(io, artifact)) {
            rm_rf(io, tmp);
            try commit_srcstore_fact(st, src_hash, pkg.name, e);
            return artifact;
        }
        defer rm_rf(io, tmp);
        return e.set("cannot install clean source '{s}': {s}", .{ artifact, errstr_e(en) });
    }

    // durability of the rename before the metadata commit (best-effort)
    fsync_dir_best_effort(st.root());

    // METADATA LAST: the single atomic commit point, mirroring fx_store_build
    try commit_srcstore_fact(st, src_hash, pkg.name, e);
    return artifact;
}

// ─── GC (store.c:386-656) ──────────────────────────────────────────────────

/// Pinned-snapshot fact bag (strings resolved via the interner); the whole
/// bag lives in the fx_store_gc call's arena.
const PairBag = struct {
    db: *DlDb,
    alloc: std.mem.Allocator,
    a: std.ArrayList([]const u8) = .empty, // dep: from / store: hash
    b: std.ArrayList([]const u8) = .empty, // dep: to / store: name
    oom: bool = false,
};

fn pair_cb(cols: [*]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    const pb: *PairBag = @ptrCast(@alignCast(user.?));
    // arity-1 relations (pkg) have NO second column — never read cols[1]
    // (an out-of-bounds read yields a garbage sym id and a false failure)
    const x = cl.dl_intern_str_of(pb.db, cols[0]) orelse {
        pb.oom = true;
        return 1;
    };
    const y: []const u8 = if (arity >= 2) blk: {
        const ys = cl.dl_intern_str_of(pb.db, cols[1]) orelse {
            pb.oom = true;
            return 1;
        };
        break :blk std.mem.span(ys);
    } else "";
    const xd = pb.alloc.dupe(u8, std.mem.span(x)) catch {
        pb.oom = true;
        return 1;
    };
    const yd = pb.alloc.dupe(u8, y) catch {
        pb.alloc.free(xd);
        pb.oom = true;
        return 1;
    };
    pb.a.append(pb.alloc, xd) catch {
        pb.alloc.free(xd);
        pb.alloc.free(yd);
        pb.oom = true;
        return 1;
    };
    pb.b.append(pb.alloc, yd) catch {
        pb.alloc.free(xd);
        pb.alloc.free(yd);
        pb.oom = true;
        return 1;
    };
    return 0;
}

/// String-set membership (small MVP sizes: linear scan is fine).
fn in_set(set: []const []const u8, s: []const u8) bool {
    for (set) |x| {
        if (std.mem.eql(u8, x, s)) return true;
    }
    return false;
}

/// Name-level reachability fixpoint over pinned dep edges (worklist BFS).
/// The set is arena-owned.
fn reachable_names(
    a: std.mem.Allocator,
    deps: *const PairBag,
    root: []const u8,
    e: *ErrBuf,
) Error![][]const u8 {
    var set: std.ArrayList([]const u8) = .empty;
    const r0 = a.dupe(u8, root) catch return e.set("out of memory computing reachability", .{});
    set.append(a, r0) catch return e.set("out of memory computing reachability", .{});
    var progress = true;
    while (progress) {
        progress = false;
        for (deps.a.items, 0..) |from, i| {
            if (!in_set(set.items, from)) continue;
            if (in_set(set.items, deps.b.items[i])) continue;
            const dup = a.dupe(u8, deps.b.items[i]) catch
                return e.set("out of memory computing reachability", .{});
            set.append(a, dup) catch
                return e.set("out of memory computing reachability", .{});
            progress = true;
        }
    }
    return set.items;
}

fn hex64(s: []const u8) bool {
    // the caller has checked s.len >= 66
    for (s[0..64]) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return false;
    }
    return true;
}

/// strtol(suffix, &end, 10) with the C's full-consume check and overflow
/// clamping; null when there are no digits or trailing junk remains.
fn trailing_pid(s: []const u8) ?i64 {
    var i: usize = 0;
    while (i < s.len and (s[i] == ' ' or (s[i] >= 9 and s[i] <= 13))) i += 1;
    var neg = false;
    if (i < s.len and (s[i] == '+' or s[i] == '-')) {
        neg = s[i] == '-';
        i += 1;
    }
    var ndigits: usize = 0;
    var v: i64 = 0;
    while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {
        ndigits += 1;
        if (ndigits <= 18) v = v * 10 + (s[i] - '0');
    }
    if (ndigits == 0 or i != s.len) return null;
    if (ndigits > 18) return if (neg) std.math.minInt(i64) else std.math.maxInt(i64);
    return if (neg) -v else v;
}

/// Sweep ONE scratch directory for crash leftovers whose owning pid is
/// gone: the current <root>.build area plus the legacy <root>/.tmp of
/// stores built before the scratch dir moved out of the store.  A live pid
/// (possibly a concurrent build) is never touched.
fn sweep_orphan_scratch(io: Io, dir: []const u8) void {
    var d = Io.Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch return;
    defer d.close(io);
    var it = d.iterate();
    while (it.next(io) catch null) |te| {
        if (std.mem.eql(u8, te.name, ".") or std.mem.eql(u8, te.name, "..")) continue;
        const lastdash = std.mem.lastIndexOfScalar(u8, te.name, '-') orelse continue;
        const pid = trailing_pid(te.name[lastdash + 1 ..]) orelse continue;
        if (pid <= 0 or pid > std.math.maxInt(c_int)) continue;
        if (kill(@intCast(pid), 0) == 0 or errno() != ESRCH) continue; // alive/unknown
        var jb: [4 * FX_PATH_MAX]u8 = undefined;
        const junk = std.fmt.bufPrint(&jb, "{s}/{s}", .{ dir, te.name }) catch continue;
        rm_rf(io, junk);
    }
}

/// GC sweep relative to `root_pkg`: publish, pin the LATEST snapshot,
/// compute name-level reachability from root_pkg over the pinned dep facts,
/// then — metadata FIRST (atomic txn per unreachable fact), then dirs —
/// delete every well-formed store dir whose name is not reachable.
/// Malformed dir names are reported, not deleted.
pub fn fx_store_gc(io: Io, s: ?*Store, root_pkg: []const u8, e: *ErrBuf) Error!void {
    const st = s orelse return e.set("internal: null args to fx_store_gc", .{});

    var arena = std.heap.ArenaAllocator.init(c_alloc);
    defer arena.deinit();
    const a = arena.allocator();

    // 0. PUBLISH FIRST, then pin: the pinned read must include every fact
    // durably committed since the last publish.  Without this, the dir
    // sweep (name-based) can remove a dir whose committed store fact is
    // invisible to the pinned view, leaving DANGLING metadata.
    if (cl.dl_publish_snapshot(st.db) != 0)
        return e.set("cannot publish store snapshot before gc", .{});

    // 1. pin the LATEST published snapshot (immutable on-disk view)
    const total = dl_snapshot_versions(st.db, null, 0);
    if (total <= 0)
        return e.set("no published snapshot in the store db — run a build first", .{});
    const vers = a.alloc(u32, @intCast(total)) catch return e.set("out of memory", .{});
    _ = dl_snapshot_versions(st.db, vers.ptr, @intCast(total));
    const pinned = vers[@as(usize, @intCast(total)) - 1];

    // 2. read pkg / dep / store / srcstore from the PINNED version
    var deps: PairBag = .{ .db = st.db, .alloc = a };
    var stores: PairBag = .{ .db = st.db, .alloc = a };
    var srcstores: PairBag = .{ .db = st.db, .alloc = a };
    var pkgs_bag: PairBag = .{ .db = st.db, .alloc = a };
    const rd = dl_query_version(st.db, pinned, "dep", pair_cb, &deps);
    const rs = dl_query_version(st.db, pinned, "store", pair_cb, &stores);
    const rss = dl_query_version(st.db, pinned, "srcstore", pair_cb, &srcstores);
    const rp = dl_query_version(st.db, pinned, "pkg", pair_cb, &pkgs_bag);
    if (rd < 0 or rs < 0 or rss < 0 or rp < 0 or
        deps.oom or stores.oom or srcstores.oom or pkgs_bag.oom)
    {
        return e.set(
            "pinned snapshot read failed (version {d}): dep={d} store={d} " ++
                "srcstore={d} pkg={d} oom={d}{d}{d}{d}",
            .{
                pinned,                          rd,            rs,             rss,
                rp,                              @intFromBool(deps.oom), @intFromBool(stores.oom),
                @intFromBool(srcstores.oom),     @intFromBool(pkgs_bag.oom),
            },
        );
    }

    if (!in_set(pkgs_bag.a.items, root_pkg))
        return e.set("gc root '{s}' is not a package in the pinned snapshot", .{root_pkg});

    // 3. liveness: name-level reachability from the root
    const live = try reachable_names(a, &deps, root_pkg, e);

    // 4. METADATA FIRST: atomically txn-delete the unreachable store AND
    // srcstore facts (a crash after this leaves reapable orphan dirs —
    // never dangling metadata pointing at missing dirs)
    var removed_facts: usize = 0;
    for (stores.a.items, 0..) |hash, i| {
        const name = stores.b.items[i];
        if (in_set(live, name)) continue; // name reachable
        const cols = blk: {
            const hz = a.dupeZ(u8, hash) catch break :blk null;
            const c0 = cl.dl_intern_str(st.db, hz.ptr);
            const nz = a.dupeZ(u8, name) catch break :blk null;
            const c1 = cl.dl_intern_str(st.db, nz.ptr);
            if (c0 == 0 or c1 == 0) break :blk null;
            break :blk [2]u32{ c0, c1 };
        } orelse return e.set("out of memory interning gc fact", .{});
        if (dl_txn_begin(st.db) != 0)
            return e.set("txn begin failed", .{});
        if (dl_txn_delete_fact(st.db, "store", &cols, 2) != 0 or dl_txn_commit(st.db) != 0) {
            _ = dl_txn_rollback(st.db);
            return e.set("gc metadata txn failed for '{s}-{s}'", .{ hash, name });
        }
        removed_facts += 1;
    }
    // srcstore facts are unreachable exactly when their NAME is unreachable:
    // liveness is name-level, so a clean-source artifact for an unreachable
    // package is unreachable too
    for (srcstores.a.items, 0..) |hash, i| {
        const name = srcstores.b.items[i];
        if (in_set(live, name)) continue; // name reachable
        const cols = blk: {
            const hz = a.dupeZ(u8, hash) catch break :blk null;
            const c0 = cl.dl_intern_str(st.db, hz.ptr);
            const nz = a.dupeZ(u8, name) catch break :blk null;
            const c1 = cl.dl_intern_str(st.db, nz.ptr);
            if (c0 == 0 or c1 == 0) break :blk null;
            break :blk [2]u32{ c0, c1 };
        } orelse return e.set("out of memory interning gc fact", .{});
        if (dl_txn_begin(st.db) != 0)
            return e.set("txn begin failed", .{});
        if (dl_txn_delete_fact(st.db, "srcstore", &cols, 2) != 0 or dl_txn_commit(st.db) != 0) {
            _ = dl_txn_rollback(st.db);
            return e.set("gc metadata txn failed for srcstore '{s}-{s}'", .{ hash, name });
        }
        removed_facts += 1;
    }

    // 5. then sweep the unreachable DIRS (well-formed <64hex>-<name> and
    // <64hex>-<name>-src only; malformed entries are reported loudly, never
    // deleted)
    var removed_dirs: usize = 0;
    var d = Io.Dir.cwd().openDir(io, st.root(), .{ .iterate = true }) catch {
        const en = errno();
        return e.set("cannot read store root: {s}", .{errstr_e(en)});
    };
    defer d.close(io);
    var it = d.iterate();
    while (it.next(io) catch null) |ent| {
        const nm = ent.name;
        if (nm.len == 0 or nm[0] == '.') continue; // .db/CURRENT
        if (nm.len < 66 or nm[64] != '-' or !hex64(nm)) {
            err_print("fxstore: gc: skipping malformed store entry '{s}'\n", .{nm});
            continue;
        }
        // liveness: check the FULL name first (a built dir "<64hex>-<NAME>"
        // where NAME itself ends in "-src"), then the "-src"-stripped base
        // (a clean-source dir "<64hex>-<NAME>-src").  Keep the dir if EITHER
        // is live — GC must never delete a live package's dir and leave
        // dangling store metadata (package names are arbitrary Text).
        const pkgname = nm[65..];
        if (in_set(live, pkgname)) continue;
        if (pkgname.len > 4 and std.mem.eql(u8, pkgname[pkgname.len - 4 ..], "-src")) {
            if (in_set(live, pkgname[0 .. pkgname.len - 4])) continue;
        }
        var pb: [4 * FX_PATH_MAX]u8 = undefined;
        const path = std.fmt.bufPrint(&pb, "{s}/{s}", .{ st.root(), nm }) catch continue;
        rm_rf(io, path);
        removed_dirs += 1;
    }

    // 6. sweep crash leftovers whose owning pid is gone: the current
    // <root>.build scratch area, plus the legacy <root>/.tmp.
    sweep_orphan_scratch(io, st.build());
    {
        var lb: [FX_PATH_MAX:0]u8 = undefined;
        if (std.fmt.bufPrintZ(&lb, "{s}/{s}", .{ st.root(), FX_TMP_SUBDIR })) |legacy| {
            sweep_orphan_scratch(io, legacy);
        } else |_| {}
    }

    out_print(
        "fxstore gc: root '{s}' — {d} store fact(s) and {d} dir(s) removed " ++
            "({d} live package name(s))\n",
        .{ root_pkg, removed_facts, removed_dirs, live.len },
    );
}

// ─── Timeline/rollback: as-of fact reader + roll-forward (store.c:662-947) ──

/// Raw sym-id fact bag over dl_query_version (tuples are interned sym ids
/// that resolve directly against the live db's shared/persisted interner).
const RawBag = struct {
    tuples: std.ArrayList(u32) = .empty, // arity * n values
    n: usize = 0,
    arity: u8 = 0,
    oom: bool = false, // raw_cb stopped early on allocation failure
};

fn raw_cb(cols: [*]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    const bag: *RawBag = @ptrCast(@alignCast(user.?));
    bag.arity = arity;
    bag.tuples.appendSlice(c_alloc, cols[0..arity]) catch {
        bag.oom = true;
        return 1; // OOM: stop
    };
    bag.n += 1;
    return 0;
}

fn rawbag_free(bag: *RawBag) void {
    bag.tuples.deinit(c_alloc);
    bag.* = .{};
}

/// Read all facts of `rel` as-of `version`.  A relation ABSENT from that
/// version (dl_query_version returns -1; older snapshots predate srcstore)
/// is treated as EMPTY when allow_absent — hard-error only when it is false
/// ('store' is always present in every snapshot).
fn version_bag(
    db: *DlDb,
    version: u32,
    rel: [*:0]const u8,
    allow_absent: bool,
    out: *RawBag,
    e: *ErrBuf,
) Error!void {
    out.* = .{};
    const n = dl_query_version(db, version, rel, raw_cb, out);
    if (n < 0) {
        if (allow_absent) {
            rawbag_free(out);
            return;
        }
        return e.set("snapshot {d} has no '{s}' relation", .{ version, std.mem.span(rel) });
    }
}

/// Txn helpers: buffer delete/add of every fact in a bag (relations must be
/// declared; the swap txn declares them idempotently first).
fn txn_delete_bag(db: *DlDb, rel: [*:0]const u8, bag: *const RawBag) c_int {
    for (0..bag.n) |i| {
        if (dl_txn_delete_fact(db, rel, bag.tuples.items[i * bag.arity ..][0..bag.arity].ptr, bag.arity) != 0)
            return -1;
    }
    return 0;
}

fn txn_add_bag(db: *DlDb, rel: [*:0]const u8, bag: *const RawBag) c_int {
    for (0..bag.n) |i| {
        if (dl_txn_add_fact(db, rel, bag.tuples.items[i * bag.arity ..][0..bag.arity].ptr, bag.arity) != 0)
            return -1;
    }
    return 0;
}

/// One fixed-arity relation as recorded in a snapshot manifest (name owned
/// by the caller's arena).
const RelInfo = struct {
    name: [:0]u8,
    arity: u8,
    idb: bool,
};

/// dl_relation_cb receiver: collects a dl_snapshot_relations enumeration.
const RelEnumCtx = struct {
    a: std.mem.Allocator,
    rels: std.ArrayList(RelInfo) = .empty,
    failed: bool = false,

    fn cb(name: [*:0]const u8, arity: u8, idb: c_int, user: ?*anyopaque) callconv(.c) c_int {
        const self: *RelEnumCtx = @ptrCast(@alignCast(user.?));
        const dup = self.a.dupeZ(u8, std.mem.span(name)) catch {
            self.failed = true;
            return 1;
        };
        self.rels.append(self.a, .{ .name = dup, .arity = arity, .idb = idb != 0 }) catch {
            self.a.free(dup);
            self.failed = true;
            return 1;
        };
        return 0;
    }
};

/// Enumerate the fixed-arity relations of snapshot `version`'s manifest.
fn snapshot_rels(db: *DlDb, version: u32, a: std.mem.Allocator, e: *ErrBuf) Error![]RelInfo {
    var ctx = RelEnumCtx{ .a = a };
    if (dl_snapshot_relations(db, version, RelEnumCtx.cb, &ctx) < 0 or ctx.failed)
        return e.set("cannot enumerate relations of snapshot {d}", .{version});
    return ctx.rels.items;
}

/// The snapshot-complete rollback swap set: the union of the fixed-arity
/// relations in `version`'s and `live`'s manifests, minus what the swap must
/// NOT touch — IDB-flagged entries in EITHER manifest (derived data,
/// data-driven: 'closure' today, re-computed by fx_closure_rebuild after the
/// swap; a future IDB relation outside that program would linger stale) and
/// the reserved 'rev' CAS relation (dl_txn_add/delete_fact reject it).
/// A relation only in `version`'s manifest is declared fresh and repopulated;
/// one only in `live`'s is cleared to empty (absent-as-empty).  An arity
/// disagreement across the two manifests is a hard error: rolling back
/// across a schema change would corrupt the swap.
fn rollback_swap_rels(
    db: *DlDb,
    version: u32,
    live: u32,
    a: std.mem.Allocator,
    e: *ErrBuf,
) Error![]RelInfo {
    const rels_v = try snapshot_rels(db, version, a, e);
    const rels_live = try snapshot_rels(db, live, a, e);

    var merged: std.ArrayList(RelInfo) = .empty;
    for (rels_v) |r|
        merged.append(a, r) catch return e.set("out of memory", .{});
    for (rels_live) |lr| {
        for (merged.items) |*m| {
            if (std.mem.eql(u8, m.name, lr.name)) {
                if (m.arity != lr.arity)
                    return e.set(
                        "relation '{s}' is arity {d} in snapshot {d} but {d} in snapshot {d} — cannot roll back across a schema change",
                        .{ m.name, m.arity, version, lr.arity, live },
                    );
                m.idb = m.idb or lr.idb;
                break;
            }
        } else {
            merged.append(a, lr) catch return e.set("out of memory", .{});
        }
    }

    var out: std.ArrayList(RelInfo) = .empty;
    for (merged.items) |m| {
        if (m.idb) continue; // re-derived after the swap, never copied
        if (std.mem.eql(u8, m.name, "rev")) continue; // CAS system relation
        out.append(a, m) catch return e.set("out of memory", .{});
    }
    return out.items;
}

/// Read the CURRENT snapshot version: best-effort parse of
/// <root>/.db/snapshots/CURRENT, falling back to the highest published
/// version when the file is unreadable.
pub fn fx_store_current_version(io: Io, s: ?*const Store, out: *u32, e: *ErrBuf) Error!void {
    const st = s orelse return e.set("internal: null args", .{});
    var cb: [FX_PATH_MAX:0]u8 = undefined;
    const cur = std.fmt.bufPrintZ(&cb, "{s}/{s}/snapshots/CURRENT", .{ st.root(), FX_DB_SUBDIR }) catch
        return e.set("CURRENT path too long", .{});
    if (Io.Dir.cwd().openFile(io, cur, .{ .mode = .read_only })) |f| {
        defer f.close(io);
        var buf: [256]u8 = undefined;
        const got = f.readPositionalAll(io, &buf, 0) catch 0;
        if (scan_ulong(buf[0..got])) |v| {
            if (v > 0 and v <= std.math.maxInt(u32)) {
                out.* = @intCast(v);
                return;
            }
        }
    } else |_| {}
    // fall back to the highest published version
    const total = dl_snapshot_versions(st.db, null, 0);
    if (total <= 0)
        return e.set("no published snapshot in the store db — run a build first", .{});
    var arena = std.heap.ArenaAllocator.init(c_alloc);
    defer arena.deinit();
    const vers = arena.allocator().alloc(u32, @intCast(total)) catch return e.set("out of memory", .{});
    _ = dl_snapshot_versions(st.db, vers.ptr, @intCast(total));
    out.* = vers[@as(usize, @intCast(total)) - 1];
}

/// fscanf(f, "%lu"): optional whitespace + sign, then decimal digits
/// (wrapping like the C's unsigned long parse); null when no match.
fn scan_ulong(bytes: []const u8) ?u64 {
    var i: usize = 0;
    while (i < bytes.len and (bytes[i] == ' ' or (bytes[i] >= 9 and bytes[i] <= 13))) i += 1;
    var neg = false;
    if (i < bytes.len and (bytes[i] == '+' or bytes[i] == '-')) {
        neg = bytes[i] == '-';
        i += 1;
    }
    const d0 = i;
    var v: u64 = 0;
    while (i < bytes.len and bytes[i] >= '0' and bytes[i] <= '9') : (i += 1)
        v = v *% 10 +% (bytes[i] - '0');
    if (i == d0) return null;
    return if (neg) 0 -% v else v;
}

/// Print a machine-parseable timeline of every published snapshot version:
///   <v> [CURRENT] roots: <n1>,<n2>  closure: <k>  store: <s>  srcstore: <t>
/// (empty roots -> "roots: (none)"; "no versions" when none are published).
pub fn fx_store_timeline(io: Io, s: ?*Store, e: *ErrBuf) Error!void {
    const st = s orelse return e.set("internal: null store", .{});
    const total = dl_snapshot_versions(st.db, null, 0);
    if (total < 0)
        return e.set("cannot enumerate snapshot versions", .{});
    out_print("fxstore: timeline of {s} ({d} version(s)):\n", .{ st.root(), total });
    if (total == 0) {
        out_print("  no versions\n", .{});
        return;
    }

    var arena = std.heap.ArenaAllocator.init(c_alloc);
    defer arena.deinit();
    const vers = arena.allocator().alloc(u32, @intCast(total)) catch return e.set("out of memory", .{});
    _ = dl_snapshot_versions(st.db, vers.ptr, @intCast(total));

    var cur: u32 = 0;
    var scratch = ErrBuf{};
    fx_store_current_version(io, st, &cur, &scratch) catch {}; // best-effort

    var ok = true;
    var i: c_long = 0;
    while (i < total and ok) : (i += 1) {
        const v = vers[@intCast(i)];
        var roots: RawBag = .{};
        var closure: RawBag = .{};
        var store: RawBag = .{};
        var srcstore: RawBag = .{};
        defer {
            rawbag_free(&roots);
            rawbag_free(&closure);
            rawbag_free(&store);
            rawbag_free(&srcstore);
        }
        var failed = false;
        version_bag(st.db, v, "root", true, &roots, e) catch {
            failed = true;
        };
        if (!failed) version_bag(st.db, v, "closure", true, &closure, e) catch {
            failed = true;
        };
        if (!failed) version_bag(st.db, v, "store", false, &store, e) catch {
            failed = true;
        };
        if (!failed) version_bag(st.db, v, "srcstore", true, &srcstore, e) catch {
            failed = true;
        };
        if (failed) {
            ok = false;
            continue;
        }
        out_print("  {d}{s} roots: ", .{ v, if (v == cur) " [CURRENT]" else "" });
        if (roots.n == 0) {
            out_print("(none)", .{});
        } else {
            for (roots.tuples.items, 0..) |sym, k| {
                const nm = cl.dl_intern_str_of(st.db, sym);
                if (k != 0) out_print(",", .{});
                out_print("{s}", .{if (nm) |m| std.mem.span(m) else "?"});
            }
        }
        out_print("  closure: {d}  store: {d}  srcstore: {d}\n", .{ closure.n, store.n, srcstore.n });
    }
    if (!ok) return error.FxStore;
}

/// Atomic rewrite of the CURRENT file (write CURRENT.tmp + fsync + rename),
/// mirroring datalog-dafsa's own atomic CURRENT flip.
fn write_current(s: *Store, version: u32, e: *ErrBuf) Error!void {
    var zb: [4 * FX_PATH_MAX:0]u8 = undefined;
    const dir = std.fmt.bufPrintZ(&zb, "{s}/{s}/snapshots", .{ s.root(), FX_DB_SUBDIR }) catch
        return e.set("snapshot path too long", .{});
    var tb: [4 * FX_PATH_MAX:0]u8 = undefined;
    const tmp = std.fmt.bufPrintZ(&tb, "{s}/CURRENT.tmp", .{dir}) catch
        return e.set("snapshot path too long", .{});
    var fb: [4 * FX_PATH_MAX:0]u8 = undefined;
    const final = std.fmt.bufPrintZ(&fb, "{s}/CURRENT", .{dir}) catch
        return e.set("snapshot path too long", .{});
    var buf: [32]u8 = undefined;
    const bytes = std.fmt.bufPrint(&buf, "{d}\n", .{version}) catch unreachable;
    const fd = open(tmp.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (fd < 0) {
        const en = errno();
        return e.set("cannot open '{s}': {s}", .{ tmp, errstr_e(en) });
    }
    const w = write(fd, bytes.ptr, bytes.len);
    if (w != @as(isize, @intCast(bytes.len)) or fsync(fd) != 0) {
        const en = errno();
        _ = close(fd);
        _ = unlink(tmp.ptr);
        return e.set("cannot write '{s}': {s}", .{ tmp, errstr_e(en) });
    }
    _ = close(fd);
    if (rename(tmp.ptr, final.ptr) != 0) {
        const en = errno();
        _ = unlink(tmp.ptr);
        return e.set("cannot rename '{s}' -> '{s}': {s}", .{ tmp, final, errstr_e(en) });
    }
}

/// Roll back the store to a previously published snapshot `version`:
///   hard (recovery-only): atomically rewrite the CURRENT file to point at
///     `version`; no new version, no fact mutation.
///   soft (roll-forward, default): publish the current state FIRST (so
///     un-published facts fold into a version and pre-rollback state is
///     preserved as an undoable version), then in ONE atomic txn restore
///     EVERY relation to `version` — the restorable set enumerated from the
///     version's manifest, not a hardcoded name list — then re-derive
///     `closure` via fx_closure_rebuild (publishing the rollback result —
///     two new versions, CURRENT advances monotonically).
pub fn fx_store_rollback(s: ?*Store, version: u32, hard: bool, e: *ErrBuf) Error!void {
    const st = s orelse return e.set("internal: null store", .{});

    var arena = std.heap.ArenaAllocator.init(c_alloc);
    defer arena.deinit();
    const a = arena.allocator();

    // validate `version` is a published snapshot
    const total = dl_snapshot_versions(st.db, null, 0);
    if (total <= 0)
        return e.set("no published snapshot in the store db — run a build first", .{});
    const vers = a.alloc(u32, @intCast(total)) catch return e.set("out of memory", .{});
    _ = dl_snapshot_versions(st.db, vers.ptr, @intCast(total));
    var found = false;
    for (vers[0..@intCast(total)]) |vv| {
        if (vv == version) {
            found = true;
            break;
        }
    }
    if (!found)
        return e.set("no such version {d} (have {d} version(s))", .{ version, total });

    if (hard)
        return write_current(st, version, e);

    // ── roll-forward ──

    // 1. PUBLISH FIRST: un-published facts (a crashed build) fold into a
    // version, and the just-published latest == live (the swap below must
    // be diffed against the published latest, not the live WAL).  This also
    // preserves the pre-rollback state as an undoable version.
    if (cl.dl_publish_snapshot(st.db) != 0)
        return e.set("cannot publish store snapshot before rollback", .{});

    // 2. resolve the swap set from BOTH manifests (the target `version`'s
    //    and the just-published live one) — snapshot-complete: every
    //    restorable relation the recorded schema names, not a hardcoded
    //    subset.  IDB rels ('closure') and reserved 'rev' are excluded.
    const total2 = dl_snapshot_versions(st.db, null, 0);
    if (total2 <= 0)
        return e.set("no published snapshot after rollback publish", .{});
    const vers2 = a.alloc(u32, @intCast(total2)) catch return e.set("out of memory", .{});
    _ = dl_snapshot_versions(st.db, vers2.ptr, @intCast(total2));
    const live_v = vers2[@as(usize, @intCast(total2)) - 1];
    const swap = try rollback_swap_rels(st.db, version, live_v, a, e);

    // 3. keep `version`'s pkg/dep/root bags aside: the swap restores them
    //    like any other relation, and fx_closure_rebuild then re-derives the
    //    fixpoint from exactly these facts (NOT closure — an IDB excluded
    //    from the swap set above).
    var vpkg: RawBag = .{};
    var vdep: RawBag = .{};
    var vroot: RawBag = .{};
    defer {
        rawbag_free(&vpkg);
        rawbag_free(&vdep);
        rawbag_free(&vroot);
    }
    try version_bag(st.db, version, "pkg", true, &vpkg, e);
    try version_bag(st.db, version, "dep", true, &vdep, e);
    try version_bag(st.db, version, "root", true, &vroot, e);

    // 4. declare every swap relation idempotently — guarantees the txn
    //    add/delete succeed even for relations that exist only in `version`'s
    //    manifest and were never declared live (e.g. after a re-init).
    for (swap) |rel| {
        if (cl.dl_declare_relation(st.db, rel.name.ptr, rel.arity) != 0)
            return e.set("cannot declare relation '{s}' for rollback", .{rel.name});
    }

    // 5. ONE atomic txn, per relation: delete every LIVE fact (dl_prefix —
    //    the one live-WAL reader, so the clear targets exactly the state
    //    txn_delete_fact mutates; the publish above did not change the
    //    in-memory relations), then add `version`'s facts (allow_absent: a
    //    relation missing from `version`'s manifest reads as empty, i.e.
    //    cleared-to-empty).  One WAL + one fsync for the whole swap.
    if (dl_txn_begin(st.db) != 0)
        return e.set("txn begin failed (another txn open?)", .{});
    var txn_failed = false;
    for (swap) |rel| {
        var live_bag: RawBag = .{};
        defer rawbag_free(&live_bag);
        var vb: RawBag = .{};
        defer rawbag_free(&vb);

        const n_live = dl_prefix(st.db, rel.name.ptr, null, 0, raw_cb, &live_bag);
        if (n_live < 0 or live_bag.oom) {
            txn_failed = true;
            break;
        }
        version_bag(st.db, version, rel.name.ptr, true, &vb, e) catch {
            txn_failed = true;
            break;
        };
        if (vb.oom or
            txn_delete_bag(st.db, rel.name.ptr, &live_bag) != 0 or
            txn_add_bag(st.db, rel.name.ptr, &vb) != 0)
        {
            txn_failed = true;
            break;
        }
    }
    if (txn_failed or dl_txn_commit(st.db) != 0) {
        _ = dl_txn_rollback(st.db);
        return e.set("rollback metadata txn failed", .{});
    }

    // 6. re-derive closure from `version`'s pkg/dep/root.  Re-clearing and
    // re-adding pkg/dep/root is harmless (the swap already set them); this
    // re-materializes the fixpoint through dl_load_rules+dl_compile and
    // publishes a NEW version (the rollback result).
    var ce = cl.ErrBuf{};
    cl.fx_closure_rebuild(
        st.db,
        vpkg.tuples.items,
        vdep.tuples.items,
        vroot.tuples.items,
        &ce,
    ) catch return e.set("{s}", .{ce.slice()});
}

/// Generation GC: keep at most `n` most-recent snapshot versions, pruning
/// the rest (dl_set_snapshot_retain + dl_publish_snapshot; the prune is
/// applied at the END of the successful publish).  Snapshot VERSION dirs
/// only — artifact store dirs are `gc`'s job.
pub fn fx_store_gc_retain(io: Io, s: ?*Store, n: u32, e: *ErrBuf) Error!void {
    const st = s orelse return e.set("internal: null store", .{});
    if (n == 0) return e.set("gc --retain requires N >= 1", .{});
    // Guard the --hard interaction: if CURRENT (from the file) no longer
    // points at the newest published version, this process's publish would
    // RENUMBER (new = CURRENT+1) and rm_rf() real snapshot dirs, and the
    // retention prune could then drop the CURRENT-pointed version — leaving
    // a dangling CURRENT and shredded history.  Refuse loudly instead.
    {
        var cur: u32 = 0;
        var scratch = ErrBuf{};
        if (fx_store_current_version(io, st, &cur, &scratch)) |_| {
            const total = dl_snapshot_versions(st.db, null, 0);
            if (total > 0) {
                var arena = std.heap.ArenaAllocator.init(c_alloc);
                defer arena.deinit();
                if (arena.allocator().alloc(u32, @intCast(total))) |vs| {
                    _ = dl_snapshot_versions(st.db, vs.ptr, @intCast(total));
                    const newest = vs[@as(usize, @intCast(total)) - 1];
                    if (cur != newest)
                        return e.set(
                            "CURRENT ({d}) is not the newest version ({d}) — " ++
                                "a 'rollback --hard' repointed it; fix that first " ++
                                "('fxstore rollback --hard {d}'), then retry gc --retain",
                            .{ cur, newest, newest },
                        );
                } else |_| {}
            }
        } else |_| {}
    }
    if (dl_set_snapshot_retain(st.db, n) != 0)
        return e.set("cannot set snapshot retention to {d}", .{n});
    // the prune is applied at the END of a successful publish
    if (cl.dl_publish_snapshot(st.db) != 0)
        return e.set("cannot publish to apply snapshot retention", .{});
}


const testing = std.testing;

fn tio() Io {
    return std.testing.io;
}

/// A unique temp store root per test (dl_open holds a process-lifetime
/// fcntl F_SETLK single-writer lock: never two dbs live at once).
fn temp_root(buf: *[64:0]u8) ![:0]u8 {
    var seed: [8]u8 = undefined;
    tio().random(&seed);
    const r = std.mem.readInt(u64, &seed, .little);
    return std.fmt.bufPrintZ(buf, "/tmp/fx-u4-{x:0>16}", .{r});
}

/// Delete the store root (including a legacy .tmp inside it) and the
/// <root>.build sibling.
fn cleanup_store(io: Io, root: [:0]const u8) void {
    Io.Dir.cwd().deleteTree(io, root) catch {};
    var bb: [80:0]u8 = undefined;
    const b = std.fmt.bufPrintZ(&bb, "{s}.build", .{root}) catch return;
    Io.Dir.cwd().deleteTree(io, b) catch {};
}

/// g_out_fd/g_err_fd capture: begin() points stdout at `out_path` and
/// stderr at `err_path`, end()/end_err() restore the fds and return the
/// captured bytes (caller frees).
const Capture = struct {
    saved_out: c_int,
    saved_err: c_int,
    saved_bld_out: @TypeOf(bld.g_out_fd),
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
            .saved_bld_out = bld.g_out_fd,
            .out_file = of,
            .err_file = ef,
            .out_path = out_path,
            .err_path = err_path,
        };
    }

    fn redirect(self: *Capture) void {
        g_out_fd = self.out_file.handle;
        g_err_fd = self.err_file.handle;
        // the recipe executor echoes actions through build.zig's own fd
        bld.g_out_fd = self.out_file.handle;
    }

    fn restore(self: *Capture) void {
        g_out_fd = self.saved_out;
        g_err_fd = self.saved_err;
        bld.g_out_fd = self.saved_bld_out;
        // end() + end_err() both restore; closing twice is EBADF (panic
        // under Threaded Io, and it deadlocks the --listen=- runner)
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

/// Swallow the recipe executor's echoes for the rest of the scope:
/// build.zig's g_out_fd defaults to fd 1, which under `zig test --listen=-`
/// is the runner PROTOCOL pipe — a raw write there hangs the runner.
const EchoGuard = struct {
    saved: @TypeOf(bld.g_out_fd),
    file: Io.File,

    fn begin() !EchoGuard {
        const f = try Io.Dir.cwd().createFile(tio(), "/dev/null", .{});
        const g = EchoGuard{ .saved = bld.g_out_fd, .file = f };
        bld.g_out_fd = f.handle;
        return g;
    }

    fn release(self: *EchoGuard) void {
        bld.g_out_fd = self.saved;
        self.file.close(tio());
    }
};

/// Whether the interned fact rel(a,b) exists in the live db.
fn fact_exists(db: *DlDb, rel: [*:0]const u8, a_val: []const u8, b_val: []const u8) bool {
    var za: [256:0]u8 = undefined;
    var zb: [256:0]u8 = undefined;
    const az = std.fmt.bufPrintZ(&za, "{s}", .{a_val}) catch return false;
    const bz = std.fmt.bufPrintZ(&zb, "{s}", .{b_val}) catch return false;
    const c0 = cl.dl_intern_str(db, az.ptr);
    const c1 = cl.dl_intern_str(db, bz.ptr);
    if (c0 == 0 or c1 == 0) return false;
    const cols = [2]u32{ c0, c1 };
    return dl_lookup(db, rel, &cols, 2) != 0;
}

// hand-built fixture packages (closure.zig's link pattern): fetch sources +
// in-process recipes only, so tests never need the sandbox.

fn test_pkg(name: []const u8, deps: []const []const u8) Package {
    return .{
        .name = name,
        .version = "1",
        .src = .{ .kind = .fetch, .url = "https://example.com/x", .hash = "00" },
        .deps = deps,
        .target = name,
    };
}

fn link(pset: *pkgs.PackageSet, table: []Package) void {
    for (table[0 .. table.len - 1], 0..) |*p, i| p.next = &table[i + 1];
    pset.head = &table[0];
    pset.count = table.len;
}

/// The main.c per-package flow: derivation hash (+dep paths) -> store path
/// -> ensure_source (Path src) -> fx_store_build.
fn build_pkg(
    io: Io,
    s: *Store,
    pkg: *const Package,
    dep_names: []const []const u8,
    dep_paths: []const []const u8,
    e: *ErrBuf,
) Error!void {
    var hash: [65]u8 = undefined;
    var de = drv.ErrBuf{};
    drv.fx_derivation_hash(io, pkg, dep_paths, &hash, &de) catch return e.set("{s}", .{de.slice()});
    var fpb: [4 * FX_PATH_MAX]u8 = undefined;
    const final_path = drv.fx_derivation_store_path(io, pkg, dep_paths, s.root(), &fpb, &de) catch
        return e.set("{s}", .{de.slice()});
    var src_buf: [FX_PATH_MAX]u8 = undefined;
    var src_path: ?[]const u8 = null;
    if (pkg.src.kind == .path) {
        var sh: [65]u8 = undefined;
        drv.fx_content_hash_dir(io, pkg.src.path.?, pkg.excludes, &sh, &de) catch
            return e.set("{s}", .{de.slice()});
        src_path = try fx_store_ensure_source(io, s, pkg, sh[0..64], &src_buf, e);
    }
    return fx_store_build(io, s, pkg, hash[0..64], final_path, src_path, dep_names, dep_paths, e);
}

/// A pid that is definitely gone (kill(pid,0) == ESRCH), by scanning upward
/// from this test process's pid.
fn dead_pid() c_int {
    const me = getpid();
    var cand: c_int = me + 17;
    var tries: usize = 0;
    while (tries < 10000) : (tries += 1) {
        cand += 3;
        if (cand <= 0) continue;
        if (kill(cand, 0) != 0 and errno() == ESRCH) return cand;
    }
    return 0;
}

// ─── fx_store_open / fx_store_close ─────────────────────────────────────────

test "fx_store_open/close: layout, trailing-slash normalization, rejections, reopen" {
    const io = tio();
    var rb: [64:0]u8 = undefined;
    const root = try temp_root(&rb);
    defer cleanup_store(io, root);

    var e = ErrBuf{};

    // empty root
    try testing.expectError(error.FxStore, fx_store_open(io, "", &e));
    try testing.expectEqualStrings("store root must be non-empty", e.slice());

    // root exists as a FILE
    {
        var f = try Io.Dir.cwd().createFile(io, root, .{ .truncate = true });
        f.close(io);
    }
    try testing.expectError(error.FxStore, fx_store_open(io, root, &e));
    try testing.expect(std.mem.startsWith(u8, e.slice(), "store root '/tmp/fx-u4-"));
    try testing.expect(std.mem.endsWith(u8, e.slice(), "' is not a directory"));
    Io.Dir.cwd().deleteTree(io, root) catch {};

    // trailing slashes normalize; root + <root>.build + root/.db created
    var fb: [96:0]u8 = undefined;
    const slashed = try std.fmt.bufPrintZ(&fb, "{s}///", .{root});
    var s = try fx_store_open(io, slashed, &e);
    try testing.expectEqualStrings(root, s.root());
    try testing.expect(is_dir(io, s.build()));
    var dbb: [96:0]u8 = undefined;
    const dbdir = try std.fmt.bufPrintZ(&dbb, "{s}/.db", .{root});
    try testing.expect(is_dir(io, dbdir));
    fx_store_close(s);
    fx_store_close(null); // NULL-safe

    // reopen on an existing store is idempotent
    s = try fx_store_open(io, root, &e);
    try testing.expectEqualStrings(root, fx_store_root(s));
    try testing.expect(fx_store_db(s) != null);
    fx_store_close(s);

    // build dir exists as a FILE -> rejected
    var rb2: [64:0]u8 = undefined;
    const root2 = try temp_root(&rb2);
    defer cleanup_store(io, root2);
    try Io.Dir.cwd().createDirPath(io, root2);
    var fb2: [80:0]u8 = undefined;
    const bf2 = try std.fmt.bufPrintZ(&fb2, "{s}.build", .{root2});
    {
        var f = try Io.Dir.cwd().createFile(io, bf2, .{ .truncate = true });
        f.close(io);
    }
    try testing.expectError(error.FxStore, fx_store_open(io, root2, &e));
    try testing.expect(std.mem.startsWith(u8, e.slice(), "build dir '/tmp/fx-u4-"));
    try testing.expect(std.mem.endsWith(u8, e.slice(), "' is not a directory"));
}

test "fx_store_open rejects a cross-filesystem build sibling (skipped without mount)" {
    const io = tio();
    var rb: [64:0]u8 = undefined;
    const mp = try temp_root(&rb);
    defer Io.Dir.cwd().deleteTree(io, mp) catch {};
    Io.Dir.cwd().createDirPath(io, mp) catch return error.SkipZigTest;
    // the mount point ITSELF is the store root, so <root>.build lands on the
    // PARENT filesystem — the one layout fx_store_open rejects
    if (mount("tmpfs", mp, "tmpfs", 0, null) != 0) return error.SkipZigTest;
    defer _ = umount(mp);
    var e = ErrBuf{};
    try testing.expectError(error.FxStore, fx_store_open(io, mp, &e));
    try testing.expect(std.mem.startsWith(u8, e.slice(), "build dir '/tmp/fx-u4-"));
    try testing.expect(std.mem.indexOf(u8, e.slice(), "is on a different filesystem") != null);
    // the created .build sibling must not linger on the parent fs
    var bb: [80:0]u8 = undefined;
    const b = try std.fmt.bufPrintZ(&bb, "{s}.build", .{mp});
    Io.Dir.cwd().deleteTree(io, b) catch {};
}

extern "c" fn mount(src: [*:0]const u8, tgt: [*:0]const u8, fstype: [*:0]const u8, flags: c_ulong, data: ?*anyopaque) c_int;
extern "c" fn umount(tgt: [*:0]const u8) c_int;

// ─── fx_store_build ─────────────────────────────────────────────────────────

test "fx_store_build: end-to-end Path-src build, adoption, stale same-pid scratch" {
    const io = tio();
    var pe = pkgs.ErrBuf{};
    var pset: pkgs.PackageSet = undefined;
    try pkgs.fx_packageset_load(&pset, "zig/corpus/packageset/good.dhall", &pe);
    defer pset.deinit();
    const hello = pset.find("hello").?;

    // swap the sandbox-running recipe for an in-process one (mkdir + touch)
    var acts = [_]pkgs.Action{
        .{ .kind = .mkdir, .a = "out" },
        .{ .kind = .touch, .a = "out/made.txt" },
    };
    acts[0].next = &acts[1];
    hello.recipe = &acts[0];

    var rb: [64:0]u8 = undefined;
    const root = try temp_root(&rb);
    defer cleanup_store(io, root);
    var e = ErrBuf{};
    const s = try fx_store_open(io, root, &e);
    defer fx_store_close(s);
    var eg = try EchoGuard.begin();
    defer eg.release();

    // the main.c compute_paths flow: clean src + derivation hash + store path
    var de = drv.ErrBuf{};
    var src_hash: [65]u8 = undefined;
    try drv.fx_content_hash_dir(io, hello.src.path.?, hello.excludes, &src_hash, &de);
    var src_buf: [FX_PATH_MAX]u8 = undefined;
    const src_path = try fx_store_ensure_source(io, s, hello, src_hash[0..64], &src_buf, &e);
    var hash: [65]u8 = undefined;
    try drv.fx_derivation_hash(io, hello, &.{}, &hash, &de);
    var fpb: [4 * FX_PATH_MAX]u8 = undefined;
    const final_path = try drv.fx_derivation_store_path(io, hello, &.{}, root, &fpb, &de);

    try fx_store_build(io, s, hello, hash[0..64], final_path, src_path, &.{}, &.{}, &e);

    // final dir exists with the artifact; store(hash,name) committed
    try testing.expect(is_dir(io, final_path));
    var ab: [512]u8 = undefined;
    const art = try std.fmt.bufPrint(&ab, "{s}/out/made.txt", .{final_path});
    try testing.expect((try Io.Dir.cwd().statFile(io, art, .{})).kind == .file);
    try testing.expect(fact_exists(s.db, "store", hash[0..64], "hello"));
    // the dir name is <hash>-<name>
    const base = final_path[std.mem.lastIndexOfScalar(u8, final_path, '/').? + 1 ..];
    try testing.expect(std.mem.startsWith(u8, base, hash[0..64]));
    try testing.expect(std.mem.endsWith(u8, base, "-hello"));

    // idempotent re-build ADOPTS (no rebuild): a marker inside the final dir
    // proves the content was not replaced
    var mb: [512]u8 = undefined;
    const marker = try std.fmt.bufPrint(&mb, "{s}/adopt.marker", .{final_path});
    {
        var f = try Io.Dir.cwd().createFile(io, marker, .{ .truncate = true });
        f.close(io);
    }
    try fx_store_build(io, s, hello, hash[0..64], final_path, src_path, &.{}, &.{}, &e);
    _ = try Io.Dir.cwd().statFile(io, marker, .{});

    // crash-sim: a stale SAME-PID scratch dir remains (crash before rename
    // cleanup) and the final dir is gone: the rerun reaps the stale tmp and
    // re-installs; the already-committed fact makes the commit idempotent
    var sb: [512:0]u8 = undefined;
    const stale = try std.fmt.bufPrintZ(&sb, "{s}/{s}-{d}", .{ s.build(), base, getpid() });
    try Io.Dir.cwd().createDirPath(io, stale);
    var jb: [560:0]u8 = undefined;
    const junk = try std.fmt.bufPrintZ(&jb, "{s}/junk.txt", .{stale});
    {
        var f = try Io.Dir.cwd().createFile(io, junk, .{ .truncate = true });
        f.close(io);
    }
    Io.Dir.cwd().deleteTree(io, final_path) catch {};
    try fx_store_build(io, s, hello, hash[0..64], final_path, src_path, &.{}, &.{}, &e);
    try testing.expect(is_dir(io, final_path));
    _ = try Io.Dir.cwd().statFile(io, art, .{});
    try testing.expect(!is_dir(io, stale)); // stale same-pid tmp was rm_rf'd
    try testing.expect(fact_exists(s.db, "store", hash[0..64], "hello"));
}

// ─── fx_store_ensure_source ─────────────────────────────────────────────────

test "fx_store_ensure_source: clean artifact, srcstore fact, adoption, TOCTOU" {
    const io = tio();
    // a tiny source tree of our own (the corpus trees are pinned by U2/U3)
    var tb: [64:0]u8 = undefined;
    var seed: [8]u8 = undefined;
    tio().random(&seed);
    const tree = try std.fmt.bufPrintZ(&tb, "/tmp/fx-u4-src-{x:0>16}", .{std.mem.readInt(u64, &seed, .little)});
    defer Io.Dir.cwd().deleteTree(io, tree) catch {};
    try Io.Dir.cwd().createDirPath(io, tree);
    var pb: [96:0]u8 = undefined;
    const a_txt = try std.fmt.bufPrintZ(&pb, "{s}/a.txt", .{tree});
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = a_txt, .data = "A" });
    var pb2: [96:0]u8 = undefined;
    const sub = try std.fmt.bufPrintZ(&pb2, "{s}/sub", .{tree});
    try Io.Dir.cwd().createDirPath(io, sub);
    var pb3: [128:0]u8 = undefined;
    const b_txt = try std.fmt.bufPrintZ(&pb3, "{s}/sub/b.txt", .{tree});
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = b_txt, .data = "B" });

    var pkg = Package{
        .name = "lib",
        .version = "1",
        .src = .{ .kind = .path, .path = tree },
        .target = "lib",
    };

    var rb: [64:0]u8 = undefined;
    const root = try temp_root(&rb);
    defer cleanup_store(io, root);
    var e = ErrBuf{};
    const s = try fx_store_open(io, root, &e);
    defer fx_store_close(s);

    var de = drv.ErrBuf{};
    var h0: [65]u8 = undefined;
    try drv.fx_content_hash_dir(io, tree, pkg.excludes, &h0, &de);
    var nb: [128]u8 = undefined;
    const want_art = try std.fmt.bufPrint(&nb, "{s}/{s}-lib-src", .{ root, h0[0..64] });

    // non-Path sources are rejected
    var fetchy = pkg;
    fetchy.src = .{ .kind = .fetch, .url = "u", .hash = "h" };
    var buf2: [FX_PATH_MAX]u8 = undefined;
    try testing.expectError(error.FxStore, fx_store_ensure_source(io, s, &fetchy, h0[0..64], &buf2, &e));
    try testing.expectEqualStrings("internal: ensure_source on a non-Path source", e.slice());

    // TOCTOU: mutate the source AFTER hashing -> the stale hash is rejected.
    // This must run BEFORE the artifact exists: once <hash>-<name>-src is
    // materialized, ensure_source takes the idempotent-adoption branch
    // (exactly like store.c:331) and never re-hashes the source.
    var pb4: [96:0]u8 = undefined;
    const c_txt = try std.fmt.bufPrintZ(&pb4, "{s}/c.txt", .{tree});
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = c_txt, .data = "C" });
    var buf3: [FX_PATH_MAX]u8 = undefined;
    try testing.expectError(error.FxStore, fx_store_ensure_source(io, s, &pkg, h0[0..64], &buf3, &e));
    var wb: [512]u8 = undefined;
    const want_msg = try std.fmt.bufPrint(&wb, "source '{s}' changed between path computation and build (expected clean hash {s}..., got ", .{ tree, h0[0..16] });
    try testing.expect(std.mem.startsWith(u8, e.slice(), want_msg));
    try testing.expect(std.mem.endsWith(u8, e.slice(), "...); re-run fxstore build"));
    try testing.expect(!is_dir(io, want_art)); // the failed attempt left no artifact

    // restore the tree to the hashed state, then materialize for real
    try Io.Dir.cwd().deleteTree(io, c_txt);
    var buf: [FX_PATH_MAX]u8 = undefined;
    const art = try fx_store_ensure_source(io, s, &pkg, h0[0..64], &buf, &e);
    // the clean copy materialized; the srcstore fact committed
    try testing.expectEqualStrings(want_art, art);
    try testing.expect(is_dir(io, art));
    var ab: [512]u8 = undefined;
    const a_bytes = try Io.Dir.cwd().readFileAlloc(io, try std.fmt.bufPrint(&ab, "{s}/a.txt", .{art}), testing.allocator, .limited(64));
    defer testing.allocator.free(a_bytes);
    try testing.expectEqualStrings("A", a_bytes);
    try testing.expect(fact_exists(s.db, "srcstore", h0[0..64], "lib"));

    // idempotent re-ensure ADOPTS (marker inside the artifact survives)
    var mb: [512]u8 = undefined;
    const marker = try std.fmt.bufPrint(&mb, "{s}/adopt.marker", .{art});
    {
        var f = try Io.Dir.cwd().createFile(io, marker, .{ .truncate = true });
        f.close(io);
    }
    _ = try fx_store_ensure_source(io, s, &pkg, h0[0..64], &buf, &e);
    _ = try Io.Dir.cwd().statFile(io, marker, .{});

    // with the CURRENT hash it materializes a second, distinct artifact
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = c_txt, .data = "C" });
    var h1: [65]u8 = undefined;
    try drv.fx_content_hash_dir(io, tree, pkg.excludes, &h1, &de);
    try testing.expect(!std.mem.eql(u8, h0[0..64], h1[0..64]));
    const art1 = try fx_store_ensure_source(io, s, &pkg, h1[0..64], &buf3, &e);
    try testing.expect(is_dir(io, art1));
    try testing.expect(fact_exists(s.db, "srcstore", h1[0..64], "lib"));
}

// ─── fx_store_gc ────────────────────────────────────────────────────────────

test "fx_store_gc: liveness sweep, malformed report, orphan scratch sweep" {
    const io = tio();
    var rb: [64:0]u8 = undefined;
    const root = try temp_root(&rb);
    defer cleanup_store(io, root);
    var e = ErrBuf{};
    const s = try fx_store_open(io, root, &e);
    defer fx_store_close(s);
    var eg = try EchoGuard.begin();
    defer eg.release();

    var de = drv.ErrBuf{};
    var fpb: [4 * FX_PATH_MAX]u8 = undefined;

    // hello (leaf) <- world (dep hello); in-process recipes
    var acts = [_]pkgs.Action{.{ .kind = .touch, .a = "made.txt" }};
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var tbl = [_]Package{
        blk: {
            var p = test_pkg("hello", &.{});
            p.recipe = &acts[0];
            break :blk p;
        },
        test_pkg("world", &.{"hello"}),
    };
    var pset: pkgs.PackageSet = .{ .arena = arena_inst };
    link(&pset, &tbl);

    var ce = cl.ErrBuf{};
    try cl.fx_closure_compute(s.db, &pset, &.{}, &ce); // publishes v1
    try build_pkg(io, s, &tbl[0], &.{}, &.{}, &e);
    const hello_final = try drv.fx_derivation_store_path(io, &tbl[0], &.{}, root, &fpb, &de);
    try build_pkg(io, s, &tbl[1], &.{"hello"}, &.{hello_final}, &e);
    var wfb: [4 * FX_PATH_MAX]u8 = undefined;
    const world_final = try drv.fx_derivation_store_path(io, &tbl[1], &.{hello_final}, root, &wfb, &de);
    // the store index is keyed by the DERIVATION hash build_pkg committed
    // (never the fetch fixture's src.hash "00")
    var hb: [65]u8 = undefined;
    try drv.fx_derivation_hash(io, &tbl[0], &.{}, &hb, &de);
    var whb: [65]u8 = undefined;
    try drv.fx_derivation_hash(io, &tbl[1], &.{hello_final}, &whb, &de);

    // a srcstore fact + dir for an unreachable name (as an old build might
    // have left behind) — created after the world-rooted gc below
    const gh = "aa" ** 32;
    var gb: [256:0]u8 = undefined;
    const ghost_dir = try std.fmt.bufPrintZ(&gb, "{s}/{s}-ghost-src", .{ root, gh });

    var ob: [96:0]u8 = undefined;
    var eb: [96:0]u8 = undefined;
    const out_path = try std.fmt.bufPrintZ(&ob, "{s}.out", .{root});
    const err_path = try std.fmt.bufPrintZ(&eb, "{s}.err", .{root});
    var wb: [256]u8 = undefined;

    // gc with root=world: everything (2 names) is live, nothing removed
    {
        var cap = try Capture.begin(out_path, err_path);
        cap.redirect();
        try fx_store_gc(io, s, "world", &e);
        const out = try cap.end();
        defer testing.allocator.free(out);
        const want = try std.fmt.bufPrint(&wb, "fxstore gc: root 'world' — 0 store fact(s) and 0 dir(s) removed (2 live package name(s))\n", .{});
        try testing.expect(std.mem.indexOf(u8, out, want) != null);
    }
    try testing.expect(is_dir(io, world_final));
    try testing.expect(fact_exists(s.db, "store", whb[0..64], "world"));

    // NOW leave behind a srcstore fact + dir for an unreachable name (as an
    // old build might have left behind)
    {
        const c0 = cl.dl_intern_str(s.db, gh);
        const c1 = cl.dl_intern_str(s.db, "ghost");
        try testing.expect(c0 != 0 and c1 != 0);
        const cols = [2]u32{ c0, c1 };
        _ = dl_txn_begin(s.db);
        _ = dl_txn_add_fact(s.db, "srcstore", &cols, 2);
        _ = dl_txn_commit(s.db);
    }
    try testing.expect(fact_exists(s.db, "srcstore", gh, "ghost"));
    try Io.Dir.cwd().createDirPath(io, ghost_dir);

    // gc with root=hello: world + ghost are unreachable — metadata FIRST,
    // then dirs
    {
        var cap = try Capture.begin(out_path, err_path);
        cap.redirect();
        try fx_store_gc(io, s, "hello", &e);
        const out = try cap.end();
        defer testing.allocator.free(out);
        const want = try std.fmt.bufPrint(&wb, "fxstore gc: root 'hello' — 2 store fact(s) and 2 dir(s) removed (1 live package name(s))\n", .{});
        try testing.expect(std.mem.indexOf(u8, out, want) != null);
    }
    try testing.expect(!is_dir(io, world_final)); // dir swept
    try testing.expect(!fact_exists(s.db, "store", whb[0..64], "world")); // fact deleted
    try testing.expect(!fact_exists(s.db, "srcstore", gh, "ghost"));
    try testing.expect(!is_dir(io, ghost_dir)); // "-src" dir swept
    try testing.expect(is_dir(io, hello_final)); // live: untouched

    // malformed entries are reported (stderr), never deleted; a well-formed
    // but unreachable dir IS swept
    var gb2: [128:0]u8 = undefined;
    const garbage = try std.fmt.bufPrintZ(&gb2, "{s}/garbage", .{root});
    try Io.Dir.cwd().createDirPath(io, garbage);
    var nb2: [128:0]u8 = undefined;
    const notes = try std.fmt.bufPrintZ(&nb2, "{s}/notes.txt", .{root});
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = notes, .data = "keep me" });
    var lb: [128:0]u8 = undefined;
    const loner = try std.fmt.bufPrintZ(&lb, "{s}/{s}-loner", .{ root, "bb" ** 32 });
    try Io.Dir.cwd().createDirPath(io, loner);
    {
        var cap = try Capture.begin(out_path, err_path);
        cap.redirect();
        try fx_store_gc(io, s, "hello", &e);
        const out = try cap.end();
        defer testing.allocator.free(out);
        const errs = try cap.end_err();
        defer testing.allocator.free(errs);
        const want = try std.fmt.bufPrint(&wb, "fxstore gc: root 'hello' — 0 store fact(s) and 1 dir(s) removed (1 live package name(s))\n", .{});
        try testing.expect(std.mem.indexOf(u8, out, want) != null);
        try testing.expect(std.mem.indexOf(u8, errs, "fxstore: gc: skipping malformed store entry 'garbage'\n") != null);
        try testing.expect(std.mem.indexOf(u8, errs, "fxstore: gc: skipping malformed store entry 'notes.txt'\n") != null);
    }
    try testing.expect(is_dir(io, garbage)); // NOT deleted
    {
        // notes.txt is a FILE: assert it still exists (is_dir is false for it)
        const kept = Io.Dir.cwd().statFile(io, notes, .{}) catch null;
        try testing.expect(kept != null);
    }
    try testing.expect(!is_dir(io, loner)); // well-formed unreachable: swept

    // orphan scratch sweep: a dead-pid workdir in <root>.build and in the
    // legacy <root>/.tmp is reaped; a LIVE-pid one is never touched
    const dp = dead_pid();
    var sb: [320:0]u8 = undefined;
    var stale: ?[:0]u8 = null;
    if (dp != 0) {
        stale = try std.fmt.bufPrintZ(&sb, "{s}.build/x-{d}", .{ root, dp });
        try Io.Dir.cwd().createDirPath(io, stale.?);
    }
    var lb3: [320:0]u8 = undefined;
    const live_pid_dir = try std.fmt.bufPrintZ(&lb3, "{s}.build/y-{d}", .{ root, getpid() });
    try Io.Dir.cwd().createDirPath(io, live_pid_dir);
    var tb2: [320:0]u8 = undefined;
    const legacy = try std.fmt.bufPrintZ(&tb2, "{s}/.tmp", .{root});
    try Io.Dir.cwd().createDirPath(io, legacy);
    var sb2: [400:0]u8 = undefined;
    var stale_legacy: ?[:0]u8 = null;
    if (dp != 0) {
        stale_legacy = try std.fmt.bufPrintZ(&sb2, "{s}/z-{d}", .{ legacy, dp });
        try Io.Dir.cwd().createDirPath(io, stale_legacy.?);
    }
    {
        var cap = try Capture.begin(out_path, err_path);
        cap.redirect();
        try fx_store_gc(io, s, "hello", &e);
        const out = try cap.end();
        defer testing.allocator.free(out);
        const want = try std.fmt.bufPrint(&wb, "fxstore gc: root 'hello' — 0 store fact(s) and 0 dir(s) removed (1 live package name(s))\n", .{});
        try testing.expect(std.mem.indexOf(u8, out, want) != null);
    }
    if (stale) |sp| try testing.expect(!is_dir(io, sp)); // dead pid: swept
    if (stale_legacy) |sp| try testing.expect(!is_dir(io, sp)); // legacy .tmp: swept
    try testing.expect(is_dir(io, live_pid_dir)); // live pid: never touched
}

// ─── fx_store_current_version + fx_store_timeline ───────────────────────────

test "fx_store_current_version + fx_store_timeline: CURRENT file, fallback, exact lines" {
    const io = tio();
    var rb: [64:0]u8 = undefined;
    const root = try temp_root(&rb);
    defer cleanup_store(io, root);
    var e = ErrBuf{};
    const s = try fx_store_open(io, root, &e);
    defer fx_store_close(s);

    var ob: [96:0]u8 = undefined;
    var eb: [96:0]u8 = undefined;
    const out_path = try std.fmt.bufPrintZ(&ob, "{s}.out", .{root});
    const err_path = try std.fmt.bufPrintZ(&eb, "{s}.err", .{root});
    var wb: [512]u8 = undefined;

    // no published snapshot: timeline prints "no versions"; current errors
    {
        var cap = try Capture.begin(out_path, err_path);
        cap.redirect();
        try fx_store_timeline(io, s, &e);
        const out = try cap.end();
        defer testing.allocator.free(out);
        const want = try std.fmt.bufPrint(&wb, "fxstore: timeline of {s} (0 version(s)):\n  no versions\n", .{root});
        try testing.expectEqualStrings(want, out);
    }
    var cur: u32 = 0;
    try testing.expectError(error.FxStore, fx_store_current_version(io, s, &cur, &e));
    try testing.expectEqualStrings("no published snapshot in the store db — run a build first", e.slice());
    var eg = try EchoGuard.begin();
    defer eg.release();

    // v1: closure = {hello} (root hello; world merely depends on hello);
    // v2: after committing hello's store fact; v3: after committing world's
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var tbl = [_]Package{
        test_pkg("hello", &.{}),
        test_pkg("world", &.{"hello"}),
    };
    var pset: pkgs.PackageSet = .{ .arena = arena_inst };
    link(&pset, &tbl);
    var de = drv.ErrBuf{};
    var fpb: [4 * FX_PATH_MAX]u8 = undefined;
    var ce = cl.ErrBuf{};
    try cl.fx_closure_compute(s.db, &pset, &.{"hello"}, &ce); // publishes v1
    try build_pkg(io, s, &tbl[0], &.{}, &.{}, &e);
    try fx_store_publish(s, &e); // v2
    const hello_final = try drv.fx_derivation_store_path(io, &tbl[0], &.{}, root, &fpb, &de);
    try build_pkg(io, s, &tbl[1], &.{"hello"}, &.{hello_final}, &e);
    try fx_store_publish(s, &e); // v3 (world's own fact committed)

    try fx_store_current_version(io, s, &cur, &e);
    try testing.expectEqual(@as(u32, 3), cur);

    {
        var cap = try Capture.begin(out_path, err_path);
        cap.redirect();
        try fx_store_timeline(io, s, &e);
        const out = try cap.end();
        defer testing.allocator.free(out);
        const head = try std.fmt.bufPrint(&wb, "fxstore: timeline of {s} (3 version(s)):\n", .{root});
        try testing.expect(std.mem.startsWith(u8, out, head));
        const l1 = try std.fmt.bufPrint(&wb, "  1 roots: hello  closure: 1  store: 0  srcstore: 0\n", .{});
        try testing.expect(std.mem.indexOf(u8, out, l1) != null);
        const l2 = try std.fmt.bufPrint(&wb, "  2 roots: hello  closure: 1  store: 1  srcstore: 0\n", .{});
        try testing.expect(std.mem.indexOf(u8, out, l2) != null);
        const l3 = try std.fmt.bufPrint(&wb, "  3 [CURRENT] roots: hello  closure: 1  store: 2  srcstore: 0\n", .{});
        try testing.expect(std.mem.indexOf(u8, out, l3) != null);
    }

    // CURRENT-file parse + fallback: junk, zero, and whitespace-prefixed
    var cb: [256:0]u8 = undefined;
    const cur_file = try std.fmt.bufPrintZ(&cb, "{s}/.db/snapshots/CURRENT", .{root});
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = cur_file, .data = "junk\n" });
    try fx_store_current_version(io, s, &cur, &e);
    try testing.expectEqual(@as(u32, 3), cur); // parse fail -> highest published
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = cur_file, .data = "0\n" });
    try fx_store_current_version(io, s, &cur, &e);
    try testing.expectEqual(@as(u32, 3), cur); // v > 0 required
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = cur_file, .data = "  2\n" });
    try fx_store_current_version(io, s, &cur, &e);
    try testing.expectEqual(@as(u32, 2), cur); // %lu skips leading whitespace
}

// ─── fx_store_rollback ──────────────────────────────────────────────────────

test "fx_store_rollback: roll-forward restores facts + re-derives closure; hard repoints CURRENT" {
    const io = tio();
    var rb: [64:0]u8 = undefined;
    const root = try temp_root(&rb);
    defer cleanup_store(io, root);
    var e = ErrBuf{};
    const s = try fx_store_open(io, root, &e);
    defer fx_store_close(s);

    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var tbl = [_]Package{
        test_pkg("hello", &.{}),
        test_pkg("world", &.{"hello"}),
    };
    var pset: pkgs.PackageSet = .{ .arena = arena_inst };
    link(&pset, &tbl);
    var eg = try EchoGuard.begin();
    defer eg.release();

    var ce = cl.ErrBuf{};
    try cl.fx_closure_compute(s.db, &pset, &.{}, &ce); // v1
    try build_pkg(io, s, &tbl[0], &.{}, &.{}, &e);
    try fx_store_publish(s, &e); // v2: store = {hello}
    var fpb: [4 * FX_PATH_MAX]u8 = undefined;
    var de = drv.ErrBuf{};
    const hello_final = try drv.fx_derivation_store_path(io, &tbl[0], &.{}, root, &fpb, &de);
    try build_pkg(io, s, &tbl[1], &.{"hello"}, &.{hello_final}, &e);
    try fx_store_publish(s, &e); // v3: store = {hello,world}

    var cur: u32 = 0;
    try fx_store_current_version(io, s, &cur, &e);
    try testing.expectEqual(@as(u32, 3), cur);
    var hhb: [65]u8 = undefined;
    try drv.fx_derivation_hash(io, &tbl[0], &.{}, &hhb, &de);
    var whb: [65]u8 = undefined;
    try drv.fx_derivation_hash(io, &tbl[1], &.{hello_final}, &whb, &de);
    try testing.expect(fact_exists(s.db, "store", hhb[0..64], "hello"));
    try testing.expect(fact_exists(s.db, "store", whb[0..64], "world"));

    // unknown version
    try testing.expectError(error.FxStore, fx_store_rollback(s, 99, false, &e));
    try testing.expectEqualStrings("no such version 99 (have 3 version(s))", e.slice());

    // roll-forward to v2: store facts restored to v2's, closure re-derived,
    // two new versions, CURRENT advances
    try fx_store_rollback(s, 2, false, &e);
    try testing.expect(fact_exists(s.db, "store", hhb[0..64], "hello"));
    try testing.expect(!fact_exists(s.db, "store", whb[0..64], "world"));
    const names = try cl.fx_closure_names(s.db, &ce);
    defer cl.free_names(names);
    try testing.expectEqual(@as(usize, 2), names.len); // v2's EDB: both pkgs
    try fx_store_current_version(io, s, &cur, &e);
    try testing.expectEqual(@as(u32, 5), cur); // 3 + 2 new versions
    const total = dl_snapshot_versions(s.db, null, 0);
    try testing.expectEqual(@as(c_long, 5), total);

    // hard rollback: repoints CURRENT, no new version, no fact mutation
    try fx_store_rollback(s, 3, true, &e);
    try fx_store_current_version(io, s, &cur, &e);
    try testing.expectEqual(@as(u32, 3), cur);
    try testing.expectEqual(@as(c_long, 5), dl_snapshot_versions(s.db, null, 0));
    try testing.expect(!fact_exists(s.db, "store", whb[0..64], "world")); // unchanged

    // a store with no published snapshot is an error
    var rb2: [64:0]u8 = undefined;
    const root2 = try temp_root(&rb2);
    defer cleanup_store(io, root2);
    const s2 = try fx_store_open(io, root2, &e);
    defer fx_store_close(s2);
    try testing.expectError(error.FxStore, fx_store_rollback(s2, 1, false, &e));
    try testing.expectEqualStrings("no published snapshot in the store db — run a build first", e.slice());
}

// ─── ported U4: snapshot-complete rollback over install/provides/boot_grace ──

/// Collect the LIVE (WAL-replayed) tuples of `rel` via dl_prefix — the one
/// reader that ignores the pinned snapshot (dl.h CAVEAT: dl_query/dl_iter
/// prefer the newest published snapshot) — exactly what the rollback swap
/// clears.  Test-only mirror of fx-init's U4 live_rows helper.
const LiveRows = struct {
    rows: [16][8]u32 = undefined,
    n: usize = 0,

    fn cb(cols: [*]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
        const self: *LiveRows = @ptrCast(@alignCast(user.?));
        if (self.n >= 16 or arity > 8) return 1;
        var i: u8 = 0;
        while (i < arity) : (i += 1) self.rows[self.n][i] = cols[i];
        self.n += 1;
        return 0;
    }
};

fn live_rows(db: *DlDb, rel: [*:0]const u8) !LiveRows {
    var out = LiveRows{};
    const n = dl_prefix(db, rel, null, 0, LiveRows.cb, &out);
    if (n < 0) return error.PrefixFailed;
    return out;
}

fn sym_of(db: *DlDb, id: u32) []const u8 {
    const p = cl.dl_intern_str_of(db, id) orelse "";
    return std.mem.span(p);
}

fn str_lt(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

/// Set-equality on canonicalized, sorted lines (expectEqualSlices compares
/// slice ELEMENTS — pointer identity for strings, not bytes).
fn expect_lines(expected: []const []const u8, actual: []const []const u8) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |x, a| try testing.expectEqualStrings(x, a);
}

test "fx_store_rollback: snapshot-complete swap restores every recorded relation (U4)" {
    const io = tio();
    var rb: [64:0]u8 = undefined;
    const root = try temp_root(&rb);
    defer cleanup_store(io, root);
    var e = ErrBuf{};
    const s = try fx_store_open(io, root, &e);
    defer fx_store_close(s);
    const db = s.db;

    const ha = "a" ** 64;
    const hb = "b" ** 64;
    const hz = "c" ** 64;
    const gen = "ef" ** 32;

    // fixture fact writers — the activate.zig encoding (fx-init init.zig
    // U4): symbol columns via dl_intern_str, mode/ms RAW u32 columns.
    const F = struct {
        fn install(d: *DlDb, target: [:0]const u8, origin: [:0]const u8, mode: u32, gh: [:0]const u8) !void {
            const cols = [4]u32{ cl.dl_intern_str(d, target.ptr), cl.dl_intern_str(d, origin.ptr), mode, cl.dl_intern_str(d, gh.ptr) };
            if (dl_txn_add_fact(d, "install", &cols, 4) != 0) return error.AddFact;
        }
        fn del_install(d: *DlDb, target: [:0]const u8, origin: [:0]const u8, mode: u32, gh: [:0]const u8) !void {
            const cols = [4]u32{ cl.dl_intern_str(d, target.ptr), cl.dl_intern_str(d, origin.ptr), mode, cl.dl_intern_str(d, gh.ptr) };
            if (dl_txn_delete_fact(d, "install", &cols, 4) != 0) return error.DelFact;
        }
        fn provides(d: *DlDb, pkg: [:0]const u8, sdir: [:0]const u8) !void {
            const cols = [2]u32{ cl.dl_intern_str(d, pkg.ptr), cl.dl_intern_str(d, sdir.ptr) };
            if (dl_txn_add_fact(d, "provides", &cols, 2) != 0) return error.AddFact;
        }
        fn del_provides(d: *DlDb, pkg: [:0]const u8, sdir: [:0]const u8) !void {
            const cols = [2]u32{ cl.dl_intern_str(d, pkg.ptr), cl.dl_intern_str(d, sdir.ptr) };
            if (dl_txn_delete_fact(d, "provides", &cols, 2) != 0) return error.DelFact;
        }
        fn boot_grace(d: *DlDb, ms: u32) !void {
            const cols = [1]u32{ms}; // RAW u32 column
            if (dl_txn_add_fact(d, "boot_grace", &cols, 1) != 0) return error.AddFact;
        }
        fn del_boot_grace(d: *DlDb, ms: u32) !void {
            const cols = [1]u32{ms};
            if (dl_txn_delete_fact(d, "boot_grace", &cols, 1) != 0) return error.DelFact;
        }
    };

    // v1: a PRE-prov snapshot — boot_grace only, plus the minimal pkg/root
    // EDB fx_closure_rebuild re-derives closure from.  install/provides are
    // not even declared (the old-snapshot shape rollback must tolerate).
    try testing.expectEqual(@as(c_int, 0), cl.dl_declare_relation(db, "boot_grace", 1));
    try testing.expectEqual(@as(c_int, 0), cl.dl_declare_relation(db, "pkg", 1));
    try testing.expectEqual(@as(c_int, 0), cl.dl_declare_relation(db, "dep", 2));
    try testing.expectEqual(@as(c_int, 0), cl.dl_declare_relation(db, "root", 1));
    {
        try testing.expectEqual(@as(c_int, 0), dl_txn_begin(db));
        try F.boot_grace(db, 30000);
        const pkg_a = [1]u32{cl.dl_intern_str(db, "a")};
        const pkg_b = [1]u32{cl.dl_intern_str(db, "b")};
        const root_a = [1]u32{cl.dl_intern_str(db, "a")};
        try testing.expectEqual(@as(c_int, 0), dl_txn_add_fact(db, "pkg", &pkg_a, 1));
        try testing.expectEqual(@as(c_int, 0), dl_txn_add_fact(db, "pkg", &pkg_b, 1));
        try testing.expectEqual(@as(c_int, 0), dl_txn_add_fact(db, "root", &root_a, 1));
        try testing.expectEqual(@as(c_int, 0), dl_txn_commit(db));
    }
    try testing.expectEqual(@as(c_int, 0), cl.dl_publish_snapshot(db)); // v1

    // v2: a good activation (install x2 / provides x2 / boot_grace 15000).
    try testing.expectEqual(@as(c_int, 0), cl.dl_declare_relation(db, "install", 4));
    try testing.expectEqual(@as(c_int, 0), cl.dl_declare_relation(db, "provides", 2));
    {
        try testing.expectEqual(@as(c_int, 0), dl_txn_begin(db));
        try F.del_boot_grace(db, 30000);
        try F.boot_grace(db, 15000);
        try F.install(db, "/bin/hello", ha ++ "-hello", 0, gen);
        try F.install(db, "/etc/motd", gen ++ "-system-generation/etc/motd", 0o644, gen);
        try F.provides(db, "hello", ha ++ "-hello");
        try F.provides(db, "world", hb ++ "-world");
        try testing.expectEqual(@as(c_int, 0), dl_txn_commit(db));
    }
    try testing.expectEqual(@as(c_int, 0), cl.dl_publish_snapshot(db)); // v2

    // v3: the failed activation — divergent facts under a different
    // genhash, published (what production pins for the clear enumeration).
    {
        try testing.expectEqual(@as(c_int, 0), dl_txn_begin(db));
        try F.del_install(db, "/bin/hello", ha ++ "-hello", 0, gen);
        try F.del_install(db, "/etc/motd", gen ++ "-system-generation/etc/motd", 0o644, gen);
        try F.del_provides(db, "hello", ha ++ "-hello");
        try F.del_provides(db, "world", hb ++ "-world");
        try F.del_boot_grace(db, 15000);
        try F.install(db, "/bin/evil", hz ++ "-evil", 0, hz);
        try F.provides(db, "evil", hz ++ "-evil");
        try F.boot_grace(db, 9999);
        try testing.expectEqual(@as(c_int, 0), dl_txn_commit(db));
    }
    try testing.expectEqual(@as(c_int, 0), cl.dl_publish_snapshot(db)); // v3
    try testing.expectEqual(@as(c_long, 3), dl_snapshot_versions(db, null, 0));

    // Live-set canonicalizer: install/provides/boot_grace rows to lines.
    const Canon = struct {
        db: *DlDb,
        lines: [16][]const u8 = undefined,
        bufs: [16][320]u8 = undefined,
        n: usize = 0,

        fn add(self: *@This(), comptime fmt: []const u8, args: anytype) void {
            self.lines[self.n] = std.fmt.bufPrint(&self.bufs[self.n], fmt, args) catch unreachable;
            self.n += 1;
        }
        fn install(self: *@This(), lr: LiveRows) void {
            for (lr.rows[0..lr.n]) |r| self.add("{s}|{s}|0o{o}|{s}", .{
                sym_of(self.db, r[0]), sym_of(self.db, r[1]), r[2], sym_of(self.db, r[3]),
            });
        }
        fn provides(self: *@This(), lr: LiveRows) void {
            for (lr.rows[0..lr.n]) |r| self.add("{s}|{s}", .{ sym_of(self.db, r[0]), sym_of(self.db, r[1]) });
        }
        fn boot_grace(self: *@This(), lr: LiveRows) void {
            for (lr.rows[0..lr.n]) |r| self.add("{d}", .{r[0]});
        }
        fn sorted(self: *@This()) []const []const u8 {
            std.mem.sort([]const u8, self.lines[0..self.n], {}, str_lt);
            return self.lines[0..self.n];
        }
    };

    const exp_install = [_][]const u8{
        "/bin/hello|" ++ ha ++ "-hello|0o0|" ++ gen,
        "/etc/motd|" ++ gen ++ "-system-generation/etc/motd|0o644|" ++ gen,
    };
    const exp_provides = [_][]const u8{
        "hello|" ++ ha ++ "-hello",
        "world|" ++ hb ++ "-world",
    };

    // arm (a) — THE gap fix: rollback to v2 restores install/provides
    // exactly and clears v3's evil facts (live reads via dl_prefix).
    try fx_store_rollback(s, 2, false, &e);
    {
        var c = Canon{ .db = db };
        c.install(try live_rows(db, "install"));
        try expect_lines(&exp_install, c.sorted());
    }
    {
        var c = Canon{ .db = db };
        c.provides(try live_rows(db, "provides"));
        try expect_lines(&exp_provides, c.sorted());
    }
    {
        var c = Canon{ .db = db };
        c.boot_grace(try live_rows(db, "boot_grace"));
        const exp = [_][]const u8{"15000"};
        try expect_lines(&exp, c.sorted());
    }
    {
        // closure re-derived from v2's restored pkg/dep/root EDB
        var ce = cl.ErrBuf{};
        const names = try cl.fx_closure_names(db, &ce);
        defer cl.free_names(names);
        try testing.expectEqual(@as(usize, 1), names.len); // root a (dep empty)
    }

    // arm (b) — the dl_prefix arm: a committed-but-UNPUBLISHED txn (crash
    // between an activation's commit and its publish) leaves live tuples the
    // newest snapshot lacks; the swap's live clear must still catch them
    // (publish-first folds them into a version, dl_prefix clears them).
    try testing.expectEqual(@as(c_int, 0), dl_txn_begin(db));
    try F.del_install(db, "/bin/hello", ha ++ "-hello", 0, gen);
    try F.install(db, "/bin/ghost", hz ++ "-ghost", 0, hz);
    try F.del_provides(db, "world", hb ++ "-world");
    try F.provides(db, "ghost", hz ++ "-ghost");
    try F.del_boot_grace(db, 15000);
    try F.boot_grace(db, 4242);
    try testing.expectEqual(@as(c_int, 0), dl_txn_commit(db));
    // deliberately NO publish before the rollback
    try fx_store_rollback(s, 2, false, &e);
    {
        var c = Canon{ .db = db };
        c.install(try live_rows(db, "install"));
        try expect_lines(&exp_install, c.sorted());
    }
    {
        var c = Canon{ .db = db };
        c.provides(try live_rows(db, "provides"));
        try expect_lines(&exp_provides, c.sorted());
    }
    {
        var c = Canon{ .db = db };
        c.boot_grace(try live_rows(db, "boot_grace"));
        const exp = [_][]const u8{"15000"};
        try expect_lines(&exp, c.sorted());
    }

    // arm (c) — rollback to the pre-prov v1: install/provides absent from
    // v1's manifest => absent-as-empty (cleared, nothing re-added), while
    // v1's boot_grace comes back.
    try fx_store_rollback(s, 1, false, &e);
    {
        var c = Canon{ .db = db };
        c.install(try live_rows(db, "install"));
        try testing.expectEqual(@as(usize, 0), c.sorted().len);
    }
    {
        var c = Canon{ .db = db };
        c.provides(try live_rows(db, "provides"));
        try testing.expectEqual(@as(usize, 0), c.sorted().len);
    }
    {
        var c = Canon{ .db = db };
        c.boot_grace(try live_rows(db, "boot_grace"));
        const exp = [_][]const u8{"30000"};
        try expect_lines(&exp, c.sorted());
    }
    {
        var ce = cl.ErrBuf{};
        const names = try cl.fx_closure_names(db, &ce);
        defer cl.free_names(names);
        try testing.expectEqual(@as(usize, 1), names.len);
    }

    // version accounting: 3 fixtures + 3 rollbacks x (publish + closure
    // rebuild) = 9, CURRENT at the newest.
    try testing.expectEqual(@as(c_long, 9), dl_snapshot_versions(db, null, 0));
    var cur: u32 = 0;
    try fx_store_current_version(io, s, &cur, &e);
    try testing.expectEqual(@as(u32, 9), cur);
}

// ─── fx_store_gc_retain ─────────────────────────────────────────────────────

test "fx_store_gc_retain: N >= 1, prune at publish, --hard CURRENT guard" {
    const io = tio();
    var rb: [64:0]u8 = undefined;
    const root = try temp_root(&rb);
    defer cleanup_store(io, root);
    var e = ErrBuf{};
    const s = try fx_store_open(io, root, &e);
    defer fx_store_close(s);

    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    var tbl = [_]Package{
        test_pkg("hello", &.{}),
        test_pkg("world", &.{"hello"}),
    };
    var pset: pkgs.PackageSet = .{ .arena = arena_inst };
    link(&pset, &tbl);
    var eg = try EchoGuard.begin();
    defer eg.release();

    var ce = cl.ErrBuf{};
    try cl.fx_closure_compute(s.db, &pset, &.{}, &ce); // v1
    try build_pkg(io, s, &tbl[0], &.{}, &.{}, &e);
    try fx_store_publish(s, &e); // v2
    var fpb: [4 * FX_PATH_MAX]u8 = undefined;
    var de = drv.ErrBuf{};
    const hello_final = try drv.fx_derivation_store_path(io, &tbl[0], &.{}, root, &fpb, &de);
    try build_pkg(io, s, &tbl[1], &.{"hello"}, &.{hello_final}, &e);
    try fx_store_publish(s, &e); // v3
    try testing.expectEqual(@as(c_long, 3), dl_snapshot_versions(s.db, null, 0));
    var whb: [65]u8 = undefined;
    try drv.fx_derivation_hash(io, &tbl[1], &.{hello_final}, &whb, &de);

    // n = 0 is rejected
    try testing.expectError(error.FxStore, fx_store_gc_retain(io, s, 0, &e));
    try testing.expectEqualStrings("gc --retain requires N >= 1", e.slice());

    // keep the 2 most-recent versions (prune applied at the publish); the
    // retain publish itself advances CURRENT to the new version (v4)
    try fx_store_gc_retain(io, s, 2, &e);
    try testing.expectEqual(@as(c_long, 2), dl_snapshot_versions(s.db, null, 0));
    var cur: u32 = 0;
    try fx_store_current_version(io, s, &cur, &e);
    try testing.expectEqual(@as(u32, 4), cur);

    // --hard guard: CURRENT no longer the newest -> refuse loudly (v2 was
    // pruned, so repoint at the older RETAINED version v3)
    try fx_store_rollback(s, 3, true, &e);
    try testing.expectError(error.FxStore, fx_store_gc_retain(io, s, 1, &e));
    const want = "CURRENT (3) is not the newest version (4) — a 'rollback --hard' repointed it; " ++
        "fix that first ('fxstore rollback --hard 4'), then retry gc --retain";
    try testing.expectEqualStrings(want, e.slice());

    // after fixing CURRENT the prune goes through: only the newest remains
    try fx_store_rollback(s, 4, true, &e);
    try fx_store_gc_retain(io, s, 1, &e);
    try testing.expectEqual(@as(c_long, 1), dl_snapshot_versions(s.db, null, 0));
    try fx_store_current_version(io, s, &cur, &e);
    try testing.expectEqual(@as(u32, 5), cur); // the prune publish created v5
    try testing.expect(fact_exists(s.db, "store", whb[0..64], "world")); // v5 facts intact
}
