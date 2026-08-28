// derivation.zig — faithful Zig port of derivation.c (U2): the canonical
// derivation serializer, the sha256 store path, and the clean-source Merkle
// hash (+ optional streaming copy) behind THE CONTENT-ADDRESSING CONTRACT:
//
//     <store_root>/<hex64>-<name>,  hex64 = sha256_hex(canonical_derivation(P))
//
// BYTE-EXACTNESS: this module must hash identically to the C — store paths
// are the content addresses of the whole system.  Every serialization choice
// below is pinned to derivation.c: strings are u32-BIG-ENDIAN length-prefixed
// (never NUL- or whitespace-delimited — paths and commands may contain
// either), lists are u32-BE counts, tags are the positionally fixed bytes
// S C M R T V L H E N X, dep paths are sorted with strcmp byte order, and
// clean-tree children are streamed sorted by name.  sha256_hex is dhall-c's
// FIPS 180-4 (dhall_mod.sha256 — the very implementation the C links), so
// digests are byte-identical by construction.  Goldens from the real C are
// pinned in the tests at the bottom (see zig/corpus/derivation/).
//
// DIFFERENCES FROM C (mechanical only — never byte-level):
//   * Every filesystem op takes the 0.16 `io: std.Io` interface (the C calls
//     libc directly).  Tests pass std.testing.io; main() passes init.io.
//   * The per-call scratch (child paths, DirEnt table) lives in one arena per
//     fx_clean_tree call instead of malloc/free at every goto label.
//   * libc strerror(errno) text is reproduced by a small error->message table
//     (errstr) so the fx_err messages read the same.
//   * A readdir error aborts the walk loudly; the C's readdir loop cannot
//     detect one (NULL == EOF there) and would silently hash a truncated
//     stream — a C bug not worth reproducing.
const std = @import("std");
const dhall = @import("dhall");
const ps = @import("packageset");

const sha256_hex = dhall.sha256.sha256_hex;

// The U1 types this module serializes (packageset.zig).
const ActionKind = ps.ActionKind;
const Action = ps.Action;
const Package = ps.Package;

const Io = std.Io;
const File = Io.File;
const c_alloc = std.heap.c_allocator;

pub const Error = error{FxDerivation};

pub const err_cap_default = 2048;

/// The fx_err helper (fxstore.h) as a context struct: the C threads
/// `char *err, size_t errcap` through every entry point and signals failure
/// by return value; here every failure path calls ErrBuf.set (with the
/// verbatim derivation.c format string) and returns error.FxDerivation.
pub const ErrBuf = struct {
    buf: [err_cap_default]u8 = undefined,
    len: usize = 0,

    pub fn set(self: *ErrBuf, comptime fmt: []const u8, args: anytype) error{FxDerivation} {
        var aw: std.Io.Writer.Allocating = .init(c_alloc);
        defer aw.deinit();
        aw.writer.print(fmt, args) catch unreachable;
        const s = aw.written();
        const n = @min(s.len, self.buf.len - 1);
        @memcpy(self.buf[0..n], s[0..n]);
        self.buf[n] = 0;
        self.len = n;
        return error.FxDerivation;
    }

    pub fn slice(self: *const ErrBuf) []const u8 {
        return self.buf[0..self.len];
    }
};

/// strerror(errno) text for the errors this module can surface, so the
/// fx_err messages read exactly like the C's "%s: %s" + strerror pairs.
fn errstr(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "No such file or directory",
        error.AccessDenied, error.PermissionDenied => "Permission denied",
        error.NotDir => "Not a directory",
        error.IsDir => "Is a directory",
        error.NameTooLong => "File name too long",
        error.NoSpaceLeft => "No space left on device",
        error.SymLinkLoop => "Too many levels of symbolic links",
        error.PathAlreadyExists => "File exists",
        error.DirNotEmpty => "Directory not empty",
        error.NotSameFileSystem => "Invalid cross-device link",
        error.InputOutput => "Input/output error",
        error.NoDevice => "No such device",
        error.FileBusy => "Text file busy",
        // readlink on a non-symlink: C sees EINVAL
        error.NotLink => "Invalid argument",
        error.SystemResources => "Cannot allocate memory",
        error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => "Too many open files",
        else => @errorName(err),
    };
}

// ─── Growable byte buffer (derivation.c:53-93) ──────────────────────────────

const Buf = struct {
    list: std.ArrayList(u8) = .empty,

    fn deinit(self: *Buf) void {
        self.list.deinit(c_alloc);
    }

    fn put(self: *Buf, bytes: []const u8, e: *ErrBuf) Error!void {
        self.list.appendSlice(c_alloc, bytes) catch return e.set("out of memory", .{});
    }

    /// u32 big-endian (network order): machine-independent canonical lengths
    fn u32be(self: *Buf, v: u32, e: *ErrBuf) Error!void {
        try self.put(&.{
            @truncate(v >> 24), @truncate(v >> 16),
            @truncate(v >> 8),  @truncate(v),
        }, e);
    }

    fn byte(self: *Buf, ch: u8, e: *ErrBuf) Error!void {
        try self.put(&.{ch}, e);
    }

    /// canonical string: u32-BE length + raw bytes, NO NUL terminator
    fn str(self: *Buf, s: []const u8, e: *ErrBuf) Error!void {
        if (s.len > 0xFFFFFFFF)
            return e.set("string too long for u32 length: {s}...", .{s[0..32]});
        try self.u32be(@intCast(s.len), e);
        try self.put(s, e);
    }
};

// ─── Clean-source exclusion table (derivation.c:111-132) ────────────────────
// 'Clean' = the source inputs a `make -B <target>` recipe recompiles from.
// Everything else — git/checkout state, committed build binaries, caches —
// must NOT influence the store path, so it is EXCLUDED from the clean-tree
// hash AND from the materialized clean copy.  Excluded entries are SILENT
// SKIPS, not errors — a source tree may legitimately contain them, and the
// hash must be independent of their presence/absence.  Everything else (data
// files, .dhall, .md, headers, hidden files) is SOURCE and is hashed/copied.
fn fx_clean_excluded(basename: []const u8, is_dir: bool) bool {
    // matches BOTH a top-level .git directory AND a submodule gitfile
    if (std.mem.eql(u8, basename, ".git")) return true;
    if (is_dir) {
        const dirs = [_][]const u8{ ".cache", "build", "build-tmp", "__pycache__", ".py-site", "pydl" };
        for (dirs) |d| {
            if (std.mem.eql(u8, basename, d)) return true;
        }
        return std.mem.startsWith(u8, basename, "dl-test-");
    }
    const exts = [_][]const u8{ ".o", ".a", ".so", ".com", ".dbg", ".elf", ".wasm" };
    for (exts) |ext| {
        // basename.len > ext.len: a file named exactly ".o" is NOT excluded
        if (basename.len > ext.len and std.mem.endsWith(u8, basename, ext)) return true;
    }
    return std.mem.startsWith(u8, basename, ".ape-");
}

/// Per-package exclusion: `entry` is a RELATIVE-PATH-PREFIX within the src
/// tree.  A child with relative path `rel` is excluded when rel==entry OR rel
/// starts with entry+"/" (i.e. entry is an ancestor directory path-prefix).
/// Empty list excludes nothing.  Applied on top of fx_clean_excluded,
/// identically in hash and copy modes so the store path is the same whether
/// the caller hashes (compute_paths) or materializes (fx_store_ensure_source).
fn fx_excluded_by_rel(rel: []const u8, excludes: []const []const u8) bool {
    for (excludes) |entry| {
        if (entry.len == 0) continue; // defense-in-depth: empty entries are
        // rejected at parse time
        if (std.mem.startsWith(u8, rel, entry) and
            (rel.len == entry.len or rel[entry.len] == '/'))
            return true;
    }
    return false;
}

// ─── File content hashing (with optional streaming copy) ────────────────────

/// sha256 of a regular file's bytes; when `dst` is non-NULL the file is
/// copied to it in the SAME single pass, so the bytes written are exactly the
/// bytes hashed — the copy-mode hash is byte-identical to the hash-only walk
/// BY CONSTRUCTION (no second serializer to drift).  The mode is NOT part of
/// the hash (only bytes + type byte), but in copy mode the written file is
/// chmod'd to the SOURCE mode (preserving e.g. the exec bit for checked-in
/// scripts) so the clean copy faithfully mirrors the source.
fn sha256_file_copy(
    io: Io,
    a: std.mem.Allocator,
    path: []const u8,
    dst: ?[]const u8,
    src_mode: u32,
    out: *[65]u8,
    e: *ErrBuf,
) Error!void {
    const root = Io.Dir.cwd();
    var f = root.openFile(io, path, .{}) catch |err|
        return e.set("cannot open source file '{s}': {s}", .{ path, errstr(err) });
    defer f.close(io);
    const st = f.stat(io) catch |err|
        return e.set("read error on '{s}': {s}", .{ path, errstr(err) });
    const bytes = a.alloc(u8, @intCast(st.size)) catch return e.set("out of memory", .{});
    defer a.free(bytes);
    _ = f.readPositionalAll(io, bytes, 0) catch |err|
        return e.set("read error on '{s}': {s}", .{ path, errstr(err) });

    if (dst) |dd| {
        var g = root.createFile(io, dd, .{ .read = false, .truncate = true }) catch |err|
            return e.set("cannot create '{s}': {s}", .{ dd, errstr(err) });
        defer g.close(io);
        g.writeStreamingAll(io, bytes) catch
            return e.set("write error on '{s}'", .{dd});
        // 01777 (not 07777): mask setuid/setgid off FILES — a build store must
        // never materialize a setuid binary owned by the building user from
        // source-tree content (inert in a single-user store, a real hazard on
        // a shared/root store).  Sticky bit (01000) kept; dir setgid/sticky
        // are handled separately in fx_clean_tree_rel and are harmless.
        g.setPermissions(io, File.Permissions.fromMode(src_mode & 0o1777)) catch |err|
            return e.set("cannot chmod '{s}': {s}", .{ dd, errstr(err) });
    }
    sha256_hex(bytes, out);
}

// ─── fx_clean_tree — clean Merkle hash of a source tree + optional copy ─────
// The ONE Merkle serializer, in two modes:
//   dst == null : hash-only walk (compute_paths' source hashing, verify)
//   dst != null : copy+hash in a single walk (fx_store_ensure_source) —
//                 dirs are mkdir'd, files stream-copied, symlinks recreated,
//                 ALL with the SAME serializer as the hash-only mode, so the
//                 materialized copy's hash == the hash-only walk's hash.
// Stream = for each NON-EXCLUDED direct child of `dir` (SORTED by name,
// strcmp): buf_str(child_name) + byte 'd'|'f'|'l' + buf_str(child content
// hash); a directory child's hash is its own recursive stream hash, a regular
// file child's is sha256 of its bytes, a symlink child's is sha256 of its
// readlink target (type 'l' — preserved from the original hashing).  The
// returned hash is sha256 over the top-level stream.  Hidden files are
// CONTENT (only "." and ".." are skipped); excluded entries are SILENT SKIPS;
// special files (sockets, devices, fifos) are rejected loudly.
// PER-PACKAGE EXCLUDES: `excludes` (may be empty) add RELATIVE-PATH-PREFIX
// patterns on top of the global table — applied in BOTH modes, so copy-hash
// == walk-hash stays true even with excludes.  In copy mode created
// dirs/files are chmod'd to the SOURCE mode (mode bits are NOT hashed, so
// store paths are unaffected).
const DirEnt = struct {
    name: []const u8,
    hash: [65]u8,
    type: u8, // 'd' | 'f' | 'l'
};

fn dirent_lt(_: void, a: DirEnt, b: DirEnt) bool {
    // strcmp byte order (unsigned, locale-independent)
    return std.mem.order(u8, a.name, b.name) == .lt;
}

fn str_lt(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// Recursive core of fx_clean_tree.  `rel` is the child's RELATIVE path within
/// the src tree ("" at the root) — used for per-package path-prefix excludes,
/// which are applied identically in hash and copy modes.  In copy mode the
/// created dirs/files are chmod'd to the source mode (mode is NOT hashed).
fn fx_clean_tree_rel(
    io: Io,
    a: std.mem.Allocator,
    dir: []const u8,
    dst: ?[]const u8,
    excludes: []const []const u8,
    rel: []const u8,
    hash_out: *[65]u8,
    e: *ErrBuf,
) Error!void {
    const root = Io.Dir.cwd();
    var d = root.openDir(io, dir, .{ .iterate = true }) catch |err|
        return e.set("cannot open source dir '{s}': {s}", .{ dir, errstr(err) });
    defer d.close(io);

    var ents: std.ArrayList(DirEnt) = .empty;
    defer {
        for (ents.items) |ent| a.free(ent.name);
        ents.deinit(a);
    }

    var it = d.iterate();
    while (it.next(io) catch |err|
        return e.set("cannot read dir '{s}': {s}", .{ dir, errstr(err) }))
    |entry|
    {
        const name = entry.name;
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        // full child path (bounded: dir + '/' + name)
        const child = std.fmt.allocPrint(a, "{s}/{s}", .{ dir, name }) catch
            return e.set("out of memory", .{});
        defer a.free(child);

        const st = root.statFile(io, child, .{ .follow_symlinks = false }) catch |err|
            return e.set("cannot stat '{s}': {s}", .{ child, errstr(err) });
        const mode: u32 = @intFromEnum(st.permissions);

        // relative path of this child within the src tree (for excludes)
        const child_rel = if (rel.len > 0)
            std.fmt.allocPrint(a, "{s}/{s}", .{ rel, name }) catch return e.set("out of memory", .{})
        else
            a.dupe(u8, name) catch return e.set("out of memory", .{});
        defer a.free(child_rel);

        // silent skip of excluded entries — global table (git state, committed
        // binaries, caches) AND per-package path-prefix excludes
        if (fx_clean_excluded(name, st.kind == .directory) or
            fx_excluded_by_rel(child_rel, excludes)) continue;

        // copy-mode destination child path (null in hash-only mode)
        const dchild: ?[]const u8 = if (dst) |dd|
            std.fmt.allocPrint(a, "{s}/{s}", .{ dd, name }) catch return e.set("out of memory", .{})
        else
            null;
        defer if (dchild) |dc| a.free(dc);

        var ent = DirEnt{ .name = &.{}, .hash = undefined, .type = 0 };

        if (st.kind == .directory) {
            ent.type = 'd';
            if (dchild) |dc| {
                root.createDir(io, dc, File.Permissions.fromMode(0o755)) catch |err|
                    return e.set("cannot create '{s}': {s}", .{ dc, errstr(err) });
            }
            try fx_clean_tree_rel(io, a, child, dchild, excludes, child_rel, &ent.hash, e);
            // preserve the source dir mode AFTER filling the copy: applying it
            // before the recursion would strip the owner-write bit from a
            // read-only source dir (e.g. `chmod -R a-w vendor`) and make every
            // child creation inside it fail with EACCES.  (Mode is NOT hashed,
            // so ordering cannot affect the store path.)
            if (dchild) |dc| {
                root.setFilePermissions(io, dc, File.Permissions.fromMode(mode & 0o7777), .{}) catch |err|
                    return e.set("cannot chmod '{s}': {s}", .{ dc, errstr(err) });
            }
        } else if (st.kind == .file) {
            ent.type = 'f';
            try sha256_file_copy(io, a, child, dchild, mode, &ent.hash, e);
        } else if (st.kind == .sym_link) {
            // A symlink is content: its TARGET (readlink bytes) is hashed,
            // type 'l'.  This keeps the store path a function of the actual
            // tree content — a symlink retarget changes the hash — while
            // accepting trees that legitimately contain symlinks.  In copy
            // mode it is recreated via symlink(); a broken symlink (readlink
            // succeeds, target missing) is still hashed and copied faithfully.
            // (The readlink buffer is PATH_MAX-1 like the C: an absurdly long
            // target truncates to the same bytes that get hashed.)
            ent.type = 'l';
            var target: [std.fs.max_path_bytes]u8 = undefined;
            const tl = root.readLink(io, child, target[0 .. target.len - 1]) catch |err|
                return e.set("readlink '{s}': {s}", .{ child, errstr(err) });
            sha256_hex(target[0..tl], &ent.hash);
            if (dchild) |dc| {
                root.symLink(io, target[0..tl], dc, .{}) catch |err|
                    return e.set("symlink '{s}': {s}", .{ dc, errstr(err) });
            }
        } else {
            return e.set("unsupported special source entry '{s}'", .{child});
        }

        ent.name = a.dupe(u8, name) catch return e.set("out of memory", .{});
        ents.append(a, ent) catch return e.set("out of memory", .{});
    }

    // readdir order is filesystem-dependent: SORT for determinism
    std.mem.sort(DirEnt, ents.items, {}, dirent_lt);

    var b: Buf = .{};
    defer b.deinit();
    for (ents.items) |ent| {
        try b.str(ent.name, e);
        try b.byte(ent.type, e);
        try b.str(ent.hash[0..64], e); // the C buf_str's char[65] → strlen 64
    }
    sha256_hex(b.list.items, hash_out);
}

/// Public entry: root has the empty relative path.  `dst` (the copy target,
/// which must already exist) selects copy mode; pass null for a hash-only
/// walk.  `excludes` may be empty.
pub fn fx_clean_tree(
    io: Io,
    dir: []const u8,
    dst: ?[]const u8,
    excludes: []const []const u8,
    hash_out: *[65]u8,
    e: *ErrBuf,
) Error!void {
    var arena = std.heap.ArenaAllocator.init(c_alloc);
    defer arena.deinit();
    return fx_clean_tree_rel(io, arena.allocator(), dir, dst, excludes, "", hash_out, e);
}

/// Thin wrapper: hash-only clean walk (no copy).
pub fn fx_content_hash_dir(
    io: Io,
    dir: []const u8,
    excludes: []const []const u8,
    hash_out: *[65]u8,
    e: *ErrBuf,
) Error!void {
    return fx_clean_tree(io, dir, null, excludes, hash_out, e);
}

// ─── Canonical action tags (fixed one-byte kind markers) ────────────────────

fn act_tag(k: ActionKind) u8 {
    return switch (k) {
        .shell => 'S',
        .copy => 'C',
        .mkdir => 'M',
        .rm => 'R',
        .touch => 'T',
        .move => 'V',
        .symlink => 'L',
        .chmod => 'H',
        .echo => 'E',
        .env => 'N',
        .run => 'X',
    };
}

fn buf_action(b: *Buf, act: *const Action, e: *ErrBuf) Error!void {
    try b.byte(act_tag(act.kind), e);
    if (act.kind == .run) {
        // X (Run): u32-BE argc then each arg len-prefixed
        if (act.argv.len > std.math.maxInt(u32))
            return e.set("Run argv too long", .{});
        try b.u32be(@intCast(act.argv.len), e);
        for (act.argv) |arg| try b.str(arg, e);
        return;
    }
    // every other action: one or two len-prefixed Text fields (a [, b])
    try b.str(act.a orelse "", e);
    switch (act.kind) {
        .copy, .move, .symlink, .chmod, .env => try b.str(act.b orelse "", e),
        else => {},
    }
}

/// Canonical derivation serialization with a PRECOMPUTED clean source hash:
/// for SRC_PATH, `src_hash` is the clean-tree hash (fx_content_hash_dir /
/// fx_clean_tree) computed by the caller ONCE and stored in PathEntry.src_hash
/// so compute_paths and fx_store_ensure_source share it (no double hash walk,
/// and the derivation hash and the materialized src are provably the same
/// content).  For SRC_FETCH, src_hash must be null and url+hash are used.
///
/// Layout (all strings u32-BE length-prefixed, NO NUL):
///   1. magic            "fxstore-drv-v1\n"
///   2. name             5. target
///   3. version          6. recipe: u32-BE count, per action IN ORDER
///   4. src              7. deps: u32-BE count, each FULL store path, SORTED
pub fn fx_derivation_hash_ex(
    p: *const Package,
    src_hash: ?[]const u8,
    dep_paths: []const []const u8,
    hash_out: *[65]u8,
    e: *ErrBuf,
) Error!void {
    if (p.src.kind == .path and src_hash == null)
        return e.set("internal: SRC_PATH without a precomputed src hash", .{});

    var b: Buf = .{};
    defer b.deinit();

    // (1) magic — versioned so a format change can never silently alias
    try b.str("fxstore-drv-v1\n", e);

    // (2) name, (3) version
    try b.str(p.name, e);
    try b.str(p.version, e);

    // (4) src: 'P' + clean content-hash of the tree | 'F' + url + hash
    if (p.src.kind == .path) {
        try b.byte('P', e);
        try b.str(src_hash.?, e);
    } else {
        try b.byte('F', e);
        try b.str(p.src.url orelse "", e);
        try b.str(p.src.hash orelse "", e);
    }

    // (5) target
    try b.str(p.target, e);

    // (6) recipe: u32 count + actions IN ORDER (order is semantic)
    var na: u32 = 0;
    var it = p.recipe;
    while (it) |act| : (it = act.next) na += 1;
    try b.u32be(na, e);
    it = p.recipe;
    while (it) |act| : (it = act.next) try buf_action(&b, act, e);

    // (7) deps: u32 count + each direct dep's FULL store path, SORTED
    // (enforced here — callers may pass any order)
    const sorted = c_alloc.alloc([]const u8, dep_paths.len) catch
        return e.set("out of memory", .{});
    defer c_alloc.free(sorted);
    @memcpy(sorted, dep_paths);
    std.mem.sort([]const u8, sorted, {}, str_lt);
    try b.u32be(@intCast(dep_paths.len), e);
    for (sorted) |dp| try b.str(dp, e);

    sha256_hex(b.list.items, hash_out);
}

/// Convenience wrapper: compute the clean source hash (hash-only walk) then
/// delegate to fx_derivation_hash_ex.  Callers that already computed the hash
/// (compute_paths, which must reuse it for fx_store_ensure_source) call the
/// _ex form directly.
pub fn fx_derivation_hash(
    io: Io,
    p: *const Package,
    dep_paths: []const []const u8,
    hash_out: *[65]u8,
    e: *ErrBuf,
) Error!void {
    if (p.src.kind == .path) {
        var src_hash: [65]u8 = undefined;
        try fx_content_hash_dir(io, p.src.path orelse "", p.excludes, &src_hash, e);
        return fx_derivation_hash_ex(p, src_hash[0..64], dep_paths, hash_out, e);
    }
    return fx_derivation_hash_ex(p, null, dep_paths, hash_out, e);
}

/// Store path layout: "<store_root>/<hex64>-<name>", written into `out` with
/// the C's snprintf(out, cap, ...) truncation semantics.  Returns the
/// (possibly truncated) written slice; `out` is NUL-terminated when space
/// remains.
pub fn fx_store_path_of(store_root: []const u8, hash: []const u8, name: []const u8, out: []u8) []const u8 {
    if (out.len == 0) return out[0..0];
    var n: usize = 0;
    for ([_][]const u8{ store_root, "/", hash, "-", name }) |part| {
        if (n == out.len - 1) break;
        const m = @min(part.len, out.len - 1 - n);
        @memcpy(out[n..][0..m], part[0..m]);
        n += m;
    }
    out[n] = 0;
    return out[0..n];
}

/// Convenience: derivation hash + store path in one call.
pub fn fx_derivation_store_path(
    io: Io,
    p: *const Package,
    dep_paths: []const []const u8,
    store_root: []const u8,
    path_out: []u8,
    e: *ErrBuf,
) Error![]const u8 {
    var hash: [65]u8 = undefined;
    try fx_derivation_hash(io, p, dep_paths, &hash, e);
    return fx_store_path_of(store_root, hash[0..64], p.name, path_out);
}

// ─── unit tests ──────────────────────────────────────────────────────────────
//
// Golden hashes are byte-exact outputs of the REAL C implementation
// (derivation.c + dhall-c sha256.c, compiled with zig cc) run against the
// fixture tree built by zig/corpus/derivation/build-tree.sh — mirrored
// byte-for-byte by build_fixture_tree below.  Full provenance:
// zig/corpus/derivation/golden.txt.

const testing = std.testing;

/// std.testing.io is runtime-valued (it borrows the test runner's Threaded),
/// so it must be fetched inside a function scope.
fn tio() Io {
    return std.testing.io;
}

const GOLDEN_TREE = "9ce6878162d0b3530b4f14052a162ba006f06c03348208faa69b6653974fb77d";
const GOLDEN_EX_DOCS_CACHE = "55487a0c4d255e9cc833f7f94b5c24d3e86a1d0ca50fff5f8b9da527d074e90e";
const GOLDEN_EX_SUB = "33157cdee891b8ff855c8a385436e8e1fe012e5285f556bcd957b50a39f4c128";
const GOLDEN_EX_SUB_NESTED = "8d5365071e921b6a1c665591f8b8fdf586b1522e628d28c33617738531f06f61";
const GOLDEN_EX_DOC = "f6c55669d2f1f4f87b427fda06e69aca0f1ba3cf693b8cf2cd7949de9c3d31ba";
const GOLDEN_DRV_A = "abba1e23badb9571e9bc8cdfdeaff04c7d094369174533243c91a6cb14b5505c";
const GOLDEN_DRV_A2 = "a8351aef418b068429a0bca069793f3a5312770cb9fae0133e88c94572588ce4";
const GOLDEN_DRV_B = "ec3a58c8c40f5b33a4cb4dd5cdea14cea3b0415d3a51a2be9252e0a911e8b35a";

extern "c" fn mkfifo(path: [*:0]const u8, mode: c_uint) c_int;

fn scratch_path(io: Io, a: std.mem.Allocator) ![]const u8 {
    // unique per run: tests must never see leftovers from a previous run
    var seed: [4]u8 = undefined;
    io.random(&seed);
    return std.fmt.allocPrint(a, "/tmp/fx-u2-test-{x:0>8}", .{std.mem.readInt(u32, &seed, .little)});
}

fn op_path(a: std.mem.Allocator, root: []const u8, rel: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "{s}/{s}", .{ root, rel });
}

fn mk_dir(a: std.mem.Allocator, root: []const u8, rel: []const u8) !void {
    const path = try op_path(a, root, rel);
    defer a.free(path);
    try Io.Dir.cwd().createDir(tio(), path, File.Permissions.fromMode(0o755));
}

fn put_file(a: std.mem.Allocator, root: []const u8, rel: []const u8, content: []const u8, mode: u32) !void {
    const path = try op_path(a, root, rel);
    defer a.free(path);
    var f = try Io.Dir.cwd().createFile(tio(), path, .{ .read = false, .truncate = true });
    defer f.close(tio());
    try f.writeStreamingAll(tio(), content);
    try f.setPermissions(tio(), File.Permissions.fromMode(mode));
}

fn put_symlink(a: std.mem.Allocator, root: []const u8, rel: []const u8, target: []const u8) !void {
    const path = try op_path(a, root, rel);
    defer a.free(path);
    try Io.Dir.cwd().symLink(tio(), target, path, .{});
}

fn put_fifo(a: std.mem.Allocator, root: []const u8, rel: []const u8) !void {
    const path = try op_path(a, root, rel);
    defer a.free(path);
    const path_z = try a.dupeZ(u8, path);
    defer a.free(path_z);
    if (mkfifo(path_z.ptr, 0o644) != 0) return error.MkFifoFailed;
}

fn stat_path(path: []const u8) ?File.Stat {
    return Io.Dir.cwd().statFile(tio(), path, .{ .follow_symlinks = false }) catch null;
}

/// THE fixture tree — a byte-for-byte Zig mirror of
/// zig/corpus/derivation/build-tree.sh (the C oracle hashed exactly this).
/// Exercises every exclusion-table row, hidden files as content, nested
/// dirs, symlinks (live + broken), the ".o"-exactly edge case, and the
/// per-package excludes targets (docs/cache, sub, sub/nested.txt).
fn build_fixture_tree(a: std.mem.Allocator, root: []const u8) !void {
    try mk_dir(a, root, "");
    try put_file(a, root, ".ape-obj", "ape prefix file\n", 0o644); // excluded: .ape- prefix
    try mk_dir(a, root, ".cache"); // excluded dir
    try put_file(a, root, ".cache/c", "cache\n", 0o644);
    try mk_dir(a, root, ".git"); // excluded dir
    try put_file(a, root, ".git/config", "gitconfig\n", 0o644);
    try put_file(a, root, ".gitignore", "*.o\n", 0o644); // CONTENT (not ".git")
    try put_file(a, root, ".hidden", "hidden content\n", 0o644); // hidden = CONTENT
    try put_file(a, root, ".o", "exactly dot o\n", 0o644); // NOT excluded (len rule)
    try mk_dir(a, root, ".py-site"); // excluded dir
    try put_file(a, root, ".py-site/s", "s\n", 0o644);
    try put_file(a, root, "Makefile", "all:\n\techo hi\n", 0o755); // exec bit survives copy
    try put_file(a, root, "README.md", "# fixture\n", 0o644);
    try mk_dir(a, root, "__pycache__"); // excluded dir
    try put_file(a, root, "__pycache__/p.pyc", "pyc\n", 0o644);
    try put_file(a, root, "app.elf", "elf\n", 0o644); // excluded ext
    try put_symlink(a, root, "broken", "no-such-target"); // broken symlink = content
    try mk_dir(a, root, "build"); // excluded dir
    try put_file(a, root, "build/out.bin", "binary\n", 0o644);
    try mk_dir(a, root, "build-tmp"); // excluded dir
    try put_file(a, root, "build-tmp/t", "t\n", 0o644);
    try put_file(a, root, "debug.dbg", "dbg\n", 0o644); // excluded ext
    try mk_dir(a, root, "dl-test-sandbox"); // excluded dl-test- prefix
    try put_file(a, root, "dl-test-sandbox/x", "x\n", 0o644);
    try mk_dir(a, root, "doc"); // content
    try put_file(a, root, "doc/note.txt", "doc note\n", 0o644);
    try mk_dir(a, root, "docs"); // content; per-pkg exclude target below
    try put_file(a, root, "docs/keep.txt", "docs keep\n", 0o644);
    try mk_dir(a, root, "docs/cache"); // per-pkg exclude target
    try put_file(a, root, "docs/cache/c.txt", "cache\n", 0o644);
    try put_file(a, root, "lib.a", "ar\n", 0o644); // excluded ext
    try put_symlink(a, root, "link", "README.md"); // live symlink = content
    try put_file(a, root, "mod.wasm", "wasm\n", 0o644); // excluded ext
    try mk_dir(a, root, "objects"); // content
    try put_file(a, root, "objects/foo.o", "obj\n", 0o644); // excluded ext
    try put_file(a, root, "objects/keep.o.txt", "not an object\n", 0o644); // content
    try put_file(a, root, "plugin.so", "so\n", 0o644); // excluded ext
    try put_file(a, root, "prog.com", "com\n", 0o644); // excluded ext
    try mk_dir(a, root, "pydl"); // excluded dir
    try put_file(a, root, "pydl/d", "d\n", 0o644);
    try put_file(a, root, "setuid-src", "s\n", 0o4755); // content; fchmod mask case
    try mk_dir(a, root, "sub"); // content
    try put_file(a, root, "sub/.git", "gitdir: /real/git\n", 0o644); // excluded: .git FILE
    try put_file(a, root, "sub/nested.txt", "nested\n", 0o644); // per-pkg exclude target
    try mk_dir(a, root, "sub/deeper");
    try put_file(a, root, "sub/deeper/deep.txt", "deep\n", 0o644);
}

fn expect_clean_hash(tree: []const u8, excludes: []const []const u8, want: []const u8) !void {
    var e = ErrBuf{};
    var h: [65]u8 = undefined;
    try fx_content_hash_dir(tio(), tree, excludes, &h, &e);
    try testing.expectEqualStrings(want, h[0..64]);
}

test "clean-tree Merkle hash: byte-exact goldens vs the C implementation" {
    const a = testing.allocator;
    const scratch = try scratch_path(tio(), a);
    defer a.free(scratch);
    try mk_dir(a, "", scratch);
    defer Io.Dir.cwd().deleteTree(tio(), scratch) catch {};
    const tree = try op_path(a, scratch, "tree");
    defer a.free(tree);
    try build_fixture_tree(a, tree);

    try expect_clean_hash(tree, &.{}, GOLDEN_TREE);
    try expect_clean_hash(tree, &.{"docs/cache"}, GOLDEN_EX_DOCS_CACHE);
    try expect_clean_hash(tree, &.{"sub"}, GOLDEN_EX_SUB);
    try expect_clean_hash(tree, &.{"sub/nested.txt"}, GOLDEN_EX_SUB_NESTED);
    // prefix boundary: "doc" must NOT exclude "docs" (rel[3] == 's', not '/')
    try expect_clean_hash(tree, &.{"doc"}, GOLDEN_EX_DOC);
    // empty exclude entries are defense-skipped (rejected at parse time)
    try expect_clean_hash(tree, &.{ "", "docs/cache" }, GOLDEN_EX_DOCS_CACHE);

    // an empty dir hashes to sha256("") — the empty Merkle stream
    const empty = try op_path(a, scratch, "empty");
    defer a.free(empty);
    try mk_dir(a, empty, "");
    try expect_clean_hash(empty, &.{}, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

test "exclusion table: excluded-class junk never changes the hash; real content does" {
    const a = testing.allocator;
    const scratch = try scratch_path(tio(), a);
    defer a.free(scratch);
    try mk_dir(a, "", scratch);
    defer Io.Dir.cwd().deleteTree(tio(), scratch) catch {};
    const tree = try op_path(a, scratch, "tree");
    defer a.free(tree);
    try build_fixture_tree(a, tree);

    // add MORE excluded-class junk at various depths — hash must not move
    try put_file(a, tree, "objects/extra.o", "more obj\n", 0o644);
    try mk_dir(a, tree, "sub/.cache");
    try put_file(a, tree, "sub/.cache/n", "n\n", 0o644);
    try mk_dir(a, tree, "dl-test-x");
    try put_file(a, tree, "dl-test-x/y", "y\n", 0o644);
    try put_file(a, tree, ".ape-more", "ape\n", 0o644);
    try put_file(a, tree, "doc/.git", "gitdir: elsewhere\n", 0o644); // .git as FILE
    try expect_clean_hash(tree, &.{}, GOLDEN_TREE);

    // control: a NON-excluded file DOES change the hash
    try put_file(a, tree, "newfile.txt", "new\n", 0o644);
    var h: [65]u8 = undefined;
    var e = ErrBuf{};
    try fx_content_hash_dir(tio(), tree, &.{}, &h, &e);
    try testing.expect(!std.mem.eql(u8, h[0..64], GOLDEN_TREE));
}

test "special source entries (fifo) are rejected loudly" {
    const a = testing.allocator;
    const scratch = try scratch_path(tio(), a);
    defer a.free(scratch);
    try mk_dir(a, "", scratch);
    defer Io.Dir.cwd().deleteTree(tio(), scratch) catch {};
    const fifodir = try op_path(a, scratch, "fifo");
    defer a.free(fifodir);
    try mk_dir(a, fifodir, "");
    try put_file(a, fifodir, "ok.txt", "fine\n", 0o644);
    try put_fifo(a, fifodir, "pipe");

    var e = ErrBuf{};
    var h: [65]u8 = undefined;
    try testing.expectError(error.FxDerivation, fx_content_hash_dir(tio(), fifodir, &.{}, &h, &e));
    const want_err = try std.fmt.allocPrint(testing.allocator, "unsupported special source entry '{s}/pipe'", .{fifodir});
    defer testing.allocator.free(want_err);
    try testing.expectEqualStrings(want_err, e.slice());
}

fn expect_entry(dir: []const u8, rel: []const u8) !void {
    const p = try op_path(testing.allocator, dir, rel);
    defer testing.allocator.free(p);
    try testing.expect(stat_path(p) != null);
}

fn expect_absent(dir: []const u8, rel: []const u8) !void {
    const p = try op_path(testing.allocator, dir, rel);
    defer testing.allocator.free(p);
    try testing.expect(stat_path(p) == null);
}

test "copy-mode: copy-hash == walk-hash, clean structure, fchmod mask contract" {
    const a = testing.allocator;
    const scratch = try scratch_path(tio(), a);
    defer a.free(scratch);
    try mk_dir(a, "", scratch);
    defer Io.Dir.cwd().deleteTree(tio(), scratch) catch {};
    const tree = try op_path(a, scratch, "tree");
    defer a.free(tree);
    try build_fixture_tree(a, tree);
    const copy = try op_path(a, scratch, "copy");
    defer a.free(copy);
    try mk_dir(a, copy, ""); // dst dir must already exist
    const copy2 = try op_path(a, scratch, "copy2");
    defer a.free(copy2);
    try mk_dir(a, copy2, "");

    // copy-mode hash == the hash-only walk's hash (byte-identical serializer)
    var h: [65]u8 = undefined;
    var e = ErrBuf{};
    try fx_clean_tree(tio(), tree, copy, &.{}, &h, &e);
    try testing.expectEqualStrings(GOLDEN_TREE, h[0..64]);
    // ...and re-hashing the materialized copy reproduces it exactly
    try expect_clean_hash(copy, &.{}, GOLDEN_TREE);

    // copy mode honors per-package excludes identically
    try fx_clean_tree(tio(), tree, copy2, &.{"docs/cache"}, &h, &e);
    try testing.expectEqualStrings(GOLDEN_EX_DOCS_CACHE, h[0..64]);
    try expect_clean_hash(copy2, &.{}, GOLDEN_EX_DOCS_CACHE);
    try expect_absent(copy2, "docs/cache");
    try expect_entry(copy2, "docs/keep.txt");

    // structure: content present...
    try expect_entry(copy, ".gitignore");
    try expect_entry(copy, ".hidden");
    try expect_entry(copy, ".o"); // ".o"-exactly is NOT an excluded ext
    try expect_entry(copy, "Makefile");
    try expect_entry(copy, "README.md");
    try expect_entry(copy, "doc/note.txt");
    try expect_entry(copy, "docs/keep.txt");
    try expect_entry(copy, "docs/cache/c.txt");
    try expect_entry(copy, "objects/keep.o.txt");
    try expect_entry(copy, "setuid-src");
    try expect_entry(copy, "sub/nested.txt");
    try expect_entry(copy, "sub/deeper/deep.txt");
    // ...excluded entries silently skipped (never copied)...
    try expect_absent(copy, ".git");
    try expect_absent(copy, ".ape-obj");
    try expect_absent(copy, ".cache");
    try expect_absent(copy, ".py-site");
    try expect_absent(copy, "__pycache__");
    try expect_absent(copy, "build");
    try expect_absent(copy, "build-tmp");
    try expect_absent(copy, "dl-test-sandbox");
    try expect_absent(copy, "pydl");
    try expect_absent(copy, "app.elf");
    try expect_absent(copy, "debug.dbg");
    try expect_absent(copy, "lib.a");
    try expect_absent(copy, "mod.wasm");
    try expect_absent(copy, "plugin.so");
    try expect_absent(copy, "prog.com");
    try expect_absent(copy, "objects/foo.o");
    try expect_absent(copy, "sub/.git");
    // ...symlinks recreated with their original targets...
    {
        const p = try op_path(a, copy, "link");
        defer a.free(p);
        var buf: [64]u8 = undefined;
        const n = try Io.Dir.cwd().readLink(tio(), p, &buf);
        try testing.expectEqualStrings("README.md", buf[0..n]);
    }
    {
        const p = try op_path(a, copy, "broken");
        defer a.free(p);
        var buf: [64]u8 = undefined;
        const n = try Io.Dir.cwd().readLink(tio(), p, &buf);
        try testing.expectEqualStrings("no-such-target", buf[0..n]);
    }
    // ...and modes faithfully mirrored (masked): exec bit kept on files,
    // setuid stripped (01777), regular modes preserved.
    {
        const p = try op_path(a, copy, "Makefile");
        defer a.free(p);
        const st = stat_path(p).?;
        try testing.expectEqual(File.Kind.file, st.kind);
        try testing.expectEqual(@as(u32, 0o755), @intFromEnum(st.permissions) & 0o7777);
    }
    {
        const p = try op_path(a, copy, "setuid-src");
        defer a.free(p);
        const st = stat_path(p).?;
        try testing.expectEqual(@as(u32, 0o755), @intFromEnum(st.permissions) & 0o1777); // 04755 masked
    }
    {
        const p = try op_path(a, copy, "README.md");
        defer a.free(p);
        const st = stat_path(p).?;
        try testing.expectEqual(@as(u32, 0o644), @intFromEnum(st.permissions) & 0o7777);
    }
}

// ─── derivation serializer ───────────────────────────────────────────────────

/// Mirrors the C oracle's Package `a` (see zig/corpus/derivation/oracle.c):
/// all 11 action kinds in order, path src, two deps passed UNSORTED.
fn build_pkg_a(a: std.mem.Allocator) !Package {
    const mk = try a.create(Action);
    mk.* = .{ .kind = .shell, .a = "make hello" };
    const cp = try a.create(Action);
    cp.* = .{ .kind = .copy, .a = "hello", .b = "bin/hello" };
    const md = try a.create(Action);
    md.* = .{ .kind = .mkdir, .a = "bin" };
    const rm = try a.create(Action);
    rm.* = .{ .kind = .rm, .a = "old" };
    const tc = try a.create(Action);
    tc.* = .{ .kind = .touch, .a = "stamp" };
    const mv = try a.create(Action);
    mv.* = .{ .kind = .move, .a = "a", .b = "b" };
    const sl = try a.create(Action);
    sl.* = .{ .kind = .symlink, .a = "target", .b = "link" };
    const ch = try a.create(Action);
    ch.* = .{ .kind = .chmod, .a = "bin/hello", .b = "0755" };
    const ec = try a.create(Action);
    ec.* = .{ .kind = .echo, .a = "hello world" };
    const ev = try a.create(Action);
    ev.* = .{ .kind = .env, .a = "CC", .b = "cc" };
    const rn = try a.create(Action);
    rn.* = .{ .kind = .run, .argv = &.{ "./configure", "--prefix=/build" } };
    mk.next = cp;
    cp.next = md;
    md.next = rm;
    rm.next = tc;
    tc.next = mv;
    mv.next = sl;
    sl.next = ch;
    ch.next = ec;
    ec.next = ev;
    ev.next = rn;
    return .{
        .name = "hello",
        .version = "1.0",
        .src = .{ .kind = .path, .path = "/src/hello" },
        .target = "hello",
        .recipe = mk,
    };
}

const DEP_ZZZ = "/fx/store/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff-zzz-dep";
const DEP_AAA = "/fx/store/0000000000000000000000000000000000000000000000000000000000000000-aaa-dep";
const DEP_ZZZ_1 = "/fx/store/1111111111111111111111111111111111111111111111111111111111111111-zzz-dep";

test "derivation hash: byte-exact goldens vs C; dep sorting and sensitivity" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();
    var e = ErrBuf{};
    var h: [65]u8 = undefined;

    // a REAL fixture tree: fx_derivation_store_path walks it for the src hash
    const scratch = try scratch_path(tio(), a);
    try mk_dir(a, "", scratch);
    defer Io.Dir.cwd().deleteTree(tio(), scratch) catch {};
    const tree = try op_path(a, scratch, "tree");
    defer a.free(tree);
    try build_fixture_tree(a, tree);

    var pa = try build_pkg_a(a);
    const deps = [_][]const u8{ DEP_ZZZ, DEP_AAA }; // passed UNSORTED

    try fx_derivation_hash_ex(&pa, GOLDEN_TREE, &deps, &h, &e);
    try testing.expectEqualStrings(GOLDEN_DRV_A, h[0..64]);

    // dep order is NOT semantic: any permutation hashes identically
    const deps_rev = [_][]const u8{ DEP_AAA, DEP_ZZZ };
    try fx_derivation_hash_ex(&pa, GOLDEN_TREE, &deps_rev, &h, &e);
    try testing.expectEqualStrings(GOLDEN_DRV_A, h[0..64]);

    // the hash is the Nix-style fixed point: changing a dep path changes it
    const deps2 = [_][]const u8{ DEP_ZZZ_1, DEP_AAA };
    try fx_derivation_hash_ex(&pa, GOLDEN_TREE, &deps2, &h, &e);
    try testing.expectEqualStrings(GOLDEN_DRV_A2, h[0..64]);

    // convenience wrapper: same package through fx_derivation_store_path.
    // Its src.path must be the REAL tree (the wrapper walks it); the store
    // path depends only on the resulting src HASH, so pointing it at the
    // fixture tree reproduces the C's fx_derivation_store_path byte-for-byte.
    pa.src.path = tree;
    var sp: [128]u8 = undefined;
    const got = try fx_derivation_store_path(tio(), &pa, &deps, "/fx/store", &sp, &e);
    try testing.expectEqualStrings(
        "/fx/store/" ++ GOLDEN_DRV_A ++ "-hello",
        got,
    );

    // fetch-src derivation (src_hash must be null; url+hash are serialized)
    const world = Package{
        .name = "world",
        .version = "2.3.4",
        .src = .{
            .kind = .fetch,
            .url = "https://example.com/world-2.3.4.tar.gz",
            .hash = "f2ca1bb3c199e6c9eda0f4d1e7bb8b4b0f1b2a3c4d5e6f708192a3b4c5d6e7f8",
        },
        .target = "world",
        .recipe = null,
    };
    const deps_b = [_][]const u8{"/fx/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello"};
    try fx_derivation_hash_ex(&world, null, &deps_b, &h, &e);
    try testing.expectEqualStrings(GOLDEN_DRV_B, h[0..64]);
    try fx_derivation_hash_ex(&world, null, &.{}, &h, &e);
    try testing.expect(!std.mem.eql(u8, h[0..64], GOLDEN_DRV_B)); // deps participate

    // SRC_PATH without a precomputed hash is rejected, with the C's text
    try testing.expectError(error.FxDerivation, fx_derivation_hash_ex(&pa, null, &deps, &h, &e));
    try testing.expectEqualStrings("internal: SRC_PATH without a precomputed src hash", e.slice());
}

test "derivation serialization: action order is semantic; fields are too" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();
    var e = ErrBuf{};
    var h: [65]u8 = undefined;

    var pa = try build_pkg_a(a);
    const deps = [_][]const u8{ DEP_ZZZ, DEP_AAA };
    try fx_derivation_hash_ex(&pa, GOLDEN_TREE, &deps, &h, &e);

    // swapping two recipe actions changes the hash (order is semantic)
    const second = pa.recipe.?.next.?;
    pa.recipe.?.next = second.next;
    second.next = pa.recipe.?.next.?.next;
    pa.recipe.?.next.?.next = second;
    var h2: [65]u8 = undefined;
    try fx_derivation_hash_ex(&pa, GOLDEN_TREE, &deps, &h2, &e);
    try testing.expect(!std.mem.eql(u8, h[0..64], h2[0..64]));

    // a version bump changes the hash
    var pv = try build_pkg_a(a);
    pv.version = "1.1";
    try fx_derivation_hash_ex(&pv, GOLDEN_TREE, &deps, &h2, &e);
    try testing.expect(!std.mem.eql(u8, h[0..64], h2[0..64]));
}

test "store path format + snprintf-style truncation" {
    var sp: [96]u8 = undefined; // 80 chars + NUL fit
    const full = fx_store_path_of("/fx/store", GOLDEN_DRV_A, "hello", &sp);
    try testing.expectEqualStrings("/fx/store/" ++ GOLDEN_DRV_A ++ "-hello", full);

    // snprintf(out, 8, ...): 7 chars + NUL
    var tiny: [8]u8 = undefined;
    const trunc = fx_store_path_of("/fx/store", GOLDEN_DRV_A, "hello", &tiny);
    try testing.expectEqualStrings("/fx/sto", trunc);
    try testing.expectEqual(@as(u8, 0), tiny[7]);

    // zero-cap writes nothing at all (snprintf semantics)
    var none: [0]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), fx_store_path_of("/fx/store", GOLDEN_DRV_A, "hello", &none).len);
}

test "fx_clean_excluded table (derivation.c:111-132)" {
    // .git: dir OR submodule gitfile
    try testing.expect(fx_clean_excluded(".git", true));
    try testing.expect(fx_clean_excluded(".git", false));
    // dir rows
    inline for (.{ ".cache", "build", "build-tmp", "__pycache__", ".py-site", "pydl" }) |d| {
        try testing.expect(fx_clean_excluded(d, true));
        try testing.expect(!fx_clean_excluded(d, false)); // dir rows are dir-only
    }
    try testing.expect(fx_clean_excluded("dl-test-sandbox", true));
    try testing.expect(!fx_clean_excluded("dl-test-sandbox", false));
    try testing.expect(!fx_clean_excluded("dl-tes", true));
    // file rows
    inline for (.{ ".o", ".a", ".so", ".com", ".dbg", ".elf", ".wasm" }) |ext| {
        try testing.expect(fx_clean_excluded("foo" ++ ext, false));
        try testing.expect(!fx_clean_excluded("foo" ++ ext, true)); // ext rows are file-only
    }
    try testing.expect(!fx_clean_excluded(".o", false)); // len boundary: bl > el
    try testing.expect(!fx_clean_excluded("foo.ox", false));
    try testing.expect(fx_clean_excluded("fo.o", false)); // "fo.o" ends with ".o"
    try testing.expect(fx_clean_excluded(".ape-nothing", false));
    try testing.expect(fx_clean_excluded(".ape-", false));
    try testing.expect(!fx_clean_excluded(".ape", false));
    // content survives
    try testing.expect(!fx_clean_excluded(".gitignore", false));
    try testing.expect(!fx_clean_excluded("main.c", false));
    try testing.expect(!fx_clean_excluded("docs", false));
}

test "fx_excluded_by_rel (derivation.c:140-152)" {
    const ex = [_][]const u8{ "docs", "vendor/ggml" };
    try testing.expect(fx_excluded_by_rel("docs", &ex)); // rel == entry
    try testing.expect(fx_excluded_by_rel("docs/cache", &ex)); // rel starts with entry+"/"
    try testing.expect(fx_excluded_by_rel("vendor/ggml", &ex));
    try testing.expect(fx_excluded_by_rel("vendor/ggml/x/y", &ex));
    // prefix must end at a '/' boundary or at end-of-string
    try testing.expect(!fx_excluded_by_rel("docsy", &ex));
    try testing.expect(!fx_excluded_by_rel("doc", &ex));
    try testing.expect(!fx_excluded_by_rel("vendor/ggmlx", &ex));
    try testing.expect(!fx_excluded_by_rel("", &ex));
    // empty entries never match anything (defense-in-depth)
    try testing.expect(!fx_excluded_by_rel("anything", &.{""}));
    try testing.expect(!fx_excluded_by_rel("anything", &.{}));
}

test "integration: fx_derivation_hash over a U1-loaded package (good.dhall)" {
    var e = ErrBuf{};
    var pe = ps.ErrBuf{}; // the U1 walker has its own ErrBuf/error flavor
    var pset: ps.PackageSet = undefined;
    try ps.fx_packageset_load(&pset, "zig/corpus/packageset/good.dhall", &pe);
    defer pset.deinit();

    const hello = pset.find("hello").?;
    var h: [65]u8 = undefined;
    var h2: [65]u8 = undefined;
    // convenience wrapper (walks src.path with the package's own excludes)
    try fx_derivation_hash(tio(), hello, &.{}, &h, &e);
    try fx_derivation_hash(tio(), hello, &.{}, &h2, &e);
    try testing.expectEqualStrings(h[0..64], h2[0..64]);
    // the _ex form with the same precomputed clean hash must agree
    var sh: [65]u8 = undefined;
    try fx_content_hash_dir(tio(), hello.src.path.?, hello.excludes, &sh, &e);
    try fx_derivation_hash_ex(hello, sh[0..64], &.{}, &h2, &e);
    try testing.expectEqualStrings(h[0..64], h2[0..64]);
    // ...and that clean hash is itself a C golden (a second tree shape, the
    // U1 fixture, hashed by the real C with hello's own excludes)
    try testing.expectEqualStrings("8942c0b3a593f89169c19a71174cf9ef9af71f70b4bbd584a2621ee1f28e7e48", sh[0..64]);

    // fetch-src package hashes without touching the filesystem
    const world = pset.find("world").?;
    const wdeps = [_][]const u8{"hello"};
    try fx_derivation_hash(tio(), world, &wdeps, &h, &e);
    try testing.expectEqual(@as(usize, 64), h.len - 1);
}
