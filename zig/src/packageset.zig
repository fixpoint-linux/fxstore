// packageset.zig — faithful Zig port of packageset.c (U1): evaluate a Dhall
// package-set.dhall and walk its normal form into a package table:
//
//     parse_source -> infer_type (best-effort, see below) -> normalize
//     -> walk the PackageSet Term tree
//
// ABOUT infer_type: the pipeline calls infer_type, but the dhake precedent is
// that the shorthand Action union literal < Tag = v > infers as a *singleton*
// union < Tag : T >, so a recipe list mixing different tags does not
// typecheck even though it normalizes correctly.  infer_type is therefore a
// WARNING-ONLY check (a real error is printed but the walk continues — the
// structural walk is the source of truth), so both the shorthand and the
// projection style (Action.Shell "...") are accepted.
//
// The term-walker helpers rec_get / term_text_cstr / union_selected follow
// the proven config.zig house style (itself a port of the C helpers).
// normalize() sorts record fields alphabetically, so every field access is
// BY LABEL (rec_get), never by index.  Text interpolation that did not
// collapse is rejected loudly (a stuck ${...} means the file references
// something the evaluator could not resolve — a wrong package table here
// silently corrupts every downstream hash).
//
// Memory model: the C mallocs every Package/Action string and frees them in
// fx_packageset_free; here each PackageSet OWNS an ArenaAllocator — all
// table strings and structs live in it, and deinit() is the single free
// point (subsuming fx_packageset_free).
const std = @import("std");
const dh = @import("dhall");
/// Parser/DhallError live in the facade's own namespace (dhall.zig), NOT
/// re-exported through dhall_mod's `pub const` surface.
const dhallz = dh.dhall;
const dhall = dh;

const ast = dhall.ast;
const parser = dhall.parser;
const typecheck = dhall.typecheck;
const normalize = dhall.normalize;
const import_mod = dhall.import_mod;
const arena = dhall.arena;

const c_alloc = std.heap.c_allocator;

extern "c" fn realpath(path: [*:0]const u8, resolved: [*]u8) ?[*:0]u8;

// ─── Types (fxstore.h; ActionKind keeps the C enum order — the U2 canonical
// serializer assigns tags in this order) ─────────────────────────────────────

pub const ActionKind = enum(u8) {
    shell,
    copy,
    mkdir,
    rm,
    touch,
    move,
    symlink,
    chmod,
    echo,
    env,
    run,
};

pub const SrcKind = enum(u8) {
    path,
    fetch,
};

pub const Src = struct {
    kind: SrcKind = .path,
    path: ?[]const u8 = null, // SRC_PATH: filesystem path to the source tree
    url: ?[]const u8 = null, // SRC_FETCH
    hash: ?[]const u8 = null, // SRC_FETCH: expected sha256 (hex)
};

pub const Action = struct {
    kind: ActionKind,
    /// shell command / mkdir / rm / touch path / copy-from / move-from /
    /// symlink-from / chmod-path / echo-text / env-key / run-program
    a: ?[]const u8 = null,
    /// copy-to / move-to / symlink-to / chmod-mode / env-value
    b: ?[]const u8 = null,
    /// argv for Run (empty for others)
    argv: []const []const u8 = &.{},
    next: ?*Action = null, // recipe linked list, package-set order
};

pub const Package = struct {
    name: []const u8,
    version: []const u8,
    src: Src = .{},
    deps: []const []const u8 = &.{}, // direct dep NAMES, package-set order
    /// optional RELATIVE-PATH-PREFIX exclusions within the src tree (only
    /// valid for a Path src); empty when absent
    excludes: []const []const u8 = &.{},
    target: []const u8, // build.target (output name; informational)
    recipe: ?*Action = null, // linked list, package-set ORDER (semantic)
    next: ?*Package = null, // package-set order
};

pub const PackageSet = struct {
    arena: std.heap.ArenaAllocator,
    head: ?*Package = null,
    count: usize = 0,

    /// fx_find_package: linear scan by name, package-set order.
    pub fn find(self: *const PackageSet, name: []const u8) ?*Package {
        var p = self.head;
        while (p) |pkg| : (p = pkg.next) {
            if (std.mem.eql(u8, pkg.name, name)) return pkg;
        }
        return null;
    }

    /// fx_packageset_free: the arena owns the whole table.
    pub fn deinit(self: *PackageSet) void {
        self.arena.deinit();
        self.head = null;
        self.count = 0;
    }
};

pub const err_cap_default = 2048;

/// The fx_err helper (fxstore.h) as a context struct: the C threads
/// `char *err, size_t errcap` through every walker and signals failure by
/// return value; here every failure path calls ErrBuf.set (with the verbatim
/// packageset.c format string) and returns error.FxPackageset.
pub const ErrBuf = struct {
    buf: [err_cap_default]u8 = undefined,
    len: usize = 0,

    /// fx_err(err, errcap, fmt, ...): format into the buffer (truncating,
    /// like vsnprintf) and always "fail".
    pub fn set(self: *ErrBuf, comptime fmt: []const u8, args: anytype) error{FxPackageset} {
        var aw: std.Io.Writer.Allocating = .init(c_alloc);
        defer aw.deinit();
        aw.writer.print(fmt, args) catch unreachable;
        const s = aw.written();
        const n = @min(s.len, self.buf.len - 1);
        @memcpy(self.buf[0..n], s[0..n]);
        self.buf[n] = 0;
        self.len = n;
        return error.FxPackageset;
    }

    pub fn slice(self: *const ErrBuf) []const u8 {
        return self.buf[0..self.len];
    }
};

// ─── Term-tree helpers (config.zig house style, C packageset.c semantics) ──

/// The C error-context builder (packageset.c:267-268): snprintf into char
/// where[160], i.e. "package '<name>'" truncated to 159 bytes.
fn alloc_where(
    a: std.mem.Allocator,
    name: []const u8,
    e: *ErrBuf,
) error{FxPackageset}![]const u8 {
    const full = std.fmt.allocPrint(a, "package '{s}'", .{name}) catch
        return e.set("out of memory", .{});
    defer a.free(full);
    return a.dupe(u8, full[0..@min(full.len, 159)]) catch
        e.set("out of memory", .{});
}

/// Look up a record-literal field BY LABEL. normalize() sorts fields
/// alphabetically, so index-based access is wrong.
fn rec_get(t: ?*dhallz.Term, label: []const u8) ?*dhallz.Term {
    const tt = t orelse return null;
    if (tt.tag != .TmRecordLit) return null;
    for (0..@intCast(tt.as.rec.n)) |i| {
        if (std.mem.eql(u8, std.mem.span(tt.as.rec.fs.?[i].label.?), label))
            return tt.as.rec.fs.?[i].value;
    }
    return null;
}

/// term_text_cstr: concatenated literal chunks; null on stuck interpolation
/// or a non-Text term.  The copy lands in the PackageSet arena so the table
/// survives the next dhall_arena reset (the C mallocs per string here).
fn term_text_cstr(a: std.mem.Allocator, t: ?*dhallz.Term) ?[]const u8 {
    const tt = t orelse return null;
    if (tt.tag != .TmText) return null;
    var len: usize = 0;
    var p: ?*dhallz.TextPart = tt.as.text;
    while (p) |part| : (p = part.next) {
        if (part.expr != null) return null; // stuck interpolation
        if (part.lit) |lit| len += std.mem.span(lit).len;
    }
    const out = a.alloc(u8, len) catch return null;
    var i: usize = 0;
    p = tt.as.text;
    while (p) |part| : (p = part.next) {
        if (part.lit) |lit| {
            const l = std.mem.span(lit);
            @memcpy(out[i .. i + l.len], l);
            i += l.len;
        }
    }
    return out;
}

/// The selected alternative of a union literal: the field carrying a value.
fn union_selected(u: ?*dhallz.Term) ?*dhallz.Field {
    const uu = u orelse return null;
    if (uu.tag != .TmUnionLit) return null;
    for (0..@intCast(uu.as.uni.n)) |i| {
        if (uu.as.uni.fs.?[i].value != null) return &uu.as.uni.fs.?[i];
    }
    return null;
}

fn list_length(list: ?*dhallz.Term) usize {
    var n: usize = 0;
    var p = list;
    while (p) |t| : (p = t.as.cons.tail) {
        if (t.tag != .TmCons) break;
        n += 1;
    }
    return n;
}

fn need_text(a: std.mem.Allocator, rec: ?*dhallz.Term, label: []const u8, where: []const u8, e: *ErrBuf) error{FxPackageset}![]const u8 {
    const f = rec_get(rec, label) orelse
        return e.set("{s}: missing field '{s}'", .{ where, label });
    return term_text_cstr(a, f) orelse
        return e.set("{s}: field '{s}' must be Text", .{ where, label });
}

// ─── Action mapping (packageset.c map_action, errors rerouted) ──────────────

fn map_action(a: std.mem.Allocator, u: ?*dhallz.Term, pkg: []const u8, e: *ErrBuf) error{FxPackageset}!*Action {
    if (u == null or u.?.tag != .TmUnionLit)
        return e.set("package '{s}': recipe element must be an Action union (< Tag = v >)", .{pkg});
    const sel = union_selected(u) orelse
        return e.set("package '{s}': malformed Action union", .{pkg});
    const act = a.create(Action) catch return e.set("out of memory", .{});
    act.* = .{ .kind = .shell };
    const tag = std.mem.span(sel.label.?);
    const w = pkg;
    const val = sel.value.?;
    if (std.mem.eql(u8, tag, "Shell")) {
        act.kind = .shell;
        act.a = term_text_cstr(a, val) orelse
            return e.set("package '{s}': < Shell = ... > value must be Text", .{w});
    } else if (std.mem.eql(u8, tag, "Copy")) {
        act.kind = .copy;
        if (val.tag != .TmRecordLit)
            return e.set("package '{s}': Copy must be a {{ from, to }} record", .{w});
        act.a = try need_text(a, val, "from", w, e);
        act.b = try need_text(a, val, "to", w, e);
    } else if (std.mem.eql(u8, tag, "Mkdir")) {
        act.kind = .mkdir;
        act.a = term_text_cstr(a, val) orelse
            return e.set("package '{s}': < Mkdir = ... > value must be Text", .{w});
    } else if (std.mem.eql(u8, tag, "Rm")) {
        act.kind = .rm;
        act.a = term_text_cstr(a, val) orelse
            return e.set("package '{s}': < Rm = ... > value must be Text", .{w});
    } else if (std.mem.eql(u8, tag, "Touch")) {
        act.kind = .touch;
        act.a = term_text_cstr(a, val) orelse
            return e.set("package '{s}': < Touch = ... > value must be Text", .{w});
    } else if (std.mem.eql(u8, tag, "Move")) {
        act.kind = .move;
        if (val.tag != .TmRecordLit)
            return e.set("package '{s}': Move must be a {{ from, to }} record", .{w});
        act.a = try need_text(a, val, "from", w, e);
        act.b = try need_text(a, val, "to", w, e);
    } else if (std.mem.eql(u8, tag, "Symlink")) {
        act.kind = .symlink;
        if (val.tag != .TmRecordLit)
            return e.set("package '{s}': Symlink must be a {{ from, to }} record", .{w});
        act.a = try need_text(a, val, "from", w, e);
        act.b = try need_text(a, val, "to", w, e);
    } else if (std.mem.eql(u8, tag, "Chmod")) {
        act.kind = .chmod;
        if (val.tag != .TmRecordLit)
            return e.set("package '{s}': Chmod must be a {{ path, mode }} record", .{w});
        act.a = try need_text(a, val, "path", w, e);
        act.b = try need_text(a, val, "mode", w, e);
    } else if (std.mem.eql(u8, tag, "Echo")) {
        act.kind = .echo;
        act.a = term_text_cstr(a, val) orelse
            return e.set("package '{s}': < Echo = ... > value must be Text", .{w});
    } else if (std.mem.eql(u8, tag, "Env")) {
        act.kind = .env;
        if (val.tag != .TmRecordLit)
            return e.set("package '{s}': Env must be a {{ key, value }} record", .{w});
        act.a = try need_text(a, val, "key", w, e);
        act.b = try need_text(a, val, "value", w, e);
    } else if (std.mem.eql(u8, tag, "Run")) {
        act.kind = .run;
        if (val.tag != .TmRecordLit)
            return e.set("package '{s}': Run must be a {{ argv : List Text }} record", .{w});
        const argv_list = rec_get(val, "argv") orelse
            return e.set("package '{s}': Run must have an 'argv' field", .{w});
        const n = list_length(argv_list);
        if (n == 0)
            return e.set("package '{s}': Run argv must be non-empty", .{w});
        const av = a.alloc([]const u8, n) catch return e.set("out of memory", .{});
        var i: usize = 0;
        var p: ?*dhallz.Term = argv_list;
        while (p) |t| : (p = t.as.cons.tail) {
            if (t.tag != .TmCons) break;
            av[i] = term_text_cstr(a, t.as.cons.head) orelse
                return e.set("package '{s}': Run argv elements must be Text", .{w});
            i += 1;
        }
        act.argv = av[0..i];
        act.a = act.argv[0]; // store program name in a for compatibility
    } else {
        return e.set("package '{s}': unknown action '< {s} = ... >'", .{ w, tag });
    }
    return act;
}

// ─── Package-name safety ────────────────────────────────────────────────────
// Store dirs are named "<hex64>-<name>", so a package name with '/' or a
// leading '.' could escape the store root (path traversal).  Enforce:
// first char alphanumeric, rest alnum or . _ + -.

fn name_safe(s: []const u8) bool {
    if (s.len == 0 or !std.ascii.isAlphanumeric(s[0])) return false;
    for (s[1..]) |c| {
        if (!std.ascii.isAlphanumeric(c) and
            c != '.' and c != '_' and c != '+' and c != '-') return false;
    }
    return true;
}

// ─── Structural walk ────────────────────────────────────────────────────────

/// Canonicalize a path: if relative, resolve against base_dir using realpath.
/// Returns an arena-owned absolute path, or null on error.  Absolute paths
/// are kept verbatim (no normalization), like the C strdup.
fn canonicalize_path(a: std.mem.Allocator, path: []const u8, base_dir: []const u8) ?[]const u8 {
    if (path.len == 0) return null;
    if (path[0] == '/') return a.dupe(u8, path) catch null;

    // Build the full path: base_dir/path, then realpath resolves symlinks
    // and normalizes.
    const full = std.fmt.allocPrint(a, "{s}/{s}", .{ base_dir, path }) catch return null;
    defer a.free(full);
    const full_z = a.dupeZ(u8, full) catch return null;
    defer a.free(full_z);
    var resolved: [std.fs.max_path_bytes]u8 = undefined;
    const r = realpath(full_z.ptr, &resolved) orelse return null;
    return a.dupe(u8, std.mem.span(r)) catch null;
}

/// Map one Src union: < Path = "..." > | < Fetch = { url, hash } >.
fn map_src(a: std.mem.Allocator, out: *Src, u: ?*dhallz.Term, pkg: []const u8, base_dir: []const u8, e: *ErrBuf) error{FxPackageset}!void {
    out.* = .{ .kind = .path };
    if (u == null or u.?.tag != .TmUnionLit)
        return e.set("package '{s}': src must be < Path = Text | Fetch = {{ url, hash }} >", .{pkg});
    const sel = union_selected(u) orelse
        return e.set("package '{s}': malformed src union", .{pkg});
    const label = std.mem.span(sel.label.?);
    if (std.mem.eql(u8, label, "Path")) {
        out.kind = .path;
        const raw_path = term_text_cstr(a, sel.value) orelse
            return e.set("package '{s}': < Path = ... > value must be Text", .{pkg});
        // Canonicalize relative paths to absolute using realpath against
        // base_dir.
        out.path = canonicalize_path(a, raw_path, base_dir) orelse
            return e.set("package '{s}': cannot canonicalize src path '{s}'", .{ pkg, raw_path });
    } else if (std.mem.eql(u8, label, "Fetch")) {
        out.kind = .fetch;
        const v = sel.value.?;
        if (v.tag != .TmRecordLit)
            return e.set("package '{s}': Fetch must be a {{ url, hash }} record", .{pkg});
        out.url = try need_text(a, v, "url", pkg, e);
        out.hash = try need_text(a, v, "hash", pkg, e);
    } else {
        return e.set("package '{s}': unknown src alternative '< {s} = ... >' (expected Path or Fetch)", .{ pkg, label });
    }
}

/// Map one normalized Package record literal into an arena-allocated Package.
fn map_package(a: std.mem.Allocator, rec: ?*dhallz.Term, base_dir: []const u8, e: *ErrBuf) error{FxPackageset}!*Package {
    const p = a.create(Package) catch return e.set("out of memory", .{});
    p.* = .{ .name = "", .version = "", .target = "" };

    p.name = try need_text(a, rec, "name", "package", e);
    const where = try alloc_where(a, p.name, e);

    if (!name_safe(p.name))
        return e.set("{s}: invalid package name (need [A-Za-z0-9][A-Za-z0-9._+-]*)", .{where});

    p.version = try need_text(a, rec, "version", where, e);

    const src_t = rec_get(rec, "src") orelse
        return e.set("{s}: missing field 'src'", .{where});
    try map_src(a, &p.src, src_t, p.name, base_dir, e);

    const deps = rec_get(rec, "deps") orelse
        return e.set("{s}: missing field 'deps'", .{where});
    if (deps.tag != .TmNil and deps.tag != .TmCons)
        return e.set("{s}: 'deps' must be a List Text", .{where});
    const ndeps = list_length(deps);
    const dep_arr = a.alloc([]const u8, ndeps) catch return e.set("out of memory", .{});
    var i: usize = 0;
    var q: ?*dhallz.Term = deps;
    while (q) |t| : (q = t.as.cons.tail) {
        if (t.tag != .TmCons) break;
        dep_arr[i] = term_text_cstr(a, t.as.cons.head) orelse
            return e.set("{s}: dependency name must be Text", .{where});
        i += 1;
    }
    p.deps = dep_arr[0..i];

    // optional `excludes : List Text` — absent field => empty list (backward
    // compat: a package-set without `excludes` still loads unchanged)
    if (rec_get(rec, "excludes")) |excl| {
        if (excl.tag != .TmNil and excl.tag != .TmCons)
            return e.set("{s}: 'excludes' must be a List Text", .{where});
        const nexcl = list_length(excl);
        const ex_arr = a.alloc([]const u8, nexcl) catch return e.set("out of memory", .{});
        var j: usize = 0;
        var xq: ?*dhallz.Term = excl;
        while (xq) |t| : (xq = t.as.cons.tail) {
            if (t.tag != .TmCons) break;
            const x = term_text_cstr(a, t.as.cons.head) orelse
                return e.set("{s}: excludes entry must be Text", .{where});
            // LOUD rejection of entries that can never match: relative paths
            // within the src tree never start with '/' or "./", never end
            // with '/', never contain "//", and "" / "." / ".." are
            // meaningless.  Silent acceptance would silently keep hashing
            // the content the author meant to exclude.
            if (x.len == 0 or x[0] == '/' or
                (x.len >= 2 and x[0] == '.' and x[1] == '/') or
                x[x.len - 1] == '/' or std.mem.indexOf(u8, x, "//") != null or
                std.mem.eql(u8, x, ".") or std.mem.eql(u8, x, ".."))
            {
                return e.set("{s}: excludes entry '{s}' is not a clean relative path within the src tree", .{ where, x });
            }
            ex_arr[j] = x;
            j += 1;
        }
        p.excludes = ex_arr[0..j];
        // excludes only apply to a local src TREE (SRC_PATH); on a Fetch
        // source (url+hash) they would be silently ignored, so reject them
        // loudly rather than let the author think the exclusion took effect.
        if (p.excludes.len > 0 and p.src.kind != .path) {
            return e.set("{s}: 'excludes' is only valid for a Path src (Fetch src is content-addressed by its own url+hash)", .{where});
        }
    }

    const build = rec_get(rec, "build") orelse
        return e.set("{s}: missing or non-record 'build' (need {{ target, recipe }})", .{where});
    if (build.tag != .TmRecordLit)
        return e.set("{s}: missing or non-record 'build' (need {{ target, recipe }})", .{where});
    p.target = try need_text(a, build, "target", where, e);

    const recipe = rec_get(build, "recipe") orelse
        return e.set("{s}: build missing 'recipe'", .{where});
    if (recipe.tag != .TmNil and recipe.tag != .TmCons)
        return e.set("{s}: 'recipe' must be a List Action", .{where});
    var tail: *?*Action = &p.recipe;
    var rq: ?*dhallz.Term = recipe;
    while (rq) |t| : (rq = t.as.cons.tail) {
        if (t.tag != .TmCons) break;
        const act = try map_action(a, t.as.cons.head, p.name, e);
        tail.* = act;
        tail = &act.next;
    }
    return p;
}

fn build_packageset(a: std.mem.Allocator, out: *PackageSet, nf: ?*dhallz.Term, base_dir: []const u8, e: *ErrBuf) error{FxPackageset}!void {
    const rec = nf orelse
        return e.set("package-set must be a record {{ packages : List Package }}", .{});
    if (rec.tag != .TmRecordLit)
        return e.set("package-set must be a record {{ packages : List Package }}", .{});
    const packages = rec_get(rec, "packages") orelse
        return e.set("package-set missing 'packages'", .{});
    if (packages.tag != .TmNil and packages.tag != .TmCons)
        return e.set("package-set 'packages' must be a List Package", .{});

    var tail: *?*Package = &out.head;
    var q: ?*dhallz.Term = packages;
    while (q) |t| : (q = t.as.cons.tail) {
        if (t.tag != .TmCons) break;
        const item = t.as.cons.head;
        if (item == null or item.?.tag != .TmRecordLit)
            return e.set("each 'packages' element must be a Package record", .{});
        const p = try map_package(a, item, base_dir, e);
        if (out.find(p.name) != null)
            return e.set("duplicate package name '{s}'", .{p.name});
        tail.* = p;
        tail = &p.next;
        out.count += 1;
    }

    // every dep must exist in the set (a wrong dep silently produces a
    // wrong closure -> wrong hash, so reject here, loudly)
    var it = out.head;
    while (it) |p| : (it = p.next) {
        for (p.deps) |d| {
            if (out.find(d) == null)
                return e.set("package '{s}' depends on '{s}' which is not in the package set", .{ p.name, d });
            if (std.mem.eql(u8, d, p.name))
                return e.set("package '{s}' depends on itself", .{p.name});
        }
    }
}

// ─── Evaluation pipeline (packageset.c fx_packageset_load pattern) ──────────

pub const LoadError = error{ FxPackageset, OutOfMemory };

/// fx_packageset_load — on success `out` holds an arena-owned package table
/// (deinit() to free); on error the errdefer releases the arena and `e`
/// holds the verbatim packageset.c error string.
pub fn fx_packageset_load(out: *PackageSet, path: []const u8, e: *ErrBuf) LoadError!void {
    out.* = .{ .arena = std.heap.ArenaAllocator.init(c_alloc) };
    errdefer out.deinit();
    const a = out.arena.allocator();

    var path_buf: [4096:0]u8 = undefined;
    if (path.len >= path_buf.len)
        return e.set("cannot open package-set file '{s}'", .{path});
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_buf);

    const f = std.c.fopen(path_z, "rb") orelse
        return e.set("cannot open package-set file '{s}'", .{path});
    defer _ = std.c.fclose(f);

    // read_all (packageset.c:394-406)
    var src_list: std.ArrayList(u8) = .empty;
    var chunk: [65536]u8 = undefined;
    while (true) {
        const n = std.c.fread(&chunk, 1, chunk.len, f);
        if (n == 0) break;
        src_list.appendSlice(c_alloc, chunk[0..n]) catch
            return e.set("out of memory reading '{s}'", .{path});
        if (n < chunk.len) break;
    }
    defer src_list.deinit(c_alloc);

    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);

    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);
    import_mod.import_loader_push_root(loader, path_z);

    var p: dhallz.Parser = std.mem.zeroes(dhallz.Parser);
    p.loader = loader;
    var derr: dhallz.DhallError = undefined;
    ast.dhall_error_clear(&derr);

    const src_z = c_alloc.dupeZ(u8, src_list.items) catch
        return e.set("out of memory reading '{s}'", .{path});
    defer c_alloc.free(src_z);

    const t = parser.parse_source(&p, src_z.ptr, path_z, &derr);
    if (t == null)
        return e.set("package-set parse error: {s}", .{std.mem.sliceTo(&derr.msg, 0)});

    // Best-effort typecheck: WARNING-only (see file header — the dhake-style
    // shorthand Action literal infers as a singleton union, so heterogeneous
    // recipes do not typecheck even though they normalize correctly).
    const ty = typecheck.infer_type(&p, t.?, &derr);
    if (ty == null) {
        std.debug.print(
            "fxstore: warning: package-set does not typecheck " ++
                "(shorthand Action literals infer as singleton unions; " ++
                "structural walk continues):\n  {s}\n",
            .{std.mem.sliceTo(&derr.msg, 0)},
        );
    }

    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        derr = normalize.normalize_get_error().*;
        return e.set("package-set normalize error: {s}", .{std.mem.sliceTo(&derr.msg, 0)});
    }

    // Extract the base directory from the package-set path for canonicalizing
    // relative Src paths.
    const base_dir = if (std.mem.lastIndexOfScalar(u8, path, '/')) |slash|
        path[0..slash]
    else
        ".";

    try build_packageset(a, out, nf, base_dir, e);
}

// ─── unit tests (fixtures in zig/corpus/packageset/) ────────────────────────

const testing = std.testing;

fn load_fixture(e: *ErrBuf, name: []const u8) LoadError!PackageSet {
    var path_buf: [512]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "zig/corpus/packageset/{s}", .{name}) catch
        return error.OutOfMemory;
    var ps: PackageSet = undefined;
    try fx_packageset_load(&ps, path, e);
    return ps;
}

/// realpath of a cwd-relative path (expected-value helper for the tests).
fn cwd_realpath(a: std.mem.Allocator, rel: []const u8) ![]const u8 {
    const z = try a.dupeZ(u8, rel);
    defer a.free(z);
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const r = realpath(z.ptr, &buf) orelse return error.FileNotFound;
    return a.dupe(u8, std.mem.span(r));
}

test "name_safe (packageset.c:192-199)" {
    const ok = [_][]const u8{ "hello", "a", "libxml2", "g++", "clang-17", "pkg.config", "a.b_c+d-e", "A9" };
    for (ok) |s| try testing.expect(name_safe(s));
    const bad = [_][]const u8{ "", ".", "..", ".hidden", "a/b", "../evil", "a b", "a\tb", "héllo", "a:", "a\\b" };
    for (bad) |s| try testing.expect(!name_safe(s));
}

test "canonicalize_path (realpath against base_dir; absolute verbatim)" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    // nonexistent -> null (realpath fails)
    try testing.expect(canonicalize_path(a, "no/such/dir", ".") == null);
    try testing.expect(canonicalize_path(a, "", ".") == null);

    // absolute path: strdup'd verbatim, NO normalization (C semantics)
    const abs = canonicalize_path(a, "/tmp/../usr", "/base") orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("/tmp/../usr", abs);

    // relative: resolved against base_dir and normalized by realpath
    const rel = canonicalize_path(a, ".", "zig/corpus/packageset") orelse return error.TestUnexpectedResult;
    const expected = try cwd_realpath(a, "zig/corpus/packageset");
    try testing.expectEqualStrings(expected, rel);
}

test "good.dhall: full table round-trip (names, versions, deps, target, src, excludes, recipe)" {
    var e = ErrBuf{};
    var ps = try load_fixture(&e, "good.dhall");
    defer ps.deinit();

    try testing.expectEqual(@as(usize, 2), ps.count);
    try testing.expect(ps.find("hello") != null);
    try testing.expect(ps.find("world") != null);
    try testing.expect(ps.find("nope") == null);

    // package-set order
    try testing.expectEqualStrings("hello", ps.head.?.name);
    try testing.expectEqualStrings("world", ps.head.?.next.?.name);
    try testing.expect(ps.head.?.next.?.next == null);

    const hello = ps.find("hello").?;
    try testing.expectEqualStrings("hello", hello.name);
    try testing.expectEqualStrings("1.0", hello.version);
    try testing.expectEqual(SrcKind.path, hello.src.kind);
    const want_path = try cwd_realpath(testing.allocator, "zig/corpus/packageset/src-tree");
    defer testing.allocator.free(want_path);
    try testing.expectEqualStrings(want_path, hello.src.path.?);
    try testing.expectEqual(@as(usize, 0), hello.deps.len);
    try testing.expectEqual(@as(usize, 2), hello.excludes.len);
    try testing.expectEqualStrings("build-out", hello.excludes[0]);
    try testing.expectEqualStrings("docs/cache", hello.excludes[1]);
    try testing.expectEqualStrings("hello", hello.target);

    // recipe: all 11 action kinds, package-set order, with their payloads
    const want_kinds = [_]ActionKind{ .shell, .copy, .mkdir, .rm, .touch, .move, .symlink, .chmod, .echo, .env, .run };
    var n: usize = 0;
    var it = hello.recipe;
    while (it) |act| : (it = act.next) {
        try testing.expect(n < want_kinds.len);
        try testing.expectEqual(want_kinds[n], act.kind);
        n += 1;
    }
    try testing.expectEqual(@as(usize, 11), n);

    const shell = hello.recipe.?;
    try testing.expectEqualStrings("make hello", shell.a.?);
    try testing.expect(shell.b == null);
    try testing.expectEqual(@as(usize, 0), shell.argv.len);

    const copy = shell.next.?;
    try testing.expectEqualStrings("hello", copy.a.?);
    try testing.expectEqualStrings("bin/hello", copy.b.?);

    const chmod = copy.next.?.next.?.next.?.next.?.next.?.next.?;
    try testing.expectEqual(ActionKind.chmod, chmod.kind);
    try testing.expectEqualStrings("bin/hello", chmod.a.?);
    try testing.expectEqualStrings("0755", chmod.b.?);

    const env = chmod.next.?.next.?;
    try testing.expectEqual(ActionKind.env, env.kind);
    try testing.expectEqualStrings("CC", env.a.?);
    try testing.expectEqualStrings("cc", env.b.?);

    const run = env.next.?;
    try testing.expectEqual(ActionKind.run, run.kind);
    try testing.expectEqual(@as(usize, 2), run.argv.len);
    try testing.expectEqualStrings("./configure", run.argv[0]);
    try testing.expectEqualStrings("--prefix=/build", run.argv[1]);
    try testing.expectEqualStrings("./configure", run.a.?); // program name compat

    const world = ps.find("world").?;
    try testing.expectEqualStrings("world", world.name);
    try testing.expectEqualStrings("2.3.4", world.version);
    try testing.expectEqual(SrcKind.fetch, world.src.kind);
    try testing.expect(world.src.path == null);
    try testing.expectEqualStrings("https://example.com/world-2.3.4.tar.gz", world.src.url.?);
    try testing.expectEqualStrings("f2ca1bb3c199e6c9eda0f4d1e7bb8b4b0f1b2a3c4d5e6f708192a3b4c5d6e7f8", world.src.hash.?);
    try testing.expectEqual(@as(usize, 1), world.deps.len);
    try testing.expectEqualStrings("hello", world.deps[0]);
    try testing.expectEqual(@as(usize, 0), world.excludes.len);
    try testing.expectEqualStrings("world", world.target);
    try testing.expect(world.recipe == null); // empty recipe -> no actions
}

test "bad fixtures: missing dep, dup name, unsafe name, excludes-on-Fetch, non-clean excludes" {
    var e = ErrBuf{};

    // missing dep
    e = .{};
    try testing.expectError(error.FxPackageset, load_fixture(&e, "missing-dep.dhall"));
    try testing.expectEqualStrings(
        "package 'world' depends on 'ghost' which is not in the package set",
        e.slice(),
    );

    // duplicate name
    e = .{};
    try testing.expectError(error.FxPackageset, load_fixture(&e, "dup-name.dhall"));
    try testing.expectEqualStrings("duplicate package name 'hello'", e.slice());

    // unsafe name (path traversal)
    e = .{};
    try testing.expectError(error.FxPackageset, load_fixture(&e, "unsafe-name.dhall"));
    try testing.expectEqualStrings(
        "package '../evil': invalid package name (need [A-Za-z0-9][A-Za-z0-9._+-]*)",
        e.slice(),
    );

    // excludes on a Fetch src
    e = .{};
    try testing.expectError(error.FxPackageset, load_fixture(&e, "excludes-fetch.dhall"));
    try testing.expectEqualStrings(
        "package 'world': 'excludes' is only valid for a Path src (Fetch src is content-addressed by its own url+hash)",
        e.slice(),
    );

    // non-clean excludes entries
    const bad_excludes = [_]struct { f: []const u8, x: []const u8 }{
        .{ .f = "excludes-abs.dhall", .x = "/abs" },
        .{ .f = "excludes-dotdot.dhall", .x = ".." },
        .{ .f = "excludes-doubleslash.dhall", .x = "a//b" },
        .{ .f = "excludes-trailing-slash.dhall", .x = "build/" },
        .{ .f = "excludes-dotslash.dhall", .x = "./x" },
    };
    for (bad_excludes) |case| {
        e = .{};
        try testing.expectError(error.FxPackageset, load_fixture(&e, case.f));
        const want = try std.fmt.allocPrint(testing.allocator, "package 'hello': excludes entry '{s}' is not a clean relative path within the src tree", .{case.x});
        defer testing.allocator.free(want);
        try testing.expectEqualStrings(want, e.slice());
    }
}

test "self-dep rejection + where[160] truncation contract" {
    var e = ErrBuf{};

    e = .{};
    try testing.expectError(error.FxPackageset, load_fixture(&e, "self-dep.dhall"));
    try testing.expectEqualStrings("package 'lonely' depends on itself", e.slice());

    // C builds the error context in char where[160] via snprintf, so a very
    // long name truncates `where` at 159 bytes; the message is that 159-byte
    // prefix + the fixed suffix.
    e = .{};
    try testing.expectError(error.FxPackageset, load_fixture(&e, "long-name.dhall"));
    try testing.expectEqual(
        @as(usize, 159 + ": invalid package name (need [A-Za-z0-9][A-Za-z0-9._+-]*)".len),
        e.len,
    );
    try testing.expect(std.mem.startsWith(u8, e.slice(), "package '.aaa"));
}

test "shorthand recipe: infer_type WARNING-only, walk succeeds (2 heterogeneous tags)" {
    var e = ErrBuf{};
    var ps = try load_fixture(&e, "shorthand.dhall");
    defer ps.deinit();
    try testing.expectEqual(@as(usize, 1), ps.count);
    const p = ps.find("mixed").?;
    var n: usize = 0;
    var it = p.recipe;
    while (it) |act| : (it = act.next) {
        try testing.expect(act.kind == .shell or act.kind == .echo);
        n += 1;
    }
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("", e.slice()); // walk produced no error
}

test "excludes absent field defaults to empty (backward compat)" {
    var e = ErrBuf{};
    var ps = try load_fixture(&e, "no-excludes-field.dhall");
    defer ps.deinit();
    const p = ps.find("plain").?;
    try testing.expectEqual(@as(usize, 0), p.excludes.len);
    try testing.expectEqual(SrcKind.path, p.src.kind);
}

test "two-load independence: each PackageSet owns its arena" {
    var e = ErrBuf{};
    var a_set = try load_fixture(&e, "good.dhall");
    defer a_set.deinit();
    var b_set = try load_fixture(&e, "shorthand.dhall");
    defer b_set.deinit();
    // The second load reset the shared dhall arena; the first table must
    // still hold its strings (it owns them).
    try testing.expectEqualStrings("hello", a_set.find("hello").?.name);
    try testing.expectEqualStrings("make hello", a_set.find("hello").?.recipe.?.a.?);
    try testing.expectEqualStrings("mixed", b_set.find("mixed").?.name);
}

test "missing package-set file error" {
    var e = ErrBuf{};
    try testing.expectError(error.FxPackageset, load_fixture(&e, "no-such-file.dhall"));
    try testing.expectEqualStrings(
        "cannot open package-set file 'zig/corpus/packageset/no-such-file.dhall'",
        e.slice(),
    );
}

test "parse error surfaces the dhall message" {
    var e = ErrBuf{};
    try testing.expectError(error.FxPackageset, load_fixture(&e, "parse-error.dhall"));
    try testing.expect(std.mem.startsWith(u8, e.slice(), "package-set parse error: "));
}
