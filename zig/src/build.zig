// build.zig — faithful Zig port of build.c (U5): the recipe executor plus
// the bwrap/palisade stage3 sandbox.  run_action/print_action come from
// dhake/src/dhake.c (453-557 / 560-579) with the two fxstore changes:
//
//   (a) relative output paths resolve against the package's temp BUILD dir
//       (workdir — the dir that becomes the store path); each direct dep's
//       store path is exported as FX_DEP_<NAME> (NAME uppercased,
//       non-alnum -> '_');
//   (b) the two EXECUTING actions (Shell, Run) run under a bwrap sandbox
//       with the palisade stage3 inner binary (vendor/palisade) exec'd at
//       its REAL host path (see the argv order in build_bwrap_argv — the
//       header's older "/init" contract predates the `--ro-bind / /` fix
//       documented in build.c:463-472).
//
// SECURITY invariants preserved verbatim:
//   - RATTAN_ and LD_ variables are scrubbed from the child environment
//     before exec (stage3 reads RATTAN_ALLOW_PTRACE = skip seccomp, plus
//     RATTAN_EXTRA_PROMISES/RATTAN_RLIMITS; LD_PRELOAD injects into the
//     exec chain).
//   - the LANDLOCK_SPEC unveils ONLY the bind-mounted paths, never "/:r".
//   - stage3-absent is a LOUD failure (exit 127), never a fallback; the
//     LOUD NON-HERMETIC fallback is reserved for bwrap-absent only.
//   - stage3/bwrap/cosmo are resolved EXACTLY ONCE (first call wins), from
//     main() before any package set is loaded — a recipe's Env action can
//     rewrite PATH or FXSTORE_STAGE3, and must not be able to re-point the
//     sandbox at its own code.
//
// DIFFERENCES FROM C (mechanical only — never observable): the bwrap argv,
// the LANDLOCK_SPEC, the scrub list, the cosmo PATH prepend and the
// NON-HERMETIC warning are all built BEFORE the fork (the C builds them in
// the child after fork), so the forked child touches only pre-built memory
// and libc — no allocator, no std.Io.  A spec/stage3/argv failure therefore
// prints the same stderr line and returns the same 127 from the parent
// without forking.  The argv builder (build_bwrap_argv) and the spec
// builder (build_landlock_spec) are factored out to be unit-testable
// WITHOUT executing anything.
const std = @import("std");
const ps = @import("packageset");

const Action = ps.Action;
const ActionKind = ps.ActionKind;
const Package = ps.Package;
const SrcKind = ps.SrcKind;

const Io = std.Io;
const Allocator = std.mem.Allocator;
const c_alloc = std.heap.c_allocator;

pub const Error = error{FxBuild};

pub const err_cap_default = 2048;

/// The fx_err helper (fxstore.h) as a context struct (the packageset/
/// derivation ErrBuf pattern) with the verbatim build.c error strings.
pub const ErrBuf = struct {
    buf: [err_cap_default]u8 = undefined,
    len: usize = 0,

    pub fn set(self: *ErrBuf, comptime fmt: []const u8, args: anytype) error{FxBuild} {
        var aw: Io.Writer.Allocating = .init(c_alloc);
        defer aw.deinit();
        aw.writer.print(fmt, args) catch unreachable;
        const s = aw.written();
        const n = @min(s.len, self.buf.len - 1);
        @memcpy(self.buf[0..n], s[0..n]);
        self.buf[n] = 0;
        self.len = n;
        return error.FxBuild;
    }

    pub fn slice(self: *const ErrBuf) []const u8 {
        return self.buf[0..self.len];
    }
};

// ─── libc surface (std.c where it exists; the C uses these directly) ───────

const FILE = opaque {};

extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;
extern "c" fn execvp(file: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;
extern "c" fn realpath(path: [*:0]const u8, resolved: [*]u8) ?[*:0]u8;
extern "c" fn strerror(errnum: c_int) [*:0]const u8;
extern "c" fn strtol(s: [*:0]const u8, endptr: ?*?[*:0]u8, base: c_int) c_long;
// open is variadic in C; the 3-arg prototype is ABI-correct for the int
// mode argument on x86_64/aarch64 (integer varargs live in registers).
extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern "c" fn remove(path: [*:0]const u8) c_int;
extern "c" fn rename(old: [*:0]const u8, new: [*:0]const u8) c_int;
extern "c" fn symlink(target: [*:0]const u8, linkpath: [*:0]const u8) c_int;
extern "c" fn chmod(path: [*:0]const u8, mode: c_uint) c_int;
extern "c" fn utimes(path: [*:0]const u8, times: ?*[2]Timeval) c_int;
extern "c" fn gettimeofday(tv: ?*Timeval, tz: ?*anyopaque) c_int;
extern "c" fn fopen(path: [*:0]const u8, mode: [*:0]const u8) ?*FILE;
extern "c" fn fread(ptr: [*]u8, size: usize, nmemb: usize, f: *FILE) usize;
extern "c" fn fwrite(ptr: [*]const u8, size: usize, nmemb: usize, f: *FILE) usize;
extern "c" fn fclose(f: *FILE) c_int;

const Timeval = extern struct { sec: isize, usec: isize };

/// glibc x86_64/aarch64 `struct stat` — only st_mode is consumed (is_dir2).
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

extern "c" fn stat(path: [*:0]const u8, st: *CStat) c_int;

// Linux x86_64/aarch64 fcntl flags (C's O_WRONLY | O_CREAT in touch_file).
const O_WRONLY: c_int = 0o1;
const O_CREAT: c_int = 0o100;
const X_OK: c_uint = 1;
const EEXIST: c_int = 17;
const ENOENT: c_int = 2;

fn errstr_e(errnum: c_int) []const u8 {
    return std.mem.span(strerror(errnum));
}

fn errno() c_int {
    return std.c._errno().*;
}

// ─── unbuffered stdout/stderr (the C printf+fflush pairs) ──────────────────

/// The action-echo fd (the C writes stdout).  Tests repoint this at a file:
/// under `zig test --listen=-` fd 1 is the test-runner PROTOCOL pipe, and a
/// raw write(1) there desyncs the runner (observed as a hang).
/// swappable so tests can capture the echoes (the zig test runner uses fd 1
/// as its --listen protocol pipe — a raw write there hangs the runner).
pub var g_out_fd: std.c.fd_t = 1;

fn out_print(comptime fmt: []const u8, args: anytype) void {
    var aw: Io.Writer.Allocating = .init(c_alloc);
    defer aw.deinit();
    aw.writer.print(fmt, args) catch return;
    const s = aw.written();
    _ = std.c.write(g_out_fd, s.ptr, s.len);
}

/// Parent-side stderr messages (no format-size bound: paths are unbounded).
fn write_err(comptime fmt: []const u8, args: anytype) void {
    var aw: Io.Writer.Allocating = .init(c_alloc);
    defer aw.deinit();
    aw.writer.print(fmt, args) catch return;
    const s = aw.written();
    _ = std.c.write(2, s.ptr, s.len);
}

// ─── Path resolution against the workdir (build.c:76-84) ───────────────────

/// malloc'd absolute path: p itself if absolute, else workdir/p.
fn resolve_path(a: Allocator, p: []const u8, workdir: []const u8) ?[]u8 {
    if (p.len == 0 or p[0] != '/')
        return std.fmt.allocPrint(a, "{s}/{s}", .{ workdir, p }) catch null;
    return a.dupe(u8, p) catch null;
}

// ─── dhake filesystem helpers (build.c:88-111, verbatim) ───────────────────

fn copy_file(from: []const u8, to: []const u8) bool {
    const fz = c_alloc.dupeZ(u8, from) catch return false;
    defer c_alloc.free(fz);
    const tz = c_alloc.dupeZ(u8, to) catch return false;
    defer c_alloc.free(tz);
    const in = fopen(fz, "rb") orelse {
        write_err("fxstore: copy: cannot open '{s}'\n", .{from});
        return false;
    };
    const outf = fopen(tz, "wb") orelse {
        write_err("fxstore: copy: cannot open '{s}'\n", .{to});
        _ = fclose(in);
        return false;
    };
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = fread(&buf, 1, buf.len, in);
        if (n == 0) break;
        if (fwrite(&buf, 1, n, outf) != n) {
            write_err("fxstore: copy: write error to '{s}'\n", .{to});
            _ = fclose(in);
            _ = fclose(outf);
            return false;
        }
    }
    _ = fclose(in);
    _ = fclose(outf);
    return true;
}

fn touch_file(path: []const u8) bool {
    const pz = c_alloc.dupeZ(u8, path) catch return false;
    defer c_alloc.free(pz);
    const fd = open(pz, O_WRONLY | O_CREAT, 0o644);
    if (fd < 0) {
        write_err("fxstore: touch: cannot open '{s}'\n", .{path});
        return false;
    }
    _ = std.c.close(fd);
    var tv: [2]Timeval = undefined;
    _ = gettimeofday(&tv[0], null);
    tv[1] = tv[0];
    _ = utimes(pz, &tv);
    return true;
}

// ─── FX_DEP_<NAME> environment injection (build.c:117-163) ─────────────────

/// "FX_DEP_" + uppercased name with non-alphanumerics mapped to '_'.
fn dep_env_name(a: Allocator, dep: []const u8) ?[:0]u8 {
    const out = a.allocSentinel(u8, 7 + dep.len, 0) catch return null;
    @memcpy(out[0..7], "FX_DEP_");
    for (dep, 0..) |ch, i|
        out[7 + i] = if (std.ascii.isAlphanumeric(ch)) std.ascii.toUpper(ch) else '_';
    return out;
}

/// Replace the FX_DEP_* environment with exactly this package's deps (the
/// clear matters: without it a previous package's FX_DEP_* would leak into
/// the next recipe built in this process).
fn set_dep_env(dep_names: []const []const u8, dep_paths: []const []const u8) c_int {
    var arena = std.heap.ArenaAllocator.init(c_alloc);
    defer arena.deinit();
    const a = arena.allocator();

    // collect the current FX_DEP_* names first — unsetenv mutates environ,
    // so the collection pass must finish before the first unsetenv
    var stale: std.ArrayListUnmanaged([:0]const u8) = .empty;
    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        const s = std.mem.span(entry);
        if (!std.mem.startsWith(u8, s, "FX_DEP_")) continue;
        const eq = std.mem.indexOfScalar(u8, s, '=') orelse s.len;
        const nm = a.dupeZ(u8, s[0..eq]) catch continue; // C: malloc fail → skip
        stale.append(a, nm) catch continue;
    }
    for (stale.items) |n| _ = unsetenv(n.ptr);

    for (dep_names, dep_paths) |dn, dp| {
        const v = dep_env_name(a, dn) orelse return -1;
        const vz = a.dupeZ(u8, dp) catch return -1;
        _ = setenv(v.ptr, vz.ptr, 1);
    }
    return 0;
}

// ─── bwrap sandbox wrapper helpers (build.c:167-182) ───────────────────────

fn is_dir2(p: ?[]const u8) bool {
    const pz = p orelse return false;
    if (pz.len == 0) return false;
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    if (pz.len >= buf.len) return false;
    @memcpy(buf[0..pz.len], pz);
    buf[pz.len] = 0;
    var st: CStat = undefined;
    return stat(@ptrCast(&buf), &st) == 0 and (st.mode & 0o170000) == 0o040000;
}

// ─── stage3 (palisade) inner sandbox binary (build.c:186-219) ──────────────

/// Pledge promise set for build recipes: rattan's agent baseline (stdio
/// rpath wpath cpath flock exec prot_exec proc recvfd) plus dpath and fattr.
/// NO inet/dns/tty: builds run network-off.
pub const FXSTORE_PROMISES = "stdio rpath wpath cpath dpath flock fattr exec prot_exec proc recvfd";

/// The compile-time FXSTORE_STAGE3_PATH default (the Makefile bakes the
/// vendor/palisade submodule's bin/stage3 into the C build here).
pub const stage3_default_path = "vendor/palisade/bin/stage3";

var g_stage3_path: ?[:0]const u8 = null;
var g_bwrap_path: ?[:0]const u8 = null;
var g_cosmo_root: ?[:0]const u8 = null;
var g_cosmo_bin: ?[:0]const u8 = null;

/// Resolved EXACTLY ONCE: the FXSTORE_STAGE3 env override if set when
/// fxstore started, else the compile-time default.  Called from main()
/// before any package-set is loaded (a recipe's Env action can set
/// arbitrary variables — a lazy read would let a recipe re-point the
/// sandbox's inner binary at its own code).
pub fn fx_stage3_resolve() void {
    if (g_stage3_path != null) return;
    const p = getenv("FXSTORE_STAGE3");
    g_stage3_path =
        if (p != null and p.?[0] != 0) std.mem.span(p.?) else stage3_default_path;
}

pub fn stage3_path() ?[]const u8 {
    return g_stage3_path;
}

fn stage3_bin() [:0]const u8 {
    if (g_stage3_path == null) fx_stage3_resolve();
    return g_stage3_path.?;
}

/// Resolved absolute bwrap path (null when not resolvable at startup).
/// Looked up ONCE, before any recipe Env action runs: execvp("bwrap")
/// searches the CURRENT PATH, which recipes control.  The child execs this
/// ABSOLUTE path (no PATH search); null means take the LOUD fallback branch.
pub fn fx_bwrap_resolve() void {
    if (g_bwrap_path != null) return;
    const path_env = getenv("PATH") orelse return;
    const dup = c_alloc.dupeZ(u8, std.mem.span(path_env)) catch return;
    defer c_alloc.free(dup);
    var it = std.mem.splitScalar(u8, dup, ':');
    while (it.next()) |tok| {
        if (tok.len == 0) continue;
        var cand: [std.fs.max_path_bytes]u8 = undefined;
        const cand_s = std.fmt.bufPrint(&cand, "{s}/bwrap", .{tok}) catch continue;
        if (cand_s.len + 1 >= cand.len) continue; // C's snprintf truncation check
        cand[cand_s.len] = 0;
        if (std.c.access(@ptrCast(&cand), X_OK) == 0) {
            g_bwrap_path = c_alloc.dupeZ(u8, cand_s) catch null;
            return;
        }
    }
}

pub fn bwrap_path() ?[]const u8 {
    return g_bwrap_path;
}

/// Resolved cosmocc toolchain install root (e.g. ~/.local/cosmo) and its
/// bin/ subdir — EXACTLY ONCE at startup: the FXSTORE_COSMO override wins,
/// else cosmocc is discovered via PATH and realpath'd (so the Landlock
/// unveil and the ro-bind use the resolved path).  root/bin stay null when
/// cosmocc is NOT resolvable — graceful absence.
pub fn fx_cosmo_resolve() void {
    if (g_cosmo_root != null) return;
    var root: ?[]const u8 = null;
    const ov = getenv("FXSTORE_COSMO");
    if (ov != null and ov.?[0] != 0) {
        // Validate like the discover path: ABSOLUTE and, after realpath, not
        // "/" ("/" would unveil the ENTIRE host fs rx from build_landlock_spec;
        // relative would exec the recipe's own workdir copies via PATH).
        const ovs = std.mem.span(ov.?);
        var real: [std.fs.max_path_bytes]u8 = undefined;
        if (ovs[0] == '/' and ovs.len < real.len) {
            @memcpy(real[0..ovs.len], ovs);
            real[ovs.len] = 0;
            if (realpath(@ptrCast(&real), &real)) |r| {
                const rs = std.mem.span(r);
                if (!std.mem.eql(u8, rs, "/")) root = c_alloc.dupe(u8, rs) catch null;
            }
        }
    } else {
        const path_env = getenv("PATH") orelse {
            // fall through to the graceful-absence tail
            if (root == null) return;
            unreachable;
        };
        const dup = c_alloc.dupeZ(u8, std.mem.span(path_env)) catch return;
        defer c_alloc.free(dup);
        var it = std.mem.splitScalar(u8, dup, ':');
        while (it.next()) |tok| {
            if (tok.len == 0) continue;
            var cand: [std.fs.max_path_bytes]u8 = undefined;
            const cand_s = std.fmt.bufPrint(&cand, "{s}/cosmocc", .{tok}) catch continue;
            if (cand_s.len + 1 >= cand.len) continue;
            cand[cand_s.len] = 0;
            if (std.c.access(@ptrCast(&cand), X_OK) != 0) continue;
            var real: [std.fs.max_path_bytes]u8 = undefined;
            if (realpath(@ptrCast(&cand), &real)) |r| {
                // real = .../cosmo/bin/cosmocc -> strip file, then bin/
                const rs = std.mem.span(r);
                if (std.mem.lastIndexOfScalar(u8, rs, '/')) |cut1| {
                    // C: cut1 > real && (cut2 = strrchr(real, '/')) && cut2 > real
                    if (cut1 > 0) {
                        if (std.mem.lastIndexOfScalar(u8, rs[0..cut1], '/')) |cut2| {
                            if (cut2 > 0) root = c_alloc.dupe(u8, rs[0..cut2]) catch null;
                        }
                    }
                }
            }
            break; // C breaks after the first PATH hit (X_OK), realpath or not
        }
    }
    const r = root orelse return; // graceful absence
    if (r.len == 0) {
        c_alloc.free(r);
        return;
    }
    g_cosmo_root = @ptrCast(r);
    g_cosmo_bin = std.fmt.allocPrintSentinel(c_alloc, "{s}/bin", .{r}, 0) catch null;
}

pub fn cosmo_root() ?[]const u8 {
    return g_cosmo_root;
}

pub fn cosmo_bin() ?[]const u8 {
    return g_cosmo_bin;
}

// ─── env scrubbing (build.c:320-341) ───────────────────────────────────────

/// Collect every RATTAN_* / LD_* variable NAME in environ (unsetenv mutates
/// environ, so collection always finishes before the first unsetenv — the
/// caller owns the returned arena memory).
fn collect_scrub_names(a: Allocator, out: *std.ArrayListUnmanaged([:0]const u8)) void {
    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        const s = std.mem.span(entry);
        if (!std.mem.startsWith(u8, s, "RATTAN_") and !std.mem.startsWith(u8, s, "LD_"))
            continue;
        const eq = std.mem.indexOfScalar(u8, s, '=') orelse s.len;
        const nm = a.dupeZ(u8, s[0..eq]) catch continue; // C: malloc fail → skip
        out.append(a, nm) catch continue;
    }
}

fn env_unset_names(names: []const [:0]const u8) void {
    for (names) |n| _ = unsetenv(n.ptr);
}

fn scrub_env() void {
    var arena = std.heap.ArenaAllocator.init(c_alloc);
    defer arena.deinit();
    var names: std.ArrayListUnmanaged([:0]const u8) = .empty;
    collect_scrub_names(arena.allocator(), &names);
    env_unset_names(names.items);
}

// ─── LANDLOCK_SPEC (build.c:346-410) ───────────────────────────────────────

/// stage3 parses LANDLOCK_SPEC through a fixed buffer (its MAX_ENV, 512
/// since M3) and dies on anything longer; use the same limit here so an
/// oversized spec fails with OUR message instead of stage3's.
pub const FX_LANDLOCK_SPEC_MAX = 512;

/// Append "path:perms" (with a ';' separator) to buf at *off.  Returns true
/// on success, false when it would not fit in buf.len (path NULL/"" is a
/// skip, not an error — SRC_FETCH packages have no src tree).
fn spec_append(buf: []u8, off: *usize, first: *bool, path: ?[]const u8, perms: []const u8) bool {
    const p = path orelse return true;
    if (p.len == 0) return true;
    const sep: usize = if (first.*) 0 else 1;
    if (off.* + p.len + 1 + perms.len + sep + 1 > buf.len) return false; // +1 ':' +1 NUL
    if (sep != 0) {
        buf[off.*] = ';';
        off.* += 1;
    }
    @memcpy(buf[off.*..][0..p.len], p);
    off.* += p.len;
    buf[off.*] = ':';
    off.* += 1;
    @memcpy(buf[off.*..][0..perms.len], perms);
    off.* += perms.len;
    buf[off.*] = 0;
    first.* = false;
    return true;
}

/// Build the LANDLOCK_SPEC "path:perms;..." unveiled for this invocation.
/// SECURITY: unveils ONLY the bind-mounted paths — never "/:r" (fxstore's
/// bwrap keeps the HOST / as the sandbox root).  Returns the written slice
/// of `buf` (NUL-terminated), or null when it would not fit (caller fails
/// LOUDLY — fail closed, never truncate).
fn build_landlock_spec(
    buf: []u8,
    cosmo: ?[]const u8,
    src_ro: ?[]const u8,
    store_root: []const u8,
    workdir: []const u8,
) ?[]const u8 {
    var off: usize = 0;
    var first = true;
    const ok =
        spec_append(buf, &off, &first, store_root, "r") and
        spec_append(buf, &off, &first, src_ro, "rx") and
        spec_append(buf, &off, &first, workdir, "rwcx") and
        spec_append(buf, &off, &first, "/usr", "rx") and
        spec_append(buf, &off, &first, "/bin", "rx") and
        spec_append(buf, &off, &first, "/lib", "rx") and
        (!is_dir2("/lib64") or spec_append(buf, &off, &first, "/lib64", "rx")) and
        // the cosmocc toolchain tree (when resolvable) is unveiled rx —
        // recipes exec cosmocc from it but cannot write to it
        (cosmo == null or spec_append(buf, &off, &first, cosmo.?, "rx")) and
        spec_append(buf, &off, &first, "/dev", "rwc") and
        spec_append(buf, &off, &first, "/proc", "r") and
        spec_append(buf, &off, &first, "/tmp", "rwc");
    if (!ok) return null;
    if (off >= FX_LANDLOCK_SPEC_MAX) return null;
    return buf[0..off :0];
}

// ─── the bwrap argv (build.c:455-538) — the testable builder ───────────────

/// Append the FULL bwrap invocation (argv[0] = "bwrap" placeholder) to
/// `argv`, every word NUL-terminated in `a`.  Exact build.c order — it is
/// order-critical (bwrap applies mounts in argv order).  Returns false on
/// allocation failure (the C's oom flag → child _exit(127)).
fn build_bwrap_argv(
    a: Allocator,
    argv: *std.ArrayListUnmanaged([:0]const u8),
    cosmo: ?[]const u8,
    stage3: []const u8,
    spec: []const u8,
    workdir: []const u8,
    src_ro: ?[]const u8,
    store_root: []const u8,
    real_argv: []const []const u8,
) bool {
    const P = struct {
        fn push(al: Allocator, list: *std.ArrayListUnmanaged([:0]const u8), s: []const u8) bool {
            const z = al.dupeZ(u8, s) catch return false;
            list.append(al, z) catch return false;
            return true;
        }
    };
    return
    // bwrap pivots to a fresh root: without `--ro-bind / /` the namespace
    // root stays EMPTY on some kernels and even /usr is unreachable (see
    // build.c:463-472).  This does NOT weaken hermeticity: the ro-binds and
    // the Landlock spec still gate everything.
    P.push(a, argv, "bwrap") and
        P.push(a, argv, "--unshare-all") and
        P.push(a, argv, "--die-with-parent") and
        P.push(a, argv, "--ro-bind") and P.push(a, argv, "/") and P.push(a, argv, "/") and
        // never uid 0 inside, even when the caller is root; bwrap maps 1000
        // -> the caller's real uid, so workdir/store writes keep ownership
        P.push(a, argv, "--uid") and P.push(a, argv, "1000") and
        P.push(a, argv, "--gid") and P.push(a, argv, "1000") and
        // fresh private /tmp, pushed BEFORE every bind: a tmpfs pushed after
        // the binds would shadow any store/src/workdir living under /tmp;
        // bind SOURCES still resolve in the original namespace
        P.push(a, argv, "--tmpfs") and P.push(a, argv, "/tmp") and
        P.push(a, argv, "--ro-bind") and P.push(a, argv, store_root) and P.push(a, argv, store_root) and
        // MVP-pragmatics toolchain binds (post-MVP: full hermeticity)
        P.push(a, argv, "--ro-bind") and P.push(a, argv, "/usr") and P.push(a, argv, "/usr") and
        P.push(a, argv, "--ro-bind") and P.push(a, argv, "/bin") and P.push(a, argv, "/bin") and
        P.push(a, argv, "--ro-bind") and P.push(a, argv, "/lib") and P.push(a, argv, "/lib") and
        (!is_dir2("/lib64") or
            (P.push(a, argv, "--ro-bind") and P.push(a, argv, "/lib64") and P.push(a, argv, "/lib64"))) and
        (src_ro == null or src_ro.?.len == 0 or
            (P.push(a, argv, "--ro-bind") and P.push(a, argv, src_ro.?) and P.push(a, argv, src_ro.?))) and
        // cosmocc toolchain tree, ro-bind at its REAL host path
        (cosmo == null or
            (P.push(a, argv, "--ro-bind") and P.push(a, argv, cosmo.?) and P.push(a, argv, cosmo.?))) and
        // workdir lives under <store_root>.build — OUTSIDE the ro-bound
        // store (a rw bind nested under a ro bind is unconstructable in
        // bwrap) — bound at its REAL host path; stage3 likewise.  Both host
        // paths exist under the ro-bound root, so no mountpoint synthesis
        // is needed (build.c:510-521).
        P.push(a, argv, "--bind") and P.push(a, argv, workdir) and P.push(a, argv, workdir) and
        P.push(a, argv, "--chdir") and P.push(a, argv, workdir) and
        P.push(a, argv, "--dev") and P.push(a, argv, "/dev") and
        P.push(a, argv, "--proc") and P.push(a, argv, "/proc") and
        P.push(a, argv, "--ro-bind") and P.push(a, argv, stage3) and P.push(a, argv, stage3) and
        P.push(a, argv, "--") and
        // stage3's argv is POSITIONAL: every word containing ':' goes into
        // the spec, the rest joins the promise string — so PROMISES and spec
        // are each pushed as ONE argv word
        P.push(a, argv, stage3) and
        P.push(a, argv, FXSTORE_PROMISES) and
        P.push(a, argv, spec) and
        P.push(a, argv, "--") and
        blk: {
            for (real_argv) |ra| if (!P.push(a, argv, ra)) break :blk false;
            break :blk true;
        };
}

/// Everything the forked child needs, built BEFORE the fork so the child
/// only touches pre-built memory and libc (no allocator, no std.Io).
const ExecPlan = struct {
    arena: std.heap.ArenaAllocator,
    /// execvp argv (argv[0] replaced with g_bwrap_path in the child, like
    /// the C's av[0] = g_bwrap_path)
    bwrap_argv: std.ArrayListUnmanaged(?[*:0]const u8) = .empty,
    /// plain fork/exec fallback argv (null-terminated)
    fallback_argv: std.ArrayListUnmanaged(?[*:0]const u8) = .empty,
    fallback_argv0: [:0]const u8 = "",
    /// prebuilt LOUD NON-HERMETIC warning (contains real_argv[0])
    warning: [:0]const u8 = "",
    /// cosmo bin/ prepended to PATH, prebuilt (null when no cosmo)
    path_prepend: ?[:0]const u8 = null,
    /// RATTAN_*/LD_* names to unsetenv in the child
    drop_names: std.ArrayListUnmanaged([:0]const u8) = .empty,
    workdir_z: [:0]const u8 = "",
};

fn exec_plan_build(
    plan: *ExecPlan,
    workdir: []const u8,
    src_ro: ?[]const u8,
    store_root: []const u8,
    real_argv: []const []const u8,
) bool {
    plan.* = .{ .arena = std.heap.ArenaAllocator.init(c_alloc) };
    errdefer plan.arena.deinit();
    const a = plan.arena.allocator();

    // C child: scrub_env (collect-then-unset; here the collect is pre-fork)
    collect_scrub_names(a, &plan.drop_names);

    // C child: prepend the cosmocc bin/ to PATH so `cosmocc` resolves inside
    // the sandbox (no-op when cosmocc is absent — graceful)
    if (g_cosmo_bin) |bin| {
        const oldp = getenv("PATH");
        plan.path_prepend = std.fmt.allocPrintSentinel(
            a,
            "{s}:{s}",
            .{ bin, if (oldp) |o| std.mem.span(o) else "" },
            0,
        ) catch null;
    }

    // workdir (for the fallback chdir)
    plan.workdir_z = a.dupeZ(u8, workdir) catch return false;

    // the C builds the warning inside the child with real_argv[0]; prebuilt
    // here so the child only writes memory that already exists
    const argv0: []const u8 = if (real_argv.len > 0) real_argv[0] else "";
    plan.warning = std.fmt.allocPrintSentinel(
        a,
        "\n*** fxstore: WARNING: bwrap not found — running NON-HERMETIC (unsandboxed): {s} ***\n\n",
        .{argv0},
        0,
    ) catch return false;

    // the fallback exec argv (plain fork/exec in the workdir)
    for (real_argv, 0..) |ra, i| {
        const z = a.dupeZ(u8, ra) catch return false;
        plan.fallback_argv.append(a, z) catch return false;
        if (i == 0) plan.fallback_argv0 = z;
    }
    plan.fallback_argv.append(a, null) catch return false;

    // the FULL bwrap argv, then the null sentinel for execvp
    var av: std.ArrayListUnmanaged([:0]const u8) = .empty;
    const st3 = stage3_bin();
    var spec_buf: [FX_LANDLOCK_SPEC_MAX + 1]u8 = undefined;
    const spec = build_landlock_spec(&spec_buf, g_cosmo_root, src_ro, store_root, workdir) orelse return false;
    if (!build_bwrap_argv(a, &av, g_cosmo_root, st3, spec, workdir, src_ro, store_root, real_argv))
        return false;
    for (av.items) |z| plan.bwrap_argv.append(a, z) catch return false;
    plan.bwrap_argv.append(a, null) catch return false;
    return true;
}

// ─── run_sandboxed (build.c:416-569) ───────────────────────────────────────

/// fork + exec real_argv under bwrap with stage3 as the inner sandbox; on
/// bwrap-absent fall back LOUDLY to plain exec in the workdir (stage3-
/// absent, by contrast, dies 127).  Returns the child's exit code (2 if
/// signaled).
fn run_sandboxed(
    workdir: []const u8,
    src_ro: ?[]const u8,
    store_root: []const u8,
    real_argv: []const []const u8,
) c_int {
    // The C performs the spec build, the stage3 access check and the argv
    // build in the child after fork; they are pure computation + stderr
    // writes, so doing them pre-fork is observably identical (same stderr,
    // same 127) and keeps the child libc-only.
    var plan: ExecPlan = undefined;
    if (!exec_plan_build(&plan, workdir, src_ro, store_root, real_argv)) {
        defer plan.arena.deinit();
        // distinguish the C's two child failures: spec overflow vs argv OOM
        var spec_buf: [FX_LANDLOCK_SPEC_MAX + 1]u8 = undefined;
        if (build_landlock_spec(&spec_buf, g_cosmo_root, src_ro, store_root, workdir) == null) {
            write_err("fxstore: cannot build LANDLOCK_SPEC for this build (store/src paths too long)\n", .{});
        } else {
            write_err("fxstore: out of memory building bwrap argv\n", .{});
        }
        return 127;
    }
    defer plan.arena.deinit();

    // stage3-absent: LOUD 127, never a fallback (checked BEFORE the bwrap
    // branch — even bwrap-absent + stage3-absent dies with THIS message)
    const st3 = stage3_bin();
    if (std.c.access(st3.ptr, X_OK) != 0) {
        write_err(
            "fxstore: stage3 not found or not executable at '{s}': {s}\n" ++
                "fxstore: build it with 'make stage3' (vendor/palisade)\n",
            .{ st3, errstr_e(errno()) },
        );
        return 127;
    }

    const pid = std.c.fork();
    if (pid < 0) {
        write_err("fxstore: fork failed: {s}\n", .{errstr_e(errno())});
        return 2;
    }
    if (pid == 0) {
        // ── child ── nothing below may degrade into a LESS-sandboxed exec.
        // libc only: pre-built memory, setenv/unsetenv, chdir, execvp.
        env_unset_names(plan.drop_names.items);
        if (plan.path_prepend) |np| _ = setenv("PATH", np.ptr, 1);

        if (g_bwrap_path == null) {
            // bwrap was not resolvable at startup: LOUD fallback directly —
            // never execvp("bwrap"), whose PATH lookup recipes control.
            _ = std.c.write(2, plan.warning.ptr, plan.warning.len);
            if (std.c.chdir(plan.workdir_z.ptr) != 0) {
                var mb: [1024]u8 = undefined;
                const m = std.fmt.bufPrint(
                    &mb,
                    "fxstore: chdir '{s}' failed: {s}\n",
                    .{ plan.workdir_z, errstr_e(errno()) },
                ) catch plan.workdir_z; // unreachable for sane paths
                _ = std.c.write(2, m.ptr, m.len);
                std.c._exit(127);
            }
            _ = execvp(plan.fallback_argv.items[0].?, @ptrCast(plan.fallback_argv.items.ptr));
            var mb: [1024]u8 = undefined;
            const m = std.fmt.bufPrint(
                &mb,
                "fxstore: exec '{s}' failed: {s}\n",
                .{ plan.fallback_argv0, errstr_e(errno()) },
            ) catch plan.fallback_argv0;
            _ = std.c.write(2, m.ptr, m.len);
            std.c._exit(127);
        }
        plan.bwrap_argv.items[0] = g_bwrap_path.?; // argv[0] = the real binary
        _ = execvp(g_bwrap_path.?, @ptrCast(plan.bwrap_argv.items.ptr));
        var mb: [256]u8 = undefined;
        const m = std.fmt.bufPrint(
            &mb,
            "fxstore: bwrap exec failed: {s}\n",
            .{errstr_e(errno())},
        ) catch "fxstore: bwrap exec failed\n";
        _ = std.c.write(2, m.ptr, m.len);
        std.c._exit(127);
    }
    // ── parent ──
    var status: c_int = 0;
    if (std.c.waitpid(pid, &status, 0) < 0) {
        write_err("fxstore: waitpid failed: {s}\n", .{errstr_e(errno())});
        return 2;
    }
    if (std.os.linux.W.IFEXITED(@bitCast(status)))
        return @intCast(std.os.linux.W.EXITSTATUS(@bitCast(status)));
    return 2; // signaled
}

// ─── run_action (dhake.c 453-557, ported; build.c:573-691) ─────────────────

fn run_action(
    a: *const Action,
    workdir: []const u8,
    src_ro: ?[]const u8,
    store_root: []const u8,
) c_int {
    // the C dereferences a->a / a->b per-case unchecked (the parser
    // guarantees each kind's payload fields); missing fields read as ""
    const aa: []const u8 = a.a orelse "";
    const ab: []const u8 = a.b orelse "";

    switch (a.kind) {
        .shell => {
            out_print("{s}\n", .{aa}); // echo, like make
            const sh_argv = [_][]const u8{ "/bin/sh", "-c", aa };
            return run_sandboxed(workdir, src_ro, store_root, &sh_argv);
        },
        .copy => {
            out_print("cp {s} {s}\n", .{ aa, ab });
            var arena = std.heap.ArenaAllocator.init(c_alloc);
            defer arena.deinit();
            const ar = arena.allocator();
            const from = resolve_path(ar, aa, workdir);
            const to = resolve_path(ar, ab, workdir);
            const ok = from != null and to != null and copy_file(from.?, to.?);
            return if (ok) 0 else 1;
        },
        .mkdir => {
            out_print("mkdir {s}\n", .{aa});
            var arena = std.heap.ArenaAllocator.init(c_alloc);
            defer arena.deinit();
            const p = resolve_path(arena.allocator(), aa, workdir) orelse return 1;
            const pz = c_alloc.dupeZ(u8, p) catch return 1;
            defer c_alloc.free(pz);
            if (mkdir(pz.ptr, 0o755) != 0 and errno() != EEXIST) {
                write_err("fxstore: mkdir: {s}\n", .{errstr_e(errno())});
            } else return 0;
            return 1;
        },
        .rm => {
            out_print("rm {s}\n", .{aa});
            var arena = std.heap.ArenaAllocator.init(c_alloc);
            defer arena.deinit();
            const p = resolve_path(arena.allocator(), aa, workdir) orelse return 1;
            const pz = c_alloc.dupeZ(u8, p) catch return 1;
            defer c_alloc.free(pz);
            if (remove(pz.ptr) != 0 and errno() != ENOENT) {
                write_err("fxstore: rm: {s}\n", .{errstr_e(errno())});
            } else return 0;
            return 1;
        },
        .touch => {
            out_print("touch {s}\n", .{aa});
            var arena = std.heap.ArenaAllocator.init(c_alloc);
            defer arena.deinit();
            const p = resolve_path(arena.allocator(), aa, workdir) orelse return 1;
            return if (touch_file(p)) 0 else 1;
        },
        .move => {
            out_print("mv {s} {s}\n", .{ aa, ab });
            var arena = std.heap.ArenaAllocator.init(c_alloc);
            defer arena.deinit();
            const ar = arena.allocator();
            const from = resolve_path(ar, aa, workdir);
            const to = resolve_path(ar, ab, workdir);
            if (from == null or to == null) return 1;
            const fz = c_alloc.dupeZ(u8, from.?) catch return 1;
            defer c_alloc.free(fz);
            const tz = c_alloc.dupeZ(u8, to.?) catch return 1;
            defer c_alloc.free(tz);
            if (rename(fz.ptr, tz.ptr) != 0) {
                write_err("fxstore: move: {s}\n", .{errstr_e(errno())});
                return 1;
            }
            return 0;
        },
        .symlink => {
            out_print("ln -s {s} {s}\n", .{ aa, ab });
            var arena = std.heap.ArenaAllocator.init(c_alloc);
            defer arena.deinit();
            const ar = arena.allocator();
            const from = resolve_path(ar, aa, workdir);
            const to = resolve_path(ar, ab, workdir);
            if (from == null or to == null) return 1;
            const fz = c_alloc.dupeZ(u8, from.?) catch return 1;
            defer c_alloc.free(fz);
            const tz = c_alloc.dupeZ(u8, to.?) catch return 1;
            defer c_alloc.free(tz);
            if (symlink(fz.ptr, tz.ptr) != 0) {
                write_err("fxstore: symlink: {s}\n", .{errstr_e(errno())});
                return 1;
            }
            return 0;
        },
        .chmod => {
            out_print("chmod {s} {s}\n", .{ ab, aa });
            var arena = std.heap.ArenaAllocator.init(c_alloc);
            defer arena.deinit();
            const p = resolve_path(arena.allocator(), aa, workdir) orelse return 1;
            const pz = c_alloc.dupeZ(u8, p) catch return 1;
            defer c_alloc.free(pz);
            const mz = c_alloc.dupeZ(u8, ab) catch return 1;
            defer c_alloc.free(mz);
            std.c._errno().* = 0;
            var end: ?[*:0]u8 = null;
            const mode = strtol(mz.ptr, &end, 8);
            if (errno() != 0 or end == null or end == mz.ptr or end.?[0] != 0 or
                mode < 0 or mode > 0o7777)
            {
                write_err("fxstore: chmod: invalid mode '{s}' (expected octal 0..7777)\n", .{ab});
            } else if (chmod(pz.ptr, @intCast(mode)) != 0) {
                write_err("fxstore: chmod: {s}\n", .{errstr_e(errno())});
            } else return 0;
            return 1;
        },
        .echo => {
            out_print("{s}\n", .{aa});
            return 0;
        },
        .env => {
            out_print("export {s}={s}\n", .{ aa, ab });
            const az = c_alloc.dupeZ(u8, aa) catch return 0;
            defer c_alloc.free(az);
            const bz = c_alloc.dupeZ(u8, ab) catch return 0;
            defer c_alloc.free(bz);
            _ = setenv(az.ptr, bz.ptr, 1);
            return 0;
        },
        .run => {
            out_print("{s}", .{aa});
            for (a.argv[1..]) |arg| out_print(" {s}", .{arg});
            out_print("\n", .{});
            return run_sandboxed(workdir, src_ro, store_root, a.argv);
        },
    }
}

// ─── fx_build_recipe (build.c:700-796) ─────────────────────────────────────

/// Environment snapshot/restore: the Env action mutates THIS process's
/// environment (setenv) and FX_DEP_* are set per package; without a
/// save/restore, package A's exports leak into package B's recipe when both
/// are built in one process — same store path, different build environment
/// (silent nondeterminism).
const EnvSnap = struct {
    v: std.ArrayListUnmanaged([:0]u8) = .empty,

    fn take() EnvSnap {
        var s = EnvSnap{};
        var i: usize = 0;
        while (std.c.environ[i]) |entry| : (i += 1) {
            const dup = c_alloc.dupeZ(u8, std.mem.span(entry)) catch continue; // best-effort
            s.v.append(c_alloc, dup) catch c_alloc.free(dup);
        }
        return s;
    }

    fn restore(s: *const EnvSnap) void {
        // collect current var NAMES first (unsetenv mutates environ)
        var cur: std.ArrayListUnmanaged([:0]u8) = .empty;
        {
            var i: usize = 0;
            while (std.c.environ[i]) |entry| : (i += 1) {
                const sv = std.mem.span(entry);
                const eq = std.mem.indexOfScalar(u8, sv, '=') orelse sv.len;
                const nm = c_alloc.dupeZ(u8, sv[0..eq]) catch continue;
                cur.append(c_alloc, nm) catch c_alloc.free(nm);
            }
        }
        for (cur.items) |n| _ = unsetenv(n.ptr);
        for (cur.items) |n| c_alloc.free(n);
        cur.deinit(c_alloc);

        for (s.v.items) |entry| {
            const eq = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
            entry[eq] = 0;
            _ = setenv(@ptrCast(entry.ptr), @ptrCast(entry.ptr + eq + 1), 1);
            entry[eq] = '=';
        }
    }

    fn deinit(s: *EnvSnap) void {
        for (s.v.items) |e| c_alloc.free(e);
        s.v.deinit(c_alloc);
    }
};

/// Execute the package's recipe inside `workdir` (the temp build dir under
/// <store_root>.build, a SIBLING of the store).  Relative paths resolve
/// against workdir; deps are exported as FX_DEP_<NAME> env vars and passed
/// through to run_sandboxed for the ro-bind.  `src_path` is the CLEAN
/// source artifact for a .path-src package (null for .fetch).  Returns the
/// first failing action's exit code; error.FxBuild on an executor error
/// (err set).
pub fn fx_build_recipe(
    p: *const Package,
    workdir: []const u8,
    dep_names: []const []const u8,
    dep_paths: []const []const u8,
    store_root: []const u8,
    src_path: ?[]const u8,
    e: *ErrBuf,
) Error!c_int {
    // (the C's null-args check is unrepresentable here: p is non-optional,
    // workdir/store_root are slices)
    var snap = EnvSnap.take();
    defer snap.deinit();
    defer snap.restore();

    // Path sources are mounted read-only into the sandbox at their own
    // path; Fetch sources have no local tree.  For .path the source is the
    // CLEAN materialized artifact in the store (src_path) — NOT the raw
    // checkout (a TIGHTENING).
    var src_ro: ?[]const u8 = null;
    if (p.src.kind == .path) {
        const sp = src_path orelse "";
        if (sp.len == 0)
            return e.set("internal: SRC_PATH package '{s}' without a clean src_path", .{p.name});
        src_ro = sp;
    }

    if (set_dep_env(dep_names, dep_paths) != 0)
        return e.set("out of memory setting FX_DEP_* env", .{});

    // Export the ro-bound source tree as FX_SRC so recipes can
    // `cp -a "$FX_SRC"/. .`; cleared on exit by env_restore.
    if (src_ro) |sr| {
        const sz = c_alloc.dupeZ(u8, sr) catch
            return e.set("out of memory setting FX_SRC env", .{});
        defer c_alloc.free(sz);
        _ = setenv("FX_SRC", sz.ptr, 1);
    }

    var rc: c_int = 0;
    var act = p.recipe;
    while (act) |x| : (act = x.next) {
        rc = run_action(x, workdir, src_ro, store_root);
        if (rc != 0) break;
    }
    return rc;
}

// ─── print_action (dhake.c 560-579, verbatim; build.c:800-818) ─────────────

/// The exact per-action echo line (fx_print_action's stdout bytes).
fn action_line(a: *const Action, w: *Io.Writer) Io.Writer.Error!void {
    const aa: []const u8 = a.a orelse "";
    const ab: []const u8 = a.b orelse "";
    switch (a.kind) {
        .shell => try w.print("{s}\n", .{aa}),
        .copy => try w.print("cp {s} {s}\n", .{ aa, ab }),
        .mkdir => try w.print("mkdir {s}\n", .{aa}),
        .rm => try w.print("rm {s}\n", .{aa}),
        .touch => try w.print("touch {s}\n", .{aa}),
        .move => try w.print("mv {s} {s}\n", .{ aa, ab }),
        .symlink => try w.print("ln -s {s} {s}\n", .{ aa, ab }),
        .chmod => try w.print("chmod {s} {s}\n", .{ ab, aa }),
        .echo => try w.print("echo {s}\n", .{aa}),
        .env => try w.print("export {s}={s}\n", .{ aa, ab }),
        .run => {
            try w.print("{s}", .{aa});
            for (a.argv[1..]) |arg| try w.print(" {s}", .{arg});
            try w.print("\n", .{});
        },
    }
}

/// Echo one action to stdout (like make / dhake).
pub fn fx_print_action(a: *const Action) void {
    var aw: Io.Writer.Allocating = .init(c_alloc);
    defer aw.deinit();
    action_line(a, &aw.writer) catch return;
    const s = aw.written();
    _ = std.c.write(g_out_fd, s.ptr, s.len);
}

// ─── tests (all sandbox-free: pure builders + in-process fs + env) ─────────

const testing = std.testing;

fn tio() Io {
    return std.testing.io;
}

/// A scratch dir under the repo cwd (the zig build test cwd), deleted on exit.
fn scratch_dir(a: Allocator, name: []const u8) ![]u8 {
    const p = try std.fmt.allocPrint(a, "zig/.tmp-build-{s}-{d}", .{ name, std.c.getpid() });
    errdefer a.free(p);
    Io.Dir.cwd().deleteTree(tio(), p) catch {};
    try Io.Dir.cwd().createDirPath(tio(), p);
    return p;
}

fn write_file(path: []const u8, bytes: []const u8) !void {
    const f = try Io.Dir.cwd().createFile(tio(), path, .{});
    defer f.close(tio());
    var buf: [4096]u8 = undefined;
    var w = f.writer(tio(), &buf);
    try w.interface.writeAll(bytes);
    try w.interface.flush();
}

fn read_file_alloc(a: Allocator, path: []const u8) ![]u8 {
    const f = try Io.Dir.cwd().openFile(tio(), path, .{});
    defer f.close(tio());
    const st = try f.stat(tio());
    const out = try a.alloc(u8, @intCast(st.size));
    _ = try f.readPositionalAll(tio(), out, 0);
    return out;
}

/// Redirect the action-echo fd into a scratch file and return it; the
/// caller restores g_out_fd and frees `path`.  (The zig test runner's fd 1
/// is the --listen protocol pipe — a raw write there desyncs the runner.)
fn capture_out(path: []const u8) !std.c.fd_t {
    const f = try Io.Dir.cwd().createFile(tio(), path, .{ .truncate = true });
    return f.handle;
}

fn mk_action(kind: ActionKind, x: ?[]const u8, y: ?[]const u8) Action {
    return .{ .kind = kind, .a = x, .b = y };
}

test "dep_env_name: uppercase + non-alnum to underscore" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings("FX_DEP_MY_PKG", (dep_env_name(a, "my-pkg").?));
    try testing.expectEqualStrings("FX_DEP_A_B", (dep_env_name(a, "a.b").?));
    try testing.expectEqualStrings("FX_DEP_LIB_XML2", (dep_env_name(a, "lib_xml2").?));
    try testing.expectEqualStrings("FX_DEP_V1_2_3", (dep_env_name(a, "v1.2.3").?));
    try testing.expectEqualStrings("FX_DEP_A__B_", (dep_env_name(a, "a+-b!").?));
    try testing.expectEqualStrings("FX_DEP_", (dep_env_name(a, "").?));
    // digits keep, uppercase latin keeps, alnum boundary exact
    try testing.expectEqualStrings("FX_DEP_ABC123", (dep_env_name(a, "abc123").?));
}

test "spec_append: separators, empty skip, overflow fails closed" {
    var buf: [32]u8 = undefined;
    var off: usize = 0;
    var first = true;

    // empty path is a skip, not an error (SRC_FETCH has no src tree)
    try testing.expect(spec_append(&buf, &off, &first, "", "rx"));
    try testing.expect(spec_append(&buf, &off, &first, null, "rx"));
    try testing.expectEqual(@as(usize, 0), off);
    try testing.expect(first);

    try testing.expect(spec_append(&buf, &off, &first, "/store", "r"));
    try testing.expectEqualStrings("/store:r", buf[0..off]);
    try testing.expect(!first);
    try testing.expect(spec_append(&buf, &off, &first, "/src", "rx"));
    try testing.expectEqualStrings("/store:r;/src:rx", buf[0..off]);

    // overflow: does not fit → false, buffer untouched (fail closed)
    var small: [8]u8 = undefined;
    var off2: usize = 0;
    var first2 = true;
    try testing.expect(!spec_append(&small, &off2, &first2, "/store", "r")); // 9 > 8
    try testing.expectEqual(@as(usize, 0), off2);
    try testing.expect(spec_append(&small, &off2, &first2, "/sto", "r")); // 6 <= 8
    try testing.expectEqualStrings("/sto:r", small[0..off2]);
    try testing.expect(!spec_append(&small, &off2, &first2, "/b", "r")); // 12 > 8
    try testing.expectEqual(@as(usize, 6), off2);
}

test "build_landlock_spec: exact format, budget, src_ro absent" {
    var buf: [FX_LANDLOCK_SPEC_MAX + 1]u8 = undefined;

    // without /lib64 and without cosmo
    const lib64 = is_dir2("/lib64");
    const want = try std.fmt.allocPrint(testing.allocator, "/store:r;/src:rx;/wd:rwcx;/usr:rx;/bin:rx;/lib:rx{s};/dev:rwc;/proc:r;/tmp:rwc", .{if (lib64) ";/lib64:rx" else ""});
    defer testing.allocator.free(want);
    const s = build_landlock_spec(&buf, null, "/src", "/store", "/wd").?;
    try testing.expectEqualStrings(want, s);
    try testing.expect(s.len <= FX_LANDLOCK_SPEC_MAX);

    // with cosmo root unveiled rx before /dev
    const s2 = build_landlock_spec(&buf, "/home/u/.local/cosmo", "/src", "/store", "/wd").?;
    const want2 = try std.fmt.allocPrint(testing.allocator, "/store:r;/src:rx;/wd:rwcx;/usr:rx;/bin:rx;/lib:rx{s};/home/u/.local/cosmo:rx;/dev:rwc;/proc:r;/tmp:rwc", .{if (lib64) ";/lib64:rx" else ""});
    defer testing.allocator.free(want2);
    try testing.expectEqualStrings(want2, s2);

    // src_ro null or empty (SRC_FETCH): skipped, not an error
    const s3 = build_landlock_spec(&buf, null, null, "/store", "/wd").?;
    try testing.expect(std.mem.indexOf(u8, s3, "/src") == null);
    try testing.expect(std.mem.startsWith(u8, s3, "/store:r;/wd:rwcx"));

    // budget: a too-long spec fails closed (null), never truncates
    const long = try std.fmt.allocPrint(testing.allocator, "/{s}", .{"x" ** (FX_LANDLOCK_SPEC_MAX + 8)});
    defer testing.allocator.free(long);
    try testing.expect(build_landlock_spec(&buf, null, long, "/store", "/wd") == null);
}

test "bwrap argv: exact build.c order for a Shell action" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var av: std.ArrayListUnmanaged([:0]const u8) = .empty;

    const real_argv = [_][]const u8{ "/bin/sh", "-c", "echo hi" };
    try testing.expect(build_bwrap_argv(
        a,
        &av,
        null,
        "/st3",
        "/store:r;/src:rx",
        "/wd",
        "/src",
        "/store",
        &real_argv,
    ));

    const lib64 = is_dir2("/lib64");
    var want: std.ArrayListUnmanaged([]const u8) = .empty;
    defer want.deinit(testing.allocator);
    try want.appendSlice(testing.allocator, &.{
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--ro-bind", "/", "/",
        "--uid",     "1000",
        "--gid",     "1000",
        "--tmpfs",   "/tmp",
        "--ro-bind", "/store", "/store",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/bin", "/bin",
        "--ro-bind", "/lib", "/lib",
    });
    if (lib64) try want.appendSlice(testing.allocator, &.{ "--ro-bind", "/lib64", "/lib64" });
    try want.appendSlice(testing.allocator, &.{
        "--ro-bind", "/src", "/src",
        "--bind",    "/wd",  "/wd",
        "--chdir",   "/wd",
        "--dev",     "/dev",
        "--proc",    "/proc",
        "--ro-bind", "/st3", "/st3",
        "--",
        "/st3",
        FXSTORE_PROMISES,
        "/store:r;/src:rx",
        "--",
        "/bin/sh",
        "-c",
        "echo hi",
    });
    try testing.expectEqual(want.items.len, av.items.len);
    for (want.items, av.items) |wv, gv| try testing.expectEqualStrings(wv, gv);

    // every word is properly NUL-terminated for execvp
    for (av.items) |z| try testing.expect(z[z.len] == 0);
}

test "bwrap argv: Run action, no src_ro, with cosmo" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var av: std.ArrayListUnmanaged([:0]const u8) = .empty;

    const real_argv = [_][]const u8{ "./configure", "--prefix=/usr" };
    try testing.expect(build_bwrap_argv(
        a,
        &av,
        "/cosmo",
        "/st3",
        "SPEC",
        "/wd",
        null,
        "/store",
        &real_argv,
    ));

    const lib64 = is_dir2("/lib64");
    var want: std.ArrayListUnmanaged([]const u8) = .empty;
    defer want.deinit(testing.allocator);
    try want.appendSlice(testing.allocator, &.{
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--ro-bind", "/", "/",
        "--uid",     "1000",
        "--gid",     "1000",
        "--tmpfs",   "/tmp",
        "--ro-bind", "/store", "/store",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/bin", "/bin",
        "--ro-bind", "/lib", "/lib",
    });
    if (lib64) try want.appendSlice(testing.allocator, &.{ "--ro-bind", "/lib64", "/lib64" });
    try want.appendSlice(testing.allocator, &.{
        "--ro-bind", "/cosmo", "/cosmo",
        "--bind",    "/wd",     "/wd",
        "--chdir",   "/wd",
        "--dev",     "/dev",
        "--proc",    "/proc",
        "--ro-bind", "/st3",    "/st3",
        "--",
        "/st3",
        FXSTORE_PROMISES,
        "SPEC",
        "--",
        "./configure",
        "--prefix=/usr",
    });
    try testing.expectEqual(want.items.len, av.items.len);
    for (want.items, av.items) |wv, gv| try testing.expectEqualStrings(wv, gv);

    // src_ro ABSENT (SRC_FETCH): no src bind anywhere
    for (av.items) |z| try testing.expect(!std.mem.eql(u8, z, "/src"));
}

test "resolve_path: absolute kept, relative prefixed with workdir" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings("/abs/path", (resolve_path(a, "/abs/path", "/wd").?));
    try testing.expectEqualStrings("/wd/rel.txt", (resolve_path(a, "rel.txt", "/wd").?));
    try testing.expectEqualStrings("/wd/", (resolve_path(a, "", "/wd").?));
    try testing.expectEqualStrings("/wd/a/b/c", (resolve_path(a, "a/b/c", "/wd").?));
}

test "copy_file + touch_file: real fs, temp dir" {
    const a = testing.allocator;
    const scratch = try scratch_dir(a, "fs");
    defer a.free(scratch);
    defer Io.Dir.cwd().deleteTree(tio(), scratch) catch {};

    const from = try std.fmt.allocPrint(a, "{s}/in.bin", .{scratch});
    defer a.free(from);
    const to = try std.fmt.allocPrint(a, "{s}/out.bin", .{scratch});
    defer a.free(to);
    const payload = "fxstore copy_file payload \x00\x01\x02 binary-safe";
    try write_file(from, payload);

    try testing.expect(copy_file(from, to));
    const got = try read_file_alloc(a, to);
    defer a.free(got);
    try testing.expectEqualSlices(u8, payload, got);

    // missing source fails (rc 1 path) with the C message on stderr
    const bad_to = try std.fmt.allocPrint(a, "{s}/nope/dir/out.bin", .{scratch});
    defer a.free(bad_to);
    try testing.expect(!copy_file(from, bad_to));

    // touch creates a missing file...
    const fresh = try std.fmt.allocPrint(a, "{s}/fresh.txt", .{scratch});
    defer a.free(fresh);
    try testing.expect(touch_file(fresh));
    const st = try Io.Dir.cwd().statFile(tio(), fresh, .{});
    try testing.expect(st.kind == .file);

    // ...and updates an existing one (mtime >= before)
    const before = (try Io.Dir.cwd().statFile(tio(), fresh, .{})).mtime;
    try testing.expect(touch_file(fresh));
    const after = (try Io.Dir.cwd().statFile(tio(), fresh, .{})).mtime;
    try testing.expect(after.nanoseconds >= before.nanoseconds);
}

test "set_dep_env: stale FX_DEP_* cleared, new deps set" {
    const n1 = "FX_DEP_STALE_PKG";
    const n2 = "FX_DEP_OTHER";
    _ = setenv(n1, "/old/stale", 1);
    _ = setenv(n2, "/old/other", 1);
    defer _ = unsetenv(n1);
    defer _ = unsetenv(n2);

    try testing.expect(set_dep_env(
        &.{ "my-pkg", "b.b" },
        &.{ "/store/aaa-my-pkg", "/store/bbb-b.b" },
    ) == 0);

    try testing.expect(getenv(n1) == null); // stale gone
    try testing.expect(getenv(n2) == null); // FX_DEP_OTHER also matches the FX_DEP_ prefix → stale
    try testing.expectEqualStrings("/store/aaa-my-pkg", std.mem.span(getenv("FX_DEP_MY_PKG").?));
    try testing.expectEqualStrings("/store/bbb-b.b", std.mem.span(getenv("FX_DEP_B_B").?));

    // empty dep list clears everything
    try testing.expect(set_dep_env(&.{}, &.{}) == 0);
    try testing.expect(getenv("FX_DEP_MY_PKG") == null);
    try testing.expect(getenv("FX_DEP_B_B") == null);
}

test "scrub_env: RATTAN_* and LD_* dropped, others kept" {
    const keeps = [_][]const u8{ "PATH", "HOME", "FXSTORE_STAGE3" };
    const drops = [_][]const u8{
        "RATTAN_ALLOW_PTRACE", "RATTAN_EXTRA_PROMISES", "RATTAN_RLIMITS",
        "LD_PRELOAD",          "LD_LIBRARY_PATH",       "LD_DEBUG",
    };
    for (drops) |d| {
        const dz = try c_alloc.dupeZ(u8, d);
        defer c_alloc.free(dz);
        _ = setenv(dz.ptr, "evil", 1);
    }
    defer for (drops) |d| {
        const dz = c_alloc.dupeZ(u8, d) catch continue;
        _ = unsetenv(dz.ptr);
    };
    // a "kept" var that is not in the ambient env: set it explicitly
    try testing.expect(getenv("FXSTORE_STAGE3") == null);
    _ = setenv("FXSTORE_STAGE3", "/kept", 1);
    defer _ = unsetenv("FXSTORE_STAGE3");

    scrub_env();

    for (drops) |d| {
        const dz = try c_alloc.dupeZ(u8, d);
        defer c_alloc.free(dz);
        try testing.expect(getenv(dz.ptr) == null);
    }
    for (keeps) |k| {
        const kz = try c_alloc.dupeZ(u8, k);
        defer c_alloc.free(kz);
        try testing.expect(getenv(kz.ptr) != null);
    }
}

test "fx_print_action: golden line for every action kind" {
    const cases = [_]struct { kind: ActionKind, x: []const u8, y: []const u8, want: []const u8 }{
        .{ .kind = .shell, .x = "make all", .y = "", .want = "make all\n" },
        .{ .kind = .copy, .x = "in.txt", .y = "out.txt", .want = "cp in.txt out.txt\n" },
        .{ .kind = .mkdir, .x = "build", .y = "", .want = "mkdir build\n" },
        .{ .kind = .rm, .x = "junk", .y = "", .want = "rm junk\n" },
        .{ .kind = .touch, .x = "stamp", .y = "", .want = "touch stamp\n" },
        .{ .kind = .move, .x = "a", .y = "b", .want = "mv a b\n" },
        .{ .kind = .symlink, .x = "target", .y = "link", .want = "ln -s target link\n" },
        .{ .kind = .chmod, .x = "script.sh", .y = "755", .want = "chmod 755 script.sh\n" },
        // NB: print_action echoes "echo ..."; run_action's Echo prints the raw text
        .{ .kind = .echo, .x = "hello", .y = "", .want = "echo hello\n" },
        .{ .kind = .env, .x = "CC", .y = "cc", .want = "export CC=cc\n" },
    };
    for (cases) |c| {
        const act = mk_action(c.kind, c.x, if (c.y.len > 0) c.y else null);
        var buf: [256]u8 = undefined;
        var w = Io.Writer.fixed(&buf);
        try action_line(&act, &w);
        try testing.expectEqualStrings(c.want, w.buffer[0..w.end]);
    }

    // Run: argv joined with single spaces
    var run = Action{ .kind = .run, .a = "./configure", .argv = &.{ "./configure", "--prefix=/usr", "CC=cc" } };
    var buf: [256]u8 = undefined;
    var w = Io.Writer.fixed(&buf);
    try action_line(&run, &w);
    try testing.expectEqualStrings("./configure --prefix=/usr CC=cc\n", w.buffer[0..w.end]);

    // single-argv Run has no trailing space (.a is argv[0] compat)
    run.a = "only";
    run.argv = &.{"only"};
    var buf2: [256]u8 = undefined;
    var w2 = Io.Writer.fixed(&buf2);
    try action_line(&run, &w2);
    try testing.expectEqualStrings("only\n", w2.buffer[0..w2.end]);
}

test "in-process actions: full recipe fs effects in a temp workdir" {
    const a = testing.allocator;
    const wd = try scratch_dir(a, "actions");
    defer a.free(wd);
    defer Io.Dir.cwd().deleteTree(tio(), wd) catch {};

    // Touch, Copy, Mkdir, Chmod, Symlink, Move, Rm, Echo, Env — in-process
    const acts = try a.alloc(Action, 11);
    defer a.free(acts);
    acts[0] = mk_action(.echo, "build starting", null);
    acts[1] = mk_action(.mkdir, "sub", null);
    acts[2] = mk_action(.touch, "sub/stamp.txt", null);
    acts[3] = mk_action(.env, "MY_BUILD_VAR", "1");
    acts[4] = mk_action(.copy, "sub/stamp.txt", "sub/copy.txt");
    acts[5] = mk_action(.chmod, "sub/copy.txt", "741");
    acts[6] = mk_action(.symlink, "sub/copy.txt", "sub/link.txt");
    acts[7] = mk_action(.move, "sub/copy.txt", "sub/moved.txt");
    acts[8] = mk_action(.rm, "sub/moved.txt", null);
    acts[9] = mk_action(.touch, "abs-ignored", null);
    // absolute path: NOT resolved against workdir
    acts[9] = .{ .kind = .touch, .a = "keep.txt" };
    acts[10] = mk_action(.touch, "keep2.txt", null);

    // capture the make-style echo stream (never write the runner's fd 1)
    const out_path = try std.fmt.allocPrint(a, "{s}/echo.log", .{wd});
    defer a.free(out_path);
    const saved_fd = g_out_fd;
    defer g_out_fd = saved_fd;
    g_out_fd = try capture_out(out_path);

    for (acts) |*act| {
        try testing.expectEqual(@as(c_int, 0), run_action(act, wd, null, "/unused-store"));
    }

    // Mkdir
    const sub = try std.fmt.allocPrint(a, "{s}/sub", .{wd});
    defer a.free(sub);
    try testing.expect((try Io.Dir.cwd().statFile(tio(), sub, .{})).kind == .directory);
    // Touch + Copy + Chmod
    const stamp = try std.fmt.allocPrint(a, "{s}/sub/stamp.txt", .{wd});
    defer a.free(stamp);
    try testing.expect((try Io.Dir.cwd().statFile(tio(), stamp, .{})).kind == .file);
    const perm = (try Io.Dir.cwd().statFile(tio(), stamp, .{})).permissions;
    // open(0644) is umask-subjected in C too — assert owner rw survives
    try testing.expect(@intFromEnum(perm) & 0o600 == 0o600);
    // Move + Rm: copy.txt was moved to moved.txt, then removed again
    const moved = try std.fmt.allocPrint(a, "{s}/sub/moved.txt", .{wd});
    defer a.free(moved);
    try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(tio(), moved, .{}));
    // Symlink: target is the RESOLVED path (workdir-prefixed, C semantics)
    const link = try std.fmt.allocPrint(a, "{s}/sub/link.txt", .{wd});
    defer a.free(link);
    var lbuf: [std.fs.max_path_bytes]u8 = undefined;
    const llen = try Io.Dir.cwd().readLink(tio(), link, &lbuf);
    const want_target = try std.fmt.allocPrint(a, "{s}/sub/copy.txt", .{wd});
    defer a.free(want_target);
    try testing.expectEqualStrings(want_target, lbuf[0..llen]);
    // Env action mutated THIS process's env
    try testing.expectEqualStrings("1", std.mem.span(getenv("MY_BUILD_VAR").?));
    _ = unsetenv("MY_BUILD_VAR");

    // golden echo stream: every action echoes make-style, BEFORE executing;
    // Echo prints the raw text (not "echo ..."); all paths echo the RAW
    // action strings — only the syscalls use the resolved paths (like C)
    const echo_log = try read_file_alloc(a, out_path);
    defer a.free(echo_log);
    const want_log = "build starting\nmkdir sub\ntouch sub/stamp.txt\nexport MY_BUILD_VAR=1\ncp sub/stamp.txt sub/copy.txt\nchmod 741 sub/copy.txt\nln -s sub/copy.txt sub/link.txt\nmv sub/copy.txt sub/moved.txt\nrm sub/moved.txt\ntouch keep.txt\ntouch keep2.txt\n";
    try testing.expectEqualStrings(want_log, echo_log);

    // error paths: copy from a missing file → 1
    const bad = mk_action(.copy, "no-such-src", "dst");
    try testing.expectEqual(@as(c_int, 1), run_action(&bad, wd, null, "/s"));
    // invalid chmod mode → 1
    const badmode = mk_action(.chmod, "sub/stamp.txt", "9999");
    try testing.expectEqual(@as(c_int, 1), run_action(&badmode, wd, null, "/s"));
    const badmode2 = mk_action(.chmod, "sub/stamp.txt", "08x");
    try testing.expectEqual(@as(c_int, 1), run_action(&badmode2, wd, null, "/s"));
    // rm of a missing file is tolerated (ENOENT) → 0
    const rm_missing = mk_action(.rm, "already-gone", null);
    try testing.expectEqual(@as(c_int, 0), run_action(&rm_missing, wd, null, "/s"));
    // mkdir of an existing dir is tolerated (EEXIST) → 0
    try testing.expectEqual(@as(c_int, 0), run_action(&acts[1], wd, null, "/s"));
}

test "run_sandboxed: stage3-absent dies 127 LOUDLY (no bwrap needed)" {
    const st3 = stage3_bin();
    const st3_absent = std.c.access(st3.ptr, X_OK) != 0;
    if (!st3_absent) {
        std.debug.print("(stage3 present at '{s}' — skipping the 127 test)\n", .{st3});
        return;
    }
    // Shell action in a real temp workdir; the sandbox paths need not exist
    // for the check to fire (access fails first), but keep them real anyway.
    const a = testing.allocator;
    const wd = try scratch_dir(a, "sb");
    defer a.free(wd);
    defer Io.Dir.cwd().deleteTree(tio(), wd) catch {};
    const saved_fd = g_out_fd;
    defer g_out_fd = saved_fd;
    const out_path = try std.fmt.allocPrint(a, "{s}/echo.log", .{wd});
    defer a.free(out_path);
    g_out_fd = try capture_out(out_path);
    const sh_argv = [_][]const u8{ "/bin/sh", "-c", "echo should never run" };
    try testing.expectEqual(@as(c_int, 127), run_sandboxed(wd, null, "/unused", &sh_argv));
}

test "fx_build_recipe: env snapshot/restore, FX_SRC, FX_DEP_*, Echo-only recipe" {
    const a = testing.allocator;
    const wd = try scratch_dir(a, "recipe");
    defer a.free(wd);
    defer Io.Dir.cwd().deleteTree(tio(), wd) catch {};

    // a pre-existing env var the recipe overwrites via an Env action
    _ = setenv("FX_BUILD_TEST", "before", 1);
    _ = setenv("FX_DEP_STALE", "/stale", 1);

    var acts = [_]Action{
        mk_action(.env, "FX_BUILD_TEST", "during"),
        mk_action(.echo, "building now", null),
        mk_action(.touch, "artifact.bin", null),
    };
    // link the recipe list
    acts[0].next = &acts[1];
    acts[1].next = &acts[2];

    var pkg = Package{
        .name = "tester",
        .version = "1.0",
        .src = .{ .kind = .path, .path = "/src/raw" },
        .target = "artifact.bin",
        .recipe = &acts[0],
    };

    const saved_fd = g_out_fd;
    defer g_out_fd = saved_fd;
    const out_path = try std.fmt.allocPrint(a, "{s}/echo.log", .{wd});
    defer a.free(out_path);
    g_out_fd = try capture_out(out_path);

    var e = ErrBuf{};
    const rc = try fx_build_recipe(
        &pkg,
        wd,
        &.{"dep-a"},
        &.{"/store/hash-dep-a"},
        "/store",
        "/store/aaa-src-tester",
        &e,
    );
    try testing.expectEqual(@as(c_int, 0), rc);

    // the artifact landed in the workdir (relative → workdir)
    const art = try std.fmt.allocPrint(a, "{s}/artifact.bin", .{wd});
    defer a.free(art);
    try testing.expect((try Io.Dir.cwd().statFile(tio(), art, .{})).kind == .file);

    // env fully restored: FX_DEP_STALE back, FX_DEP_DEP_A gone, FX_SRC gone,
    // FX_BUILD_TEST back to "before" (the Env action's mutation undone)
    try testing.expectEqualStrings("/stale", std.mem.span(getenv("FX_DEP_STALE").?));
    try testing.expect(getenv("FX_DEP_DEP_A") == null);
    try testing.expect(getenv("FX_SRC") == null);
    try testing.expectEqualStrings("before", std.mem.span(getenv("FX_BUILD_TEST").?));
    _ = unsetenv("FX_DEP_STALE");
    _ = unsetenv("FX_BUILD_TEST");

    // .path package with an empty src_path → LOUD internal error
    const rc2 = fx_build_recipe(&pkg, wd, &.{}, &.{}, "/store", "", &e);
    try testing.expectError(error.FxBuild, rc2);
    try testing.expectEqualStrings(
        "internal: SRC_PATH package 'tester' without a clean src_path",
        e.slice(),
    );

    // .fetch package: src_ro stays null (no FX_SRC), recipe runs anyway
    pkg.src.kind = .fetch;
    acts[0] = mk_action(.echo, "fetch build", null);
    acts[0].next = null;
    const rc3 = try fx_build_recipe(&pkg, wd, &.{}, &.{}, "/store", null, &e);
    try testing.expectEqual(@as(c_int, 0), rc3);
    try testing.expect(getenv("FX_SRC") == null);
}

test "optional bwrap integration: trivial Shell recipe end-to-end (skipped without bwrap+stage3)" {
    fx_bwrap_resolve();
    const st3 = stage3_bin();
    if (g_bwrap_path == null or std.c.access(st3.ptr, X_OK) != 0) {
        std.debug.print("(bwrap or stage3 absent — LOUD skip of the sandbox e2e test)\n", .{});
        return;
    }
    const a = testing.allocator;
    const wd = try scratch_dir(a, "e2e");
    defer a.free(wd);
    defer Io.Dir.cwd().deleteTree(tio(), wd) catch {};

    var acts = [_]Action{
        mk_action(.shell, "echo ran-in-sandbox > proof.txt", null),
    };
    var pkg = Package{
        .name = "e2e",
        .version = "0",
        .src = .{ .kind = .fetch }, // no src bind needed
        .target = "proof.txt",
        .recipe = &acts[0],
    };
    const saved_fd = g_out_fd;
    defer g_out_fd = saved_fd;
    const out_path = try std.fmt.allocPrint(a, "{s}/echo.log", .{wd});
    defer a.free(out_path);
    g_out_fd = try capture_out(out_path);

    // the C contract: workdir/store are ABSOLUTE paths (<store>.build/...)
    var real: [std.fs.max_path_bytes]u8 = undefined;
    const wdz = try std.fmt.allocPrintSentinel(a, "{s}", .{wd}, 0);
    defer a.free(wdz);
    const abs = realpath(wdz, &real) orelse return error.FxBuild;
    const abs_wd = std.mem.span(abs);
    // stage3 was resolved earlier in this process to the RELATIVE default;
    // the sandbox needs the ABSOLUTE path (the C Makefile bakes the absolute
    // vendor path into FXSTORE_STAGE3_PATH).  Re-resolve with the override.
    var real3: [std.fs.max_path_bytes]u8 = undefined;
    const st3z = try std.fmt.allocPrintSentinel(a, "{s}", .{stage3_bin()}, 0);
    defer a.free(st3z);
    const abs3 = realpath(st3z, &real3) orelse return error.FxBuild;
    _ = setenv("FXSTORE_STAGE3", abs3, 1);
    defer _ = unsetenv("FXSTORE_STAGE3");
    g_stage3_path = null; // test-only: production resolves exactly once
    fx_stage3_resolve();

    var e = ErrBuf{};
    const rc = try fx_build_recipe(&pkg, abs_wd, &.{}, &.{}, abs_wd, null, &e); // abs_wd doubles as a real store root
    try testing.expectEqual(@as(c_int, 0), rc);
    const proof = try std.fmt.allocPrint(a, "{s}/proof.txt", .{wd});
    defer a.free(proof);
    const got = try read_file_alloc(a, proof);
    defer a.free(got);
    try testing.expectEqualStrings("ran-in-sandbox\n", got);
}
