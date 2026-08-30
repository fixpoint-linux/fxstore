// build.zig — fxstore Zig port, unit 1 scaffold: the dhall-c Zig core as a
// single module via its facade (the fx-init/zig/build.zig pattern; fxstore
// vendors dhall-c but NOT its zig core — the canonical one lives in the
// sibling checkout ../dhall-c).  The datalog-dafsa engine is linked as the
// Zig-built libdatalog.so from the sibling ../datalog-dafsa checkout
// (linkDatalog, below) so the closure/store FFI units don't have to touch
// the build.
//
// NOTE: build.zig lives at the REPO ROOT, not zig/ — zig 0.16 locates
// build.zig only in the cwd or its parents, and the gate runs `zig build`
// from the repo root; zig/build.zig would be unreachable from there.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dhall_mod = b.createModule(.{
        .root_source_file = b.path("../dhall-c/zig/src/dhall_mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // packageset: the U1 walker (port of packageset.c), pure Zig over the
    // dhall Zig core — no dl_* FFI, no fxstore C linking.
    const packageset_mod = b.createModule(.{
        .root_source_file = b.path("zig/src/packageset.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "dhall", .module = dhall_mod },
        },
    });

    // derivation: the U2 canonical serializer + clean-tree Merkle hash/copy +
    // store path (port of derivation.c), pure Zig over dhall_mod.sha256 and
    // the U1 types — no dl_* FFI, no fxstore C linking.
    const derivation_mod = b.createModule(.{
        .root_source_file = b.path("zig/src/derivation.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "dhall", .module = dhall_mod },
            .{ .name = "packageset", .module = packageset_mod },
        },
    });

    // closure: the U3 datalog closure fixpoint + topo-sort (port of
    // closure.c), dl_* FFI to the Zig-built libdatalog.so — the engine stays
    // behind the .so ABI; only the wrapper logic is ported.
    const closure_mod = b.createModule(.{
        .root_source_file = b.path("zig/src/closure.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "packageset", .module = packageset_mod },
        },
    });
    // the closure unit tests open LIVE dbs, so the module links libdatalog.so
    // (the fx-init dedicated-test-module pattern); linked below.

    // build: the U5 recipe executor + bwrap/stage3 sandbox (port of
    // build.c), pure POSIX fork/exec over the U1 types — no dl_* FFI, no
    // fxstore C linking.
    const build_mod = b.createModule(.{
        .root_source_file = b.path("zig/src/build.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "packageset", .module = packageset_mod },
        },
    });

    // store: the U4 store layout + atomic install + metadata-LAST txn +
    // pinned-snapshot GC + timeline/rollback (port of store.c), dl_* FFI to
    // the Zig-built libdatalog.so and the U2/U3/U5 Zig modules it composes.
    const store_mod = b.createModule(.{
        .root_source_file = b.path("zig/src/store.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "packageset", .module = packageset_mod },
            .{ .name = "derivation", .module = derivation_mod },
            .{ .name = "closure", .module = closure_mod },
            .{ .name = "build", .module = build_mod },
        },
    });
    // the store unit tests open LIVE dbs, so the module links libdatalog.so
    // (the fx-init dedicated-test-module pattern); linked below.

    // datalog-dafsa engine: link the Zig-built libdatalog.so from the sibling
    // ../datalog-dafsa checkout (the migrated engine) instead of compiling the
    // stale vendored C engine into this binary.  The .so exports the full
    // dl_*/dafsa_*/tokenize/regex_* surface the closure/store dl_* externs
    // need; the baked absolute rpath lets the unit tests (which open live dbs)
    // resolve the .so at runtime without LD_LIBRARY_PATH.
    linkDatalog(b, closure_mod);
    linkDatalog(b, store_mod);

    // main: the U6 CLI (port of main.c) — the final 'fxstore' executable,
    // wiring ALL five ported units together; links libdatalog.so because
    // closure/store carry the dl_* externs.  (main.zig itself needs no dhall
    // import: it reaches the dhall core through packageset.)
    const main_mod = b.createModule(.{
        .root_source_file = b.path("zig/src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "packageset", .module = packageset_mod },
            .{ .name = "derivation", .module = derivation_mod },
            .{ .name = "closure", .module = closure_mod },
            .{ .name = "store", .module = store_mod },
            .{ .name = "build", .module = build_mod },
        },
    });
    linkDatalog(b, main_mod);
    const fxstore_exe = b.addExecutable(.{ .name = "fxstore", .root_module = main_mod });
    b.installArtifact(fxstore_exe);

    // packageset.zig unit tests (fixtures in zig/corpus/packageset/) and
    // derivation.zig unit tests (goldens in zig/corpus/derivation/) and
    // closure.zig unit tests (live dl_open dbs under /tmp).
    const ps_tests = b.addTest(.{ .root_module = packageset_mod });
    const run_ps_tests = b.addRunArtifact(ps_tests);
    const drv_tests = b.addTest(.{ .root_module = derivation_mod });
    const run_drv_tests = b.addRunArtifact(drv_tests);
    const cl_tests = b.addTest(.{ .root_module = closure_mod });
    const run_cl_tests = b.addRunArtifact(cl_tests);
    // build.zig unit tests (sandbox-free: argv/spec builders, env, in-process fs).
    const bld_tests = b.addTest(.{ .root_module = build_mod });
    const run_bld_tests = b.addRunArtifact(bld_tests);
    // store.zig unit tests (live dbs + printf capture under /tmp).
    const st_tests = b.addTest(.{ .root_module = store_mod });
    const run_st_tests = b.addRunArtifact(st_tests);
    // main.zig unit tests (usage/parse_args/template goldens under /tmp).
    const main_tests = b.addTest(.{ .root_module = main_mod });
    const run_main_tests = b.addRunArtifact(main_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_ps_tests.step);
    test_step.dependOn(&run_drv_tests.step);
    test_step.dependOn(&run_cl_tests.step);
    test_step.dependOn(&run_bld_tests.step);
    test_step.dependOn(&run_st_tests.step);
    test_step.dependOn(&run_main_tests.step);
}

// Link the Zig-built datalog-dafsa engine .so (sibling ../datalog-dafsa
// checkout) into `m`.  The library path and the baked rpath are both the .so's
// absolute directory, so linked binaries/tests resolve it at runtime from any
// cwd.  `b.path` resolves the relative path against the build root.
fn linkDatalog(b: *std.Build, m: *std.Build.Module) void {
    m.linkSystemLibrary("datalog", .{});
    m.addLibraryPath(b.path("../datalog-dafsa/zig-out/lib"));
    m.addRPath(b.path("../datalog-dafsa/zig-out/lib"));
}
