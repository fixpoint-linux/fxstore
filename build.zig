// build.zig — fxstore Zig port, unit 1 scaffold: the dhall-c Zig core as a
// single module via its facade (the fx-init/zig/build.zig pattern; fxstore
// vendors dhall-c but NOT its zig core — the canonical one lives in the
// sibling checkout ../dhall-c).  The datalog-dafsa engine is BUILT IN THIS
// GRAPH from the pinned submodule vendor/datalog-dafsa (see linkDatalog,
// below): its Zig sources become a static libdatalog.a for the target being
// built, so the closure/store FFI units link an archive this build produced
// — never a prebuilt .so or a library path outside this repo.
//
// NOTE: build.zig lives at the REPO ROOT, not zig/ — zig 0.16 locates
// build.zig only in the cwd or its parents, and the gate runs `zig build`
// from the repo root; zig/build.zig would be unreachable from there.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // -----------------------------------------------------------------------
    // libdatalog linkage: the engine is BUILT HERE, from the pinned submodule.
    //
    // vendor/datalog-dafsa is a git submodule (.gitmodules, branch = main) and
    // is the canonical engine: 100% Zig sources under zig/src, C headers only
    // under src/.  Those sources are compiled into a STATIC libdatalog.a in
    // this build graph, for whatever -Dtarget the user passes, and that
    // archive is linked into every module carrying the dl_* externs.  Static
    // for BOTH targets: an in-graph archive is target-coupled by
    // construction, nothing has to resolve a shared object at runtime, and
    // the musl/i386 targets cannot link a glibc .so at all.  No library path
    // and no rpath points outside this repo.
    // -----------------------------------------------------------------------
    const datalog_mod = b.createModule(.{
        .root_source_file = b.path("vendor/datalog-dafsa/zig/src/hybrid.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "dafsa_abi", .module = b.createModule(.{
                .root_source_file = b.path("vendor/datalog-dafsa/vendor/dafsa/zig/src/abi.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }) },
        },
    });
    const datalog_lib = b.addLibrary(.{
        .name = "datalog",
        .linkage = .static,
        .root_module = datalog_mod,
    });
    datalog_lib.root_module.addIncludePath(b.path("vendor/datalog-dafsa/src"));
    datalog_lib.root_module.addIncludePath(b.path("vendor/datalog-dafsa/vendor/dafsa"));

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
    // closure.c), dl_* FFI to the libdatalog archive this build produces from
    // vendor/datalog-dafsa — the engine stays behind its C ABI; only the
    // wrapper logic is ported.
    const closure_mod = b.createModule(.{
        .root_source_file = b.path("zig/src/closure.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "packageset", .module = packageset_mod },
        },
    });
    // the closure unit tests open LIVE dbs, so the module links libdatalog
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
    // libdatalog and the U2/U3/U5 Zig modules it composes.
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
    // the store unit tests open LIVE dbs, so the module links libdatalog
    // (the fx-init dedicated-test-module pattern); linked below.

    // provenance: the Lens-2 query ENGINE (port-side unit U2) — read-only
    // what/why/verify over the snapshot-versioned install/provides facts
    // fx-activate writes into the store db.  Imports only the Zig store
    // modules (closure/store/packageset/derivation — never main.zig), dl_*
    // FFI to libdatalog for the as-of readers.
    const prov_mod = b.createModule(.{
        .root_source_file = b.path("zig/src/provenance.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "packageset", .module = packageset_mod },
            .{ .name = "derivation", .module = derivation_mod },
            .{ .name = "closure", .module = closure_mod },
            .{ .name = "store", .module = store_mod },
        },
    });
    // the provenance unit tests open LIVE dbs, so the module links
    // libdatalog (the fx-init dedicated-test-module pattern); linked below.

    // datalog-dafsa engine: link the in-graph static libdatalog.a built above
    // from the vendored submodule.  The archive exports the full
    // dl_*/dafsa_*/tokenize/regex_* surface the closure/store dl_* externs
    // need, and because it is a static link the unit tests (which open live
    // dbs) need no library path, rpath or LD_LIBRARY_PATH to resolve it.
    linkDatalog(closure_mod, datalog_lib);
    linkDatalog(store_mod, datalog_lib);
    linkDatalog(prov_mod, datalog_lib);

    // main: the U6 CLI (port of main.c) — the final 'fxstore' executable,
    // wiring ALL five ported units together; links libdatalog because
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
            .{ .name = "provenance", .module = prov_mod },
        },
    });
    linkDatalog(main_mod, datalog_lib);
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
    // provenance.zig unit tests (live dbs + fixture rootfs/store under /tmp;
    // the corpus packageset good.dhall is the package graph).
    const prov_tests = b.addTest(.{ .root_module = prov_mod });
    const run_prov_tests = b.addRunArtifact(prov_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_ps_tests.step);
    test_step.dependOn(&run_drv_tests.step);
    test_step.dependOn(&run_cl_tests.step);
    test_step.dependOn(&run_bld_tests.step);
    test_step.dependOn(&run_st_tests.step);
    test_step.dependOn(&run_main_tests.step);
    test_step.dependOn(&run_prov_tests.step);
}

// Link the datalog-dafsa engine into `m`: unconditionally the in-graph static
// libdatalog.a compiled from vendor/datalog-dafsa (see the engine block at the
// top of build()), for every target.  There is no shared-object arm, no
// library path and no rpath — the archive is part of this build's output, so
// linked binaries/tests carry the engine with them.
fn linkDatalog(m: *std.Build.Module, datalog_lib: *std.Build.Step.Compile) void {
    m.linkLibrary(datalog_lib);
}
