const std = @import("std");

/// The set of modules produced by `buildModules`. The exposable ones are registered
/// via `addModule` (retrievable by dependents through `dep.module(name)`) when
/// `expose` is true; `accel_impl`, `executor_types`, `zkvm_io` and `zkvm_root` stay private.
const ModuleSet = struct {
    zesu_allocator: *std.Build.Module,
    primitives: *std.Build.Module,
    accelerators: *std.Build.Module,
    precompile_types: *std.Build.Module,
    bytecode: *std.Build.Module,
    state: *std.Build.Module,
    database: *std.Build.Module,
    context: *std.Build.Module,
    precompile: *std.Build.Module,
    interpreter: *std.Build.Module,
    handler: *std.Build.Module,
    inspector: *std.Build.Module,
    input: *std.Build.Module,
    output: *std.Build.Module,
    hardfork: *std.Build.Module,
    rlp_decode: *std.Build.Module,
    mpt: *std.Build.Module,
    ssz_decode: *std.Build.Module,
    ssz_output: *std.Build.Module,
    db: *std.Build.Module,
    executor: *std.Build.Module,
    runner: *std.Build.Module,
    zkvm_io: *std.Build.Module,
    /// Freestanding only, private (used by the in-repo rv64im-object build): the relocatable-object
    /// root that wires runner + extern IO + allocator and exports main().
    zkvm_root: ?*std.Build.Module,
};

/// Create (and optionally expose) zesu's whole module graph for a single target.
///
/// Backends are selected by target so the same call serves native builds and zkVM guests:
///   accel_impl = freestanding ? extern_bridge.zig : default.zig
///   zkvm_io    = freestanding ? extern_io.zig     : io/interface.zig
/// The allocator root is supplied by the caller (`allocator.zig` settable singleton for the
/// exposed graph; `bump_alloc.zig` for the standalone rv64im object).
fn buildModules(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    expose: bool,
    alloc_root: std.Build.LazyPath,
    crypto_prefix: []const u8,
) ModuleSet {
    const freestanding = target.result.os.tag == .freestanding;

    const mkmod = struct {
        fn f(bb: *std.Build, exp: bool, name: []const u8, opts: std.Build.Module.CreateOptions) *std.Build.Module {
            return if (exp) bb.addModule(name, opts) else bb.createModule(opts);
        }
    }.f;

    // ── Foundation ────────────────────────────────────────────────────────────
    const zesu_allocator = mkmod(b, expose, "zesu_allocator", .{
        .root_source_file = alloc_root,
        .target = target,
        .optimize = optimize,
    });

    const primitives = mkmod(b, expose, "primitives", .{
        .root_source_file = b.path("src/evm/primitives/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // accel_impl is a private leaf: native crypto (default.zig) or the zkvm-standards extern
    // bridge (extern_bridge.zig, whose zkvm_* symbols the host resolves at link).
    const accel_impl = b.createModule(.{
        .root_source_file = b.path(if (freestanding) "src/crypto/extern_bridge.zig" else "src/crypto/default.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (!freestanding) {
        accel_impl.addImport("zesu_allocator", zesu_allocator);
        // default.zig @cImports system crypto headers (e.g. secp256k1.h). C include paths are
        // per-module and don't cross the dependency boundary, so set it on the accel_impl module
        // itself — that way dependents (and our own apps/tests) resolve the @cImport without each
        // consumer re-adding an include path to a module they can't see. `crypto_prefix` is the
        // caller-provided prefix (overridable via -Dcrypto-prefix; see build()).
        accel_impl.addIncludePath(.{ .cwd_relative = b.fmt("{s}/include", .{crypto_prefix}) });
    }

    const accelerators = mkmod(b, expose, "accelerators", .{
        .root_source_file = b.path("src/crypto/accelerators.zig"),
        .target = target,
        .optimize = optimize,
    });
    accelerators.addImport("accel_impl", accel_impl);

    const precompile_types = mkmod(b, expose, "precompile_types", .{
        .root_source_file = b.path("src/evm/precompile/types.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── EVM ───────────────────────────────────────────────────────────────────
    const bytecode = mkmod(b, expose, "bytecode", .{
        .root_source_file = b.path("src/evm/bytecode/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    bytecode.addImport("primitives", primitives);
    bytecode.addImport("zesu_allocator", zesu_allocator);
    bytecode.addImport("accelerators", accelerators);

    const state = mkmod(b, expose, "state", .{
        .root_source_file = b.path("src/evm/state/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    state.addImport("primitives", primitives);
    state.addImport("bytecode", bytecode);
    state.addImport("zesu_allocator", zesu_allocator);

    const database = mkmod(b, expose, "database", .{
        .root_source_file = b.path("src/evm/database/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    database.addImport("primitives", primitives);
    database.addImport("state", state);
    database.addImport("bytecode", bytecode);

    const context = mkmod(b, expose, "context", .{
        .root_source_file = b.path("src/evm/context/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    context.addImport("primitives", primitives);
    context.addImport("bytecode", bytecode);
    context.addImport("state", state);
    context.addImport("database", database);
    context.addImport("zesu_allocator", zesu_allocator);

    const precompile = mkmod(b, expose, "precompile", .{
        .root_source_file = b.path("src/evm/precompile/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    precompile.addImport("primitives", primitives);
    precompile.addImport("zesu_allocator", zesu_allocator);
    precompile.addImport("precompile_types", precompile_types);
    precompile.addImport("accelerators", accelerators);

    const interpreter = mkmod(b, expose, "interpreter", .{
        .root_source_file = b.path("src/evm/interpreter/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    interpreter.addImport("primitives", primitives);
    interpreter.addImport("bytecode", bytecode);
    interpreter.addImport("context", context);
    interpreter.addImport("database", database);
    interpreter.addImport("state", state);
    interpreter.addImport("precompile", precompile);
    interpreter.addImport("zesu_allocator", zesu_allocator);
    interpreter.addImport("accelerators", accelerators);

    const handler = mkmod(b, expose, "handler", .{
        .root_source_file = b.path("src/evm/handler/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    handler.addImport("primitives", primitives);
    handler.addImport("bytecode", bytecode);
    handler.addImport("state", state);
    handler.addImport("database", database);
    handler.addImport("interpreter", interpreter);
    handler.addImport("context", context);
    handler.addImport("precompile", precompile);
    handler.addImport("zesu_allocator", zesu_allocator);

    const inspector = mkmod(b, expose, "inspector", .{
        .root_source_file = b.path("src/evm/inspector/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    inspector.addImport("primitives", primitives);
    inspector.addImport("context", context);
    inspector.addImport("interpreter", interpreter);
    inspector.addImport("database", database);

    // ── Stateless base ──────────────────────────────────────────────────────
    const input = mkmod(b, expose, "input", .{
        .root_source_file = b.path("src/stateless/input.zig"),
        .target = target,
        .optimize = optimize,
    });
    input.addImport("primitives", primitives);

    const output = mkmod(b, expose, "output", .{
        .root_source_file = b.path("src/stateless/output.zig"),
        .target = target,
        .optimize = optimize,
    });
    output.addImport("primitives", primitives);

    const hardfork = mkmod(b, expose, "hardfork", .{
        .root_source_file = b.path("src/stateless/hardfork.zig"),
        .target = target,
        .optimize = optimize,
    });
    hardfork.addImport("primitives", primitives);

    const rlp_decode = mkmod(b, expose, "rlp_decode", .{
        .root_source_file = b.path("src/stateless/rlp_decode.zig"),
        .target = target,
        .optimize = optimize,
    });
    rlp_decode.addImport("primitives", primitives);
    rlp_decode.addImport("input", input);

    const mpt = mkmod(b, expose, "mpt", .{
        .root_source_file = b.path("src/stateless/mpt/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    mpt.addImport("primitives", primitives);
    mpt.addImport("input", input);
    mpt.addImport("accelerators", accelerators);

    // Deferred: rlp_decode needs mpt (created above).
    rlp_decode.addImport("mpt", mpt);

    const ssz_decode = mkmod(b, expose, "ssz_decode", .{
        .root_source_file = b.path("src/stateless/stateless/ssz.zig"),
        .target = target,
        .optimize = optimize,
    });
    ssz_decode.addImport("input", input);
    ssz_decode.addImport("rlp_decode", rlp_decode);

    const ssz_output = mkmod(b, expose, "ssz_output", .{
        .root_source_file = b.path("src/stateless/stateless/ssz_output.zig"),
        .target = target,
        .optimize = optimize,
    });
    ssz_output.addImport("input", input);
    ssz_output.addImport("accelerators", accelerators);

    // executor_types: shared type definitions — private (not a consumer entry point).
    const executor_types = b.createModule(.{
        .root_source_file = b.path("src/stateless/executor/types.zig"),
        .target = target,
        .optimize = optimize,
    });

    const db = mkmod(b, expose, "db", .{
        .root_source_file = b.path("src/stateless/db/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    db.addImport("primitives", primitives);
    db.addImport("state", state);
    db.addImport("bytecode", bytecode);
    db.addImport("mpt", mpt);
    db.addImport("executor_types", executor_types);

    const executor = mkmod(b, expose, "executor", .{
        .root_source_file = b.path("src/stateless/executor/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    executor.addImport("executor_types", executor_types);
    executor.addImport("zesu_allocator", zesu_allocator);
    executor.addImport("primitives", primitives);
    executor.addImport("input", input);
    executor.addImport("output", output);
    executor.addImport("mpt", mpt);
    executor.addImport("rlp_decode", rlp_decode);
    executor.addImport("hardfork", hardfork);
    executor.addImport("db", db);
    executor.addImport("context", context);
    executor.addImport("state", state);
    executor.addImport("bytecode", bytecode);
    executor.addImport("database", database);
    executor.addImport("handler", handler);
    executor.addImport("interpreter", interpreter);
    executor.addImport("precompile", precompile);
    executor.addImport("accelerators", accelerators);

    // zkvm_io is private: native stdin/env (io/interface.zig) or the extern C-ABI refs
    // (zkvm/extern_io.zig) the zkVM host resolves at link.
    const zkvm_io = b.createModule(.{
        .root_source_file = b.path(if (freestanding) "src/zkvm/extern_io.zig" else "src/io/interface.zig"),
        .target = target,
        .optimize = optimize,
    });

    const runner = mkmod(b, expose, "runner", .{
        .root_source_file = b.path("src/stateless/stateless/run.zig"),
        .target = target,
        .optimize = optimize,
    });
    runner.addImport("executor", executor);
    runner.addImport("ssz_decode", ssz_decode);
    runner.addImport("ssz_output", ssz_output);
    runner.addImport("zkvm_io", zkvm_io);

    var zkvm_root: ?*std.Build.Module = null;
    if (freestanding) {
        // zkvm_root stays PRIVATE (never addModule'd). It wires the full turnkey object
        // (runner + extern IO + allocator) and exports main(). It must NOT be exposed: the
        // exposed graph roots `zesu_allocator` on the settable singleton, and a consumer
        // building this as an object gets no chance to call set() before main() runs (get()
        // would panic on a freestanding default). The turnkey object is instead produced by the
        // `rv64im-object` step (which wires the bump allocator over ZKVM_HEAP_POS/TOP) and
        // published as zesu.rv64im.o. Module consumers import the leaf modules and call set().
        const root = b.createModule(.{
            .root_source_file = b.path("src/zkvm/root.zig"),
            .target = target,
            .optimize = optimize,
        });
        root.addImport("runner", runner);
        root.addImport("zkvm_io", zkvm_io);
        root.addImport("zesu_allocator", zesu_allocator);
        zkvm_root = root;
    }

    return .{
        .zesu_allocator = zesu_allocator,
        .primitives = primitives,
        .accelerators = accelerators,
        .precompile_types = precompile_types,
        .bytecode = bytecode,
        .state = state,
        .database = database,
        .context = context,
        .precompile = precompile,
        .interpreter = interpreter,
        .handler = handler,
        .inspector = inspector,
        .input = input,
        .output = output,
        .hardfork = hardfork,
        .rlp_decode = rlp_decode,
        .mpt = mpt,
        .ssz_decode = ssz_decode,
        .ssz_output = ssz_output,
        .db = db,
        .executor = executor,
        .runner = runner,
        .zkvm_io = zkvm_io,
        .zkvm_root = zkvm_root,
    };
}

/// Link the native crypto C libraries onto a host exe/test.
/// No-op for freestanding targets (their crypto symbols are externs resolved by the zkVM host).
fn addCryptoLibraries(
    step: *std.Build.Step.Compile,
    target: std.Build.ResolvedTarget,
    inc: []const u8,
    blst: []const u8,
    mcl: []const u8,
    linux: bool,
) void {
    if (target.result.os.tag == .freestanding) return;

    step.root_module.addIncludePath(.{ .cwd_relative = inc });
    step.root_module.linkSystemLibrary("c", .{});
    step.root_module.linkSystemLibrary("m", .{});
    step.root_module.linkSystemLibrary("secp256k1", .{});
    step.root_module.linkSystemLibrary("ssl", .{});
    step.root_module.linkSystemLibrary("crypto", .{});
    step.root_module.addObjectFile(.{ .cwd_relative = blst });
    if (linux) {
        // mcl: link dynamically on Linux to avoid unresolved libstdc++ refs embedded in the .a.
        step.root_module.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
        step.root_module.linkSystemLibrary("mcl", .{});
    } else {
        step.root_module.addObjectFile(.{ .cwd_relative = mcl });
        step.root_module.link_libcpp = true;
    }
}

fn addRunStep(
    bb: *std.Build,
    name: []const u8,
    desc: []const u8,
    exe: *std.Build.Step.Compile,
    fixed_args: []const []const u8,
) void {
    const step = bb.step(name, desc);
    const cmd = bb.addRunArtifact(exe);
    cmd.step.dependOn(bb.getInstallStep());
    cmd.addArgs(fixed_args);
    if (bb.args) |args| cmd.addArgs(args);
    step.dependOn(&cmd.step);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── Platform detection ────────────────────────────────────────────────────
    const is_linux = b.graph.host.result.os.tag == .linux;
    // Native crypto dependency prefix. Defaults per OS (Homebrew on macOS, /usr/local on Linux),
    // overridable for non-default setups (e.g. Intel-mac /usr/local) without patching the build.
    const crypto_prefix: []const u8 = b.option(
        []const u8,
        "crypto-prefix",
        "Native crypto dependency prefix (default: /opt/homebrew on macOS, /usr/local on Linux)",
    ) orelse (if (is_linux) "/usr/local" else "/opt/homebrew");
    const crypto_include = b.fmt("{s}/include", .{crypto_prefix});
    // HACK: unlike secp256k1/OpenSSL (resolved via linkSystemLibrary → pkg-config/system search),
    // mcl and blst ship no pkg-config metadata, so the linker can't locate them on its own —
    // addCryptoLibraries hands it the static archives by explicit path. We presume both live under
    // `<crypto_prefix>/lib` (libblst.a, libmcl.a). Assuming they share one directory is itself a bit
    // of a hack
    const libblst_path = b.fmt("{s}/lib/libblst.a", .{crypto_prefix});
    const libmcl_path = b.fmt("{s}/lib/libmcl.a", .{crypto_prefix});

    // ── Module graph (exposed via addModule; backends selected by target) ──────
    const mods = buildModules(b, target, optimize, true, b.path("src/evm/allocator.zig"), crypto_prefix);

    // ── zesu binary ───────────────────────────────────────────────────────────
    const stateless_exe = b.addExecutable(.{
        .name = "zesu",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/stateless/stateless/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    stateless_exe.root_module.addImport("rlp_decode", mods.rlp_decode);
    stateless_exe.root_module.addImport("input", mods.input);
    stateless_exe.root_module.addImport("mpt", mods.mpt);
    stateless_exe.root_module.addImport("executor", mods.executor);
    stateless_exe.root_module.addImport("zesu_allocator", mods.zesu_allocator);
    stateless_exe.root_module.addImport("zkvm_io", mods.zkvm_io);
    stateless_exe.root_module.addImport("ssz_decode", mods.ssz_decode);
    stateless_exe.root_module.addImport("accelerators", mods.accelerators);
    addCryptoLibraries(stateless_exe, target, crypto_include, libblst_path, libmcl_path, is_linux);
    b.installArtifact(stateless_exe);
    addRunStep(b, "run", "Run the zesu app", stateless_exe, &.{});

    // ── t8n: Ethereum State Transition Tool ───────────────────────────────────
    const t8n_input_module = b.createModule(.{
        .root_source_file = b.path("tools/t8n/input.zig"),
        .target = target,
        .optimize = optimize,
    });
    t8n_input_module.addImport("executor", mods.executor);

    const t8n_exe = b.addExecutable(.{
        .name = "t8n",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/t8n/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    t8n_exe.root_module.addImport("executor", mods.executor);
    t8n_exe.root_module.addImport("hardfork", mods.hardfork);
    addCryptoLibraries(t8n_exe, target, crypto_include, libblst_path, libmcl_path, is_linux);
    b.installArtifact(t8n_exe);
    addRunStep(b, "t8n", "Run the t8n state transition tool", t8n_exe, &.{});

    // ── spec-test-runner ──────────────────────────────────────────────────────
    const spec_test_exe = b.addExecutable(.{
        .name = "spec-test-runner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/spec_test/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    spec_test_exe.root_module.addImport("t8n_input", t8n_input_module);
    spec_test_exe.root_module.addImport("executor", mods.executor);
    spec_test_exe.root_module.addImport("hardfork", mods.hardfork);
    addCryptoLibraries(spec_test_exe, target, crypto_include, libblst_path, libmcl_path, is_linux);
    b.installArtifact(spec_test_exe);
    addRunStep(b, "state-tests", "Run execution-spec-tests state fixtures", spec_test_exe, &.{});

    // ── blockchain-test-runner ────────────────────────────────────────────────
    const blockchain_runner_module = b.createModule(.{
        .root_source_file = b.path("tools/blockchain_test/runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    blockchain_runner_module.addImport("primitives", mods.primitives);
    blockchain_runner_module.addImport("executor", mods.executor);
    blockchain_runner_module.addImport("mpt", mods.mpt);
    blockchain_runner_module.addImport("hardfork", mods.hardfork);

    const bc_test_exe = b.addExecutable(.{
        .name = "blockchain-test-runner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/blockchain_test/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    bc_test_exe.root_module.addImport("runner", blockchain_runner_module);
    addCryptoLibraries(bc_test_exe, target, crypto_include, libblst_path, libmcl_path, is_linux);
    b.installArtifact(bc_test_exe);
    addRunStep(b, "blockchain-tests", "Run Ethereum blockchain test fixtures", bc_test_exe, &.{});

    // ── zkevm-blockchain-test-runner ──────────────────────────────────────────
    const zkevm_test_exe = b.addExecutable(.{
        .name = "zkevm-blockchain-test-runner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/zkevm_test/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    zkevm_test_exe.root_module.addImport("ssz_decode", mods.ssz_decode);
    zkevm_test_exe.root_module.addImport("ssz_output", mods.ssz_output);
    zkevm_test_exe.root_module.addImport("executor", mods.executor);
    addCryptoLibraries(zkevm_test_exe, target, crypto_include, libblst_path, libmcl_path, is_linux);
    b.installArtifact(zkevm_test_exe);
    addRunStep(b, "zkevm-tests", "Run zkevm blockchain test fixtures", zkevm_test_exe, &.{ "--fixtures", "spec-tests/fixtures/zkevm/blockchain_tests" });

    // ── hive-rlp: Hive consume-rlp execution client ───────────────────────────
    const hive_exe = b.addExecutable(.{
        .name = "hive-rlp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/hive/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    hive_exe.root_module.addImport("primitives", mods.primitives);
    hive_exe.root_module.addImport("executor", mods.executor);
    hive_exe.root_module.addImport("hardfork", mods.hardfork);
    hive_exe.root_module.addImport("mpt", mods.mpt);
    addCryptoLibraries(hive_exe, target, crypto_include, libblst_path, libmcl_path, is_linux);
    b.installArtifact(hive_exe);
    b.step("hive-rlp", "Build and install the Hive consume-rlp client").dependOn(b.getInstallStep());

    // ── Tests ─────────────────────────────────────────────────────────────────
    const test_step = b.step("test", "Run all unit tests");

    for ([_]struct { m: *std.Build.Module, name: []const u8 }{
        .{ .m = mods.precompile, .name = "precompile" },
        .{ .m = mods.interpreter, .name = "interpreter" },
        .{ .m = mods.handler, .name = "handler" },
        .{ .m = mods.mpt, .name = "mpt" },
        .{ .m = mods.rlp_decode, .name = "rlp_decode" },
    }) |t| {
        const tst = b.addTest(.{ .root_module = t.m });
        _ = t.name;
        addCryptoLibraries(tst, target, crypto_include, libblst_path, libmcl_path, is_linux);
        test_step.dependOn(&b.addRunArtifact(tst).step);
    }

    // MPT integration tests
    {
        const m = b.createModule(.{
            .root_source_file = b.path("src/stateless/mpt/test.zig"),
            .target = target,
            .optimize = optimize,
        });
        m.addImport("primitives", mods.primitives);
        m.addImport("mpt", mods.mpt);
        m.addImport("input", mods.input);
        const tst = b.addTest(.{ .root_module = m });
        addCryptoLibraries(tst, target, crypto_include, libblst_path, libmcl_path, is_linux);
        test_step.dependOn(&b.addRunArtifact(tst).step);
    }

    // WitnessDatabase integration tests
    {
        const m = b.createModule(.{
            .root_source_file = b.path("src/stateless/db/test.zig"),
            .target = target,
            .optimize = optimize,
        });
        m.addImport("primitives", mods.primitives);
        m.addImport("state", mods.state);
        m.addImport("bytecode", mods.bytecode);
        m.addImport("mpt", mods.mpt);
        m.addImport("input", mods.input);
        m.addImport("db", mods.db);
        const tst = b.addTest(.{ .root_module = m });
        addCryptoLibraries(tst, target, crypto_include, libblst_path, libmcl_path, is_linux);
        test_step.dependOn(&b.addRunArtifact(tst).step);
    }

    // ── rv64im relocatable object ─────────────────────────────────────────────
    //
    // Produces zig-out/lib/zesu.o: a relocatable rv64im ELF with all EVM and stateless
    // execution logic compiled in, but IO, crypto accelerators, heap and logging left as
    // unresolved extern references per zkvm-standards. Built from a private graph wired with
    // the bump allocator (over ZKVM_HEAP_POS/TOP) so the standalone object needs no set() call.
    //
    // Build with: zig build rv64im-object
    // Verify undefined refs: llvm-nm zig-out/lib/zesu.o | grep ' U '
    {
        const rv64im_target = b.resolveTargetQuery(.{
            .cpu_arch = .riscv64,
            .cpu_model = .{ .explicit = &std.Target.riscv.cpu.baseline_rv64 },
            .cpu_features_add = std.Target.riscv.featureSet(&.{ .m, .zicclsm }),
            .cpu_features_sub = std.Target.riscv.featureSet(&.{ .a, .c, .d, .f, .zicsr, .zaamo, .zalrsc }),
            .os_tag = .freestanding,
            .abi = .none,
        });

        const obj_mods = buildModules(b, rv64im_target, optimize, false, b.path("src/zkvm/bump_alloc.zig"), crypto_prefix);

        const rv64_obj = b.addObject(.{
            .name = "zesu",
            .root_module = obj_mods.zkvm_root.?,
        });
        rv64_obj.root_module.code_model = .medium;

        const obj_step = b.step("rv64im-object", "Build relocatable rv64im ELF object (zesu.o)");
        const install_obj = b.addInstallFile(rv64_obj.getEmittedBin(), "lib/zesu.o");
        obj_step.dependOn(&install_obj.step);
    }

    // ── Fixture fetch steps ───────────────────────────────────────────────────
    const spec_test_version = "tests-bal@v7.2.0";
    const fetch_fixtures_step = b.step("fetch-fixtures", "Download execution-specs " ++ spec_test_version ++ " fixtures");
    fetch_fixtures_step.dependOn(&b.addSystemCommand(&.{
        "sh", "-c",
        "marker=spec-tests/.fixtures-" ++ spec_test_version ++ " && " ++
            "[ -f \"$marker\" ] && echo 'Fixtures already up to date.' && exit 0; " ++
            "echo 'Downloading execution-specs " ++ spec_test_version ++ " fixtures...' && " ++
            "rm -rf spec-tests/fixtures && mkdir -p spec-tests/fixtures && " ++
            "encoded=$(printf '%s' '" ++ spec_test_version ++ "' | sed 's/@/%40/g') && " ++
            "curl -fL \"https://github.com/ethereum/execution-specs/releases/download/${encoded}/fixtures_bal.tar.gz\" " ++
            "| tar xz --strip-components=1 -C spec-tests/fixtures/ && " ++
            "touch \"$marker\" && " ++
            "echo 'Done. Fixtures extracted to spec-tests/fixtures/'",
    }).step);

    const zkevm_version = "tests-zkevm@v0.4.1";
    const fetch_zkevm_step = b.step("fetch-zkevm-fixtures", "Download " ++ zkevm_version ++ " execution-specs fixtures");
    fetch_zkevm_step.dependOn(&b.addSystemCommand(&.{
        "sh", "-c",
        "rm -rf spec-tests/fixtures/zkevm && " ++
            "mkdir -p spec-tests/fixtures/zkevm && " ++
            "echo 'Downloading " ++ zkevm_version ++ " fixtures...' && " ++
            "encoded=$(printf '%s' '" ++ zkevm_version ++ "' | sed 's/@/%40/g') && " ++
            "curl -fL \"https://github.com/ethereum/execution-specs/releases/download/${encoded}/fixtures_zkevm.tar.gz\" " ++
            "| tar xz --strip-components=1 -C spec-tests/fixtures/zkevm/ && " ++
            "echo 'Done. Fixtures extracted to spec-tests/fixtures/zkevm/'",
    }).step);
}
