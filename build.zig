const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── Platform detection ────────────────────────────────────────────────────
    const is_linux = b.graph.host.result.os.tag == .linux;
    const crypto_prefix: []const u8 = if (is_linux) "/usr/local" else "/opt/homebrew";
    const crypto_include = b.fmt("{s}/include", .{crypto_prefix});
    const libblst_path = b.fmt("{s}/lib/libblst.a", .{crypto_prefix});
    const libmcl_path = b.fmt("{s}/lib/libmcl.a", .{crypto_prefix});

    // ── Crypto linking helper ─────────────────────────────────────────────────
    //
    // mcl: on Linux, the .a archive embeds libstdc++ references that Zig/LLD
    // cannot resolve reliably against the system libstdc++. Use the .so instead
    // (runtime resolution by the OS dynamic linker). On macOS, Homebrew mcl is
    // compiled with clang/libc++ so static linking with linkLibCpp() works.
    const addCryptoLibraries = struct {
        fn add(
            step: *std.Build.Step.Compile,
            inc: []const u8,
            blst: []const u8,
            mcl: []const u8,
            linux: bool,
        ) void {
            step.root_module.addIncludePath(.{ .cwd_relative = inc });
            step.root_module.linkSystemLibrary("c", .{});
            step.root_module.linkSystemLibrary("m", .{});
            step.root_module.linkSystemLibrary("secp256k1", .{});
            step.root_module.linkSystemLibrary("ssl", .{});
            step.root_module.linkSystemLibrary("crypto", .{});
            step.root_module.addObjectFile(.{ .cwd_relative = blst });
            if (linux) {
                step.root_module.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
                step.root_module.linkSystemLibrary("mcl", .{});
            } else {
                step.root_module.addObjectFile(.{ .cwd_relative = mcl });
                step.root_module.link_libcpp = true;
            }
        }
    }.add;

    // ── Run step helper ───────────────────────────────────────────────────────
    const addRunStep = struct {
        fn add(
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
    }.add;

    // ── Foundation modules ────────────────────────────────────────────────────

    // Single allocator module (std.heap.c_allocator for native). Overridden in zesu-zkvm builds.
    const zesu_allocator_module = b.createModule(.{
        .root_source_file = b.path("src/evm/allocator.zig"),
        .target = target,
        .optimize = optimize,
    });

    const primitives_module = b.createModule(.{
        .root_source_file = b.path("src/evm/primitives/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // accel_impl: native crypto via std.crypto + C libs (libsecp256k1, OpenSSL, blst, mcl).
    // Include paths and C library links are added per-exe by addCryptoLibraries.
    const accel_impl_module = b.createModule(.{
        .root_source_file = b.path("src/crypto/default.zig"),
        .target = target,
        .optimize = optimize,
    });
    accel_impl_module.addImport("zesu_allocator", zesu_allocator_module);

    const accelerators_module = b.createModule(.{
        .root_source_file = b.path("src/crypto/accelerators.zig"),
        .target = target,
        .optimize = optimize,
    });
    accelerators_module.addImport("accel_impl", accel_impl_module);

    const precompile_types_module = b.createModule(.{
        .root_source_file = b.path("src/evm/precompile/types.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── EVM modules ───────────────────────────────────────────────────────────

    const bytecode_module = b.createModule(.{
        .root_source_file = b.path("src/evm/bytecode/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    bytecode_module.addImport("primitives", primitives_module);
    bytecode_module.addImport("zesu_allocator", zesu_allocator_module);
    bytecode_module.addImport("accelerators", accelerators_module);

    const state_module = b.createModule(.{
        .root_source_file = b.path("src/evm/state/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    state_module.addImport("primitives", primitives_module);
    state_module.addImport("bytecode", bytecode_module);
    state_module.addImport("zesu_allocator", zesu_allocator_module);

    const database_module = b.createModule(.{
        .root_source_file = b.path("src/evm/database/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    database_module.addImport("primitives", primitives_module);
    database_module.addImport("state", state_module);
    database_module.addImport("bytecode", bytecode_module);

    const context_module = b.createModule(.{
        .root_source_file = b.path("src/evm/context/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    context_module.addImport("primitives", primitives_module);
    context_module.addImport("bytecode", bytecode_module);
    context_module.addImport("state", state_module);
    context_module.addImport("database", database_module);
    context_module.addImport("zesu_allocator", zesu_allocator_module);

    const precompile_module = b.createModule(.{
        .root_source_file = b.path("src/evm/precompile/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    precompile_module.addImport("primitives", primitives_module);
    precompile_module.addImport("zesu_allocator", zesu_allocator_module);
    precompile_module.addImport("precompile_types", precompile_types_module);
    precompile_module.addImport("accelerators", accelerators_module);

    const interpreter_module = b.createModule(.{
        .root_source_file = b.path("src/evm/interpreter/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    interpreter_module.addImport("primitives", primitives_module);
    interpreter_module.addImport("bytecode", bytecode_module);
    interpreter_module.addImport("context", context_module);
    interpreter_module.addImport("database", database_module);
    interpreter_module.addImport("state", state_module);
    interpreter_module.addImport("precompile", precompile_module);
    interpreter_module.addImport("zesu_allocator", zesu_allocator_module);
    interpreter_module.addImport("accelerators", accelerators_module);

    const handler_module = b.createModule(.{
        .root_source_file = b.path("src/evm/handler/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    handler_module.addImport("primitives", primitives_module);
    handler_module.addImport("bytecode", bytecode_module);
    handler_module.addImport("state", state_module);
    handler_module.addImport("database", database_module);
    handler_module.addImport("interpreter", interpreter_module);
    handler_module.addImport("context", context_module);
    handler_module.addImport("precompile", precompile_module);
    handler_module.addImport("zesu_allocator", zesu_allocator_module);

    // ── Stateless base modules ────────────────────────────────────────────────

    const input_module = b.createModule(.{
        .root_source_file = b.path("src/stateless/input.zig"),
        .target = target,
        .optimize = optimize,
    });
    input_module.addImport("primitives", primitives_module);

    const output_module = b.createModule(.{
        .root_source_file = b.path("src/stateless/output.zig"),
        .target = target,
        .optimize = optimize,
    });
    output_module.addImport("primitives", primitives_module);

    const hardfork_module = b.createModule(.{
        .root_source_file = b.path("src/stateless/hardfork.zig"),
        .target = target,
        .optimize = optimize,
    });
    hardfork_module.addImport("primitives", primitives_module);

    const rlp_decode_module = b.createModule(.{
        .root_source_file = b.path("src/stateless/rlp_decode.zig"),
        .target = target,
        .optimize = optimize,
    });
    rlp_decode_module.addImport("primitives", primitives_module);
    rlp_decode_module.addImport("input", input_module);

    // ── MPT modules ───────────────────────────────────────────────────────────

    const mpt_module = b.createModule(.{
        .root_source_file = b.path("src/stateless/mpt/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    mpt_module.addImport("primitives", primitives_module);
    mpt_module.addImport("input", input_module);
    mpt_module.addImport("accelerators", accelerators_module);

    // Wire deferred mpt dependency into rlp_decode.
    rlp_decode_module.addImport("mpt", mpt_module);

    // ── Executor ──────────────────────────────────────────────────────────────

    const executor_types_module = b.createModule(.{
        .root_source_file = b.path("src/stateless/executor/types.zig"),
        .target = target,
        .optimize = optimize,
    });

    const db_module = b.createModule(.{
        .root_source_file = b.path("src/stateless/db/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    db_module.addImport("primitives", primitives_module);
    db_module.addImport("state", state_module);
    db_module.addImport("bytecode", bytecode_module);
    db_module.addImport("mpt", mpt_module);
    db_module.addImport("executor_types", executor_types_module);

    const executor_module = b.createModule(.{
        .root_source_file = b.path("src/stateless/executor/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    executor_module.addImport("executor_types", executor_types_module);
    executor_module.addImport("zesu_allocator", zesu_allocator_module);
    executor_module.addImport("primitives", primitives_module);
    executor_module.addImport("input", input_module);
    executor_module.addImport("output", output_module);
    executor_module.addImport("mpt", mpt_module);
    executor_module.addImport("rlp_decode", rlp_decode_module);
    executor_module.addImport("hardfork", hardfork_module);
    executor_module.addImport("db", db_module);
    executor_module.addImport("context", context_module);
    executor_module.addImport("state", state_module);
    executor_module.addImport("bytecode", bytecode_module);
    executor_module.addImport("database", database_module);
    executor_module.addImport("handler", handler_module);
    executor_module.addImport("precompile", precompile_module);
    executor_module.addImport("accelerators", accelerators_module);

    // ── I/O module ────────────────────────────────────────────────────────────
    const zkvm_io_module = b.createModule(.{
        .root_source_file = b.path("src/io/interface.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── SSZ helper modules ────────────────────────────────────────────────────
    const ssz_decode_module = b.createModule(.{
        .root_source_file = b.path("src/stateless/stateless/ssz.zig"),
        .target = target,
        .optimize = optimize,
    });
    ssz_decode_module.addImport("input", input_module);
    ssz_decode_module.addImport("rlp_decode", rlp_decode_module);

    const ssz_output_module = b.createModule(.{
        .root_source_file = b.path("src/stateless/stateless/ssz_output.zig"),
        .target = target,
        .optimize = optimize,
    });
    ssz_output_module.addImport("input", input_module);
    ssz_output_module.addImport("accelerators", accelerators_module);

    // runner: SSZ stream execution entry point (platform-independent execution core).
    // Wire the native zkvm_io so `runStateless` reads from stdin/env.
    const runner_module = b.createModule(.{
        .root_source_file = b.path("src/stateless/stateless/run.zig"),
        .target = target,
        .optimize = optimize,
    });
    runner_module.addImport("executor", executor_module);
    runner_module.addImport("ssz_decode", ssz_decode_module);
    runner_module.addImport("ssz_output", ssz_output_module);
    runner_module.addImport("zkvm_io", zkvm_io_module);

    // ── zevm_stateless binary ─────────────────────────────────────────────────

    const stateless_exe = b.addExecutable(.{
        .name = "zesu",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/stateless/stateless/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    stateless_exe.root_module.addImport("rlp_decode", rlp_decode_module);
    stateless_exe.root_module.addImport("input", input_module);
    stateless_exe.root_module.addImport("mpt", mpt_module);
    stateless_exe.root_module.addImport("executor", executor_module);
    stateless_exe.root_module.addImport("zesu_allocator", zesu_allocator_module);
    stateless_exe.root_module.addImport("zkvm_io", zkvm_io_module);
    stateless_exe.root_module.addImport("ssz_decode", ssz_decode_module);
    stateless_exe.root_module.addImport("accelerators", accelerators_module);
    addCryptoLibraries(stateless_exe, crypto_include, libblst_path, libmcl_path, is_linux);
    b.installArtifact(stateless_exe);
    addRunStep(b, "run", "Run the zevm_stateless app", stateless_exe, &.{});

    // ── t8n: Ethereum State Transition Tool ───────────────────────────────────

    const t8n_input_module = b.createModule(.{
        .root_source_file = b.path("tools/t8n/input.zig"),
        .target = target,
        .optimize = optimize,
    });
    t8n_input_module.addImport("executor", executor_module);

    const t8n_exe = b.addExecutable(.{
        .name = "t8n",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/t8n/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    t8n_exe.root_module.addImport("executor", executor_module);
    t8n_exe.root_module.addImport("hardfork", hardfork_module);
    addCryptoLibraries(t8n_exe, crypto_include, libblst_path, libmcl_path, is_linux);
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
    spec_test_exe.root_module.addImport("executor", executor_module);
    spec_test_exe.root_module.addImport("hardfork", hardfork_module);
    addCryptoLibraries(spec_test_exe, crypto_include, libblst_path, libmcl_path, is_linux);
    b.installArtifact(spec_test_exe);
    addRunStep(b, "state-tests", "Run execution-spec-tests state fixtures", spec_test_exe, &.{});

    // ── blockchain-test-runner ────────────────────────────────────────────────

    const blockchain_runner_module = b.createModule(.{
        .root_source_file = b.path("tools/blockchain_test/runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    blockchain_runner_module.addImport("primitives", primitives_module);
    blockchain_runner_module.addImport("executor", executor_module);
    blockchain_runner_module.addImport("mpt", mpt_module);
    blockchain_runner_module.addImport("hardfork", hardfork_module);

    const bc_test_exe = b.addExecutable(.{
        .name = "blockchain-test-runner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/blockchain_test/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    bc_test_exe.root_module.addImport("runner", blockchain_runner_module);
    addCryptoLibraries(bc_test_exe, crypto_include, libblst_path, libmcl_path, is_linux);
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
    zkevm_test_exe.root_module.addImport("ssz_decode", ssz_decode_module);
    zkevm_test_exe.root_module.addImport("ssz_output", ssz_output_module);
    zkevm_test_exe.root_module.addImport("executor", executor_module);
    addCryptoLibraries(zkevm_test_exe, crypto_include, libblst_path, libmcl_path, is_linux);
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
    hive_exe.root_module.addImport("primitives", primitives_module);
    hive_exe.root_module.addImport("executor", executor_module);
    hive_exe.root_module.addImport("hardfork", hardfork_module);
    hive_exe.root_module.addImport("mpt", mpt_module);
    addCryptoLibraries(hive_exe, crypto_include, libblst_path, libmcl_path, is_linux);
    b.installArtifact(hive_exe);
    b.step("hive-rlp", "Build and install the Hive consume-rlp client").dependOn(b.getInstallStep());

    // ── Tests ─────────────────────────────────────────────────────────────────

    const test_step = b.step("test", "Run all unit tests");

    for ([_]struct { m: *std.Build.Module, name: []const u8 }{
        .{ .m = precompile_module, .name = "precompile" },
        .{ .m = interpreter_module, .name = "interpreter" },
        .{ .m = handler_module, .name = "handler" },
        .{ .m = mpt_module, .name = "mpt" },
    }) |t| {
        const tst = b.addTest(.{ .root_module = t.m });
        _ = t.name;
        addCryptoLibraries(tst, crypto_include, libblst_path, libmcl_path, is_linux);
        test_step.dependOn(&b.addRunArtifact(tst).step);
    }

    // MPT integration tests
    {
        const m = b.createModule(.{
            .root_source_file = b.path("src/stateless/mpt/test.zig"),
            .target = target,
            .optimize = optimize,
        });
        m.addImport("primitives", primitives_module);
        m.addImport("mpt", mpt_module);
        m.addImport("input", input_module);
        const tst = b.addTest(.{ .root_module = m });
        addCryptoLibraries(tst, crypto_include, libblst_path, libmcl_path, is_linux);
        test_step.dependOn(&b.addRunArtifact(tst).step);
    }

    // WitnessDatabase integration tests
    {
        const m = b.createModule(.{
            .root_source_file = b.path("src/stateless/db/test.zig"),
            .target = target,
            .optimize = optimize,
        });
        m.addImport("primitives", primitives_module);
        m.addImport("state", state_module);
        m.addImport("bytecode", bytecode_module);
        m.addImport("mpt", mpt_module);
        m.addImport("input", input_module);
        m.addImport("db", db_module);
        const tst = b.addTest(.{ .root_module = m });
        addCryptoLibraries(tst, crypto_include, libblst_path, libmcl_path, is_linux);
        test_step.dependOn(&b.addRunArtifact(tst).step);
    }

    // ── Fixture fetch steps ───────────────────────────────────────────────────

    const spec_test_version = "bal@v5.6.1";
    const fetch_fixtures_step = b.step("fetch-fixtures", "Download execution-spec-tests " ++ spec_test_version ++ " fixtures");
    fetch_fixtures_step.dependOn(&b.addSystemCommand(&.{
        "sh", "-c",
        "marker=spec-tests/.fixtures-" ++ spec_test_version ++ " && " ++
            "[ -f \"$marker\" ] && echo 'Fixtures already up to date.' && exit 0; " ++
            "echo 'Downloading execution-spec-tests " ++ spec_test_version ++ " fixtures...' && " ++
            "rm -rf spec-tests/fixtures && mkdir -p spec-tests/fixtures && " ++
            "encoded=$(printf '%s' '" ++ spec_test_version ++ "' | sed 's/@/%40/g') && " ++
            "curl -fL \"https://github.com/ethereum/execution-spec-tests/releases/download/${encoded}/fixtures_bal.tar.gz\" " ++
            "| tar xz --strip-components=1 -C spec-tests/fixtures/ && " ++
            "touch \"$marker\" && " ++
            "echo 'Done. Fixtures extracted to spec-tests/fixtures/'",
    }).step);

    const zkevm_version = "zkevm@v0.3.4";
    const fetch_zkevm_step = b.step("fetch-zkevm-fixtures", "Download " ++ zkevm_version ++ " execution-spec-tests fixtures");
    fetch_zkevm_step.dependOn(&b.addSystemCommand(&.{
        "sh", "-c",
        "rm -rf spec-tests/fixtures/zkevm && " ++
            "mkdir -p spec-tests/fixtures/zkevm && " ++
            "echo 'Downloading " ++ zkevm_version ++ " fixtures...' && " ++
            "encoded=$(printf '%s' '" ++ zkevm_version ++ "' | sed 's/@/%40/g') && " ++
            "curl -fL \"https://github.com/ethereum/execution-spec-tests/releases/download/${encoded}/fixtures_zkevm.tar.gz\" " ++
            "| tar xz --strip-components=1 -C spec-tests/fixtures/zkevm/ && " ++
            "echo 'Done. Fixtures extracted to spec-tests/fixtures/zkevm/'",
    }).step);
}
