const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── Foundation modules ────────────────────────────────────────────────────

    // Single allocator module (std.heap.c_allocator for native). Override for zkVM targets by
    // calling addImport("zesu_allocator", your_module) on each consuming module.
    const zesu_allocator_module = b.addModule("zesu_allocator", .{
        .root_source_file = b.path("../src/evm/allocator.zig"),
        .target = target,
        .optimize = optimize,
    });

    const primitives_module = b.addModule("primitives", .{
        .root_source_file = b.path("../src/evm/primitives/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── Crypto accelerator ────────────────────────────────────────────────────
    // extern_bridge.zig: accel_impl for zkvm builds. Declares extern fn zkvm_*
    // symbols resolved at link time from zisk_accel.o (ZisK CSR implementations).
    const extern_bridge_module = b.createModule(.{
        .root_source_file = b.path("../src/crypto/extern_bridge.zig"),
        .target = target,
        .optimize = optimize,
    });

    const accelerators_module = b.addModule("accelerators", .{
        .root_source_file = b.path("../src/crypto/accelerators.zig"),
        .target = target,
        .optimize = optimize,
    });
    accelerators_module.addImport("accel_impl", extern_bridge_module);

    const precompile_types_module = b.addModule("precompile_types", .{
        .root_source_file = b.path("../src/evm/precompile/types.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── EVM modules ──────────────────────────────────────────────────────────

    const bytecode_module = b.addModule("bytecode", .{
        .root_source_file = b.path("../src/evm/bytecode/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    bytecode_module.addImport("primitives", primitives_module);
    bytecode_module.addImport("zesu_allocator", zesu_allocator_module);
    bytecode_module.addImport("accelerators", accelerators_module);

    const state_module = b.addModule("state", .{
        .root_source_file = b.path("../src/evm/state/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    state_module.addImport("primitives", primitives_module);
    state_module.addImport("bytecode", bytecode_module);
    state_module.addImport("zesu_allocator", zesu_allocator_module);

    const database_module = b.addModule("database", .{
        .root_source_file = b.path("../src/evm/database/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    database_module.addImport("primitives", primitives_module);
    database_module.addImport("state", state_module);
    database_module.addImport("bytecode", bytecode_module);

    const context_module = b.addModule("context", .{
        .root_source_file = b.path("../src/evm/context/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    context_module.addImport("primitives", primitives_module);
    context_module.addImport("bytecode", bytecode_module);
    context_module.addImport("state", state_module);
    context_module.addImport("database", database_module);
    context_module.addImport("zesu_allocator", zesu_allocator_module);

    const precompile_module = b.addModule("precompile", .{
        .root_source_file = b.path("../src/evm/precompile/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    precompile_module.addImport("primitives", primitives_module);
    precompile_module.addImport("zesu_allocator", zesu_allocator_module);
    precompile_module.addImport("precompile_types", precompile_types_module);
    precompile_module.addImport("accelerators", accelerators_module);

    const interpreter_module = b.addModule("interpreter", .{
        .root_source_file = b.path("../src/evm/interpreter/main.zig"),
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

    const handler_module = b.addModule("handler", .{
        .root_source_file = b.path("../src/evm/handler/main.zig"),
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

    const inspector_module = b.addModule("inspector", .{
        .root_source_file = b.path("../src/evm/inspector/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    inspector_module.addImport("primitives", primitives_module);
    inspector_module.addImport("context", context_module);
    inspector_module.addImport("interpreter", interpreter_module);
    inspector_module.addImport("database", database_module);

    // ── Stateless base modules ────────────────────────────────────────────────

    const input_module = b.addModule("input", .{
        .root_source_file = b.path("../src/stateless/input.zig"),
        .target = target,
        .optimize = optimize,
    });
    input_module.addImport("primitives", primitives_module);

    const output_module = b.addModule("output", .{
        .root_source_file = b.path("../src/stateless/output.zig"),
        .target = target,
        .optimize = optimize,
    });
    output_module.addImport("primitives", primitives_module);

    const hardfork_module = b.addModule("hardfork", .{
        .root_source_file = b.path("../src/stateless/hardfork.zig"),
        .target = target,
        .optimize = optimize,
    });
    hardfork_module.addImport("primitives", primitives_module);

    // rlp_decode needs mpt (created below) — wire "mpt" after mpt_module is created.
    const rlp_decode_module = b.addModule("rlp_decode", .{
        .root_source_file = b.path("../src/stateless/rlp_decode.zig"),
        .target = target,
        .optimize = optimize,
    });
    rlp_decode_module.addImport("primitives", primitives_module);
    rlp_decode_module.addImport("input", input_module);

    // ── MPT modules ──────────────────────────────────────────────────────────

    const mpt_module = b.addModule("mpt", .{
        .root_source_file = b.path("../src/stateless/mpt/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    mpt_module.addImport("primitives", primitives_module);
    mpt_module.addImport("input", input_module);
    mpt_module.addImport("accelerators", accelerators_module);

    // Wire deferred mpt dependency into rlp_decode.
    rlp_decode_module.addImport("mpt", mpt_module);

    const ssz_decode_module = b.addModule("ssz_decode", .{
        .root_source_file = b.path("../src/stateless/stateless/ssz.zig"),
        .target = target,
        .optimize = optimize,
    });
    ssz_decode_module.addImport("input", input_module);
    ssz_decode_module.addImport("rlp_decode", rlp_decode_module);

    const ssz_output_module = b.addModule("ssz_output", .{
        .root_source_file = b.path("../src/stateless/stateless/ssz_output.zig"),
        .target = target,
        .optimize = optimize,
    });
    ssz_output_module.addImport("input", input_module);
    ssz_output_module.addImport("accelerators", accelerators_module);

    // executor_types: canonical EVM/block type definitions shared by executor and db.
    const executor_types_module = b.createModule(.{
        .root_source_file = b.path("../src/stateless/executor/types.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── WitnessDatabase ───────────────────────────────────────────────────────

    const db_module = b.addModule("db", .{
        .root_source_file = b.path("../src/stateless/db/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    db_module.addImport("primitives", primitives_module);
    db_module.addImport("state", state_module);
    db_module.addImport("bytecode", bytecode_module);
    db_module.addImport("mpt", mpt_module);
    db_module.addImport("executor_types", executor_types_module);

    // ── Executor ─────────────────────────────────────────────────────────────

    const executor_module = b.addModule("executor", .{
        .root_source_file = b.path("../src/stateless/executor/main.zig"),
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
    executor_module.addImport("interpreter", interpreter_module);
    executor_module.addImport("handler", handler_module);
    executor_module.addImport("precompile", precompile_module);
    executor_module.addImport("accelerators", accelerators_module);

    // runner: SSZ stream execution entry point.
    // Reads SSZ input via the injected `zkvm_io` module, executes the block,
    // and returns the serialized output bytes + success flag.
    // "zkvm_io" is NOT wired here — the consumer must inject a platform-specific
    // implementation (e.g. memory-mapped I/O for ZisK, stdin/env for native).
    const runner_module = b.addModule("runner", .{
        .root_source_file = b.path("../src/stateless/stateless/run.zig"),
        .target = target,
        .optimize = optimize,
    });
    runner_module.addImport("executor", executor_module);
    runner_module.addImport("ssz_decode", ssz_decode_module);
    runner_module.addImport("ssz_output", ssz_output_module);

    // ── Freestanding (zkvm) build: relocatable rv64im object ─────────────────
    //
    // When this package is consumed with a freestanding target (e.g.
    //   b.dependency("zesu_core", .{ .target = rv64im_target })
    // ), produce a relocatable ELF object with unresolved extern refs that
    // satisfy the zkvm-standards ABI.  Consumers retrieve it via:
    //   zesu_core_dep.artifact("zesu")
    if (target.result.os.tag == .freestanding) {
        const bump_alloc_mod = b.createModule(.{
            .root_source_file = b.path("../src/zkvm/bump_alloc.zig"),
            .target = target,
            .optimize = optimize,
        });
        // Override zesu_allocator (std.heap.c_allocator → bump allocator)
        for ([_]*std.Build.Module{
            bytecode_module,
            state_module,
            context_module,
            precompile_module,
            interpreter_module,
            handler_module,
            executor_module,
        }) |mod| {
            mod.addImport("zesu_allocator", bump_alloc_mod);
        }

        // zkvm_io: extern_io — read_input/write_output as C-ABI extern refs
        const extern_io_mod = b.createModule(.{
            .root_source_file = b.path("../src/zkvm/extern_io.zig"),
            .target = target,
            .optimize = optimize,
        });
        runner_module.addImport("zkvm_io", extern_io_mod);

        // Named public module so consumers can build the rv64im object:
        //   const zesu_obj = b.addObject(.{
        //       .name = "zesu",
        //       .root_module = zesu_core_dep.module("zkvm_root"),
        //   });
        const zkvm_root_mod = b.addModule("zkvm_root", .{
            .root_source_file = b.path("../src/zkvm/root.zig"),
            .target = target,
            .optimize = optimize,
        });
        zkvm_root_mod.addImport("runner", runner_module);
        zkvm_root_mod.addImport("zkvm_io", extern_io_mod);
        zkvm_root_mod.addImport("zesu_allocator", bump_alloc_mod);
    }
}
