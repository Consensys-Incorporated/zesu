const std = @import("std");
const primitives = @import("primitives");
const main = @import("main.zig");
const alloc_mod = @import("zesu_allocator");
const accel = @import("accelerators");

/// SHA-256 precompile
pub const SHA256 = main.Precompile.new(
    main.PrecompileId.Sha256,
    main.u64ToAddress(2),
    sha256Run,
);

/// RIPEMD-160 precompile
pub const RIPEMD160 = main.Precompile.new(
    main.PrecompileId.Ripemd160,
    main.u64ToAddress(3),
    ripemd160Run,
);

pub fn sha256Run(input: []const u8, gas_limit: u64) main.PrecompileResult {
    const cost = main.calcLinearCost(input.len, 60, 12);
    if (cost > gas_limit)
        return .{ .err = main.PrecompileError.OutOfGas };

    var output: [32]u8 = undefined;
    accel.sha256(input, &output);

    const heap_out = alloc_mod.get().dupe(u8, &output) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = main.PrecompileError.OutOfGas };
    };
    return .{ .success = main.PrecompileOutput.new(cost, heap_out) };
}

pub fn ripemd160Run(input: []const u8, gas_limit: u64) main.PrecompileResult {
    const gas_used = main.calcLinearCost(input.len, 600, 120);
    if (gas_used > gas_limit)
        return .{ .err = main.PrecompileError.OutOfGas };

    // accel.ripemd160 writes the EVM output layout directly (12 zero bytes +
    // 20-byte digest), so the host result lands straight in the heap buffer —
    // no intermediate copy or re-pad needed.
    const heap_out = alloc_mod.get().alloc(u8, 32) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = main.PrecompileError.OutOfGas };
    };
    accel.ripemd160(input, heap_out[0..32]);
    return .{ .success = main.PrecompileOutput.new(gas_used, heap_out) };
}
