const std = @import("std");
const main = @import("main.zig");
const alloc_mod = @import("zesu_allocator");
const accel = @import("accelerators");

/// BLAKE2f compression function precompile (EIP-152)
pub const FUN = main.Precompile.new(
    main.PrecompileId.Blake2F,
    main.u64ToAddress(9),
    blake2fRun,
);

const F_ROUND: u64 = 1;
const INPUT_LENGTH: usize = 213;

/// BLAKE2f run: parse EVM input, delegate to accel.blake2f, return heap-allocated output.
/// Input format: [4B rounds][64B h][128B m][8B t_0][8B t_1][1B f]
pub fn blake2fRun(input: []const u8, gas_limit: u64) main.PrecompileResult {
    if (input.len != INPUT_LENGTH)
        return .{ .err = main.PrecompileError.Blake2WrongLength };

    const rounds = std.mem.readInt(u32, input[0..4], .big);
    const gas_used = @as(u64, rounds) * F_ROUND;
    if (gas_used > gas_limit)
        return .{ .err = main.PrecompileError.OutOfGas };

    // Validate f flag before calling compress
    const f_flag = input[212];
    if (f_flag > 1)
        return .{ .err = main.PrecompileError.Blake2WrongFinalIndicatorFlag };

    // Some zkvm implementations require h, m, and t to be 8-byte aligned.
    // m/t sit at input offsets 68/196 (both 4 mod 8), so we copy all three
    // into aligned stack buffers. This is cheap and harmless for implementations
    // that don't require alignment. h is also updated in place by accel.blake2f.
    var h_bytes: [64]u8 align(8) = undefined;
    @memcpy(&h_bytes, input[4..68]);
    var m_bytes: [128]u8 align(8) = undefined;
    @memcpy(&m_bytes, input[68..196]);
    var t_bytes: [16]u8 align(8) = undefined;
    @memcpy(&t_bytes, input[196..212]);

    if (!accel.blake2f(rounds, &h_bytes, &m_bytes, &t_bytes, f_flag))
        return .{ .err = main.PrecompileError.Blake2WrongFinalIndicatorFlag };

    const heap_out = alloc_mod.get().dupe(u8, &h_bytes) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = main.PrecompileError.OutOfGas };
    };
    return .{ .success = main.PrecompileOutput.new(gas_used, heap_out) };
}
