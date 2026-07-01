const std = @import("std");
const primitives = @import("primitives");
const main = @import("main.zig");
const alloc_mod = @import("zesu_allocator");
const accel = @import("accelerators");

/// Modular exponentiation precompiles for different specs
pub const BYZANTIUM = main.Precompile.new(
    main.PrecompileId.ModExp,
    main.u64ToAddress(5),
    byzantiumRun,
);

pub const BERLIN = main.Precompile.new(
    main.PrecompileId.ModExp,
    main.u64ToAddress(5),
    berlinRun,
);

pub const OSAKA = main.Precompile.new(
    main.PrecompileId.ModExp,
    main.u64ToAddress(5),
    osakaRun,
);

/// Right pad input to specified length
fn rightPad(comptime len: usize, input: []const u8) [len]u8 {
    var output: [len]u8 = [_]u8{0} ** len;
    const copy_len = @min(input.len, len);
    std.mem.copyForwards(u8, output[0..copy_len], input[0..copy_len]);
    return output;
}

/// Left pad input to specified length
fn leftPadVec(allocator: std.mem.Allocator, input: []const u8, len: usize) ![]u8 {
    if (input.len >= len) {
        return try allocator.dupe(u8, input);
    }
    var output = try allocator.alloc(u8, len);
    @memset(output[0..(len - input.len)], 0);
    @memcpy(output[(len - input.len)..], input);
    return output;
}

/// Right pad input vector
fn rightPadVec(input: []const u8, len: usize) []const u8 {
    if (input.len >= len) {
        return input[0..len];
    }
    // For simplicity, we'll handle padding in the caller
    return input;
}

/// Extract U256 from bytes (big-endian)
fn extractU256(bytes: []const u8) primitives.U256 {
    const padded = rightPad(32, bytes);
    // Convert to U256 - simplified for now
    var result: primitives.U256 = 0;
    for (padded) |b| {
        result = result * 256 + b;
    }
    return result;
}

/// Calculate iteration count for modexp
fn calculateIterationCount(exp_length: u64, exp_highp: primitives.U256, multiplier: u64) u64 {
    if (exp_length <= 32 and exp_highp == 0) {
        return 0;
    } else if (exp_length <= 32) {
        // Count bits in exp_highp
        var bits: u64 = 0;
        var val = exp_highp;
        while (val > 0) {
            bits += 1;
            val >>= 1;
        }
        return if (bits > 0) bits - 1 else 0;
    } else {
        var bits: u64 = 0;
        var val = exp_highp;
        while (val > 0) {
            bits += 1;
            val >>= 1;
        }
        const base_iter = std.math.mul(u64, multiplier, exp_length - 32) catch return std.math.maxInt(u64);
        const highp_iter: u64 = if (bits > 0) bits - 1 else 0;
        return @max(std.math.add(u64, base_iter, highp_iter) catch std.math.maxInt(u64), 1);
    }
}

/// Calculate gas cost for Byzantium
fn byzantiumGasCalc(base_len: u64, exp_len: u64, mod_len: u64, exp_highp: primitives.U256) u64 {
    // EIP-198: complexity uses max(base_len, mod_len), not exp_len.
    const max_len = @max(base_len, mod_len);
    const iteration_count = calculateIterationCount(exp_len, exp_highp, 8);
    // EIP-198: multiply by max(adjusted_exp_length, 1), not raw iteration_count.
    const effective_iter: u64 = @max(iteration_count, 1);

    // Use u128 for squaring to avoid overflow (max_len is u64, (u64_max)^2 fits in u128).
    const x: u128 = @as(u128, max_len);
    var complexity: u128 = 0;
    if (max_len <= 64) {
        complexity = x * x;
    } else if (max_len <= 1024) {
        complexity = (x * x) / 4 + 96 * x - 3072;
    } else {
        complexity = (x * x) / 16 + 480 * x - 199680;
    }

    // complexity * effective_iter may overflow u128 for huge inputs — saturate to maxInt(u64).
    const product = std.math.mul(u128, complexity, @as(u128, effective_iter)) catch return std.math.maxInt(u64);
    const result = product / 20;
    return if (result > std.math.maxInt(u64)) std.math.maxInt(u64) else @as(u64, @intCast(result));
}

/// Calculate gas cost for Berlin (EIP-2565)
fn berlinGasCalc(base_len: u64, exp_len: u64, mod_len: u64, exp_highp: primitives.U256) u64 {
    // EIP-2565: complexity uses max(base_len, mod_len), NOT exp_len
    const max_len = @max(base_len, mod_len);
    const iteration_count = calculateIterationCount(exp_len, exp_highp, 8);
    // EIP-2565: effective_iter = max(iter, 1) and result = max(200, complexity * effective_iter / 3)
    const effective_iter: u64 = @max(iteration_count, 1);
    const words = (std.math.add(u64, max_len, 7) catch return std.math.maxInt(u64)) / 8;
    const complexity = std.math.mul(u64, words, words) catch return std.math.maxInt(u64);
    const gas = std.math.mul(u64, complexity, effective_iter) catch return std.math.maxInt(u64);
    return @max(200, gas / 3);
}

/// Calculate gas cost for Osaka (EIP-7823 and EIP-7883)
/// Formula: max(500, complexity * iteration_count)
/// where complexity is based on max(base_len, mod_len), not exp_len
fn osakaGasCalc(base_len: u64, exp_len: u64, mod_len: u64, exp_highp: primitives.U256) u64 {
    // Use max(base_len, mod_len) for complexity, not exp_len
    const max_len = @max(base_len, mod_len);
    const iteration_count = calculateIterationCount(exp_len, exp_highp, 16);

    var complexity: u64 = 0;
    if (max_len <= 32) {
        complexity = 16;
    } else {
        const words = (max_len + 7) / 8;
        complexity = 2 * words * words;
    }

    // EIP-7883: use max(1, iteration_count) so a zero exponent costs complexity, not 0
    const effective_iter = if (iteration_count == 0) @as(u64, 1) else iteration_count;
    const gas = complexity * effective_iter;
    return @max(@as(u64, 500), gas);
}

/// Run modexp with specific gas calculation
fn runInner(
    input: []const u8,
    gas_limit: u64,
    min_gas: u64,
    calc_gas: *const fn (u64, u64, u64, primitives.U256) u64,
    is_osaka: bool,
) main.PrecompileResult {
    if (min_gas > gas_limit) {
        return main.PrecompileResult{ .err = main.PrecompileError.OutOfGas };
    }

    const HEADER_LENGTH: usize = 96;

    // EVM spec: if input is shorter than the 96-byte header, missing bytes are treated as zeros.
    // Never error here — the precompile always succeeds (or OOGs), it never returns an error
    // for short input.
    var header: [HEADER_LENGTH]u8 = [_]u8{0} ** HEADER_LENGTH;
    const header_copy = @min(input.len, HEADER_LENGTH);
    @memcpy(header[0..header_copy], input[0..header_copy]);

    // Extract lengths from header (32 bytes each, big-endian)
    const base_len_bytes = rightPad(32, header[0..32]);
    const exp_len_bytes = rightPad(32, header[32..64]);
    const mod_len_bytes = rightPad(32, header[64..96]);

    const base_len_u256 = extractU256(&base_len_bytes);
    const exp_len_u256 = extractU256(&exp_len_bytes);
    const mod_len_u256 = extractU256(&mod_len_bytes);

    // Check EIP-7823 limits for Osaka (1024 bytes per parameter)
    const EIP7823_LIMIT: u64 = 1024;
    if (is_osaka) {
        if (base_len_u256 > EIP7823_LIMIT or exp_len_u256 > EIP7823_LIMIT or mod_len_u256 > EIP7823_LIMIT) {
            return main.PrecompileResult{ .err = main.PrecompileError.ModexpEip7823LimitSize };
        }
    }

    const base_len = @as(usize, @intCast(@min(base_len_u256, std.math.maxInt(usize))));
    const exp_len = @as(usize, @intCast(@min(exp_len_u256, std.math.maxInt(usize))));
    const mod_len = @as(usize, @intCast(@min(mod_len_u256, std.math.maxInt(usize))));

    // Extract exponent high part (first 32 bytes or exp_len, whichever is smaller)
    const exp_highp_len = @min(exp_len, 32);
    const data_start = HEADER_LENGTH;
    const exp_start = std.math.add(usize, data_start, base_len) catch
        return main.PrecompileResult{ .err = main.PrecompileError.OutOfGas };

    var exp_highp_bytes: [32]u8 = [_]u8{0} ** 32;
    if (input.len > exp_start) {
        const available = @min(exp_highp_len, input.len - exp_start);
        // Place available bytes at the MSB side of the 32-byte big-endian representation.
        // Remaining (exp_highp_len - available) bytes are implicitly zero (right-padding for truncated input).
        const padding = 32 - exp_highp_len;
        @memcpy(exp_highp_bytes[padding..][0..available], input[exp_start..][0..available]);
    }
    const exp_highp = extractU256(&exp_highp_bytes);

    // Calculate gas cost
    const gas_cost = calc_gas(base_len, exp_len, mod_len, exp_highp);
    if (gas_cost > gas_limit) {
        return main.PrecompileResult{ .err = main.PrecompileError.OutOfGas };
    }

    // mod_len == 0 → output is always empty, regardless of base_len.
    // Must check before computing total_data_len to avoid allocating a
    // multi-TB buffer when base_len is large (e.g. truncated 96-byte header).
    if (mod_len == 0) {
        return main.PrecompileResult{ .success = main.PrecompileOutput.new(gas_cost, &[_]u8{}) };
    }

    // Extract base, exponent, and modulus.
    // EVM spec: reading calldata beyond its length gives zeros — zero-pad if input is short.
    // Guard against input shorter than the 96-byte header (already zero-extended in header above).
    const data_after_header = if (input.len > HEADER_LENGTH) input[HEADER_LENGTH..] else &[_]u8{};
    const total_data_len = std.math.add(usize, base_len, std.math.add(usize, exp_len, mod_len) catch
        return main.PrecompileResult{ .err = main.PrecompileError.OutOfGas }) catch
        return main.PrecompileResult{ .err = main.PrecompileError.OutOfGas };
    var data_buf: ?[]u8 = null;
    const data: []const u8 = blk: {
        if (data_after_header.len >= total_data_len) {
            break :blk data_after_header[0..total_data_len];
        } else {
            const buf = alloc_mod.get().alloc(u8, total_data_len) catch
                return main.PrecompileResult{ .err = main.PrecompileError.OutOfGas };
            @memset(buf, 0);
            @memcpy(buf[0..data_after_header.len], data_after_header);
            data_buf = buf;
            break :blk buf;
        }
    };
    defer if (data_buf) |buf| alloc_mod.get().free(buf);

    const base = if (base_len > 0) data[0..base_len] else &[_]u8{};
    const exp = if (exp_len > 0) data[base_len..][0..exp_len] else &[_]u8{};
    const modulus = if (mod_len > 0) data[base_len + exp_len ..][0..mod_len] else &[_]u8{};

    // Allocate output buffer (left-padded with zeros to mod_len bytes) via c_allocator.
    // This buffer is owned by the caller and must NOT be freed here.
    const heap_out = alloc_mod.get().alloc(u8, mod_len) catch
        return main.PrecompileResult{ .err = main.PrecompileError.OutOfGas };
    @memset(heap_out, 0);
    _ = accel.modexp(base, exp, modulus, heap_out);

    return main.PrecompileResult{ .success = main.PrecompileOutput.new(gas_cost, heap_out) };
}

/// Byzantium modexp run
pub fn byzantiumRun(input: []const u8, gas_limit: u64) main.PrecompileResult {
    return runInner(input, gas_limit, 0, byzantiumGasCalc, false);
}

/// Berlin modexp run
pub fn berlinRun(input: []const u8, gas_limit: u64) main.PrecompileResult {
    return runInner(input, gas_limit, 200, berlinGasCalc, false);
}

/// Osaka modexp run
pub fn osakaRun(input: []const u8, gas_limit: u64) main.PrecompileResult {
    return runInner(input, gas_limit, 500, osakaGasCalc, true);
}
