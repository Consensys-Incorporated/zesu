/// Modular exponentiation — standalone pure-Zig implementation.
/// Extracted from zevm precompile/modexp.zig.
///
/// Computes base^exp % modulus for arbitrary-precision integers.
/// Implements the raw crypto primitive; gas/ABI handling lives in the
/// precompile dispatch layer (src/evm/precompile/).
const std = @import("std");
const alloc_mod = @import("zesu_allocator");

/// Compute base^exp % modulus and write the result into `output`.
/// `output` must be pre-zeroed and exactly `modulus.len` bytes.
/// Returns false only if a catastrophic allocation failure occurs.
pub fn modexp(
    base: []const u8,
    exp: []const u8,
    modulus: []const u8,
    output: []u8,
) bool {
    std.debug.assert(output.len == modulus.len);
    @memset(output, 0);

    const base_trimmed = trimLeadingZeros(base);
    const exp_trimmed = trimLeadingZeros(exp);
    const mod_trimmed = trimLeadingZeros(modulus);

    if (mod_trimmed.len == 0) return true; // output already zero

    // Fast path for small values (fit in u64)
    if (base_trimmed.len <= 8 and exp_trimmed.len <= 8 and mod_trimmed.len <= 8) {
        var base_val: u64 = 0;
        for (base_trimmed) |b| base_val = base_val * 256 + b;
        var exp_val: u64 = 0;
        for (exp_trimmed) |b| exp_val = exp_val * 256 + b;
        var mod_val: u64 = 0;
        for (mod_trimmed) |b| mod_val = mod_val * 256 + b;

        if (mod_val == 0) return true;

        var result: u64 = 1 % mod_val;
        var base_pow = base_val % mod_val;
        var exp_remaining = exp_val;
        const m128: u128 = mod_val;
        while (exp_remaining > 0) {
            if (exp_remaining & 1 == 1)
                result = @truncate(@as(u128, result) * @as(u128, base_pow) % m128);
            base_pow = @truncate(@as(u128, base_pow) * @as(u128, base_pow) % m128);
            exp_remaining >>= 1;
        }

        var result_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &result_bytes, result, .big);
        const trimmed = trimLeadingZeros(&result_bytes);
        if (trimmed.len > 0 and trimmed.len <= output.len) {
            @memcpy(output[output.len - trimmed.len ..], trimmed);
        } else if (trimmed.len > output.len and output.len > 0) {
            @memcpy(output, trimmed[trimmed.len - output.len ..]);
        }
        return true;
    }

    // Big-integer path
    modexpBigInt(alloc_mod.get(), base, exp, modulus, output) catch return false;
    return true;
}

fn modexpBigInt(
    allocator: std.mem.Allocator,
    base_bytes: []const u8,
    exp_bytes: []const u8,
    mod_bytes: []const u8,
    output: []u8,
) !void {
    const BigInt = std.math.big.int.Managed;

    var base = try BigInt.init(allocator);
    defer base.deinit();
    var exp_val = try BigInt.init(allocator);
    defer exp_val.deinit();
    var modulus = try BigInt.init(allocator);
    defer modulus.deinit();
    var result = try BigInt.init(allocator);
    defer result.deinit();
    var base_pow = try BigInt.init(allocator);
    defer base_pow.deinit();
    var tmp = try BigInt.init(allocator);
    defer tmp.deinit();
    var quot = try BigInt.init(allocator);
    defer quot.deinit();

    try setManagedFromBeBytes(&base, base_bytes);
    try setManagedFromBeBytes(&exp_val, exp_bytes);
    try setManagedFromBeBytes(&modulus, mod_bytes);

    if (modulus.eqlZero()) return;

    try BigInt.divFloor(&quot, &base_pow, &base, &modulus);
    try tmp.set(1);
    try BigInt.divFloor(&quot, &result, &tmp, &modulus);

    while (!exp_val.eqlZero()) {
        if (exp_val.isOdd()) {
            try tmp.mul(&result, &base_pow);
            try BigInt.divFloor(&quot, &result, &tmp, &modulus);
        }
        try tmp.sqr(&base_pow);
        try BigInt.divFloor(&quot, &base_pow, &tmp, &modulus);
        try exp_val.shiftRight(&exp_val, 1);
    }

    writeManagedToBeBytes(result.toConst(), output);
}

fn setManagedFromBeBytes(m: *std.math.big.int.Managed, bytes: []const u8) !void {
    var start: usize = 0;
    while (start < bytes.len and bytes[start] == 0) start += 1;
    const trimmed = bytes[start..];

    if (trimmed.len == 0) {
        try m.set(0);
        return;
    }

    const limb_bytes = @sizeOf(std.math.big.Limb);
    const n_limbs = (trimmed.len + limb_bytes - 1) / limb_bytes;
    try m.ensureCapacity(n_limbs);

    @memset(m.limbs[0..n_limbs], 0);
    var i: usize = trimmed.len;
    var limb_idx: usize = 0;
    while (i > 0 and limb_idx < n_limbs) {
        const chunk_size = @min(i, limb_bytes);
        const chunk_start = i - chunk_size;
        var limb_val: std.math.big.Limb = 0;
        for (trimmed[chunk_start..i]) |byte| limb_val = (limb_val << 8) | byte;
        m.limbs[limb_idx] = limb_val;
        limb_idx += 1;
        i -= chunk_size;
    }
    m.setMetadata(true, n_limbs);
    m.normalize(n_limbs);
}

fn writeManagedToBeBytes(val: std.math.big.int.Const, output: []u8) void {
    @memset(output, 0);
    const limbs = val.limbs;
    const limb_bytes = @sizeOf(std.math.big.Limb);
    for (0..output.len) |i| {
        const limb_idx = i / limb_bytes;
        const byte_in_limb: u6 = @intCast((i % limb_bytes) * 8);
        if (limb_idx < limbs.len)
            output[output.len - 1 - i] = @truncate(limbs[limb_idx] >> byte_in_limb);
    }
}

fn trimLeadingZeros(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) i += 1;
    return bytes[i..];
}
