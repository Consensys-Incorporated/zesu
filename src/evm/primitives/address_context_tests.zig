const std = @import("std");
const primitives = @import("main.zig");

const Address = primitives.Address;
const AddressContext = primitives.AddressContext;

/// The discarded fix: fold all 20 bytes via XOR of rotations, then avalanche.
/// Kept only so these tests can construct known collisions against it and confirm
/// the current `AddressContext.hash` does not reproduce them.
fn legacyLinearFold(key: Address) u64 {
    const lo = std.mem.readInt(u64, key[0..8], .little);
    const mid = std.mem.readInt(u64, key[8..16], .little);
    const hi: u64 = std.mem.readInt(u32, key[16..20], .little);
    return primitives.mix64(lo ^ std.math.rotl(u64, mid, 27) ^ std.math.rotl(u64, hi, 13));
}

test "legacy linear fold collides on a constructed pair; current hash does not" {
    // The fold is linear over GF(2): any (d_lo, d_mid, d_hi) with
    // d_lo ^ rotl(d_mid,27) ^ rotl(d_hi,13) == 0 is a free collision offset, solvable
    // without brute force. Picking d_mid = 1, d_hi = 0 forces d_lo = rotl(1,27).
    const a: Address = [_]u8{0} ** 20;
    var b: Address = [_]u8{0} ** 20;
    std.mem.writeInt(u64, b[0..8], @as(u64, 1) << 27, .little); // d_lo
    std.mem.writeInt(u64, b[8..16], 1, .little); // d_mid

    try std.testing.expectEqual(legacyLinearFold(a), legacyLinearFold(b));

    const ctx = AddressContext{};
    try std.testing.expect(ctx.hash(a) != ctx.hash(b));
}

test "legacy linear fold collapses a whole cluster into one bucket; current hash spreads it" {
    // Same construction, swept over many d_mid values at once: every member of this
    // cluster folds to the same value under the legacy scheme -- the shape of the
    // real ~19.5k-address chain that originally motivated fixing this hash.
    const n = 4096;
    const target = legacyLinearFold([_]u8{0} ** 20);
    var legacy_collisions: usize = 0;

    var seen = std.AutoHashMapUnmanaged(u64, void){};
    defer seen.deinit(std.testing.allocator);
    const mask: u64 = n - 1;
    const ctx = AddressContext{};

    for (0..n) |i| {
        var addr: Address = [_]u8{0} ** 20;
        std.mem.writeInt(u64, addr[8..16], @intCast(i), .little); // mid = i
        std.mem.writeInt(u64, addr[0..8], std.math.rotl(u64, @as(u64, i), 27), .little); // lo = rotl(mid,27)

        if (legacyLinearFold(addr) == target) legacy_collisions += 1;
        seen.put(std.testing.allocator, ctx.hash(addr) & mask, {}) catch unreachable;
    }

    try std.testing.expectEqual(n, legacy_collisions); // every member collided under the legacy fold
    try std.testing.expect(seen.count() > n / 2); // coupon-collector bound: a real hash spreads them
}

test "AddressContext.hash depends on the block random seed" {
    defer primitives.setBlockRandomSeed([_]u8{0} ** 32);

    const addr: Address = [_]u8{0x11} ** 20;
    const ctx = AddressContext{};

    primitives.setBlockRandomSeed([_]u8{0xAA} ** 32);
    const h1 = ctx.hash(addr);
    primitives.setBlockRandomSeed([_]u8{0xBB} ** 32);
    const h2 = ctx.hash(addr);

    try std.testing.expect(h1 != h2);
}

test "a bucket assignment computed for one seed does not carry over to another" {
    // Reuses the legacy-colliding cluster above -- exactly the address set an
    // attacker would already have on hand from attacking the old scheme -- and
    // checks that a *different* block's seed redistributes it differently. This is
    // the property that turns "solve once, reuse against every future block" into
    // "the bucket map you'd have to precompute is only valid for one block's seed."
    defer primitives.setBlockRandomSeed([_]u8{0} ** 32);
    const n = 4096;
    const mask: u64 = n - 1;
    const ctx = AddressContext{};

    var addrs: [n]Address = undefined;
    for (0..n) |i| {
        var addr: Address = [_]u8{0} ** 20;
        std.mem.writeInt(u64, addr[8..16], @intCast(i), .little);
        std.mem.writeInt(u64, addr[0..8], std.math.rotl(u64, @as(u64, i), 27), .little);
        addrs[i] = addr;
    }

    primitives.setBlockRandomSeed([_]u8{0xAA} ** 32);
    var buckets_a: [n]u64 = undefined;
    for (addrs, 0..) |addr, i| buckets_a[i] = ctx.hash(addr) & mask;

    primitives.setBlockRandomSeed([_]u8{0xBB} ** 32);
    var same_bucket: usize = 0;
    for (addrs, 0..) |addr, i| {
        if ((ctx.hash(addr) & mask) == buckets_a[i]) same_bucket += 1;
    }

    // Random agreement between two independent seeds would land near n/n_buckets
    // (~1 expected match here); anywhere near `n` would mean the seed isn't
    // actually changing the bucket assignment.
    try std.testing.expect(same_bucket < n / 8);
}
