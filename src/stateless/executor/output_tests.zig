//! Equivalence tests for output.zig's hand-rolled RLP encoding and change sort, checked
//! against the generic rlp helpers and std.mem.sort.

const std = @import("std");
const mpt = @import("mpt");

const rlp = @import("./rlp_encode.zig");
const output = @import("./output.zig");

test "account encoding and change sort match the generic paths" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var prng = std.Random.DefaultPrng.init(0x6f75_7470);
    const r = prng.random();

    for (0..2000) |i| {
        // Every width from 0 to 256 bits, plus the 0x7f/0x80 single-byte boundary.
        const bits = i % 257;
        var v: u256 = if (bits == 0) 0 else r.int(u256) >> @intCast(256 - bits);
        if (i % 50 == 1) v = 0x7f + @as(u256, (i / 50) % 2);
        const nonce: u64 = @truncate(v);
        var root: [32]u8 = undefined;
        var code_hash: [32]u8 = undefined;
        r.bytes(&root);
        r.bytes(&code_hash);
        const want = try rlp.encodeList(alloc, &.{
            try rlp.encodeU64(alloc, nonce),
            try rlp.encodeU256(alloc, v),
            try rlp.encodeBytes(alloc, &root),
            try rlp.encodeBytes(alloc, &code_hash),
        });
        try std.testing.expectEqualSlices(u8, want, try output.encodeAccountRlp(alloc, nonce, v, root, code_hash));
        try std.testing.expectEqual((try rlp.encodeU256(alloc, v)).len, output.uintRlpLen(v));
    }

    for ([_]usize{ 0, 1, 31, 32, 33, 300, 5000 }) |n| {
        const changes = try alloc.alloc(mpt.BatchChange, n);
        for (changes, 0..) |*c, j| {
            r.bytes(&c.key);
            // Shared leading bytes exercise the tie-breaks past the first word.
            if (j % 3 == 0) @memset(c.key[0..9], 0x42);
            c.value = null;
        }
        const want = try alloc.dupe(mpt.BatchChange, changes);
        std.mem.sort(mpt.BatchChange, want, {}, struct {
            fn lt(_: void, a: mpt.BatchChange, b: mpt.BatchChange) bool {
                return std.mem.lessThan(u8, &a.key, &b.key);
            }
        }.lt);
        const got = try output.sortChanges(alloc, changes);
        for (want, got) |w, g| try std.testing.expectEqualSlices(u8, &w.key, &g.key);
    }
}

test "sortChanges is stable and stays correct when every key shares a first byte" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var prng = std.Random.DefaultPrng.init(0x6772_696e);
    const r = prng.random();

    // One bucket well over the insertion limit, with duplicate keys carrying distinct values.
    const n = 3000;
    const values = try alloc.alloc([1]u8, n);
    const changes = try alloc.alloc(mpt.BatchChange, n);
    for (changes, values, 0..) |*c, *v, j| {
        r.bytes(&c.key);
        c.key[0] = 0x11;
        if (j % 4 == 0) c.key[1..].* = @as([31]u8, @splat(0x99)); // duplicates
        v[0] = @truncate(j);
        c.value = v;
    }
    const want = try alloc.dupe(mpt.BatchChange, changes);
    std.mem.sort(mpt.BatchChange, want, {}, struct {
        fn lt(_: void, a: mpt.BatchChange, b: mpt.BatchChange) bool {
            return std.mem.lessThan(u8, &a.key, &b.key);
        }
    }.lt);
    const got = try output.sortChanges(alloc, changes);
    for (want, got) |w, g| {
        try std.testing.expectEqualSlices(u8, &w.key, &g.key);
        try std.testing.expectEqual(w.value.?.ptr, g.value.?.ptr); // same order among equal keys
    }
}
