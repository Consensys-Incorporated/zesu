//! Equivalence tests for output.zig's hand-rolled RLP encoding and change sort, checked
//! against the generic rlp helpers and std.mem.sort.

const std = @import("std");
const mpt = @import("mpt");

const rlp = @import("./rlp_encode.zig");
const output = @import("./output.zig");
const types = @import("executor_types");

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

fn genericReceiptRlp(alloc: std.mem.Allocator, receipt: types.Receipt) ![]u8 {
    var log_items = std.ArrayListUnmanaged([]const u8).empty;
    for (receipt.logs) |log| {
        var topic_items = std.ArrayListUnmanaged([]const u8).empty;
        for (log.topics) |t| try topic_items.append(alloc, try rlp.encodeBytes(alloc, &t));
        try log_items.append(alloc, try rlp.encodeList(alloc, &.{
            try rlp.encodeBytes(alloc, &log.address),
            try rlp.encodeList(alloc, topic_items.items),
            try rlp.encodeBytes(alloc, log.data),
        }));
    }
    const first_field = if (receipt.state_root) |sr|
        try rlp.encodeBytes(alloc, &sr)
    else
        try rlp.encodeBytes(alloc, if (receipt.status == 1) &.{0x01} else &.{});
    const body = try rlp.encodeList(alloc, &.{
        first_field,
        try rlp.encodeU64(alloc, receipt.cumulative_gas_used),
        try rlp.encodeBytes(alloc, &receipt.logs_bloom),
        try rlp.encodeList(alloc, log_items.items),
    });
    return if (receipt.type == 0) body else rlp.concat(alloc, &.{ &.{receipt.type}, body });
}

test "receipt encoding matches the generic rlp helpers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var prng = std.Random.DefaultPrng.init(0x7263_7074);
    const r = prng.random();

    // Data lengths around the single-byte, short-string and 1/2/3-length-byte boundaries.
    const data_lens = [_]usize{ 0, 1, 2, 55, 56, 255, 256, 65535, 65536, 70000 };
    for (0..400) |i| {
        _ = arena.reset(.retain_capacity);
        var receipt = std.mem.zeroes(types.Receipt);
        receipt.type = @intCast(i % 5);
        receipt.status = @intCast(i % 2);
        if (i % 7 == 3) receipt.state_root = @splat(@truncate(i));
        receipt.cumulative_gas_used = switch (i % 4) {
            0 => 0,
            1 => r.int(u7),
            2 => 0x80,
            else => r.int(u64),
        };
        r.bytes(&receipt.logs_bloom);

        const logs = try alloc.alloc(types.Log, if (i % 11 == 0) 0 else r.uintLessThan(usize, 6));
        for (logs, 0..) |*log, j| {
            log.* = std.mem.zeroes(types.Log);
            r.bytes(&log.address);
            log.topics = try alloc.alloc(types.Hash, r.uintAtMost(usize, 4));
            for (log.topics) |*t| r.bytes(t);
            const data = try alloc.alloc(u8, data_lens[(i + j) % data_lens.len]);
            r.bytes(data);
            // A lone byte below 0x80 encodes as itself; exercise both sides.
            if (data.len == 1) data[0] = if (j % 2 == 0) 0x7f else 0x80;
            log.data = data;
        }
        receipt.logs = logs;

        try std.testing.expectEqualSlices(u8, try genericReceiptRlp(alloc, receipt), try output.encodeReceiptRlp(alloc, receipt));
    }
}
