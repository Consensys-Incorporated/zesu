const std = @import("std");
const Memory = @import("memory.zig").Memory;
const Gas = @import("gas.zig").Gas;

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

fn allZero(bytes: []const u8) bool {
    return std.mem.allEqual(u8, bytes, 0);
}

// Yellow Paper (326): C_mem(a) = 3 * a + a^2 / 512, charged as the difference.
test "expandWithGas: word-aligned length and quadratic cost" {
    var mem = Memory.new();
    defer mem.deinit();
    var gas = Gas.new(1_000_000);

    try expect(mem.expandWithGas(&gas, 0));
    try expectEqual(@as(usize, 0), mem.size());
    try expectEqual(@as(u64, 1_000_000), gas.remaining);

    try expect(mem.expandWithGas(&gas, 1));
    try expectEqual(@as(usize, 32), mem.size());
    try expectEqual(@as(u64, 1_000_000 - 3), gas.remaining);

    // 1024 words: 3 * 1024 + 1024^2 / 512 = 5120.
    try expect(mem.expandWithGas(&gas, 1024 * 32));
    try expectEqual(@as(usize, 1024 * 32), mem.size());
    try expectEqual(@as(u64, 1_000_000 - 5120), gas.remaining);

    // Already covered: no charge, no change.
    try expect(mem.expandWithGas(&gas, 100));
    try expectEqual(@as(usize, 1024 * 32), mem.size());
    try expectEqual(@as(u64, 1_000_000 - 5120), gas.remaining);
}

test "expandWithGas: out of gas leaves the length unchanged" {
    var mem = Memory.new();
    defer mem.deinit();
    var gas = Gas.new(5);

    try expect(mem.expandWithGas(&gas, 32));
    try expect(!mem.expandWithGas(&gas, 64));
    try expectEqual(@as(usize, 32), mem.size());
    try expect(!mem.expandWithGas(&gas, std.math.maxInt(usize)));
    try expectEqual(@as(usize, 32), mem.size());
}

test "expandWithGas: new bytes are zero and old bytes survive, one word at a time" {
    var mem = Memory.new();
    defer mem.deinit();
    var gas = Gas.new(10_000_000);

    var len: usize = 0;
    while (len < 4096) : (len += 32) {
        try expect(mem.expandWithGas(&gas, len + 32));
        try expectEqual(len + 32, mem.size());
        try expect(std.mem.allEqual(u8, mem.buffer.items[0..len], 0xFF));
        try expect(allZero(mem.buffer.items[len..]));
        @memset(mem.buffer.items[len..], 0xFF);
    }
}

test "the unused capacity is zero after every kind of growth" {
    var mem = Memory.new();
    defer mem.deinit();
    var gas = Gas.new(10_000_000);

    try expect(mem.expandWithGas(&gas, 96));
    @memset(mem.buffer.items, 0xFF);
    try expect(allZero(mem.buffer.unusedCapacitySlice()));

    try mem.set(mem.buffer.capacity + 40, &[_]u8{ 1, 2, 3 });
    try expect(allZero(mem.buffer.items[96 .. mem.size() - 3]));
    try expect(allZero(mem.buffer.unusedCapacitySlice()));

    try mem.resize(mem.buffer.capacity + 1);
    try expect(allZero(mem.buffer.unusedCapacitySlice()));
}

test "clear: a reused buffer reads as zero" {
    var mem = Memory.new();
    defer mem.deinit();
    var gas = Gas.new(10_000_000);

    try expect(mem.expandWithGas(&gas, 256));
    @memset(mem.buffer.items, 0xFF);
    mem.clear();
    try expectEqual(@as(usize, 0), mem.size());

    try expect(mem.expandWithGas(&gas, 256));
    try expect(allZero(mem.buffer.items));
}
