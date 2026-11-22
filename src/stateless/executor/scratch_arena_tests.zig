const std = @import("std");
const ScratchArena = @import("./scratch_arena.zig");

test "a zero-length request on an empty arena still returns an address" {
    var arena = ScratchArena.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expect(arena.allocator().rawAlloc(0, .@"8", @returnAddress()) != null);
}

test "the last allocation grows in place up to the end of its chunk" {
    var arena = ScratchArena.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const first = try a.alloc(u8, 64);
    const last = try a.alloc(u8, 64);
    // Only the last allocation can grow; an earlier one can only shrink.
    try std.testing.expect(!a.resize(first, 65));
    try std.testing.expect(a.resize(first, 32));
    // The first chunk is 4096 bytes, header included.
    try std.testing.expect(!a.resize(last, 4096));
    try std.testing.expect(a.resize(last, 128));
    const next = try a.alloc(u8, 1);
    try std.testing.expectEqual(@intFromPtr(last.ptr) + 128, @intFromPtr(next.ptr));
}

test "a request that does not fit moves to a new chunk and keeps earlier data" {
    var arena = ScratchArena.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const small = try a.alloc(u8, 100);
    @memset(small, 0x11);
    const big = try a.alignedAlloc(u8, .@"32", 100_000);
    try std.testing.expect(std.mem.Alignment.@"32".check(@intFromPtr(big.ptr)));
    @memset(big, 0x22);
    const after = try a.alloc(u64, 16);
    @memset(after, 0x3333_3333_3333_3333);

    for (small) |b| try std.testing.expectEqual(@as(u8, 0x11), b);
    for (big) |b| try std.testing.expectEqual(@as(u8, 0x22), b);
    // `after` does not overlap `big`.
    const after_addr = @intFromPtr(after.ptr);
    try std.testing.expect(after_addr >= @intFromPtr(big.ptr) + big.len or after_addr + 128 <= @intFromPtr(big.ptr));
}

test "an arena is usable again after deinit" {
    var arena = ScratchArena.init(std.testing.allocator);
    const a = arena.allocator();
    _ = try a.alloc(u8, 5000);
    arena.deinit();
    // No window into the freed chunk is left behind.
    try std.testing.expectEqual(@as(usize, 0), arena.cur);
    try std.testing.expectEqual(@as(usize, 0), arena.end);

    const again = try a.alloc(u8, 16);
    @memset(again, 0x44);
    arena.deinit();
}
