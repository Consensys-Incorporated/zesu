//! Sidecar tests for rlp.zig.

const std = @import("std");

const decodeItem = @import("./rlp.zig").decodeItem;
const decodeItemCanonical = @import("./rlp.zig").decodeItemCanonical;
const beUint = @import("./rlp.zig").beUint;

test "decodeItemCanonical rejects non-canonical encodings" {
    // A single byte below 0x80 wrapped as a one-byte string.
    try std.testing.expectError(error.InvalidRlp, decodeItemCanonical(&.{ 0x81, 0x01 }));
    // The long string form for a string of 55 bytes or fewer.
    try std.testing.expectError(error.InvalidRlp, decodeItemCanonical(&.{ 0xb8, 0x01, 0x80 }));
    // A long string length with a leading zero byte.
    try std.testing.expectError(error.InvalidRlp, decodeItemCanonical(&([_]u8{ 0xb9, 0x00, 0x38 } ++ [_]u8{0} ** 56)));
    // The long list form for a payload of 55 bytes or fewer.
    try std.testing.expectError(error.InvalidRlp, decodeItemCanonical(&.{ 0xf8, 0x01, 0x80 }));
    // Canonical forms decode as with decodeItem.
    try std.testing.expectEqual(@as(usize, 1), (try decodeItemCanonical(&.{0x01})).consumed);
    try std.testing.expectEqual(@as(usize, 2), (try decodeItemCanonical(&.{ 0x81, 0x80 })).consumed);
    try std.testing.expectEqual(@as(usize, 2), (try decodeItemCanonical(&.{ 0xc1, 0x01 })).consumed);
    try std.testing.expectEqual(@as(usize, 58), (try decodeItemCanonical(&([_]u8{ 0xb8, 0x38 } ++ [_]u8{0} ** 56))).consumed);
}

test "isWellFormed checks nested lists, not just the outer header" {
    const isWellFormed = @import("./rlp.zig").isWellFormed;
    try std.testing.expect(isWellFormed(&.{ 0xc2, 0x80, 0x80 }));
    try std.testing.expect(isWellFormed(&.{ 0xc3, 0xc1, 0x80, 0x01 }));
    // A list whose only item claims one byte that is not there.
    try std.testing.expect(!isWellFormed(&.{ 0xc1, 0x81 }));
    // A nested list whose item runs past the nested list's end.
    try std.testing.expect(!isWellFormed(&.{ 0xc3, 0xc2, 0x82, 0x01 }));
    // Trailing bytes after the item.
    try std.testing.expect(!isWellFormed(&.{ 0x80, 0x80 }));
    // A nested single byte below 0x80 wrapped as a one-byte string.
    try std.testing.expect(!isWellFormed(&.{ 0xc2, 0x81, 0x01 }));
    // The long form for a short list.
    try std.testing.expect(!isWellFormed(&.{ 0xf8, 0x01, 0x80 }));
    // 32 bytes or more is never an embedded node.
    try std.testing.expect(!isWellFormed(&([_]u8{0xdf} ++ [_]u8{0x80} ** 31)));
}

test "decodeItem: a claimed length past the input is rejected, not overflowed" {
    try std.testing.expectError(error.InvalidRlp, decodeItem(&([_]u8{0xff} ** 40)));
    try std.testing.expectError(error.InvalidRlp, decodeItem(&([_]u8{0xbf} ** 40)));
}

test "beUint matches a byte-by-byte big-endian read" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rand = prng.random();
    var buf: [32]u8 = undefined;
    for (0..200) |_| {
        rand.bytes(&buf);
        const len = rand.uintAtMost(usize, 32);
        var want: u256 = 0;
        for (buf[0..len]) |b| want = (want << 8) | b;
        try std.testing.expectEqual(want, beUint(u256, buf[0..len]));
        const len128 = @min(len, 16);
        try std.testing.expectEqual(@as(u128, @intCast(want >> @intCast(8 * (len - len128)))), beUint(u128, buf[0..len128]));
    }
    try std.testing.expectEqual(@as(u256, 0), beUint(u256, &.{}));
    try std.testing.expectEqual(@as(u256, std.math.maxInt(u256)), beUint(u256, &([_]u8{0xff} ** 32)));
}
