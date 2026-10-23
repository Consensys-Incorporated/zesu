//! Canonical-form checks in decodeItemCanonical.

const std = @import("std");

const decodeItemCanonical = @import("./rlp.zig").decodeItemCanonical;

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
