//! Nibble (4-bit) path utilities and HP (hex-prefix / compact) codec for MPT.
//!
//! All functions are allocation-free; callers supply output buffers.
//!
//! HP encoding reference (Ethereum Yellow Paper, Appendix C):
//!   flag nibble = (bytes[0] >> 4)
//!     0 → extension, even path (skip first byte entirely)
//!     1 → extension, odd  path (low nibble of first byte is nibble[0])
//!     2 → leaf,      even path
//!     3 → leaf,      odd  path

const std = @import("std");

/// Convert bytes to nibbles. `out` must have length >= bytes.len * 2.
pub fn bytesToNibbles(bytes: []const u8, out: []u8) void {
    for (bytes, 0..) |byte, i| {
        out[i * 2] = byte >> 4;
        out[i * 2 + 1] = byte & 0x0f;
    }
}

/// Find the common prefix length between two nibble slices.
pub fn commonPrefixLen(a: []const u8, b: []const u8) usize {
    const len = @min(a.len, b.len);
    for (0..len) |i| {
        if (a[i] != b[i]) return i;
    }
    return len;
}

/// Encode nibbles to hex-prefix (compact) bytes. `out` must be >= (nibbles.len / 2) + 1.
/// Returns the written slice.
pub fn hpEncode(nibbles: []const u8, is_leaf: bool, out: []u8) []u8 {
    const flag: u8 = if (is_leaf) 2 else 0;
    const odd = (nibbles.len % 2) != 0;
    if (odd) {
        // flag | 1, then first nibble in low bits of first byte, then pairs
        out[0] = ((flag | 1) << 4) | nibbles[0];
        var i: usize = 1;
        var j: usize = 1;
        while (i + 1 < nibbles.len) : ({
            i += 2;
            j += 1;
        }) {
            out[j] = (nibbles[i] << 4) | nibbles[i + 1];
        }
        return out[0 .. 1 + nibbles.len / 2];
    } else {
        // flag byte (high nibble = flag, low nibble = 0), then pairs
        out[0] = flag << 4;
        var i: usize = 0;
        var j: usize = 1;
        while (i + 1 < nibbles.len) : ({
            i += 2;
            j += 1;
        }) {
            out[j] = (nibbles[i] << 4) | nibbles[i + 1];
        }
        return out[0 .. 1 + nibbles.len / 2];
    }
}

/// Decode a hex-prefix (compact) encoded path into nibbles written to `out`.
///
/// Returns `{ is_leaf, len }` where `len` is the number of nibbles written.
/// `out` must have length >= bytes.len * 2.
pub fn hpDecode(
    bytes: []const u8,
    out: []u8,
) error{InvalidHp}!struct { is_leaf: bool, len: usize } {
    if (bytes.len == 0) return error.InvalidHp;

    const flag = bytes[0] >> 4;
    if (flag > 3) return error.InvalidHp;

    const is_leaf = (flag & 0x02) != 0;
    const is_odd = (flag & 0x01) != 0;

    var out_len: usize = 0;

    if (is_odd) {
        // Low nibble of the first byte is the first path nibble.
        out[out_len] = bytes[0] & 0x0f;
        out_len += 1;
    }

    // Unpack remaining bytes as pairs of nibbles.
    for (bytes[1..]) |byte| {
        out[out_len] = byte >> 4;
        out[out_len + 1] = byte & 0x0f;
        out_len += 2;
    }

    return .{ .is_leaf = is_leaf, .len = out_len };
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

test "bytesToNibbles basic" {
    var out: [4]u8 = undefined;
    bytesToNibbles(&.{ 0xab, 0xcd }, &out);
    try std.testing.expectEqualSlices(u8, &.{ 0x0a, 0x0b, 0x0c, 0x0d }, &out);
}

test "bytesToNibbles single byte" {
    var out: [2]u8 = undefined;
    bytesToNibbles(&.{0xf0}, &out);
    try std.testing.expectEqualSlices(u8, &.{ 0x0f, 0x00 }, &out);
}

test "commonPrefixLen identical" {
    try std.testing.expectEqual(@as(usize, 3), commonPrefixLen(&.{ 1, 2, 3 }, &.{ 1, 2, 3 }));
}

test "commonPrefixLen diverges" {
    try std.testing.expectEqual(@as(usize, 2), commonPrefixLen(&.{ 1, 2, 3 }, &.{ 1, 2, 4 }));
}

test "commonPrefixLen empty" {
    try std.testing.expectEqual(@as(usize, 0), commonPrefixLen(&.{}, &.{ 1, 2 }));
}

test "hpDecode extension even (flag=0)" {
    // hpEncode([], is_leaf=false) → [0x00]
    var out: [16]u8 = undefined;
    const r = try hpDecode(&.{0x00}, &out);
    try std.testing.expect(!r.is_leaf);
    try std.testing.expectEqual(@as(usize, 0), r.len);
}

test "hpDecode extension odd (flag=1)" {
    // hpEncode([0x01], is_leaf=false) → [0x11]
    var out: [16]u8 = undefined;
    const r = try hpDecode(&.{0x11}, &out);
    try std.testing.expect(!r.is_leaf);
    try std.testing.expectEqual(@as(usize, 1), r.len);
    try std.testing.expectEqual(@as(u8, 0x01), out[0]);
}

test "hpDecode leaf even (flag=2)" {
    // hpEncode([0x01, 0x02], is_leaf=true) → [0x20, 0x12]
    var out: [16]u8 = undefined;
    const r = try hpDecode(&.{ 0x20, 0x12 }, &out);
    try std.testing.expect(r.is_leaf);
    try std.testing.expectEqual(@as(usize, 2), r.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, out[0..r.len]);
}

test "hpDecode leaf odd (flag=3)" {
    // hpEncode([0x0a, 0x01, 0x02], is_leaf=true) → [0x3a, 0x12]
    // Flag nibble = 3 (leaf, odd), low nibble of first byte = 0xa = nibble[0]
    // Then bytes[1] = 0x12 → nibbles 0x01, 0x02
    var out: [16]u8 = undefined;
    const r = try hpDecode(&.{ 0x3a, 0x12 }, &out);
    try std.testing.expect(r.is_leaf);
    try std.testing.expectEqual(@as(usize, 3), r.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x0a, 0x01, 0x02 }, out[0..r.len]);
}

test "hpDecode empty path leaf even" {
    // hpEncode([], is_leaf=true) → [0x20]
    var out: [16]u8 = undefined;
    const r = try hpDecode(&.{0x20}, &out);
    try std.testing.expect(r.is_leaf);
    try std.testing.expectEqual(@as(usize, 0), r.len);
}

test "hpDecode invalid flag" {
    var out: [16]u8 = undefined;
    try std.testing.expectError(error.InvalidHp, hpDecode(&.{0x40}, &out));
    try std.testing.expectError(error.InvalidHp, hpDecode(&.{0x50}, &out));
}

test "hpDecode empty input" {
    var out: [16]u8 = undefined;
    try std.testing.expectError(error.InvalidHp, hpDecode(&.{}, &out));
}

test "hpDecode roundtrip with compactEncode logic" {
    // Manually encode nibbles [0x03, 0x07, 0x0e] (odd, extension) = [0x13, 0x7e]
    // flag=1 (odd, extension), nibble[0]=3, then 0x7e = nibbles 7,e
    var out: [16]u8 = undefined;
    const r = try hpDecode(&.{ 0x13, 0x7e }, &out);
    try std.testing.expect(!r.is_leaf);
    try std.testing.expectEqual(@as(usize, 3), r.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0x07, 0x0e }, out[0..r.len]);
}
