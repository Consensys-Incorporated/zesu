//! Allocation-free RLP decoder.
//!
//! Produces views (slices) into the original input bytes; no heap allocation.
//! Usage pattern for iterating list items:
//!
//!   var rest = list_payload;
//!   while (rest.len > 0) {
//!       const r = try rlp.decodeItem(rest);
//!       // use r.item ...
//!       rest = rest[r.consumed..];
//!   }

const std = @import("std");

/// A decoded RLP item. Slices point into the original input bytes.
pub const RlpItem = union(enum) {
    /// A byte string (single value).
    bytes: []const u8,
    /// A list. `payload` is the raw bytes of the list body; iterate with
    /// repeated calls to `decodeItem`.
    list: []const u8,
};

pub const DecodeResult = struct {
    item: RlpItem,
    consumed: usize,
};

/// Decode one RLP item from `input`.
/// Returns the decoded item and how many bytes were consumed.
pub fn decodeItem(input: []const u8) error{InvalidRlp}!DecodeResult {
    if (input.len == 0) return error.InvalidRlp;

    const first = input[0];

    if (first <= 0x7f) {
        // Single-byte string: the byte itself is the value.
        return .{ .item = .{ .bytes = input[0..1] }, .consumed = 1 };
    } else if (first == 0x80) {
        // Empty string.
        return .{ .item = .{ .bytes = &.{} }, .consumed = 1 };
    } else if (first <= 0xb7) {
        // Short string: length = first - 0x80.
        const len: usize = first - 0x80;
        if (1 + len > input.len) return error.InvalidRlp;
        return .{ .item = .{ .bytes = input[1 .. 1 + len] }, .consumed = 1 + len };
    } else if (first <= 0xbf) {
        // Long string: next (first - 0xb7) bytes encode the length big-endian.
        const len_len: usize = first - 0xb7;
        if (1 + len_len > input.len) return error.InvalidRlp;
        const len = readBigEndian(input[1 .. 1 + len_len]) catch return error.InvalidRlp;
        if (1 + len_len + len > input.len) return error.InvalidRlp;
        return .{
            .item = .{ .bytes = input[1 + len_len .. 1 + len_len + len] },
            .consumed = 1 + len_len + len,
        };
    } else if (first <= 0xf7) {
        // Short list: payload length = first - 0xc0.
        const payload_len: usize = first - 0xc0;
        if (1 + payload_len > input.len) return error.InvalidRlp;
        return .{ .item = .{ .list = input[1 .. 1 + payload_len] }, .consumed = 1 + payload_len };
    } else {
        // Long list: next (first - 0xf7) bytes encode the payload length big-endian.
        const len_len: usize = first - 0xf7;
        if (1 + len_len > input.len) return error.InvalidRlp;
        const payload_len = readBigEndian(input[1 .. 1 + len_len]) catch return error.InvalidRlp;
        if (1 + len_len + payload_len > input.len) return error.InvalidRlp;
        return .{
            .item = .{ .list = input[1 + len_len .. 1 + len_len + payload_len] },
            .consumed = 1 + len_len + payload_len,
        };
    }
}

/// decodeItem, but also rejecting the encodings canonical RLP forbids: a single byte below
/// 0x80 wrapped as a one-byte string, and the long form, or a length with leading zero
/// bytes, for a string or list of 55 bytes or fewer. For RLP no hash binds, such as a
/// payload's transactions; hash-bound input (trie nodes, headers) needs no extra checks.
pub fn decodeItemCanonical(input: []const u8) error{InvalidRlp}!DecodeResult {
    const r = try decodeItem(input);
    const first = input[0];
    if (first == 0x81 and input[1] < 0x80) return error.InvalidRlp;
    if ((first >= 0xb8 and first <= 0xbf) or first >= 0xf8) {
        const len_len: usize = first - (if (first >= 0xf8) @as(u8, 0xf7) else @as(u8, 0xb7));
        if (input[1] == 0) return error.InvalidRlp;
        if (r.consumed - 1 - len_len <= 55) return error.InvalidRlp;
    }
    return r;
}

/// Read a big-endian unsigned integer from 1–8 bytes.
fn readBigEndian(bytes: []const u8) error{Overflow}!usize {
    if (bytes.len == 0 or bytes.len > 8) return error.Overflow;
    var result: usize = 0;
    for (bytes) |b| result = (result << 8) | b;
    return result;
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

test "single byte (0x00–0x7f)" {
    const r = try decodeItem(&.{0x42});
    try std.testing.expectEqual(@as(usize, 1), r.consumed);
    try std.testing.expectEqualSlices(u8, &.{0x42}, r.item.bytes);
}

test "single byte zero" {
    const r = try decodeItem(&.{0x00});
    try std.testing.expectEqual(@as(usize, 1), r.consumed);
    try std.testing.expectEqualSlices(u8, &.{0x00}, r.item.bytes);
}

test "empty string (0x80)" {
    const r = try decodeItem(&.{0x80});
    try std.testing.expectEqual(@as(usize, 1), r.consumed);
    try std.testing.expectEqualSlices(u8, &.{}, r.item.bytes);
}

test "short string" {
    // 0x83 = 0x80 + 3, followed by 'dog'
    const r = try decodeItem(&.{ 0x83, 'd', 'o', 'g' });
    try std.testing.expectEqual(@as(usize, 4), r.consumed);
    try std.testing.expectEqualSlices(u8, "dog", r.item.bytes);
}

test "long string" {
    // A 56-byte string: first = 0xb8 (0xb7+1), next byte = 56, then 56 data bytes.
    var data: [58]u8 = undefined;
    data[0] = 0xb8;
    data[1] = 56;
    for (data[2..], 0..) |*b, i| b.* = @intCast(i & 0xff);
    const r = try decodeItem(&data);
    try std.testing.expectEqual(@as(usize, 58), r.consumed);
    try std.testing.expectEqual(@as(usize, 56), r.item.bytes.len);
    try std.testing.expectEqualSlices(u8, data[2..], r.item.bytes);
}

test "empty list (0xc0)" {
    const r = try decodeItem(&.{0xc0});
    try std.testing.expectEqual(@as(usize, 1), r.consumed);
    try std.testing.expectEqual(@as(usize, 0), r.item.list.len);
}

test "short list with items" {
    // List containing two single-byte items 0x01 and 0x02.
    // payload = [0x01, 0x02] → first = 0xc0 + 2 = 0xc2
    const r = try decodeItem(&.{ 0xc2, 0x01, 0x02 });
    try std.testing.expectEqual(@as(usize, 3), r.consumed);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, r.item.list);
}

test "long list" {
    // A list with 56-byte payload: first = 0xf8, next = 56, then 56 zeroes.
    var data: [58]u8 = undefined;
    data[0] = 0xf8;
    data[1] = 56;
    @memset(data[2..], 0x00);
    const r = try decodeItem(&data);
    try std.testing.expectEqual(@as(usize, 58), r.consumed);
    try std.testing.expectEqual(@as(usize, 56), r.item.list.len);
}

test "malformed: empty input" {
    try std.testing.expectError(error.InvalidRlp, decodeItem(&.{}));
}

test "malformed: truncated short string" {
    // Claims 5 bytes but only 2 bytes available after the prefix.
    try std.testing.expectError(error.InvalidRlp, decodeItem(&.{ 0x85, 'a', 'b' }));
}

test "malformed: truncated long string length" {
    // 0xb8 means len_len=1 but no length byte follows.
    try std.testing.expectError(error.InvalidRlp, decodeItem(&.{0xb8}));
}

test "malformed: truncated list" {
    // 0xc3 = list with 3-byte payload, but only 1 byte follows.
    try std.testing.expectError(error.InvalidRlp, decodeItem(&.{ 0xc3, 0x01 }));
}

test "iterate list items" {
    // Encode: list(0x01, 0x02, 0x03)
    const encoded = &[_]u8{ 0xc3, 0x01, 0x02, 0x03 };
    const outer = try decodeItem(encoded);
    var rest = outer.item.list;
    var values: [3]u8 = undefined;
    var count: usize = 0;
    while (rest.len > 0) {
        const r = try decodeItem(rest);
        values[count] = r.item.bytes[0];
        count += 1;
        rest = rest[r.consumed..];
    }
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, &values);
}

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
    try std.testing.expectEqual(@as(usize, 58), (try decodeItemCanonical(&([_]u8{ 0xb8, 0x38 } ++ [_]u8{0} ** 56))).consumed);
}
