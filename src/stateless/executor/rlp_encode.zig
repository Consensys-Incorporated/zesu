//! Allocating RLP encoders. Every result is a fresh allocation the caller owns;
//! nothing frees intermediates, so pass an arena.
const std = @import("std");
const accel = @import("accelerators");

// ─── Core encoders ────────────────────────────────────────────────────────────

/// Encode a byte slice as an RLP byte-string.
pub fn encodeBytes(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    if (data.len == 1 and data[0] < 0x80) {
        return alloc.dupe(u8, data);
    } else if (data.len == 0) {
        return alloc.dupe(u8, &.{0x80});
    } else if (data.len <= 55) {
        const out = try alloc.alloc(u8, 1 + data.len);
        out[0] = @intCast(0x80 + data.len);
        @memcpy(out[1..], data);
        return out;
    } else {
        var len_buf: [8]u8 = undefined;
        const len_bytes = bigEndianLength(data.len, &len_buf);
        const out = try alloc.alloc(u8, 1 + len_bytes.len + data.len);
        out[0] = @intCast(0xb7 + len_bytes.len);
        @memcpy(out[1..][0..len_bytes.len], len_bytes);
        @memcpy(out[1 + len_bytes.len ..], data);
        return out;
    }
}

/// Encode a u64 as minimal big-endian bytes, then RLP byte-string.
pub fn encodeU64(alloc: std.mem.Allocator, n: u64) ![]u8 {
    if (n == 0) return encodeBytes(alloc, &.{});
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, n, .big);
    return encodeBytes(alloc, trimLeadingZero(&buf));
}

/// Encode a u128 as minimal big-endian bytes, then RLP byte-string.
pub fn encodeU128(alloc: std.mem.Allocator, n: u128) ![]u8 {
    if (n == 0) return encodeBytes(alloc, &.{});
    var buf: [16]u8 = undefined;
    std.mem.writeInt(u128, &buf, n, .big);
    return encodeBytes(alloc, trimLeadingZero(&buf));
}

/// Encode a u256 as minimal big-endian bytes, then RLP byte-string.
pub fn encodeU256(alloc: std.mem.Allocator, n: u256) ![]u8 {
    if (n == 0) return encodeBytes(alloc, &.{});
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &buf, n, .big);
    return encodeBytes(alloc, trimLeadingZero(&buf));
}

/// Encode a bool as 0x01 or 0x80 (empty = false).
pub fn encodeBool(alloc: std.mem.Allocator, b: bool) ![]u8 {
    return encodeBytes(alloc, if (b) &.{0x01} else &.{});
}

/// Encode a list of pre-encoded items as an RLP list.
/// Items must already be RLP-encoded (output of other encode* functions).
pub fn encodeList(alloc: std.mem.Allocator, items: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (items) |item| total += item.len;

    if (total <= 55) {
        const out = try alloc.alloc(u8, 1 + total);
        out[0] = @intCast(0xc0 + total);
        var pos: usize = 1;
        for (items) |item| {
            @memcpy(out[pos..][0..item.len], item);
            pos += item.len;
        }
        return out;
    } else {
        var len_buf: [8]u8 = undefined;
        const len_bytes = bigEndianLength(total, &len_buf);
        const out = try alloc.alloc(u8, 1 + len_bytes.len + total);
        out[0] = @intCast(0xf7 + len_bytes.len);
        @memcpy(out[1..][0..len_bytes.len], len_bytes);
        var pos: usize = 1 + len_bytes.len;
        for (items) |item| {
            @memcpy(out[pos..][0..item.len], item);
            pos += item.len;
        }
        return out;
    }
}

/// Concatenate multiple byte slices into one allocation.
pub fn concat(alloc: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (parts) |p| total += p.len;
    const out = try alloc.alloc(u8, total);
    var pos: usize = 0;
    for (parts) |p| {
        @memcpy(out[pos..][0..p.len], p);
        pos += p.len;
    }
    return out;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn trimLeadingZero(buf: []const u8) []const u8 {
    var i: usize = 0;
    while (i < buf.len and buf[i] == 0) i += 1;
    return buf[i..];
}

/// Write `n` as a minimal big-endian byte sequence into buf.
/// Returns the written slice, `buf[0..len]`.
fn bigEndianLength(n: usize, buf: *[8]u8) []const u8 {
    var v = n;
    var len: usize = 0;
    var i: usize = 7;
    while (true) {
        buf[i] = @intCast(v & 0xFF);
        len += 1;
        v >>= 8;
        if (v == 0) break;
        i -= 1;
    }
    const start = 8 - len;
    if (start > 0) {
        for (0..len) |j| buf[j] = buf[start + j];
    }
    return buf[0..len];
}

// ─── Keccak256 ────────────────────────────────────────────────────────────────

pub fn keccak256(data: []const u8) [32]u8 {
    var hash: [32]u8 = undefined;
    accel.keccak256(data, &hash);
    return hash;
}
