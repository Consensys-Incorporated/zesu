//! RLP encoders. The allocating `encode*` helpers return a fresh allocation per call and
//! never free intermediates, so pass them an arena. Hot paths instead size the whole
//! encoding with `listLen`/`strLen`/`uintLen`, allocate once, and fill it with `Writer`.
const std = @import("std");
const primitives = @import("primitives");
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
    primitives.writeBe(u128, &buf, n);
    return encodeBytes(alloc, trimLeadingZero(&buf));
}

/// Encode a u256 as minimal big-endian bytes, then RLP byte-string.
pub fn encodeU256(alloc: std.mem.Allocator, n: u256) ![]u8 {
    if (n == 0) return encodeBytes(alloc, &.{});
    var buf: [32]u8 = undefined;
    primitives.writeBe(u256, &buf, n);
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

// ─── Sized single-buffer encoding ─────────────────────────────────────────────

/// Bytes in the minimal big-endian form of a non-zero length.
pub fn lenBytes(n: usize) usize {
    return (64 - @as(usize, @clz(@as(u64, n))) + 7) / 8;
}

/// Encoded size of a list with this payload.
pub fn listLen(payload: usize) usize {
    return (if (payload <= 55) 1 else 1 + lenBytes(payload)) + payload;
}

/// Encoded size of a byte string.
pub fn strLen(data: []const u8) usize {
    if (data.len == 1 and data[0] < 0x80) return 1;
    if (data.len <= 55) return 1 + data.len;
    return 1 + lenBytes(data.len) + data.len;
}

/// Encoded size of an unsigned integer: its minimal big-endian bytes as a string.
pub fn uintLen(comptime T: type, v: T) usize {
    if (v < 0x80) return 1;
    return 1 + (@bitSizeOf(T) - @as(usize, @clz(v)) + 7) / 8;
}

/// Writes RLP into a buffer pre-sized with the `*Len` functions above. Writes past the
/// end are a sizing bug; callers check `pos == buf.len` with a runtime test, not an
/// assert, since release builds are ReleaseFast.
pub const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn byte(w: *Writer, b: u8) void {
        w.buf[w.pos] = b;
        w.pos += 1;
    }

    fn lenField(w: *Writer, n: usize) void {
        const k = lenBytes(n);
        var i = k;
        while (i > 0) {
            i -= 1;
            w.byte(@truncate(n >> @intCast(i * 8)));
        }
    }

    pub fn listHeader(w: *Writer, payload: usize) void {
        if (payload <= 55) {
            w.byte(@intCast(0xc0 + payload));
        } else {
            w.byte(@intCast(0xf7 + lenBytes(payload)));
            w.lenField(payload);
        }
    }

    pub fn str(w: *Writer, data: []const u8) void {
        if (data.len == 1 and data[0] < 0x80) return w.byte(data[0]);
        if (data.len <= 55) {
            w.byte(@intCast(0x80 + data.len));
        } else {
            w.byte(@intCast(0xb7 + lenBytes(data.len)));
            w.lenField(data.len);
        }
        @memcpy(w.buf[w.pos..][0..data.len], data);
        w.pos += data.len;
    }

    pub fn uint(w: *Writer, comptime T: type, v: T) void {
        var be: [@divExact(@bitSizeOf(T), 8)]u8 = undefined;
        primitives.writeBe(T, &be, v);
        const skip = if (v == 0) be.len else @as(usize, @clz(v)) / 8;
        w.str(be[skip..]);
    }
};

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
