/// Block Access List (BAL) RLP encoder — EIP-7928.
///
/// The executor builds the BAL itself and validates it by comparing
/// keccak256(rlp(BAL)) with the header's block_access_list_hash.
const std = @import("std");
const primitives = @import("primitives");
const mpt = @import("mpt");
const rlp = @import("./rlp_encode.zig");

// ─── Encoding types for BAL computation (EIP-7928) ───────────────────────────

pub const SlotBaiValue = struct { bai: u64, value: u256 };

pub const EncodeSlotChange = struct {
    slot: u256,
    changes: []const SlotBaiValue,
};

pub const BaiU256 = struct { bai: u64, value: u256 };
pub const BaiU64 = struct { bai: u64, value: u64 };
pub const BaiCode = struct { bai: u64, code: []const u8 };

pub const EncodeEntry = struct {
    address: primitives.Address,
    storage_changes: []const EncodeSlotChange,
    storage_reads: []const u256,
    balance_changes: []const BaiU256,
    nonce_changes: []const BaiU64,
    code_changes: []const BaiCode,
};

/// Encode the block access list as RLP and return keccak256(rlp(BAL)).
pub fn encodeAndHash(alloc: std.mem.Allocator, entries: []const EncodeEntry) ![32]u8 {
    const bytes = try encodeBalRlp(alloc, entries);
    return rlp.keccak256(bytes);
}

/// RLP of the block access list, written into one buffer: a first pass sizes every list, a
/// second writes it. Building each field as its own allocation and concatenating them cost
/// more per entry than the bytes themselves (a read-only account encodes to 27).
pub fn encodeBalRlp(alloc: std.mem.Allocator, entries: []const EncodeEntry) ![]u8 {
    const lens = try alloc.alloc(EntryLens, entries.len);
    defer alloc.free(lens);
    var payload: usize = 0;
    for (entries, lens) |e, *l| {
        l.* = EntryLens.of(e);
        payload += listLen(l.payload);
    }
    const out = try alloc.alloc(u8, listLen(payload));
    errdefer alloc.free(out);
    var w = Writer{ .buf = out };
    w.listHeader(payload);
    for (entries, lens) |e, l| w.entry(e, l);
    // Not an assert: release builds are ReleaseFast, where asserts compile out and a sizing
    // pass that disagrees with the write pass would hash a short or partly uninitialised buffer.
    if (w.pos != out.len) return error.BalSizeMismatch;
    return out;
}

/// Payload lengths of an entry's list and of its five sub-lists.
const EntryLens = struct {
    payload: usize,
    storage_changes: usize,
    storage_reads: usize,
    balance_changes: usize,
    nonce_changes: usize,
    code_changes: usize,

    fn of(e: EncodeEntry) EntryLens {
        var l: EntryLens = undefined;
        l.storage_changes = 0;
        for (e.storage_changes) |sc| l.storage_changes += listLen(slotChangePayload(sc));
        l.storage_reads = 0;
        for (e.storage_reads) |slot| l.storage_reads += uintLen(u256, slot);
        l.balance_changes = 0;
        for (e.balance_changes) |c| l.balance_changes += listLen(uintLen(u64, c.bai) + uintLen(u256, c.value));
        l.nonce_changes = 0;
        for (e.nonce_changes) |c| l.nonce_changes += listLen(uintLen(u64, c.bai) + uintLen(u64, c.value));
        l.code_changes = 0;
        for (e.code_changes) |c| l.code_changes += listLen(uintLen(u64, c.bai) + strLen(c.code));
        l.payload = strLen(&e.address) + listLen(l.storage_changes) + listLen(l.storage_reads) +
            listLen(l.balance_changes) + listLen(l.nonce_changes) + listLen(l.code_changes);
        return l;
    }
};

/// Payload of one storage change: [slot, [[bai, value], ...]].
fn slotChangePayload(sc: EncodeSlotChange) usize {
    var changes: usize = 0;
    for (sc.changes) |c| changes += listLen(uintLen(u64, c.bai) + uintLen(u256, c.value));
    return uintLen(u256, sc.slot) + listLen(changes);
}

/// Bytes in the big-endian form of a non-zero length.
fn lenBytes(n: usize) usize {
    return (64 - @as(usize, @clz(@as(u64, n))) + 7) / 8;
}

/// Encoded size of a list with this payload.
fn listLen(payload: usize) usize {
    return (if (payload <= 55) 1 else 1 + lenBytes(payload)) + payload;
}

/// Encoded size of a byte string.
fn strLen(data: []const u8) usize {
    if (data.len == 1 and data[0] < 0x80) return 1;
    if (data.len <= 55) return 1 + data.len;
    return 1 + lenBytes(data.len) + data.len;
}

/// Encoded size of an unsigned integer: its minimal big-endian bytes as a string.
fn uintLen(comptime T: type, v: T) usize {
    if (v == 0) return 1;
    if (v < 0x80) return 1;
    return 1 + (@bitSizeOf(T) - @as(usize, @clz(v)) + 7) / 8;
}

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn byte(w: *Writer, b: u8) void {
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

    fn listHeader(w: *Writer, payload: usize) void {
        if (payload <= 55) {
            w.byte(@intCast(0xc0 + payload));
        } else {
            w.byte(@intCast(0xf7 + lenBytes(payload)));
            w.lenField(payload);
        }
    }

    fn str(w: *Writer, data: []const u8) void {
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

    fn uint(w: *Writer, comptime T: type, v: T) void {
        var be: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &be, v, .big);
        const skip = if (v == 0) be.len else @as(usize, @clz(v)) / 8;
        w.str(be[skip..]);
    }

    fn entry(w: *Writer, e: EncodeEntry, l: EntryLens) void {
        w.listHeader(l.payload);
        w.str(&e.address);
        w.listHeader(l.storage_changes);
        for (e.storage_changes) |sc| {
            w.listHeader(slotChangePayload(sc));
            w.uint(u256, sc.slot);
            var changes: usize = 0;
            for (sc.changes) |c| changes += listLen(uintLen(u64, c.bai) + uintLen(u256, c.value));
            w.listHeader(changes);
            for (sc.changes) |c| {
                w.listHeader(uintLen(u64, c.bai) + uintLen(u256, c.value));
                w.uint(u64, c.bai);
                w.uint(u256, c.value);
            }
        }
        w.listHeader(l.storage_reads);
        for (e.storage_reads) |slot| w.uint(u256, slot);
        w.listHeader(l.balance_changes);
        for (e.balance_changes) |c| {
            w.listHeader(uintLen(u64, c.bai) + uintLen(u256, c.value));
            w.uint(u64, c.bai);
            w.uint(u256, c.value);
        }
        w.listHeader(l.nonce_changes);
        for (e.nonce_changes) |c| {
            w.listHeader(uintLen(u64, c.bai) + uintLen(u64, c.value));
            w.uint(u64, c.bai);
            w.uint(u64, c.value);
        }
        w.listHeader(l.code_changes);
        for (e.code_changes) |c| {
            w.listHeader(uintLen(u64, c.bai) + strLen(c.code));
            w.uint(u64, c.bai);
            w.str(c.code);
        }
    }
};
