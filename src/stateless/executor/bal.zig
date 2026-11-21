//! Block Access List (BAL) RLP encoder — EIP-7928.
//!
//! The executor builds the BAL itself and validates it by comparing
//! keccak256(rlp(BAL)) with the header's block_access_list_hash.
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
/// second writes it, so encoding makes one allocation rather than one per field.
pub fn encodeBalRlp(alloc: std.mem.Allocator, entries: []const EncodeEntry) ![]u8 {
    const lens = try alloc.alloc(EntryLens, entries.len);
    defer alloc.free(lens);
    var payload: usize = 0;
    for (entries, lens) |e, *l| {
        l.* = EntryLens.of(e);
        payload += rlp.listLen(l.payload);
    }
    const out = try alloc.alloc(u8, rlp.listLen(payload));
    errdefer alloc.free(out);
    var w = rlp.Writer{ .buf = out };
    w.listHeader(payload);
    for (entries, lens) |e, l| writeEntry(&w, e, l);
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
        for (e.storage_changes) |sc| l.storage_changes += rlp.listLen(slotChangePayload(sc));
        l.storage_reads = 0;
        for (e.storage_reads) |slot| l.storage_reads += rlp.uintLen(u256, slot);
        l.balance_changes = 0;
        for (e.balance_changes) |c| l.balance_changes += rlp.listLen(rlp.uintLen(u64, c.bai) + rlp.uintLen(u256, c.value));
        l.nonce_changes = 0;
        for (e.nonce_changes) |c| l.nonce_changes += rlp.listLen(rlp.uintLen(u64, c.bai) + rlp.uintLen(u64, c.value));
        l.code_changes = 0;
        for (e.code_changes) |c| l.code_changes += rlp.listLen(rlp.uintLen(u64, c.bai) + rlp.strLen(c.code));
        l.payload = rlp.strLen(&e.address) + rlp.listLen(l.storage_changes) + rlp.listLen(l.storage_reads) +
            rlp.listLen(l.balance_changes) + rlp.listLen(l.nonce_changes) + rlp.listLen(l.code_changes);
        return l;
    }
};

/// Payload of one storage change: [slot, [[bai, value], ...]].
fn slotChangePayload(sc: EncodeSlotChange) usize {
    var changes: usize = 0;
    for (sc.changes) |c| changes += rlp.listLen(rlp.uintLen(u64, c.bai) + rlp.uintLen(u256, c.value));
    return rlp.uintLen(u256, sc.slot) + rlp.listLen(changes);
}

/// Writes one entry: [address, storage_changes, storage_reads, balance_changes,
/// nonce_changes, code_changes], with list payloads sized by EntryLens.of.
fn writeEntry(w: *rlp.Writer, e: EncodeEntry, l: EntryLens) void {
    w.listHeader(l.payload);
    w.str(&e.address);
    w.listHeader(l.storage_changes);
    for (e.storage_changes) |sc| {
        w.listHeader(slotChangePayload(sc));
        w.uint(u256, sc.slot);
        var changes: usize = 0;
        for (sc.changes) |c| changes += rlp.listLen(rlp.uintLen(u64, c.bai) + rlp.uintLen(u256, c.value));
        w.listHeader(changes);
        for (sc.changes) |c| {
            w.listHeader(rlp.uintLen(u64, c.bai) + rlp.uintLen(u256, c.value));
            w.uint(u64, c.bai);
            w.uint(u256, c.value);
        }
    }
    w.listHeader(l.storage_reads);
    for (e.storage_reads) |slot| w.uint(u256, slot);
    w.listHeader(l.balance_changes);
    for (e.balance_changes) |c| {
        w.listHeader(rlp.uintLen(u64, c.bai) + rlp.uintLen(u256, c.value));
        w.uint(u64, c.bai);
        w.uint(u256, c.value);
    }
    w.listHeader(l.nonce_changes);
    for (e.nonce_changes) |c| {
        w.listHeader(rlp.uintLen(u64, c.bai) + rlp.uintLen(u64, c.value));
        w.uint(u64, c.bai);
        w.uint(u64, c.value);
    }
    w.listHeader(l.code_changes);
    for (e.code_changes) |c| {
        w.listHeader(rlp.uintLen(u64, c.bai) + rlp.strLen(c.code));
        w.uint(u64, c.bai);
        w.str(c.code);
    }
}
