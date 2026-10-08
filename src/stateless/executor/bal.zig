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

pub fn encodeBalRlp(alloc: std.mem.Allocator, entries: []const EncodeEntry) ![]u8 {
    var items = try std.ArrayListUnmanaged([]const u8).initCapacity(alloc, entries.len);
    for (entries) |entry| try items.append(alloc, try encodeEntryRlp(alloc, entry));
    return rlp.encodeList(alloc, items.items);
}

fn encodeEntryRlp(alloc: std.mem.Allocator, entry: EncodeEntry) ![]u8 {
    // 6 fields: address + storageChanges + storageReads + balanceChanges + nonceChanges + codeChanges
    var parts = try std.ArrayListUnmanaged([]const u8).initCapacity(alloc, 6);

    // address (always 20 bytes)
    try parts.append(alloc, try rlp.encodeBytes(alloc, &entry.address));

    // storageChanges: [ [slot_bytes, [[bai, postValue], ...]], ... ]
    {
        var sc_items = try std.ArrayListUnmanaged([]const u8).initCapacity(alloc, entry.storage_changes.len);
        for (entry.storage_changes) |sc| {
            const slot_rlp = try rlp.encodeU256(alloc, sc.slot);
            var pairs = try std.ArrayListUnmanaged([]const u8).initCapacity(alloc, sc.changes.len);
            for (sc.changes) |ch| {
                const bai_rlp = try rlp.encodeU64(alloc, ch.bai);
                const val_rlp = try rlp.encodeU256(alloc, ch.value);
                try pairs.append(alloc, try rlp.encodeList(alloc, &.{ bai_rlp, val_rlp }));
            }
            const changes_list = try rlp.encodeList(alloc, pairs.items);
            try sc_items.append(alloc, try rlp.encodeList(alloc, &.{ slot_rlp, changes_list }));
        }
        try parts.append(alloc, try rlp.encodeList(alloc, sc_items.items));
    }

    // storageReads: [ slot_bytes, ... ]
    {
        var sr_items = try std.ArrayListUnmanaged([]const u8).initCapacity(alloc, entry.storage_reads.len);
        for (entry.storage_reads) |slot| try sr_items.append(alloc, try rlp.encodeU256(alloc, slot));
        try parts.append(alloc, try rlp.encodeList(alloc, sr_items.items));
    }

    // balanceChanges: [ [bai, postBalance], ... ]
    {
        var bal_items = try std.ArrayListUnmanaged([]const u8).initCapacity(alloc, entry.balance_changes.len);
        for (entry.balance_changes) |bc| {
            const bai_rlp = try rlp.encodeU64(alloc, bc.bai);
            const val_rlp = try rlp.encodeU256(alloc, bc.value);
            try bal_items.append(alloc, try rlp.encodeList(alloc, &.{ bai_rlp, val_rlp }));
        }
        try parts.append(alloc, try rlp.encodeList(alloc, bal_items.items));
    }

    // nonceChanges: [ [bai, postNonce], ... ]
    {
        var nc_items = try std.ArrayListUnmanaged([]const u8).initCapacity(alloc, entry.nonce_changes.len);
        for (entry.nonce_changes) |nc| {
            const bai_rlp = try rlp.encodeU64(alloc, nc.bai);
            const val_rlp = try rlp.encodeU64(alloc, nc.value);
            try nc_items.append(alloc, try rlp.encodeList(alloc, &.{ bai_rlp, val_rlp }));
        }
        try parts.append(alloc, try rlp.encodeList(alloc, nc_items.items));
    }

    // codeChanges: [ [bai, postCode], ... ]
    {
        var cc_items = try std.ArrayListUnmanaged([]const u8).initCapacity(alloc, entry.code_changes.len);
        for (entry.code_changes) |cc| {
            const bai_rlp = try rlp.encodeU64(alloc, cc.bai);
            const code_rlp = try rlp.encodeBytes(alloc, cc.code);
            try cc_items.append(alloc, try rlp.encodeList(alloc, &.{ bai_rlp, code_rlp }));
        }
        try parts.append(alloc, try rlp.encodeList(alloc, cc_items.items));
    }

    return rlp.encodeList(alloc, parts.items);
}
