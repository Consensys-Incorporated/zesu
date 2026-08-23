/// Block Access List (BAL) RLP decoder/encoder — EIP-7928.
///
/// The BAL is committed in the execution payload as raw RLP bytes.
/// Actual on-wire format (confirmed from fixtures):
///   outer_list [
///     entry [
///       address (20 bytes),
///       storageChanges [ [slot:bytes, [[blockAccessIndex:u64, postValue:u256], ...]], ... ],
///       storageReads   [ slot:bytes, ... ],   // compact u256 (variable len, 0–32 bytes)
///       balanceChanges [ [blockAccessIndex:u64, postBalance:u256], ... ],
///       nonceChanges   [ [blockAccessIndex:u64, postNonce:u64], ... ],
///       codeChanges    [ [blockAccessIndex:u64, postCode:bytes], ... ],
///     ],
///     ...
///   ]
///
/// Public output is simplified:
///   nonce_changes:   last postNonce per entry ([]u64)
///   balance_changes: last postBalance per entry ([]u256)
///   code_changes:    last postCode per entry ([][]const u8)
///   storage_changes: last postValue per unique slot ([]StorageChange), sorted by slot
///   storage_reads:   slot bytes padded to [32]u8 ([]Hash), sorted
const std = @import("std");
const primitives = @import("primitives");
const mpt = @import("mpt");
const rlp = @import("./rlp_encode.zig");

pub const StorageChange = struct {
    slot: primitives.Hash,
    post_value: u256,
};

pub const BalEntry = struct {
    address: primitives.Address,
    nonce_changes: []u64,
    balance_changes: []u256,
    code_changes: [][]const u8,
    storage_changes: []StorageChange,
    storage_reads: []primitives.Hash,
};

/// Decode RLP-encoded block access list bytes into a slice of BalEntry.
/// Returns an empty slice for empty input.
pub fn decode(alloc: std.mem.Allocator, data: []const u8) ![]BalEntry {
    if (data.len == 0) return &.{};

    // Outer list
    const outer = mpt.rlp.decodeItem(data) catch return error.InvalidBAL;
    var rest = switch (outer.item) {
        .list => |p| p,
        .bytes => return error.InvalidBAL,
    };

    var entries = std.ArrayListUnmanaged(BalEntry).empty;

    while (rest.len > 0) {
        const entry_r = mpt.rlp.decodeItem(rest) catch return error.InvalidBAL;
        rest = rest[entry_r.consumed..];

        var ep = switch (entry_r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBAL,
        };

        // address: 20-byte bytes item
        const addr_r = mpt.rlp.decodeItem(ep) catch return error.InvalidBAL;
        const addr_b = switch (addr_r.item) {
            .bytes => |b| b,
            .list => return error.InvalidBAL,
        };
        if (addr_b.len != 20) return error.InvalidBAL;
        var addr: primitives.Address = undefined;
        @memcpy(&addr, addr_b);
        ep = ep[addr_r.consumed..];

        // storageChanges: [ [slot_bytes, [[blockAccessIndex, postValue], ...]], ... ]
        const storage_changes = decodeStorageChangeList(alloc, &ep) catch return error.InvalidBAL;

        // storageReads: [ slot_bytes, ... ]  (compact u256, variable len)
        const storage_reads = decodeCompactSlotList(alloc, &ep) catch return error.InvalidBAL;

        // balanceChanges: [ [blockAccessIndex, postBalance], ... ]
        const balance_changes = decodePairListU256(alloc, &ep) catch return error.InvalidBAL;

        // nonceChanges: [ [blockAccessIndex, postNonce], ... ]
        const nonce_changes = decodePairListU64(alloc, &ep) catch return error.InvalidBAL;

        // codeChanges: [ [blockAccessIndex, postCode], ... ]
        const code_changes = decodePairListBytes(alloc, &ep) catch return error.InvalidBAL;

        try entries.append(alloc, BalEntry{
            .address = addr,
            .nonce_changes = nonce_changes,
            .balance_changes = balance_changes,
            .code_changes = code_changes,
            .storage_changes = storage_changes,
            .storage_reads = storage_reads,
        });
    }

    return entries.toOwnedSlice(alloc);
}

// ─── Private decode helpers ───────────────────────────────────────────────────

/// Convert compact bytes (0–32 bytes, big-endian stripped) to a [32]u8 hash (left-zero-padded).
fn bytesTo32Padded(b: []const u8) !primitives.Hash {
    if (b.len > 32) return error.InvalidBAL;
    var out: primitives.Hash = @splat(0);
    if (b.len > 0) @memcpy(out[32 - b.len ..], b);
    return out;
}

/// Decode a list of [blockAccessIndex, u64_value] pairs; return last u64_value per entry.
fn decodePairListU64(alloc: std.mem.Allocator, ep: *[]const u8) ![]u64 {
    const list_r = mpt.rlp.decodeItem(ep.*) catch return error.InvalidBAL;
    ep.* = ep.*[list_r.consumed..];
    var payload = switch (list_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBAL,
    };
    var out = std.ArrayListUnmanaged(u64).empty;
    while (payload.len > 0) {
        const pair_r = mpt.rlp.decodeItem(payload) catch return error.InvalidBAL;
        payload = payload[pair_r.consumed..];
        var pair = switch (pair_r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBAL,
        };
        // skip blockAccessIndex
        const idx_r = mpt.rlp.decodeItem(pair) catch return error.InvalidBAL;
        pair = pair[idx_r.consumed..];
        // decode postNonce
        const val_r = mpt.rlp.decodeItem(pair) catch return error.InvalidBAL;
        const val_b = switch (val_r.item) {
            .bytes => |b| b,
            .list => return error.InvalidBAL,
        };
        out.append(alloc, try bytesToU64(val_b)) catch return error.InvalidBAL;
    }
    return out.toOwnedSlice(alloc);
}

/// Decode a list of [blockAccessIndex, u256_value] pairs; return last u256_value per entry.
fn decodePairListU256(alloc: std.mem.Allocator, ep: *[]const u8) ![]u256 {
    const list_r = mpt.rlp.decodeItem(ep.*) catch return error.InvalidBAL;
    ep.* = ep.*[list_r.consumed..];
    var payload = switch (list_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBAL,
    };
    var out = std.ArrayListUnmanaged(u256).empty;
    while (payload.len > 0) {
        const pair_r = mpt.rlp.decodeItem(payload) catch return error.InvalidBAL;
        payload = payload[pair_r.consumed..];
        var pair = switch (pair_r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBAL,
        };
        const idx_r = mpt.rlp.decodeItem(pair) catch return error.InvalidBAL;
        pair = pair[idx_r.consumed..];
        const val_r = mpt.rlp.decodeItem(pair) catch return error.InvalidBAL;
        const val_b = switch (val_r.item) {
            .bytes => |b| b,
            .list => return error.InvalidBAL,
        };
        out.append(alloc, try bytesToU256(val_b)) catch return error.InvalidBAL;
    }
    return out.toOwnedSlice(alloc);
}

/// Decode a list of [blockAccessIndex, code_bytes] pairs; return last code per entry.
fn decodePairListBytes(alloc: std.mem.Allocator, ep: *[]const u8) ![][]const u8 {
    const list_r = mpt.rlp.decodeItem(ep.*) catch return error.InvalidBAL;
    ep.* = ep.*[list_r.consumed..];
    var payload = switch (list_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBAL,
    };
    var out = std.ArrayListUnmanaged([]const u8).empty;
    while (payload.len > 0) {
        const pair_r = mpt.rlp.decodeItem(payload) catch return error.InvalidBAL;
        payload = payload[pair_r.consumed..];
        var pair = switch (pair_r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBAL,
        };
        const idx_r = mpt.rlp.decodeItem(pair) catch return error.InvalidBAL;
        pair = pair[idx_r.consumed..];
        const val_r = mpt.rlp.decodeItem(pair) catch return error.InvalidBAL;
        const val_b = switch (val_r.item) {
            .bytes => |b| b,
            .list => return error.InvalidBAL,
        };
        const copy = alloc.dupe(u8, val_b) catch return error.InvalidBAL;
        out.append(alloc, copy) catch return error.InvalidBAL;
    }
    return out.toOwnedSlice(alloc);
}

/// Decode storageChanges: [ [slot_bytes, [[idx, postValue], ...]], ... ]
/// Returns one StorageChange per unique slot (last postValue), sorted by slot.
fn decodeStorageChangeList(alloc: std.mem.Allocator, ep: *[]const u8) ![]StorageChange {
    const list_r = mpt.rlp.decodeItem(ep.*) catch return error.InvalidBAL;
    ep.* = ep.*[list_r.consumed..];
    var payload = switch (list_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBAL,
    };
    var out = std.ArrayListUnmanaged(StorageChange).empty;
    while (payload.len > 0) {
        const sc_r = mpt.rlp.decodeItem(payload) catch return error.InvalidBAL;
        payload = payload[sc_r.consumed..];
        var sc = switch (sc_r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBAL,
        };

        // slot: compact bytes
        const slot_r = mpt.rlp.decodeItem(sc) catch return error.InvalidBAL;
        const slot_b = switch (slot_r.item) {
            .bytes => |b| b,
            .list => return error.InvalidBAL,
        };
        const slot = try bytesTo32Padded(slot_b);
        sc = sc[slot_r.consumed..];

        // slotChanges: [ [blockAccessIndex, postValue], ... ]
        const changes_r = mpt.rlp.decodeItem(sc) catch return error.InvalidBAL;
        var changes = switch (changes_r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBAL,
        };

        var last_value: u256 = 0;
        while (changes.len > 0) {
            const change_r = mpt.rlp.decodeItem(changes) catch return error.InvalidBAL;
            changes = changes[change_r.consumed..];
            var change = switch (change_r.item) {
                .list => |p| p,
                .bytes => return error.InvalidBAL,
            };
            const idx_r = mpt.rlp.decodeItem(change) catch return error.InvalidBAL;
            change = change[idx_r.consumed..];
            const val_r = mpt.rlp.decodeItem(change) catch return error.InvalidBAL;
            const val_b = switch (val_r.item) {
                .bytes => |b| b,
                .list => return error.InvalidBAL,
            };
            last_value = try bytesToU256(val_b);
        }

        out.append(alloc, StorageChange{ .slot = slot, .post_value = last_value }) catch return error.InvalidBAL;
    }

    // Sort by slot (ascending, big-endian compare)
    std.mem.sort(StorageChange, out.items, {}, struct {
        pub fn lessThan(_: void, a: StorageChange, b: StorageChange) bool {
            return std.mem.lessThan(u8, &a.slot, &b.slot);
        }
    }.lessThan);

    return out.toOwnedSlice(alloc);
}

/// Decode storageReads: [ slot_bytes, ... ] — compact u256 slots (variable len 0–32 bytes).
/// Returns sorted []primitives.Hash (each slot padded to [32]u8).
fn decodeCompactSlotList(alloc: std.mem.Allocator, ep: *[]const u8) ![]primitives.Hash {
    const list_r = mpt.rlp.decodeItem(ep.*) catch return error.InvalidBAL;
    ep.* = ep.*[list_r.consumed..];
    var payload = switch (list_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBAL,
    };
    var out = std.ArrayListUnmanaged(primitives.Hash).empty;
    while (payload.len > 0) {
        const r = mpt.rlp.decodeItem(payload) catch return error.InvalidBAL;
        const b = switch (r.item) {
            .bytes => |bs| bs,
            .list => return error.InvalidBAL,
        };
        const h = try bytesTo32Padded(b);
        out.append(alloc, h) catch return error.InvalidBAL;
        payload = payload[r.consumed..];
    }

    // Sort by slot value (ascending)
    std.mem.sort(primitives.Hash, out.items, {}, struct {
        pub fn lessThan(_: void, a: primitives.Hash, b: primitives.Hash) bool {
            return std.mem.lessThan(u8, &a, &b);
        }
    }.lessThan);

    return out.toOwnedSlice(alloc);
}

fn bytesToU64(b: []const u8) !u64 {
    if (b.len > 8) return error.InvalidBAL;
    var v: u64 = 0;
    for (b) |byte| v = (v << 8) | byte;
    return v;
}

fn bytesToU256(b: []const u8) !u256 {
    if (b.len > 32) return error.InvalidBAL;
    var v: u256 = 0;
    for (b) |byte| v = (v << 8) | byte;
    return v;
}

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
