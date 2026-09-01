/// Trie root computations for EVM state transition output.
///
/// Provides computeStateRootDelta() (stateless delta mode), computeStateRoot()
/// (full-state scratch mode), computeReceiptsRoot(), computeLogsHash(),
/// and computeTxRoot() for post-execution state and receipt verification.
const std = @import("std");

const types = @import("executor_types");
const rlp = @import("./rlp_encode.zig");
const mpt_builder = @import("mpt").builder;
const mpt = @import("mpt");

// ─── Logs hash ────────────────────────────────────────────────────────────────

/// Compute logsHash: keccak256 of the RLP-encoded list of all logs across all transactions.
/// Each log is encoded as RLP([address, [topic1, ...], data]).
pub fn computeLogsHash(alloc: std.mem.Allocator, receipts: []const types.Receipt) ![32]u8 {
    var log_items = std.ArrayListUnmanaged([]const u8).empty;
    defer log_items.deinit(alloc);

    for (receipts) |receipt| {
        for (receipt.logs) |log| {
            // topics list
            var topic_items = std.ArrayListUnmanaged([]const u8).empty;
            defer topic_items.deinit(alloc);
            for (log.topics) |t| try topic_items.append(alloc, try rlp.encodeBytes(alloc, &t));
            const topics_enc = try rlp.encodeList(alloc, topic_items.items);

            // log = [address, topics_list, data]
            const log_parts = [_][]const u8{
                try rlp.encodeBytes(alloc, &log.address),
                topics_enc,
                try rlp.encodeBytes(alloc, log.data),
            };
            try log_items.append(alloc, try rlp.encodeList(alloc, &log_parts));
        }
    }

    const logs_rlp = try rlp.encodeList(alloc, log_items.items);
    return rlp.keccak256(logs_rlp);
}

// ─── Trie root computations ───────────────────────────────────────────────────

/// txRoot: transactions trie, keys = RLP(index), values = typed tx bytes.
pub fn computeTxRoot(
    alloc: std.mem.Allocator,
    txs: []const types.TxInput,
    chain_id: u64,
) ![32]u8 {
    if (txs.len == 0) return mpt_builder.EMPTY_TRIE_HASH;
    var items = try alloc.alloc(mpt_builder.KV, txs.len);
    for (txs, 0..) |*tx, i| {
        items[i].key = try rlpIndex(alloc, i);
        items[i].value = encodeTxBytes(alloc, tx, chain_id, null, null, null) catch
            try alloc.dupe(u8, &.{});
    }
    return mpt_builder.trieRoot(alloc, items);
}

/// Compute the transactions trie root from raw transaction bytes.
/// key[i] = RLP(i), value[i] = raw_txs[i] (already wire-encoded).
pub fn computeRawTxRoot(
    alloc: std.mem.Allocator,
    raw_txs: []const []const u8,
) ![32]u8 {
    if (raw_txs.len == 0) return mpt_builder.EMPTY_TRIE_HASH;
    const items = try alloc.alloc(mpt_builder.KV, raw_txs.len);
    for (raw_txs, 0..) |raw_tx, i| {
        items[i].key = try rlpIndex(alloc, i);
        items[i].value = raw_tx;
    }
    return mpt_builder.trieRoot(alloc, items);
}

/// receiptsRoot: receipts trie, keys = RLP(index), values = typed receipt RLP.
pub fn computeReceiptsRoot(
    alloc: std.mem.Allocator,
    receipts: []const types.Receipt,
) ![32]u8 {
    if (receipts.len == 0) return mpt_builder.EMPTY_TRIE_HASH;
    var items = try alloc.alloc(mpt_builder.KV, receipts.len);
    for (receipts, 0..) |receipt, i| {
        items[i].key = try rlpIndex(alloc, i);
        items[i].value = try encodeReceiptRlp(alloc, receipt);
    }
    return mpt_builder.trieRoot(alloc, items);
}

/// stateRoot for stateless execution: batch-applies all account changes in one sorted pass,
/// visiting each shared branch node exactly once instead of once per account update.
///
/// `pre_storage_roots` is the WitnessDatabase, used to look up pre-state storage roots
/// for accounts that had storage before this block (avoids redundant trie walks).
pub fn computeStateRootDelta(
    alloc: std.mem.Allocator,
    pre_state_root: [32]u8,
    alloc_map: std.AutoHashMapUnmanaged(types.Address, types.AllocAccount),
    deleted_accounts: []const types.Address,
    index: *mpt.NodeIndex,
    pre_storage_roots: anytype,
) ![32]u8 {
    const total = alloc_map.count() + deleted_accounts.len;
    if (total == 0) return pre_state_root;

    // Every RLP encoding and intermediate trie-node byte string produced while
    // batch-applying these changes is scratch: only the returned root hash
    // outlives this call, and nothing looks up `index` entries inserted during
    // this computation again afterward (each batchUpdateIndexed traversal is
    // self-contained — see mpt/main.zig's updNodeExImpl doc comment). Scope
    // them to an arena so the whole batch is reclaimed in one free instead of
    // leaking one allocation per touched trie node into the caller's allocator.
    var scratch_arena = std.heap.ArenaAllocator.init(alloc);
    defer scratch_arena.deinit();
    const scratch = scratch_arena.allocator();

    const changes = try scratch.alloc(mpt.BatchChange, total);
    var n: usize = 0;

    var it = alloc_map.iterator();
    while (it.next()) |entry| {
        const addr = entry.key_ptr.*;
        const acct = entry.value_ptr.*;
        const addr_key = mpt_builder.keccak256(&addr);

        const pre_storage_root: ?[32]u8 = acct.pre_storage_root orelse
            pre_storage_roots.storageRootFor(addr);

        const storage_root = try computeStorageRootBatch(scratch, acct, pre_storage_root, index);
        const code_hash: [32]u8 = acct.code_hash orelse
            if (acct.code.len > 0) mpt_builder.keccak256(acct.code) else KECCAK_EMPTY;

        const has_code = !std.mem.eql(u8, &code_hash, &KECCAK_EMPTY);
        const account_rlp: ?[]const u8 = if (acct.nonce == 0 and
            acct.balance == 0 and
            !has_code and
            std.mem.eql(u8, &storage_root, &mpt_builder.EMPTY_TRIE_HASH))
            null
        else
            try encodeAccountRlp(scratch, acct.nonce, acct.balance, storage_root, code_hash);

        changes[n] = .{ .key = addr_key, .value = account_rlp };
        n += 1;
    }

    for (deleted_accounts) |addr| {
        changes[n] = .{ .key = mpt_builder.keccak256(&addr), .value = null };
        n += 1;
    }

    std.mem.sort(mpt.BatchChange, changes[0..n], {}, struct {
        fn lt(_: void, a: mpt.BatchChange, b: mpt.BatchChange) bool {
            return std.mem.lessThan(u8, &a.key, &b.key);
        }
    }.lt);

    return mpt.batchUpdateIndexed(scratch, pre_state_root, changes[0..n], index);
}

/// stateRoot: state trie, keys = keccak256(address), values = account RLP.
/// `pool` is the MPT witness node pool; used for accounts whose `pre_storage_root` is set.
/// Pass `&.{}` (empty slice) when no witness is available (all roots built from scratch).
pub fn computeStateRoot(
    alloc: std.mem.Allocator,
    alloc_map: std.AutoHashMapUnmanaged(types.Address, types.AllocAccount),
    pool: []const []const u8,
) ![32]u8 {
    const count = alloc_map.count();
    if (count == 0) return mpt_builder.EMPTY_TRIE_HASH;
    var items = try alloc.alloc(mpt_builder.KV, count);
    var it = alloc_map.iterator();
    var i: usize = 0;
    while (it.next()) |entry| {
        const addr = entry.key_ptr.*;
        const acct = entry.value_ptr.*;
        // key = keccak256(address)
        const key = try alloc.dupe(u8, &mpt_builder.keccak256(&addr));
        // storage trie root
        const storage_root = try computeStorageRoot(alloc, acct, pool);
        // code hash
        const code_hash: [32]u8 = acct.code_hash orelse
            if (acct.code.len > 0) mpt_builder.keccak256(acct.code) else KECCAK_EMPTY;
        // account RLP: [nonce, balance, storageRoot, codeHash]
        const value = try encodeAccountRlp(alloc, acct.nonce, acct.balance, storage_root, code_hash);
        items[i] = .{ .key = key, .value = value };
        i += 1;
    }
    return mpt_builder.trieRoot(alloc, items);
}

/// Batch storage root update: sorts all slot changes and applies them in one pass.
/// Replaces the old two-pass (inserts-then-deletes) sequential approach.
fn computeStorageRootBatch(
    alloc: std.mem.Allocator,
    account: types.AllocAccount,
    pre_storage_root: ?[32]u8,
    index: *mpt.NodeIndex,
) ![32]u8 {
    const old_root = pre_storage_root orelse return computeStorageRootScratch(alloc, account);

    const count = account.storage.count();
    if (count == 0) return old_root;

    const changes = try alloc.alloc(mpt.BatchChange, count);
    var n: usize = 0;
    var it = account.storage.iterator();
    while (it.next()) |entry| {
        var slot_key: [32]u8 = undefined;
        std.mem.writeInt(u256, &slot_key, entry.key_ptr.*, .big);
        const slot_hash = mpt.keccak256(&slot_key);
        const val: u256 = entry.value_ptr.*;
        const val_enc: ?[]const u8 = if (val == 0) null else try rlp.encodeU256(alloc, val);
        changes[n] = .{ .key = slot_hash, .value = val_enc };
        n += 1;
    }

    std.mem.sort(mpt.BatchChange, changes[0..n], {}, struct {
        fn lt(_: void, a: mpt.BatchChange, b: mpt.BatchChange) bool {
            return std.mem.lessThan(u8, &a.key, &b.key);
        }
    }.lt);

    return mpt.batchUpdateIndexed(alloc, old_root, changes[0..n], index);
}

/// Scratch-build storage root from all non-zero slots (no witness pool needed).
fn computeStorageRootScratch(alloc: std.mem.Allocator, account: types.AllocAccount) ![32]u8 {
    const storage = account.storage;
    const count = storage.count();
    if (count == 0) return mpt_builder.EMPTY_TRIE_HASH;
    var items = try alloc.alloc(mpt_builder.KV, count);
    var it = storage.iterator();
    var i: usize = 0;
    while (it.next()) |entry| {
        if (entry.value_ptr.* == 0) continue;
        var slot_key: [32]u8 = undefined;
        std.mem.writeInt(u256, &slot_key, entry.key_ptr.*, .big);
        items[i].key = try alloc.dupe(u8, &mpt_builder.keccak256(&slot_key));
        items[i].value = try rlp.encodeU256(alloc, entry.value_ptr.*);
        i += 1;
    }
    return mpt_builder.trieRoot(alloc, items[0..i]);
}

/// Pool-based storage root: delta-updates via witness node pool (for legacy callers).
fn computeStorageRoot(
    alloc: std.mem.Allocator,
    account: types.AllocAccount,
    pool: []const []const u8,
) ![32]u8 {
    if (account.pre_storage_root) |old_root| {
        var root = old_root;
        var extra = std.ArrayListUnmanaged([]const u8).empty;
        defer extra.deinit(alloc);
        var it = account.storage.iterator();
        while (it.next()) |entry| {
            var slot_key: [32]u8 = undefined;
            std.mem.writeInt(u256, &slot_key, entry.key_ptr.*, .big);
            try mpt.updateStorageChained(alloc, &root, slot_key, entry.value_ptr.*, pool, &extra);
        }
        return root;
    }
    return computeStorageRootScratch(alloc, account);
}

fn encodeAccountRlp(
    alloc: std.mem.Allocator,
    nonce: u64,
    balance: u256,
    storage_root: [32]u8,
    code_hash: [32]u8,
) ![]u8 {
    const parts = [_][]const u8{
        try rlp.encodeU64(alloc, nonce),
        try rlp.encodeU256(alloc, balance),
        try rlp.encodeBytes(alloc, &storage_root),
        try rlp.encodeBytes(alloc, &code_hash),
    };
    return rlp.encodeList(alloc, &parts);
}

fn encodeReceiptRlp(alloc: std.mem.Allocator, receipt: types.Receipt) ![]u8 {
    // Encode logs
    var log_items = std.ArrayListUnmanaged([]const u8).empty;
    for (receipt.logs) |log| {
        var topic_items = std.ArrayListUnmanaged([]const u8).empty;
        for (log.topics) |t| try topic_items.append(alloc, try rlp.encodeBytes(alloc, &t));
        const log_parts = [_][]const u8{
            try rlp.encodeBytes(alloc, &log.address),
            try rlp.encodeList(alloc, topic_items.items),
            try rlp.encodeBytes(alloc, log.data),
        };
        try log_items.append(alloc, try rlp.encodeList(alloc, &log_parts));
    }
    const bloom_bytes: []const u8 = &receipt.logs_bloom;
    // Pre-Byzantium (EIP-658): first field is 32-byte stateRoot.
    // Post-Byzantium: first field is 1-byte status (0x01 = success, 0x00 = failure).
    const first_field = if (receipt.state_root) |sr|
        try rlp.encodeBytes(alloc, &sr)
    else
        try rlp.encodeBytes(alloc, if (receipt.status == 1) &.{0x01} else &.{});
    const parts = [_][]const u8{
        first_field,
        try rlp.encodeU64(alloc, receipt.cumulative_gas_used),
        try rlp.encodeBytes(alloc, bloom_bytes),
        try rlp.encodeList(alloc, log_items.items),
    };
    const body = try rlp.encodeList(alloc, &parts);
    return if (receipt.type == 0)
        body
    else
        rlp.concat(alloc, &.{ &.{receipt.type}, body });
}

/// RLP-encode a transaction index as the trie key.
fn rlpIndex(alloc: std.mem.Allocator, i: usize) ![]u8 {
    return rlp.encodeU64(alloc, i);
}

/// Encode a signed transaction to its wire bytes (type_byte ++ rlp for typed).
/// Falls back to empty on error.
fn encodeTxBytes(
    alloc: std.mem.Allocator,
    tx: *const types.TxInput,
    chain_id: u64,
    v_override: ?u256,
    r_override: ?u256,
    s_override: ?u256,
) ![]u8 {
    const v = v_override orelse tx.v orelse 0;
    const r = r_override orelse tx.r orelse 0;
    const s = s_override orelse tx.s orelse 0;

    // Encode access list
    var al_items = std.ArrayListUnmanaged([]const u8).empty;
    for (tx.access_list) |entry| {
        var key_items = std.ArrayListUnmanaged([]const u8).empty;
        for (entry.storage_keys) |key| try key_items.append(alloc, try rlp.encodeBytes(alloc, &key));
        const al_entry_parts = [_][]const u8{
            try rlp.encodeBytes(alloc, &entry.address),
            try rlp.encodeList(alloc, key_items.items),
        };
        try al_items.append(alloc, try rlp.encodeList(alloc, &al_entry_parts));
    }
    const al_enc = try rlp.encodeList(alloc, al_items.items);
    const to_enc = if (tx.to) |to| try rlp.encodeBytes(alloc, &to) else try rlp.encodeBytes(alloc, &.{});

    return switch (tx.type) {
        0 => blk: {
            const items = [_][]const u8{
                try rlp.encodeU64(alloc, tx.nonce orelse 0),
                try rlp.encodeU128(alloc, tx.gas_price orelse 0),
                try rlp.encodeU64(alloc, tx.gas),
                to_enc,
                try rlp.encodeU256(alloc, tx.value),
                try rlp.encodeBytes(alloc, tx.data),
                try rlp.encodeU256(alloc, v),
                try rlp.encodeU256(alloc, r),
                try rlp.encodeU256(alloc, s),
            };
            break :blk try rlp.encodeList(alloc, &items);
        },
        1 => blk: {
            const items = [_][]const u8{
                try rlp.encodeU64(alloc, tx.chain_id orelse chain_id),
                try rlp.encodeU64(alloc, tx.nonce orelse 0),
                try rlp.encodeU128(alloc, tx.gas_price orelse 0),
                try rlp.encodeU64(alloc, tx.gas),
                to_enc,
                try rlp.encodeU256(alloc, tx.value),
                try rlp.encodeBytes(alloc, tx.data),
                al_enc,
                try rlp.encodeU256(alloc, v),
                try rlp.encodeU256(alloc, r),
                try rlp.encodeU256(alloc, s),
            };
            break :blk try rlp.concat(alloc, &.{ &.{0x01}, try rlp.encodeList(alloc, &items) });
        },
        2 => blk: {
            const items = [_][]const u8{
                try rlp.encodeU64(alloc, tx.chain_id orelse chain_id),
                try rlp.encodeU64(alloc, tx.nonce orelse 0),
                try rlp.encodeU128(alloc, tx.max_priority_fee_per_gas orelse 0),
                try rlp.encodeU128(alloc, tx.max_fee_per_gas orelse 0),
                try rlp.encodeU64(alloc, tx.gas),
                to_enc,
                try rlp.encodeU256(alloc, tx.value),
                try rlp.encodeBytes(alloc, tx.data),
                al_enc,
                try rlp.encodeU256(alloc, v),
                try rlp.encodeU256(alloc, r),
                try rlp.encodeU256(alloc, s),
            };
            break :blk try rlp.concat(alloc, &.{ &.{0x02}, try rlp.encodeList(alloc, &items) });
        },
        else => return error.UnsupportedTxType,
    };
}

const KECCAK_EMPTY: [32]u8 = [_]u8{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
};
