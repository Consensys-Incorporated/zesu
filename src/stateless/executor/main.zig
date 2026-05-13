//! BlockExecutor: stateless EVM block execution using zevm.
//!
//! Caller is responsible for:
//!   - Building the NodeIndex from witness nodes (mpt.buildNodeIndex)
//!   - Decoding block_hashes from witness headers
//!
//! This module handles:
//!   1. Fork detection and Env construction.
//!   2. Transaction decoding and execution via transition().
//!   3. Post-state root and receipts root computation.
//!   4. Returning a ProofOutput for the guest to commit.

const std = @import("std");
const primitives = @import("primitives");
const input = @import("input");
const output = @import("output");
const mpt = @import("mpt");
const rlp_decode = @import("rlp_decode");

const transition_mod = @import("./transition.zig");
const output_mod = @import("./output.zig");
const fork_mod = @import("hardfork");
const tx_decode = @import("./tx_decode.zig");
const types = @import("executor_types");
const db_mod = @import("db");
const context_mod = @import("context");
const block_validation = @import("./block_validation.zig");

/// Re-export so callers can use these types without importing executor_types directly.
pub const BlockHashEntry = types.BlockHashEntry;
pub const AllocAccount = types.AllocAccount;
pub const computeRawTxRoot = output_mod.computeRawTxRoot;

/// Sub-module re-exports for tools — use @import("executor").executor_types etc.
pub const executor_types = @import("executor_types");
pub const executor_exceptions = @import("./exceptions.zig");
pub const executor_transition = @import("./transition.zig");
pub const executor_output = @import("./output.zig");
pub const executor_tx_decode = @import("./tx_decode.zig");
pub const executor_rlp_encode = @import("./rlp_encode.zig");

// ─── Private helpers ──────────────────────────────────────────────────────────

fn mapWithdrawals(alloc: std.mem.Allocator, withdrawals: []const input.Withdrawal) ![]types.Withdrawal {
    const out = try alloc.alloc(types.Withdrawal, withdrawals.len);
    for (withdrawals, 0..) |wd, i| {
        out[i] = .{ .index = wd.index, .validator_index = wd.validator_index, .address = wd.address, .amount = wd.amount };
    }
    return out;
}

fn buildEnv(
    req: input.NewPayloadRequest,
    block_hashes: []types.BlockHashEntry,
    withdrawals: []types.Withdrawal,
    parent: ?rlp_decode.ParentHeader,
) types.Env {
    const ep = &req.execution_payload;
    return .{
        .coinbase = ep.fee_recipient,
        .gas_limit = ep.gas_limit,
        .number = ep.block_number,
        .timestamp = ep.timestamp,
        .difficulty = 0,
        .base_fee = ep.base_fee_per_gas,
        .random = ep.prev_randao,
        .excess_blob_gas = ep.excess_blob_gas,
        .parent_beacon_block_root = req.parent_beacon_block_root,
        .parent_hash = ep.parent_hash,
        .block_hashes = block_hashes,
        .withdrawals = withdrawals,
        .slot_number = ep.slot_number,
        .gas_used_header = ep.gas_used,
        .blob_gas_used_header = ep.blob_gas_used,
        .parent_gas_limit = if (parent) |p| p.gas_limit else null,
        .parent_gas_used = if (parent) |p| p.gas_used else null,
        .parent_timestamp = if (parent) |p| p.timestamp else null,
        .parent_base_fee = if (parent) |p| p.base_fee_per_gas else null,
        .parent_blob_gas_used = if (parent) |p| p.blob_gas_used else null,
        .parent_excess_blob_gas = if (parent) |p| p.excess_blob_gas else null,
    };
}

/// Sentinel used by non-stateless executeBlock path: pre_alloc entries already carry
/// pre_storage_root; storageRootFor is never called in practice.
const NullStorageRoots = struct {
    pub fn storageRootFor(_: *const @This(), _: types.Address) ?types.Hash {
        return null;
    }
};

fn finalizeOutput(
    alloc: std.mem.Allocator,
    pre_state_root: [32]u8,
    result: transition_mod.TransitionResult,
    node_index: *mpt.NodeIndex,
    spec: primitives.SpecId,
    witness_db: anytype,
) !output.ProofOutput {
    const post_state_root = try output_mod.computeStateRootDelta(alloc, pre_state_root, result.alloc, result.deleted_accounts, node_index, witness_db);
    const receipts_root = try output_mod.computeReceiptsRoot(alloc, result.receipts);
    const receipts_data = try alloc.alloc(output.ReceiptData, result.receipts.len);
    for (result.receipts, 0..) |r, i| {
        receipts_data[i] = .{ .cumulative_gas_used = r.cumulative_gas_used, .success = r.status == 1, .logs_bloom = r.logs_bloom };
    }
    return .{
        .pre_state_root = pre_state_root,
        .post_state_root = post_state_root,
        .receipts_root = receipts_root,
        .receipts = receipts_data,
        .fork_name = fork_mod.specName(spec),
    };
}

fn u256ToHashLocal(value: u256) types.Hash {
    var out: types.Hash = @splat(0);
    var n = value;
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        out[i] = @intCast(n & 0xff);
        n >>= 8;
    }
    return out;
}

/// EIP system caller — accessed during system contract calls but excluded from the BAL.
const SYSTEM_ADDRESS: types.Address = .{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe,
};

/// Build a sorted slice of AccessedEntry from the WitnessDatabase access log
/// and the post-execution alloc delta.  The result is sorted ascending by address.
fn buildAccessedEntries(
    alloc: std.mem.Allocator,
    access_log: context_mod.AccessLog,
    post_alloc: std.AutoHashMapUnmanaged(types.Address, types.AllocAccount),
    deleted_accounts: []const types.Address,
) ![]types.AccessedEntry {
    var entries = std.ArrayListUnmanaged(types.AccessedEntry).empty;

    var addr_iter = access_log.accounts.iterator();
    while (addr_iter.next()) |acc_kv| {
        const address = acc_kv.key_ptr.*;
        // The EIP system caller address is a virtual address used to invoke system
        // contracts.  It is excluded from the BAL UNLESS ETH was actually sent to it
        // by a user transaction (in which case it has a real balance change and IS
        // included — e.g., test_selfdestruct_to_system_address).
        if (std.mem.eql(u8, &address, &SYSTEM_ADDRESS)) {
            if (post_alloc.get(address)) |p| {
                // Include only if balance genuinely changed (ETH was sent to SYSTEM_ADDRESS).
                if (p.balance == 0) continue;
                // Otherwise fall through: SYSTEM_ADDRESS has a real balance and belongs in BAL.
            } else continue;
        }
        const pre = acc_kv.value_ptr.*;

        const post_acct = post_alloc.get(address);

        // Selfdestructed accounts are removed from post_alloc by extractPostState.
        // For EIP-7928 BAL purposes their post-state is effectively empty (balance=0,
        // nonce unchanged, code cleared, storage cleared).  Fall back to 0/empty
        // rather than pre-state values so we correctly detect the balance change.
        const is_deleted = for (deleted_accounts) |da| {
            if (std.mem.eql(u8, &da, &address)) break true;
        } else false;

        const post_nonce = if (post_acct) |p| p.nonce else pre.nonce;
        const post_balance: u256 = if (post_acct) |p| p.balance else if (is_deleted) 0 else pre.balance;
        const post_code_hash: types.Hash = if (post_acct) |p| blk: {
            if (p.code_hash) |ch| break :blk ch;
            if (p.code.len > 0) break :blk mpt.keccak256(p.code);
            break :blk primitives.KECCAK_EMPTY;
        } else if (is_deleted) primitives.KECCAK_EMPTY else pre.code_hash;

        var storage_changes = std.ArrayListUnmanaged(types.StorageChange).empty;
        var storage_reads = std.ArrayListUnmanaged(types.Hash).empty;

        const witness_storage = access_log.storage.get(address);
        if (witness_storage) |inner| {
            var slot_map = inner;
            var slot_iter = slot_map.iterator();
            while (slot_iter.next()) |slot_kv| {
                const slot_key = slot_kv.key_ptr.*;
                const pre_val = slot_kv.value_ptr.*;
                const post_val = if (post_acct) |p| p.storage.get(slot_key) orelse pre_val else if (is_deleted) 0 else pre_val;
                const slot_hash = u256ToHashLocal(slot_key);
                // EIP-7928: a slot is a storageChange if its final value differs from the
                // pre-block value, OR if it was committed to a different value at any tx
                // boundary (cross-tx net-zero write: 0→X committed in tx1, X→0 in tx2).
                // Within-tx net-zero writes (0→X→0 all in one tx) are storageReads since
                // the tx-level committed value never left the pre-block value.
                const was_cross_tx_changed = if (access_log.committed_changed.get(address)) |slots|
                    slots.contains(slot_key)
                else
                    false;
                if (post_val != pre_val or was_cross_tx_changed) {
                    try storage_changes.append(alloc, .{ .slot = slot_hash, .post_value = post_val });
                } else {
                    try storage_reads.append(alloc, slot_hash);
                }
            }
        }

        // Also capture storage changes that weren't routed through WitnessDatabase.
        // This happens for newly-created contracts: zevm's sload() returns 0 for
        // `is_newly_created` accounts without calling db.storage(), so those slots
        // are absent from witness_storage.  For these slots pre_val is always 0.
        if (post_acct) |p| {
            var post_iter = p.storage.iterator();
            while (post_iter.next()) |post_kv| {
                const slot_key = post_kv.key_ptr.*;
                const post_val = post_kv.value_ptr.*;
                // Skip zero-value slots: pre_val is always 0 for newly-created accounts,
                // so post_val == 0 means no net change (net-zero write or just zero).
                if (post_val == 0) continue;
                const already_tracked = if (witness_storage) |ws| ws.get(slot_key) != null else false;
                if (already_tracked) continue;
                const slot_hash = u256ToHashLocal(slot_key);
                try storage_changes.append(alloc, .{ .slot = slot_hash, .post_value = post_val });
            }
        }

        std.mem.sort(types.StorageChange, storage_changes.items, {}, struct {
            pub fn lessThan(_: void, a: types.StorageChange, b: types.StorageChange) bool {
                return std.mem.lessThan(u8, &a.slot, &b.slot);
            }
        }.lessThan);
        std.mem.sort(types.Hash, storage_reads.items, {}, struct {
            pub fn lessThan(_: void, a: types.Hash, b: types.Hash) bool {
                return std.mem.lessThan(u8, &a, &b);
            }
        }.lessThan);

        try entries.append(alloc, .{
            .address = address,
            .pre_nonce = pre.nonce,
            .pre_balance = pre.balance,
            .pre_code_hash = pre.code_hash,
            .post_nonce = post_nonce,
            .post_balance = post_balance,
            .post_code_hash = post_code_hash,
            .storage_changes = try storage_changes.toOwnedSlice(alloc),
            .storage_reads = try storage_reads.toOwnedSlice(alloc),
        });
    }

    // Also include accounts that appear in post_alloc but were NOT tracked via
    // WitnessDatabase.basic() (e.g., SELFDESTRUCT beneficiary that returned InvalidProof
    // because its non-existence proof was absent from the witness — still a real access).
    var post_iter2 = post_alloc.iterator();
    while (post_iter2.next()) |kv| {
        const address = kv.key_ptr.*;
        if (access_log.accounts.contains(address)) continue; // already handled above
        // Skip addresses that aren't real state changes (coinbase zero-balance etc.)
        const p = kv.value_ptr.*;
        // Empty pre-state for accounts not in the access log.
        const pre_empty = context_mod.AccountPreState{};
        const is_deleted = for (deleted_accounts) |da| {
            if (std.mem.eql(u8, &da, &address)) break true;
        } else false;
        const post_balance: u256 = if (is_deleted) 0 else p.balance;
        const post_code_hash: types.Hash = if (p.code_hash) |ch| ch else if (p.code.len > 0) mpt.keccak256(p.code) else primitives.KECCAK_EMPTY;
        // Skip if no actual change from empty pre-state.
        if (post_balance == 0 and p.nonce == 0 and
            std.mem.eql(u8, &post_code_hash, &primitives.KECCAK_EMPTY) and
            p.storage.count() == 0 and !is_deleted) continue;

        var storage_changes2 = std.ArrayListUnmanaged(types.StorageChange).empty;
        var post_storage_iter = p.storage.iterator();
        while (post_storage_iter.next()) |slot_kv| {
            const slot_key = slot_kv.key_ptr.*;
            const post_val = slot_kv.value_ptr.*;
            if (post_val == 0) continue;
            try storage_changes2.append(alloc, .{ .slot = u256ToHashLocal(slot_key), .post_value = post_val });
        }
        std.mem.sort(types.StorageChange, storage_changes2.items, {}, struct {
            pub fn lessThan(_: void, a: types.StorageChange, b: types.StorageChange) bool {
                return std.mem.lessThan(u8, &a.slot, &b.slot);
            }
        }.lessThan);

        try entries.append(alloc, .{
            .address = address,
            .pre_nonce = pre_empty.nonce,
            .pre_balance = pre_empty.balance,
            .pre_code_hash = pre_empty.code_hash,
            .post_nonce = p.nonce,
            .post_balance = post_balance,
            .post_code_hash = post_code_hash,
            .storage_changes = try storage_changes2.toOwnedSlice(alloc),
            .storage_reads = &.{},
        });
    }

    const SortEntry = struct { addr: [20]u8, idx: u32 };
    const sort_buf = try alloc.alloc(SortEntry, entries.items.len);
    defer alloc.free(sort_buf);
    for (entries.items, 0..) |e, i| sort_buf[i] = .{ .addr = e.address, .idx = @intCast(i) };
    std.mem.sort(SortEntry, sort_buf, {}, struct {
        fn lt(_: void, a: SortEntry, b: SortEntry) bool {
            return std.mem.lessThan(u8, &a.addr, &b.addr);
        }
    }.lt);
    const sorted = try alloc.alloc(types.AccessedEntry, entries.items.len);
    for (sort_buf, 0..) |sb, j| sorted[j] = entries.items[sb.idx];
    entries.deinit(alloc);
    return sorted;
}

// ─── Public API ───────────────────────────────────────────────────────────────

pub const ExecuteBlockResult = struct {
    post_state_root: [32]u8,
    receipts_root: [32]u8,
    post_alloc: std.AutoHashMapUnmanaged(types.Address, types.AllocAccount),
    receipts: []transition_mod.Receipt,
    bal_hash: ?types.Hash = null,
    requests_hash: [32]u8 = [_]u8{0} ** 32,
};

pub fn executeBlockFromAlloc(
    alloc: std.mem.Allocator,
    pre_alloc: std.AutoHashMapUnmanaged(types.Address, types.AllocAccount),
    env: types.Env,
    txs: []types.TxInput,
    spec: primitives.SpecId,
    chain_id: u64,
    reward: i64,
) !ExecuteBlockResult {
    try block_validation.validateBlock(env, spec);
    const result = try transition_mod.transition(alloc, pre_alloc, env, txs, spec, chain_id, reward);
    try block_validation.validatePostExecution(alloc, env, spec, result.cumulative_gas, result.blob_gas_used, &.{}, &.{});
    const post_state_root = try output_mod.computeStateRoot(alloc, result.alloc, &.{});
    const receipts_root = try output_mod.computeReceiptsRoot(alloc, result.receipts);
    return .{
        .post_state_root = post_state_root,
        .receipts_root = receipts_root,
        .post_alloc = result.alloc,
        .receipts = result.receipts,
        .bal_hash = result.bal_hash,
        .requests_hash = result.requests_hash,
    };
}

pub fn executeBlock(
    alloc: std.mem.Allocator,
    pre_state_root: [32]u8,
    pre_alloc: std.AutoHashMapUnmanaged(types.Address, types.AllocAccount),
    index: *mpt.NodeIndex,
    req: input.NewPayloadRequest,
    block_hashes: []types.BlockHashEntry,
    fork_name: ?[]const u8,
) !output.ProofOutput {
    const ep = &req.execution_payload;
    const spec = if (fork_name) |name|
        fork_mod.specForBlock(name, ep.timestamp) orelse fork_mod.mainnetSpec(ep.block_number, ep.timestamp)
    else
        fork_mod.mainnetSpec(ep.block_number, ep.timestamp);

    const env = buildEnv(req, block_hashes, try mapWithdrawals(alloc, ep.withdrawals), null);
    try block_validation.validateBlock(env, spec);
    const txs = try tx_decode.decodeTxsFromInput(alloc, ep.transactions);
    const result = try transition_mod.transition(alloc, pre_alloc, env, txs, spec, 1, fork_mod.blockReward(spec));
    const null_roots = NullStorageRoots{};
    return finalizeOutput(alloc, pre_state_root, result, index, spec, &null_roots);
}

/// Stateless block execution: serves all account/storage reads from the MPT witness
/// via `WitnessDatabase` (no pre-built pre_alloc needed).
///
/// `parent_header`: parent block's gas/basefee/blob-gas fields, decoded by the caller
/// from the witness header whose hash equals `ep.parent_hash`. Used to enforce the
/// EIP-1559 basefee and EIP-4844 excess-blob-gas checks. Pass `null` to skip them
/// (e.g. when the parent is the genesis block and no header is in the witness).
pub fn executeBlockStateless(
    alloc: std.mem.Allocator,
    pre_state_root: [32]u8,
    node_index: *mpt.NodeIndex,
    req: input.NewPayloadRequest,
    witness_codes: []const []const u8,
    block_hashes: []types.BlockHashEntry,
    parent_header: ?rlp_decode.ParentHeader,
    fork_name: ?[]const u8,
    chain_id: u64,
    public_keys: []const []const u8,
) !output.ProofOutput {
    const ep = &req.execution_payload;

    const spec = if (fork_name) |name|
        fork_mod.specForBlock(name, ep.timestamp) orelse fork_mod.mainnetSpec(ep.block_number, ep.timestamp)
    else
        fork_mod.mainnetSpec(ep.block_number, ep.timestamp);

    const env = buildEnv(req, block_hashes, try mapWithdrawals(alloc, ep.withdrawals), parent_header);
    try block_validation.validateBlock(env, spec);
    const txs = try tx_decode.decodeTxsFromInput(alloc, ep.transactions);

    var ctx = context_mod.Context(db_mod.WitnessDatabase).new(
        try db_mod.WitnessDatabase.init(alloc, node_index, pre_state_root, witness_codes, block_hashes),
        spec,
    );
    ctx.block = transition_mod.buildBlockEnv(env, spec);
    ctx.cfg.chain_id = chain_id;
    ctx.cfg.disable_base_fee = (env.base_fee == null);

    const empty_pre_alloc = std.AutoHashMapUnmanaged(types.Address, types.AllocAccount).empty;
    const result = try transition_mod.transitionWithContext(
        alloc,
        &ctx,
        empty_pre_alloc,
        env,
        txs,
        spec,
        chain_id,
        fork_mod.blockReward(spec),
        public_keys,
    );
    if (ctx.ctx_error != .ok) return error.InvalidWitness;
    var access_log = ctx.journaled_state.takeAccessLog();
    defer access_log.deinit();
    const accessed = try buildAccessedEntries(alloc, access_log, result.alloc, result.deleted_accounts);
    try block_validation.validatePostExecution(alloc, env, spec, result.cumulative_gas, result.blob_gas_used, ep.block_access_list, accessed);
    return finalizeOutput(alloc, pre_state_root, result, node_index, spec, ctx.getDb());
}

/// High-level stateless execution from a fully-decoded StatelessInput.
/// Derives pre_state_root, builds the node index and block-hash table
/// internally — callers only need to supply the input and an optional
/// fork override.
pub fn executeStatelessInput(
    alloc: std.mem.Allocator,
    si: input.StatelessInput,
    fork_name: ?[]const u8,
) !output.ProofOutput {
    const ep = &si.new_payload_request.execution_payload;

    const pre_state_root_raw = rlp_decode.findPreStateRoot(si.witness.headers, ep.block_number);
    const pre_state_root = pre_state_root_raw orelse ep.state_root;

    var node_index = try mpt.buildNodeIndex(alloc, si.witness.nodes);
    defer node_index.deinit();

    const HeaderInfo = struct { number: u64, parent_hash: [32]u8, hash: [32]u8 };
    var header_infos = std.ArrayListUnmanaged(HeaderInfo).empty;
    var block_hashes = std.ArrayListUnmanaged(BlockHashEntry).empty;
    for (si.witness.headers) |hdr_rlp| {
        const hash = mpt.keccak256(hdr_rlp);
        const outer = mpt.rlp.decodeItem(hdr_rlp) catch return error.InvalidWitness;
        var rest = switch (outer.item) {
            .list => |p| p,
            .bytes => return error.InvalidWitness,
        };
        // Field [0]: parent_hash (32-byte bytes item)
        const ph_r = mpt.rlp.decodeItem(rest) catch return error.InvalidWitness;
        const ph_bytes = switch (ph_r.item) {
            .bytes => |b| b,
            .list => return error.InvalidWitness,
        };
        if (ph_bytes.len != 32) return error.InvalidWitness;
        var parent_hash: [32]u8 = undefined;
        @memcpy(&parent_hash, ph_bytes);
        rest = rest[ph_r.consumed..];
        // Skip fields [1]-[7] (7 fields between parent_hash and block number)
        var skip: usize = 0;
        while (skip < 7 and rest.len > 0) : (skip += 1) {
            const fr = mpt.rlp.decodeItem(rest) catch return error.InvalidWitness;
            rest = rest[fr.consumed..];
        }
        if (rest.len == 0) return error.InvalidWitness;
        const num_r = mpt.rlp.decodeItem(rest) catch return error.InvalidWitness;
        const num_bytes = switch (num_r.item) {
            .bytes => |b| b,
            .list => return error.InvalidWitness,
        };
        if (num_bytes.len > 8) return error.InvalidWitness;
        var number: u64 = 0;
        for (num_bytes) |b| number = (number << 8) | b;
        try block_hashes.append(alloc, .{ .number = number, .hash = hash });
        try header_infos.append(alloc, .{ .number = number, .parent_hash = parent_hash, .hash = hash });
    }

    // Validate header chain: headers must be provided in ascending block-number order
    // (each header's keccak256 must equal the next header's parent_hash), and the
    // last header's hash must match EP.parent_hash (chain anchor). Out-of-order
    // headers (e.g. reversed) break the hash-linkage check and are rejected.
    // After chain validation, the last header IS the parent block — decode its
    // gas/basefee/blob-gas fields so executeBlockStateless can populate Env.parent_*.
    var parent_header: ?rlp_decode.ParentHeader = null;
    if (header_infos.items.len > 0) {
        for (0..header_infos.items.len - 1) |k| {
            if (!std.mem.eql(u8, &header_infos.items[k].hash, &header_infos.items[k + 1].parent_hash)) {
                return error.InvalidWitness;
            }
        }
        const last = header_infos.items[header_infos.items.len - 1];
        if (!std.mem.eql(u8, &last.hash, &ep.parent_hash)) {
            return error.InvalidWitness;
        }
        parent_header = rlp_decode.decodeParentHeader(si.witness.headers[si.witness.headers.len - 1]) catch
            return error.InvalidWitness;
    }

    return executeBlockStateless(
        alloc,
        pre_state_root,
        &node_index,
        si.new_payload_request,
        si.witness.codes,
        block_hashes.items,
        parent_header,
        fork_name,
        si.chain_config.chain_id,
        si.public_keys,
    );
}
