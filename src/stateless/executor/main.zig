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
const block_hash = @import("./block_hash.zig");
const block_rlp_size = @import("block_rlp_size");

/// Re-export so callers can use these types without importing executor_types directly.
pub const BlockHashEntry = types.BlockHashEntry;
pub const AllocAccount = types.AllocAccount;
pub const computeRawTxRoot = output_mod.computeRawTxRoot;
pub const executor_block_validation = block_validation;
pub const executor_tx_signing = @import("./tx_signing.zig");

/// Sub-module re-exports for tools — use @import("executor").executor_types etc.
pub const executor_types = @import("executor_types");
pub const executor_exceptions = @import("./exceptions.zig");
pub const executor_transition = @import("./transition.zig");
pub const executor_output = @import("./output.zig");
pub const executor_tx_decode = @import("./tx_decode.zig");
pub const executor_rlp_encode = @import("./rlp_encode.zig");

// Sub-file tests are only collected when the file is referenced from the test root.
test {
    _ = block_rlp_size;
    // Zig only analyses a pub fn when something references it, so an entry point
    // with no in-repo caller can go stale and still compile. refAllDecls forces
    // every declaration through semantic analysis, so a signature change that
    // misses a call site fails `zig build test`.
    std.testing.refAllDecls(@This());
    // transition_tests.zig is a leaf test file nothing else imports, so it must be
    // referenced explicitly to be pulled into the test graph.
    _ = @import("./transition_tests.zig");
}

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
    spec: primitives.SpecId,
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
        // EIP-7934: the guest never sees the block's RLP, so its size is derived
        // from the payload fields (block_rlp_size.compute).
        .block_rlp_size = block_rlp_size.compute(ep, spec),
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
const SYSTEM_ADDRESS = primitives.SYSTEM_ADDRESS;

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
    try block_validation.validatePostExecution(env, spec, result.cumulative_gas, result.blob_gas_used, null, null);
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
    /// The payload's requests and block access list hashes, which execution must reproduce
    /// (fork.py `execute_block`).
    requests_hash: [32]u8,
    block_access_list_hash: [32]u8,
) !output.ProofOutput {
    const ep = &req.execution_payload;
    const spec = resolveSpec(ep, fork_name);

    const env = buildEnv(req, block_hashes, try mapWithdrawals(alloc, ep.withdrawals), parent_header, spec);
    try block_validation.validateBlock(env, spec);
    const txs = try tx_decode.decodeTxsFromInput(alloc, ep.transactions);

    var ctx = context_mod.Context(db_mod.WitnessDatabase).new(
        try db_mod.WitnessDatabase.init(alloc, node_index, pre_state_root, witness_codes, block_hashes),
        spec,
    );
    // Both the journal (evm_state, BAL maps, logs, etc.) and the WitnessDatabase
    // (witness_codes, deployed_codes, storage_root_cache) must be freed explicitly.
    // Both defers are declared before the defers below so they run last — after
    // finalizeOutput and validatePostExecution have consumed all journal- and
    // database-owned memory. Database is declared first so it runs after the journal
    // (LIFO): evm_state code references into the database are freed before the database itself.
    defer ctx.journaled_state.database.deinit();
    defer ctx.journaled_state.deinit();
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
    );
    // Backstop for a database error raised after the per-tx loop (mining reward,
    // withdrawals, post-block system calls) -- transitionWithContext only bails
    // out early on ctx_error while looping over transactions.
    if (ctx.ctx_error != .ok) return error.InvalidWitness;
    // Compute the commitments first so validatePostExecution can validate them
    // against the payload alongside its gas/blob/BAL checks — giving every caller
    // one authoritative verdict instead of re-comparing the roots itself.
    const proof = try finalizeOutput(alloc, pre_state_root, result, node_index, spec, ctx.getDb());
    try block_validation.validatePostExecution(env, spec, result.cumulative_gas, result.blob_gas_used, if (result.bal_hash) |h| .{ .computed = h, .expected = block_access_list_hash } else null, .{
        .computed_state_root = proof.post_state_root,
        .expected_state_root = ep.state_root,
        .computed_receipts_root = proof.receipts_root,
        .expected_receipts_root = ep.receipts_root,
    });
    if (primitives.isEnabledIn(spec, .prague) and !std.mem.eql(u8, &requests_hash, &result.requests_hash)) return error.InvalidRequests;
    return proof;
}

/// Decode the payload's opaque transaction bytes. The SSZ decoder leaves them
/// undecoded: a transaction that fails to decode invalidates the block, not the input.
fn decodePayloadTransactions(alloc: std.mem.Allocator, ep: *input.ExecutionPayload) !void {
    const transactions = try alloc.alloc(input.Transaction, ep.raw_transactions.len);
    for (ep.raw_transactions, transactions) |raw, *tx| tx.* = try rlp_decode.decodeSingleTx(alloc, raw);
    ep.transactions = transactions;
}

fn resolveSpec(ep: *const input.ExecutionPayload, fork_name: ?[]const u8) primitives.SpecId {
    if (fork_name) |name| {
        if (fork_mod.specForBlock(name, ep.timestamp)) |spec| return spec;
    }
    return fork_mod.mainnetSpec(ep.block_number, ep.timestamp);
}

/// High-level stateless execution from a fully-decoded StatelessInput.
/// Derives pre_state_root, builds the node index and block-hash table
/// internally — callers only need to supply the input and an optional
/// fork override.
pub fn executeStatelessInput(
    alloc: std.mem.Allocator,
    si_in: input.StatelessInput,
    fork_name: ?[]const u8,
) !output.ProofOutput {
    var si = si_in;
    const ep = &si.new_payload_request.execution_payload;

    const er = si.new_payload_request.execution_requests;
    const requests_hash = try transition_mod.computeRequestsHash(alloc, er.deposits, er.withdrawals, er.consolidations, er.builder_deposits, er.builder_exits);
    const block_access_list_hash = mpt.keccak256(ep.block_access_list);
    try block_hash.validate(alloc, si.new_payload_request, resolveSpec(ep, fork_name), requests_hash, block_access_list_hash);

    try decodePayloadTransactions(alloc, ep);

    // EIP-4844 / engine API: the payload's versioned hashes must equal the blob
    // hashes of its blob transactions, concatenated in transaction order
    // (reference execution_engine/new_payload.py is_valid_versioned_hashes).
    {
        var next: usize = 0;
        for (ep.transactions) |tx| {
            if (tx.tx_type != 3) continue;
            for (tx.blob_hashes) |h| {
                if (next >= si.new_payload_request.versioned_hashes.len) return error.InvalidVersionedHashes;
                if (!std.mem.eql(u8, &si.new_payload_request.versioned_hashes[next], &h)) return error.InvalidVersionedHashes;
                next += 1;
            }
        }
        if (next != si.new_payload_request.versioned_hashes.len) return error.InvalidVersionedHashes;
    }

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
    // gas/basefee/blob-gas fields so ckStateless can populate Env.parent_*.
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
        requests_hash,
        block_access_list_hash,
    );
}
