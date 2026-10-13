/// EIP system contract call handlers for pre- and post-block processing.
///
/// "System contract calls" here refers to EVM-level calls made by the
/// protocol itself (from SYSTEM_ADDRESS) to designated system contracts —
/// not OS/machine-level system calls.
///
/// All system contract calls execute outside normal gas accounting and
/// tx validation. State changes are committed on success and discarded
/// on revert.
///
/// Pre-block  (Cancun+/Prague+, before user transactions):
///   EIP-4788 — call beacon roots contract with parent_beacon_block_root as calldata.
///   EIP-2935 — call block history contract with parent_hash as calldata.
///
/// Post-block (Prague+, after user transactions):
///   EIP-7002 — withdrawal requests system contract call.
///   EIP-7251 — consolidation requests system contract call.
const std = @import("std");
const primitives = @import("primitives");
const input = @import("executor_types");
const SystemContracts = @import("input").SystemContracts;
const context_mod = @import("context");
const handler_mod = @import("handler");
const alloc_mod = @import("zesu_allocator");
const gas_costs = @import("interpreter").gas_costs;

/// EIP-8037 (Amsterdam+): SYSTEM_CALL_GAS_LIMIT = 30M + STATE_BYTES_PER_STORAGE_SET * CPSB * SYSTEM_MAX_SSTORES_PER_CALL.
/// The extra portion is intended as the system call state-gas reservoir.
/// Pre-Amsterdam: spec gives each system contract a flat 30M.
fn systemCallGasLimit(spec: primitives.SpecId) u64 {
    const base: u64 = 30_000_000 + 21_000; // 30M + intrinsic 21k (deducted before frame start)
    if (!primitives.isEnabledIn(spec, .amsterdam)) return base;
    const cpsb = gas_costs.costPerStateByte(0);
    return base + gas_costs.STATE_BYTES_PER_STORAGE_SET * cpsb * gas_costs.SYSTEM_MAX_SSTORES_PER_CALL;
}

// ─── Well-known addresses ─────────────────────────────────────────────────────

// The system contract addresses (EIP-4788/2935/7002/7251/8282) are chain
// configuration (input.SystemContracts) and are passed in by the caller.

const SYSTEM_ADDRESS = primitives.SYSTEM_ADDRESS;

// ─── Shared execution helper ──────────────────────────────────────────────────

/// Execute a single privileged system call as SYSTEM_ADDRESS.
///
/// Skips the call silently if the target contract is not deployed.
/// Discards state on any execution error — a broken system contract must not
/// invalidate the block. When `capture` is true, returns a caller-owned copy of
/// the call's return data and surfaces execution failure as
/// error.SystemContractCallFailed (see applyPostBlockCallsCapture); when false,
/// the call is fire-and-forget (see applyPreBlockCalls).
fn runSystemCallImpl(
    comptime capture: bool,
    ctx: anytype,
    instructions: *handler_mod.Instructions,
    precompiles: *handler_mod.Precompiles,
    target: input.Address,
    calldata: []const u8,
    chain_id: u64,
    alloc: if (capture) std.mem.Allocator else void,
) if (capture) error{SystemContractCallFailed}![]const u8 else void {
    const SYSTEM_CALL_GAS: u64 = systemCallGasLimit(ctx.cfg.spec);

    const account_load = ctx.journaled_state.loadAccount(target) catch {
        ctx.journaled_state.discardTx();
        return if (capture) &.{} else {};
    };
    // Skip the call if the contract has no code (also covers non-existing accounts).
    // EIP-7928 (Amsterdam+): the reference process_unchecked_system_transaction still
    // reads the target account (get_account → account_reads), so it belongs in the block
    // access list even when absent. commitTx (rather than discardTx) flushes that read into
    // the permanent BAL while still leaving the account cold for user transactions — commitTx
    // bumps the journal transaction_id, so its EIP-2929 warmth does not carry over.
    if (std.mem.eql(u8, &account_load.data.info.code_hash, &primitives.KECCAK_EMPTY)) {
        ctx.journaled_state.commitTx();
        return if (capture) &.{} else {};
    }

    // Bypass normal tx validation for system calls.
    const saved_nonce = ctx.cfg.disable_nonce_check;
    const saved_bal = ctx.cfg.disable_balance_check;
    const saved_fee = ctx.cfg.disable_fee_charge;
    const saved_basefee = ctx.cfg.disable_base_fee;
    const saved_block_gas = ctx.cfg.disable_block_gas_limit;
    const saved_chain_id_check = ctx.cfg.tx_chain_id_check;
    const saved_cfg_chain_id = ctx.cfg.chain_id;
    const saved_system_call_gas = ctx.cfg.system_call_gas;
    if (primitives.isEnabledIn(ctx.cfg.spec, .amsterdam)) {
        ctx.cfg.system_call_gas = .{
            .execution = 30_000_000,
            .reservoir = gas_costs.STATE_BYTES_PER_STORAGE_SET * gas_costs.costPerStateByte(0) * gas_costs.SYSTEM_MAX_SSTORES_PER_CALL,
        };
    }
    ctx.cfg.disable_nonce_check = true;
    ctx.cfg.disable_balance_check = true;
    ctx.cfg.disable_fee_charge = true;
    ctx.cfg.disable_base_fee = true;
    ctx.cfg.disable_block_gas_limit = true;
    ctx.cfg.tx_chain_id_check = false;
    ctx.cfg.chain_id = chain_id;
    defer {
        ctx.cfg.disable_nonce_check = saved_nonce;
        ctx.cfg.disable_balance_check = saved_bal;
        ctx.cfg.disable_fee_charge = saved_fee;
        ctx.cfg.disable_base_fee = saved_basefee;
        ctx.cfg.disable_block_gas_limit = saved_block_gas;
        ctx.cfg.tx_chain_id_check = saved_chain_id_check;
        ctx.cfg.chain_id = saved_cfg_chain_id;
        ctx.cfg.system_call_gas = saved_system_call_gas;
    }

    // Set up calldata (may be empty for post-block calls).
    var data_list: ?std.ArrayList(u8) = null;
    if (calldata.len > 0) {
        var dl = std.ArrayList(u8).empty;
        dl.appendSlice(alloc_mod.get(), calldata) catch return if (capture) &.{} else {};
        data_list = dl;
    }

    ctx.tx.caller = SYSTEM_ADDRESS;
    ctx.tx.kind = context_mod.TxKind{ .Call = target };
    ctx.tx.gas_limit = SYSTEM_CALL_GAS;
    ctx.tx.gas_price = 0;
    ctx.tx.gas_priority_fee = null;
    ctx.tx.value = 0;
    ctx.tx.nonce = 0;
    ctx.tx.tx_type = 0;
    ctx.tx.data = data_list;
    ctx.tx.access_list = context_mod.AccessList{ .items = null };
    ctx.tx.blob_hashes = null;
    ctx.tx.authorization_list = null;
    ctx.tx.chain_id = chain_id;

    // The reference never reads a system call's origin, so SYSTEM_ADDRESS may be absent
    // from the witness. Allow that only for this call's own load of it, then drop the
    // cached account so a later real read of SYSTEM_ADDRESS has to be proved.
    const origin_was_loaded = ctx.journaled_state.inner.evm_state.contains(SYSTEM_ADDRESS);
    setSystemCallOrigin(ctx, true);
    defer {
        setSystemCallOrigin(ctx, false);
        if (!origin_was_loaded) {
            if (ctx.journaled_state.inner.evm_state.fetchRemove(SYSTEM_ADDRESS)) |kv| {
                var acct = kv.value;
                acct.storage.deinit();
            }
        }
    }

    const EvmT = handler_mod.EvmFor(@TypeOf(ctx.*).DatabaseType);
    var evm = EvmT.init(ctx, null, instructions, precompiles);
    var result = handler_mod.ExecuteEvm.execute(&evm) catch {
        ctx.journaled_state.discardTx();
        if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
        ctx.tx.data = null;
        return if (capture) error.SystemContractCallFailed else {};
    };
    defer result.deinit();

    if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
    ctx.tx.data = null;

    // System calls must not increment the caller's nonce.
    // zevm always bumps nonce unconditionally, so patch it back.
    if (ctx.journaled_state.inner.evm_state.getPtr(SYSTEM_ADDRESS)) |sa| {
        if (sa.info.nonce > 0) sa.info.nonce -= 1;
    }

    if (!capture) return;
    if (result.status != .Success) return error.SystemContractCallFailed;
    return if (result.return_data.len > 0) alloc.dupe(u8, result.return_data) catch &.{} else &.{};
}

/// Mark the witness database's reads as a system call's (see WitnessDatabase.system_call_origin).
/// A no-op for databases without the flag.
fn setSystemCallOrigin(ctx: anytype, on: bool) void {
    if (@hasField(@TypeOf(ctx.journaled_state.database), "system_call_origin")) {
        ctx.journaled_state.database.system_call_origin = on;
    }
}

/// Fire-and-forget system call (pre-block: EIP-4788/EIP-2935). See runSystemCallImpl.
fn runSystemCall(
    ctx: anytype,
    instructions: *handler_mod.Instructions,
    precompiles: *handler_mod.Precompiles,
    target: input.Address,
    calldata: []const u8,
    chain_id: u64,
) void {
    runSystemCallImpl(false, ctx, instructions, precompiles, target, calldata, chain_id, {});
}

// ─── Pre-block system calls ───────────────────────────────────────────────────

/// Call the EIP-4788 (Cancun+) and EIP-2935 (Prague+) system contracts before
/// executing user transactions. Each call passes the relevant 32-byte hash as
/// calldata; the contract code handles the storage write.
pub fn applyPreBlockCalls(
    ctx: anytype,
    instructions: *handler_mod.Instructions,
    precompiles: *handler_mod.Precompiles,
    env: input.Env,
    spec: primitives.SpecId,
    chain_id: u64,
    contracts: SystemContracts,
) void {
    if (primitives.isEnabledIn(spec, .cancun)) {
        if (env.parent_beacon_block_root) |root| {
            runSystemCall(ctx, instructions, precompiles, contracts.beacon_roots, &root, chain_id);
        }
    }
    if (primitives.isEnabledIn(spec, .prague)) {
        if (env.parent_hash) |parent_hash| {
            runSystemCall(ctx, instructions, precompiles, contracts.history_storage, &parent_hash, chain_id);
        }
    }
}

// ─── Post-block system calls ──────────────────────────────────────────────────

pub const PostBlockRequestBytes = struct {
    /// Raw return bytes from the EIP-7002 system contract (76 bytes × n withdrawals).
    withdrawal_requests: []const u8,
    /// Raw return bytes from the EIP-7251 system contract (116 bytes × n consolidations).
    consolidation_requests: []const u8,
    /// EIP-8282 (Amsterdam+): raw return bytes from the builder deposit system contract.
    builder_deposit_requests: []const u8 = &.{},
    /// EIP-8282 (Amsterdam+): raw return bytes from the builder exit system contract.
    builder_exit_requests: []const u8 = &.{},
};

/// Call the post-block system contracts (Prague+: EIP-7002 withdrawals, EIP-7251
/// consolidations; Amsterdam+: EIP-8282 builder deposits/exits) and capture the raw
/// output bytes from each so the caller can compute the EIP-7685 requests_hash.
/// Caller owns the returned slices (allocated with `alloc`).
/// Returns error.SystemContractCallFailed if any post-block system contract
/// call reverts, halts, or runs out of gas (per EIP-7685: such blocks are invalid).
pub fn applyPostBlockCallsCapture(
    alloc: std.mem.Allocator,
    ctx: anytype,
    instructions: *handler_mod.Instructions,
    precompiles: *handler_mod.Precompiles,
    spec: primitives.SpecId,
    chain_id: u64,
    contracts: SystemContracts,
) error{SystemContractCallFailed}!PostBlockRequestBytes {
    if (!primitives.isEnabledIn(spec, .prague)) return .{ .withdrawal_requests = &.{}, .consolidation_requests = &.{} };
    var out: PostBlockRequestBytes = .{
        .withdrawal_requests = try runSystemCallCapture(alloc, ctx, instructions, precompiles, contracts.withdrawal_request, &.{}, chain_id),
        .consolidation_requests = try runSystemCallCapture(alloc, ctx, instructions, precompiles, contracts.consolidation_request, &.{}, chain_id),
    };
    // EIP-8282 (Amsterdam+): builder deposit (type 0x03) and builder exit (type 0x04)
    // requests. Called after the withdrawal/consolidation contracts so all post-block
    // system calls land at the same block access index for the BAL.
    if (primitives.isEnabledIn(spec, .amsterdam)) {
        out.builder_deposit_requests = try runSystemCallCapture(alloc, ctx, instructions, precompiles, contracts.builder_deposit_request, &.{}, chain_id);
        out.builder_exit_requests = try runSystemCallCapture(alloc, ctx, instructions, precompiles, contracts.builder_exit_request, &.{}, chain_id);
    }
    return out;
}

/// Like runSystemCall but returns a caller-owned copy of the return data.
/// Returns an empty slice if the contract is not deployed.
/// Returns error.SystemContractCallFailed if the call reverts, halts, or runs out of gas.
fn runSystemCallCapture(
    alloc: std.mem.Allocator,
    ctx: anytype,
    instructions: *handler_mod.Instructions,
    precompiles: *handler_mod.Precompiles,
    target: input.Address,
    calldata: []const u8,
    chain_id: u64,
) error{SystemContractCallFailed}![]const u8 {
    return runSystemCallImpl(true, ctx, instructions, precompiles, target, calldata, chain_id, alloc);
}
