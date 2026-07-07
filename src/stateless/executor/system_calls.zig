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

const BEACON_ROOTS_ADDRESS: input.Address = .{
    0x00, 0x0F, 0x3d, 0xf6, 0xD7, 0x32, 0x80, 0x7E, 0xf1, 0x31,
    0x9f, 0xB7, 0xB8, 0xBb, 0x85, 0x22, 0xd0, 0xBe, 0xac, 0x02,
};

const HISTORY_STORAGE_ADDRESS: input.Address = .{
    0x00, 0x00, 0xf9, 0x08, 0x27, 0xf1, 0xc5, 0x3a, 0x10, 0xcb,
    0x7a, 0x02, 0x33, 0x5b, 0x17, 0x53, 0x20, 0x00, 0x29, 0x35,
};

const SYSTEM_ADDRESS: input.Address = .{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe,
};

const EIP7002_ADDRESS: input.Address = .{
    0x00, 0x00, 0x09, 0x61, 0xef, 0x48, 0x0e, 0xb5, 0x5e, 0x80,
    0xd1, 0x9a, 0xd8, 0x35, 0x79, 0xa6, 0x4c, 0x00, 0x70, 0x02,
};

const EIP7251_ADDRESS: input.Address = .{
    0x00, 0x00, 0xbb, 0xdd, 0xc7, 0xce, 0x48, 0x86, 0x42, 0xfb,
    0x57, 0x9f, 0x8b, 0x00, 0xf3, 0xa5, 0x90, 0x00, 0x72, 0x51,
};

// EIP-8282 (Amsterdam+): builder execution requests system contracts.
// Builder deposit requests (request type 0x03).
const EIP8282_DEPOSIT_ADDRESS: input.Address = .{
    0x00, 0x00, 0x88, 0x4d, 0x2a, 0xa3, 0x2e, 0xaa, 0x15, 0x5f,
    0x59, 0xa2, 0xf2, 0x4e, 0xfa, 0x73, 0xd9, 0x00, 0x82, 0x82,
};

// Builder exit requests (request type 0x04).
const EIP8282_EXIT_ADDRESS: input.Address = .{
    0x00, 0x00, 0x14, 0x57, 0x4a, 0x74, 0xc8, 0x05, 0x59, 0x0a,
    0xff, 0x94, 0x99, 0xfc, 0x7a, 0x69, 0x0f, 0x00, 0x82, 0x82,
};

// ─── Shared execution helper ──────────────────────────────────────────────────

/// Execute a single privileged system call as SYSTEM_ADDRESS.
///
/// Skips the call silently if the target contract is not deployed.
/// Discards state and returns on any execution error — a broken system
/// contract must not invalidate the block.
fn runSystemCall(
    ctx: anytype,
    instructions: *handler_mod.Instructions,
    precompiles: *handler_mod.Precompiles,
    target: input.Address,
    calldata: []const u8,
    chain_id: u64,
) void {
    const SYSTEM_CALL_GAS: u64 = systemCallGasLimit(ctx.cfg.spec);

    // Skip if the contract has no code (also covers non-existing accounts).
    // Call discardTx so that the loadAccount call does not leave the target
    // address warm in the journal — otherwise user transactions in the same
    // block would see it as warm (cheap) instead of cold (EIP-2929).
    const account_load = ctx.journaled_state.loadAccount(target) catch {
        ctx.journaled_state.discardTx();
        return;
    };
    if (std.mem.eql(u8, &account_load.data.info.code_hash, &primitives.KECCAK_EMPTY)) {
        ctx.journaled_state.discardTx();
        return;
    }

    // Bypass normal tx validation for system calls.
    const saved_nonce = ctx.cfg.disable_nonce_check;
    const saved_bal = ctx.cfg.disable_balance_check;
    const saved_fee = ctx.cfg.disable_fee_charge;
    const saved_basefee = ctx.cfg.disable_base_fee;
    const saved_block_gas = ctx.cfg.disable_block_gas_limit;
    const saved_chain_id_check = ctx.cfg.tx_chain_id_check;
    const saved_cfg_chain_id = ctx.cfg.chain_id;
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
    }

    // Set up calldata (may be empty for post-block calls).
    var data_list: ?std.ArrayList(u8) = null;
    if (calldata.len > 0) {
        var dl = std.ArrayList(u8).empty;
        dl.appendSlice(alloc_mod.get(), calldata) catch return;
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

    var frames = handler_mod.FrameStack.new();
    const EvmT = handler_mod.EvmFor(@TypeOf(ctx.*).DatabaseType);
    var evm = EvmT.init(ctx, null, instructions, precompiles, &frames);
    var result = handler_mod.ExecuteEvm.execute(&evm) catch {
        ctx.journaled_state.discardTx();
        if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
        ctx.tx.data = null;
        return;
    };
    result.deinit();

    if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
    ctx.tx.data = null;

    // System calls must not increment the caller's nonce.
    // zevm always bumps nonce unconditionally, so patch it back.
    if (ctx.journaled_state.inner.evm_state.getPtr(SYSTEM_ADDRESS)) |sa| {
        if (sa.info.nonce > 0) sa.info.nonce -= 1;
    }

    // Notify the fallback database that this system call committed successfully.
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
) void {
    if (primitives.isEnabledIn(spec, .cancun)) {
        if (env.parent_beacon_block_root) |root| {
            runSystemCall(ctx, instructions, precompiles, BEACON_ROOTS_ADDRESS, &root, chain_id);
        }
    }
    if (primitives.isEnabledIn(spec, .prague)) {
        if (env.parent_hash) |parent_hash| {
            runSystemCall(ctx, instructions, precompiles, HISTORY_STORAGE_ADDRESS, &parent_hash, chain_id);
        }
    }
}

// ─── Post-block system calls ──────────────────────────────────────────────────

/// Call the EIP-7002 (withdrawal requests) and EIP-7251 (consolidation requests)
/// system contracts after all user transactions (Prague+).
///
/// Per EIP-7002/7251: if the contract has no code the call is silently skipped,
/// matching the same fail-safe behaviour as the pre-block system calls.
pub fn applyPostBlockCalls(
    ctx: anytype,
    instructions: *handler_mod.Instructions,
    precompiles: *handler_mod.Precompiles,
    spec: primitives.SpecId,
    chain_id: u64,
) void {
    if (!primitives.isEnabledIn(spec, .prague)) return;
    for ([_]input.Address{ EIP7002_ADDRESS, EIP7251_ADDRESS }) |sc_addr| {
        runSystemCall(ctx, instructions, precompiles, sc_addr, &.{}, chain_id);
    }
}

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

/// Like applyPostBlockCalls but captures and returns the raw output bytes from
/// each system contract so the caller can compute the EIP-7685 requests_hash.
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
) error{SystemContractCallFailed}!PostBlockRequestBytes {
    if (!primitives.isEnabledIn(spec, .prague)) return .{ .withdrawal_requests = &.{}, .consolidation_requests = &.{} };
    var out: PostBlockRequestBytes = .{
        .withdrawal_requests = try runSystemCallCapture(alloc, ctx, instructions, precompiles, EIP7002_ADDRESS, &.{}, chain_id),
        .consolidation_requests = try runSystemCallCapture(alloc, ctx, instructions, precompiles, EIP7251_ADDRESS, &.{}, chain_id),
    };
    // EIP-8282 (Amsterdam+): builder deposit (type 0x03) and builder exit (type 0x04)
    // requests. Called after the withdrawal/consolidation contracts so all post-block
    // system calls land at the same block access index for the BAL.
    if (primitives.isEnabledIn(spec, .amsterdam)) {
        out.builder_deposit_requests = try runSystemCallCapture(alloc, ctx, instructions, precompiles, EIP8282_DEPOSIT_ADDRESS, &.{}, chain_id);
        out.builder_exit_requests = try runSystemCallCapture(alloc, ctx, instructions, precompiles, EIP8282_EXIT_ADDRESS, &.{}, chain_id);
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
    const SYSTEM_CALL_GAS: u64 = systemCallGasLimit(ctx.cfg.spec);

    const account_load = ctx.journaled_state.loadAccount(target) catch {
        ctx.journaled_state.discardTx();
        return &.{};
    };
    if (std.mem.eql(u8, &account_load.data.info.code_hash, &primitives.KECCAK_EMPTY)) {
        ctx.journaled_state.discardTx();
        return &.{};
    }

    const saved_nonce = ctx.cfg.disable_nonce_check;
    const saved_bal = ctx.cfg.disable_balance_check;
    const saved_fee = ctx.cfg.disable_fee_charge;
    const saved_basefee = ctx.cfg.disable_base_fee;
    const saved_block_gas = ctx.cfg.disable_block_gas_limit;
    const saved_chain_id_check = ctx.cfg.tx_chain_id_check;
    const saved_cfg_chain_id = ctx.cfg.chain_id;
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
    }

    var data_list: ?std.ArrayList(u8) = null;
    if (calldata.len > 0) {
        var dl = std.ArrayList(u8).empty;
        dl.appendSlice(alloc_mod.get(), calldata) catch return &.{};
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

    var frames = handler_mod.FrameStack.new();
    const EvmT = handler_mod.EvmFor(@TypeOf(ctx.*).DatabaseType);
    var evm = EvmT.init(ctx, null, instructions, precompiles, &frames);

    var initial_gas = handler_mod.InitialAndFloorGas{ .initial_gas = 0, .floor_gas = 0 };

    handler_mod.MainnetHandler.validate(&evm, &initial_gas) catch {
        ctx.journaled_state.discardTx();
        if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
        ctx.tx.data = null;
        return error.SystemContractCallFailed;
    };

    handler_mod.MainnetHandler.preExecution(&evm, &initial_gas) catch {
        ctx.journaled_state.discardTx();
        if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
        ctx.tx.data = null;
        return error.SystemContractCallFailed;
    };

    var frame_result = handler_mod.MainnetHandler.executeFrame(&evm, initial_gas) catch {
        ctx.journaled_state.discardTx();
        if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
        ctx.tx.data = null;
        return error.SystemContractCallFailed;
    };

    if (frame_result.result.status != .Success) {
        frame_result.deinit();
        if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
        ctx.tx.data = null;
        return error.SystemContractCallFailed;
    }

    handler_mod.MainnetHandler.postExecution(&evm, &frame_result, initial_gas) catch {
        frame_result.deinit();
        if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
        ctx.tx.data = null;
        return error.SystemContractCallFailed;
    };

    const output = if (frame_result.result.return_data.len > 0) alloc.dupe(u8, frame_result.result.return_data) catch &.{} else &.{};
    frame_result.deinit();

    if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
    ctx.tx.data = null;

    if (ctx.journaled_state.inner.evm_state.getPtr(SYSTEM_ADDRESS)) |sa| {
        if (sa.info.nonce > 0) sa.info.nonce -= 1;
    }

    return output;
}
