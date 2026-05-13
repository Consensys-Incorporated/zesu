const std = @import("std");
const primitives = @import("primitives");
const context = @import("context");
const database = @import("database");
const state = @import("state");
const bytecode = @import("bytecode");
const interpreter_mod = @import("interpreter");
const main = @import("main.zig");
const alloc_mod = @import("zesu_allocator");
const validation = @import("validation.zig");

/// Mainnet EVM — heap-allocated wrapper that owns its Instructions, Precompiles, and FrameStack.
///
/// `buildMainnet` / `buildMainnetWithInspector` return `*MainnetEvm`.  Because the struct is
/// heap-allocated the addresses of `instructions`, `precompiles`, and `frame_stack` are stable
/// for the lifetime of the object, so the internal `Evm` can hold `&self.instructions` etc.
/// without dangling pointers.
///
/// Call `evm.destroy()` when done to free the heap allocation.
pub const MainnetEvm = struct {
    /// Owned instruction table and precompile set (stable addresses — do NOT move this struct).
    instructions: main.Instructions,
    precompiles: main.Precompiles,
    frame_stack: main.FrameStack,
    /// Inner Evm whose `instructions`/`precompiles`/`frame_stack` pointers reference the fields above.
    evm: main.Evm,

    /// Get the execution context.
    pub fn getContext(self: *MainnetEvm) *context.DefaultContext {
        return self.evm.ctx;
    }

    /// Create an execution frame.
    pub fn createFrame(self: *MainnetEvm, frame_data: main.FrameData) !main.Frame {
        return self.evm.createFrame(frame_data);
    }

    /// Execute a frame (delegates to the inner Evm).
    pub fn executeFrame(self: *MainnetEvm, frame: *main.Frame) !main.FrameResult {
        return self.evm.executeFrame(frame);
    }

    /// Execute a full transaction through validate → pre-exec → exec → post-exec.
    /// Convenience wrapper over `ExecuteEvm.execute(&self.evm)`.
    pub fn execute(self: *MainnetEvm) !main.ExecutionResult {
        return ExecuteEvm.execute(&self.evm);
    }

    /// Free the heap allocation created by `buildMainnet` / `buildMainnetWithInspector`.
    pub fn destroy(self: *MainnetEvm) void {
        alloc_mod.get().destroy(self);
    }
};

/// Mainnet context type alias
pub const MainnetContext = context.DefaultContext;

/// Main builder
pub const MainBuilder = struct {
    /// Build mainnet EVM without inspector.
    /// Returns a heap-allocated `*MainnetEvm`; call `evm.destroy()` when done.
    pub fn buildMainnet(self: *MainnetContext) *MainnetEvm {
        const spec = self.cfg.spec;
        const owned = alloc_mod.get().create(MainnetEvm) catch @panic("OOM in buildMainnet");
        owned.instructions = main.Instructions.new(spec);
        owned.precompiles = main.Precompiles.new(spec);
        owned.frame_stack = main.FrameStack.newPrealloc(8);
        owned.evm = main.Evm.init(self, null, &owned.instructions, &owned.precompiles, &owned.frame_stack);
        return owned;
    }

    /// Build mainnet EVM with inspector.
    /// Returns a heap-allocated `*MainnetEvm`; call `evm.destroy()` when done.
    pub fn buildMainnetWithInspector(self: *MainnetContext, inspector: *main.Inspector) *MainnetEvm {
        const spec = self.cfg.spec;
        const owned = alloc_mod.get().create(MainnetEvm) catch @panic("OOM in buildMainnetWithInspector");
        owned.instructions = main.Instructions.new(spec);
        owned.precompiles = main.Precompiles.new(spec);
        owned.frame_stack = main.FrameStack.newPrealloc(8);
        owned.evm = main.Evm.init(self, inspector, &owned.instructions, &owned.precompiles, &owned.frame_stack);
        return owned;
    }
};

/// Main context
pub const MainContext = struct {
    /// Create new mainnet context
    pub fn mainnet() MainnetContext {
        const db = database.InMemoryDB.init(alloc_mod.get());
        return context.DefaultContext.new(db, primitives.SpecId.prague);
    }
};

/// Mainnet handler — stateless, all methods are free functions grouped in a namespace.
/// All functions accept `anytype` for `evm` so they work with EvmFor(any DB type),
/// the heap-allocated `*MainnetEvm`, and stack-allocated test helpers.
pub const MainnetHandler = struct {
    /// Validate transaction — environment checks (no DB access) then caller state check.
    pub fn validate(evm: anytype, initial_gas: *validation.InitialAndFloorGas) !void {
        const ctx = evm.getContext();

        // 1. Validate block/tx/cfg fields (chain ID, gas cap, priority fee ordering)
        try validation.Validation.validateEnv(evm);

        // 2. EIP-4844: Validate blob transaction fields (Cancun+)
        try validation.Validation.validateBlobTx(&ctx.tx, &ctx.block, ctx.cfg.spec);

        // 3. EIP-7702: Validate set-code transaction fields (Prague+)
        try validation.Validation.validateEip7702Tx(&ctx.tx, ctx.cfg.spec);

        // 4. Calculate intrinsic gas and validate gas_limit covers it
        initial_gas.* = try validation.Validation.validateInitialTxGas(evm);

        // 5. Load caller, check nonce/code/balance, deduct max fee, bump nonce
        try validation.Validation.validateAgainstStateAndDeductCaller(evm, initial_gas.initial_gas);
    }

    /// Pre-execution phase — warm addresses and mark access-list items.
    ///
    /// Must run after validate() so the caller is already loaded and nonce bumped.
    /// Populates `initial_gas.auth_refund` with 12,500 (PER_EMPTY_ACCOUNT_COST/2) per valid
    /// EIP-7702 authorization where the authority account is non-empty (existing); 0 for new accounts.
    pub fn preExecution(evm: anytype, initial_gas: *validation.InitialAndFloorGas) !void {
        const ctx = evm.getContext();
        const tx = &ctx.tx;
        const spec = ctx.cfg.spec;
        const js = &ctx.journaled_state;

        // EIP-2929: Pre-warm precompile addresses (precompiles are always warm at tx start).
        {
            var addr_buf: [256]primitives.Address = undefined;
            var count: usize = 0;
            var it = evm.precompiles.precompiles.addresses.keyIterator();
            while (it.next()) |addr| {
                if (count < addr_buf.len) {
                    addr_buf[count] = addr.*;
                    count += 1;
                }
            }
            try js.warmPrecompiles(addr_buf[0..count]);
        }

        // EIP-3651 (Shanghai+): Pre-warm coinbase so CALL to coinbase is not cold
        if (primitives.isEnabledIn(spec, .shanghai)) {
            js.warmCoinbaseAccount(ctx.block.beneficiary);
        }

        // EIP-2929: Pre-warm all access-list addresses and their storage slots.
        // Use warmAccessList to mark addresses/slots warm in the access list WITHOUT eagerly
        // loading them from the database.  Gas accounting uses isCold()/isStorageCold() which
        // check warm_addresses.access_list — independent of whether the account was DB-loaded.
        // This ensures pre-warmed-but-never-touched accounts are not tracked as accessed state,
        // which is required for correct EIP-7928 Block Access List construction.
        if (tx.access_list.items) |items| {
            const allocator = alloc_mod.get();
            var map = std.AutoHashMap(
                primitives.Address,
                std.ArrayList(primitives.StorageKey),
            ).init(allocator);
            defer {
                var it = map.valueIterator();
                while (it.next()) |v| v.deinit(allocator);
                map.deinit();
            }
            for (items.items) |item| {
                const gop = try map.getOrPut(item.address);
                if (!gop.found_existing) {
                    gop.value_ptr.* = std.ArrayList(primitives.StorageKey).empty;
                }
                for (item.storage_keys.items) |key| {
                    try gop.value_ptr.*.append(allocator, key);
                }
            }
            try js.warmAccessList(map);
        }

        // EIP-7702: Apply authorization list (Prague+)
        // For each recovered authorization, validate and apply code delegation.
        if (primitives.isEnabledIn(spec, .prague)) {
            if (tx.authorization_list) |auth_list| {
                const amsterdam_cpsb: u64 = if (primitives.isEnabledIn(spec, .amsterdam))
                    interpreter_mod.gas_costs.costPerStateByte(ctx.block.gas_limit)
                else
                    0;
                for (auth_list.items) |auth_entry| {
                    switch (auth_entry) {
                        .Right => |recovered| {
                            switch (recovered.authority) {
                                .Valid => |authority_addr| {
                                    const auth = recovered.auth;

                                    // chain_id 0 means valid for any chain
                                    const chain_id_valid = auth.chain_id == 0 or
                                        auth.chain_id == @as(primitives.U256, ctx.cfg.chain_id);
                                    if (!chain_id_valid) continue;

                                    // Per EIP-7702 (EELS reference): skip without warming the authority
                                    // if auth.nonce == maxInt(u64). Applying the auth would overflow the
                                    // nonce. EELS checks this BEFORE adding the account to accessed_addresses,
                                    // so the account remains cold when execution later accesses it.
                                    if (auth.nonce == std.math.maxInt(u64)) continue;

                                    // Load authority account (marks it warm; EIP-7702 spec: always access
                                    // the signer's account even if the authorization is ultimately invalid)
                                    const load_result = js.loadAccountMutOptionalCode(authority_addr, true, false) catch continue;
                                    const journaled = load_result.data;

                                    // Per EIP-7702: skip if authority has non-empty, non-EIP-7702 code.
                                    // Only EOAs (empty code) or accounts already holding an EIP-7702
                                    // delegation designator may re-delegate.
                                    // Code with EF 01 00 prefix is treated as a delegation designator
                                    // regardless of total length (handles pre-state test fixtures).
                                    if (journaled.account.info.code) |existing_code| {
                                        const is_delegation = switch (existing_code) {
                                            .eip7702 => true,
                                            .legacy_analyzed => |bc| blk: {
                                                const orig = bc.originalBytes();
                                                break :blk orig.len >= 3 and orig[0] == 0xEF and orig[1] == 0x01 and orig[2] == 0x00;
                                            },
                                        };
                                        if (!is_delegation and !existing_code.isEmpty()) continue;
                                    }

                                    // Nonce must match exactly — skip if stale
                                    if (journaled.account.info.nonce != auth.nonce) continue;

                                    // EIP-7702 refund: the intrinsic cost charges PER_EMPTY_ACCOUNT_COST
                                    // (25,000) for each authorization to cover possible new-account creation.
                                    // If the authority already exists (non-empty), no new account is created,
                                    // so refund PER_EMPTY_ACCOUNT_COST / 2 = 12,500 (Prague).
                                    // EIP-8037 (Amsterdam+): refund 112*cpsb state gas per existing auth
                                    // (bypasses 1/5 cap — it's a pre-payment correction, not an SSTORE reward).
                                    // An account is non-empty if: nonce > 0, balance > 0, or code != empty.
                                    const is_existing = journaled.account.info.nonce > 0 or
                                        journaled.account.info.balance > 0 or
                                        !std.mem.eql(u8, &journaled.account.info.code_hash, &primitives.KECCAK_EMPTY);
                                    if (is_existing) {
                                        if (primitives.isEnabledIn(spec, .amsterdam)) {
                                            initial_gas.auth_state_refund += interpreter_mod.gas_costs.STATE_BYTES_PER_NEW_ACCOUNT * amsterdam_cpsb;
                                        } else {
                                            initial_gas.auth_refund += 12500;
                                        }
                                    }

                                    // Bump authority nonce (journaled, revertable).
                                    journaled.account.info.nonce += 1;
                                    js.nonceBumpJournalEntry(authority_addr);

                                    // Apply delegation. setCode() handles zero address → clearing code.
                                    const bc = bytecode.Bytecode{ .eip7702 = bytecode.Eip7702Bytecode.new(auth.address) };
                                    js.inner.setCode(authority_addr, bc);
                                },
                                .Invalid => {}, // skip invalid (unrecoverable) authorities
                            }
                        },
                        .Left => {}, // unrecovered signed authorization — skip
                    }
                }
            }
        }
    }

    /// Execute the transaction frame — runs the interpreter against bytecode.
    pub fn executeFrame(evm: anytype, initial: validation.InitialAndFloorGas) !main.FrameResult {
        const ctx = evm.getContext();
        const tx = &ctx.tx;
        const spec = ctx.cfg.spec;
        const initial_gas = initial.initial_gas;

        const calldata: []const u8 = if (tx.data) |data| data.items else &[_]u8{};
        // Gas available to execution = gas_limit minus intrinsic cost
        const exec_gas = tx.gas_limit - initial_gas;

        // EIP-8037 (Amsterdam+): split exec_gas into regular and state reservoir.
        // regular_gas_budget = TX_MAX_GAS_LIMIT - intrinsic_regular (regular portion only).
        // Any excess exec_gas above regular_gas_budget goes to the state gas reservoir.
        const tx_regular_exec_gas: u64 = if (primitives.isEnabledIn(spec, .amsterdam)) blk: {
            const initial_regular = initial_gas - initial.initial_state_gas;
            const regular_budget = interpreter_mod.gas_costs.TX_MAX_GAS_LIMIT -| initial_regular;
            break :blk @min(regular_budget, exec_gas);
        } else exec_gas;
        const tx_reservoir: u64 = if (primitives.isEnabledIn(spec, .amsterdam))
            exec_gas - tx_regular_exec_gas
        else
            0;

        const DB = @TypeOf(ctx.*).DatabaseType;
        var host = interpreter_mod.Host.init(DB, ctx, &evm.precompiles.precompiles);

        var return_data_buf: std.ArrayList(u8) = .empty;
        defer return_data_buf.deinit(alloc_mod.get());

        switch (tx.kind) {
            .Create => {
                // Top-level CREATE: tx validation already bumped caller nonce (skip_nonce_bump=true).
                // Intrinsic state gas (new account + auths) already charged via balance deduction.
                const setup = host.setupCreate(tx.caller, tx.value, calldata, tx_regular_exec_gas, false, 0, true, 0, false);
                switch (setup) {
                    .failed => |r| {
                        const status: main.ExecutionStatus = if (r.is_revert) .Revert else .Halt;
                        var exec_result = main.ExecutionResult.new(status, exec_gas - r.gas_remaining);
                        exec_result.return_data = alloc_mod.get().dupe(u8, r.return_data) catch @constCast(&[_]u8{});
                        return main.FrameResult.new(exec_result, r.gas_remaining, r.gas_refunded);
                    },
                    .ready => |s| {
                        const init_bytecode = bytecode.Bytecode.newRaw(calldata);
                        var root_interp = interpreter_mod.Interpreter.new(
                            interpreter_mod.Memory.new(),
                            interpreter_mod.ExtBytecode.newOwned(init_bytecode),
                            interpreter_mod.InputsImpl.new(
                                tx.caller,
                                s.new_addr,
                                tx.value,
                                @constCast(&[_]u8{}),
                                tx_regular_exec_gas,
                                .call,
                                false,
                                0,
                            ),
                            false,
                            spec,
                            tx_regular_exec_gas,
                        );
                        // EIP-8037: initialize root frame reservoir.
                        root_interp.gas.reservoir = tx_reservoir;
                        const ir = try executeIterative(root_interp, &host, &return_data_buf);
                        var cr = host.finalizeCreate(s.checkpoint, s.new_addr, ir.raw_result, ir.gas_remaining, ir.gas_refunded, ir.return_data, spec, false, ir.reservoir_remaining);
                        if (cr.success) {
                            cr.state_gas_used += ir.state_gas_used;
                        }
                        const cr_status: main.ExecutionStatus = if (cr.success) .Success else if (cr.is_revert) .Revert else .Halt;
                        var exec_result = main.ExecutionResult.new(cr_status, 0);
                        exec_result.state_gas_used = cr.state_gas_used;
                        exec_result.return_data = alloc_mod.get().dupe(u8, cr.return_data) catch @constCast(&[_]u8{});
                        var fr = main.FrameResult.new(exec_result, cr.gas_remaining, cr.gas_refunded);
                        fr.reservoir_remaining = cr.state_gas_remaining;
                        return fr;
                    },
                }
            },
            .Call => |target| {
                // Load target account and its code before executing.
                const callee_load = try ctx.journaled_state.loadAccountWithCode(target);
                var callee_code = if (callee_load.data.info.code) |c| c else bytecode.Bytecode.new();

                // EIP-7702: follow delegation one hop.
                if (callee_code.isEip7702()) {
                    const del_addr = callee_code.eip7702.address;
                    if (ctx.journaled_state.loadAccountWithCode(del_addr)) |del_load| {
                        callee_code = if (del_load.data.info.code) |del_code| del_code else bytecode.Bytecode.new();
                    } else |_| {
                        callee_code = bytecode.Bytecode.new();
                    }
                }

                // Take checkpoint for top-level CALL: state is reverted through this on failure.
                const call_checkpoint = ctx.journaled_state.getCheckpoint();

                // Value transfer for top-level CALL.
                if (tx.value > 0) {
                    const xfer_err = try ctx.journaled_state.transfer(tx.caller, target, tx.value);
                    if (xfer_err != null) {
                        ctx.journaled_state.checkpointRevert(call_checkpoint);
                        return main.FrameResult.new(
                            main.ExecutionResult.new(.Fail, exec_gas),
                            0,
                            0,
                        );
                    }
                    // EIP-7708 (Amsterdam+): emit Transfer log for ETH sent via TX.
                    if (primitives.isEnabledIn(spec, .amsterdam) and
                        !std.mem.eql(u8, &tx.caller, &target))
                    {
                        ctx.journaled_state.emitTransferLog(tx.caller, target, tx.value);
                    }
                }

                // Precompile dispatch for top-level TX targeting a precompile.
                if (evm.precompiles.get(target)) |precompile_fn| {
                    // EIP-7928 (Amsterdam+): record the precompile callee in the BAL.
                    // Mirrors the per-frame setupCallCore handling — see host.zig.
                    _ = ctx.journaled_state.loadAccount(target) catch {};
                    const pc_result = precompile_fn.execute(calldata, tx_regular_exec_gas);
                    switch (pc_result) {
                        .success => |out| {
                            if (out.reverted) {
                                ctx.journaled_state.checkpointRevert(call_checkpoint);
                                return main.FrameResult.new(
                                    main.ExecutionResult.new(.Revert, exec_gas),
                                    0,
                                    0,
                                );
                            }
                            ctx.journaled_state.checkpointCommit();
                            var fr = main.FrameResult.new(
                                main.ExecutionResult.new(.Success, out.gas_used),
                                tx_regular_exec_gas - out.gas_used,
                                0,
                            );
                            fr.reservoir_remaining = tx_reservoir;
                            return fr;
                        },
                        .err => {
                            ctx.journaled_state.checkpointRevert(call_checkpoint);
                            return main.FrameResult.new(
                                main.ExecutionResult.new(.Fail, exec_gas),
                                0,
                                0,
                            );
                        },
                    }
                }

                var root_interp = interpreter_mod.Interpreter.new(
                    interpreter_mod.Memory.new(),
                    interpreter_mod.ExtBytecode.new(callee_code),
                    interpreter_mod.InputsImpl.new(
                        tx.caller,
                        target,
                        tx.value,
                        @constCast(calldata),
                        tx_regular_exec_gas,
                        .call,
                        false,
                        0,
                    ),
                    false,
                    spec,
                    tx_regular_exec_gas,
                );
                // EIP-8037: initialize root frame reservoir.
                // EIP-7702 (Amsterdam+): add auth_state_refund back to reservoir — for existing
                // authorities, set_delegation returns the new-account state gas to the reservoir
                // so it can be consumed by execution (e.g. SSTORE) or returned as gas_left.
                root_interp.gas.reservoir = tx_reservoir + (if (primitives.isEnabledIn(spec, .amsterdam)) initial.auth_state_refund else 0);
                const ir = try executeIterative(root_interp, &host, &return_data_buf);

                if (ir.raw_result.isSuccess()) {
                    ctx.journaled_state.checkpointCommit();
                } else {
                    ctx.journaled_state.checkpointRevert(call_checkpoint);
                }

                const status: main.ExecutionStatus = switch (ir.raw_result) {
                    .stop, .@"return", .selfdestruct => .Success,
                    .revert => .Revert,
                    else => .Halt,
                };
                var exec_result = main.ExecutionResult.new(status, 0);
                exec_result.state_gas_used = ir.state_gas_used;
                exec_result.return_data = alloc_mod.get().dupe(u8, ir.return_data) catch @constCast(&[_]u8{});
                var fr = main.FrameResult.new(exec_result, ir.gas_remaining, ir.gas_refunded);
                fr.reservoir_remaining = ir.reservoir_remaining;
                return fr;
            },
        }
    }

    /// Post-execution phase — gas refund capping (EIP-3529), EIP-7623 floor, reimburse caller,
    /// reward beneficiary, and commit journal.
    pub fn postExecution(
        evm: anytype,
        result: *main.FrameResult,
        initial_gas: validation.InitialAndFloorGas,
    ) !void {
        const ctx = evm.getContext();
        const tx = &ctx.tx;
        const block = &ctx.block;
        const spec = ctx.cfg.spec;
        const js = &ctx.journaled_state;

        const is_london = primitives.isEnabledIn(spec, .london);
        const is_amsterdam = primitives.isEnabledIn(spec, .amsterdam);

        // EIP-8037 (Amsterdam+): gasUsed = tx.gas_limit - gas_remaining - reservoir_remaining.
        // This formula accounts for both regular gas and state gas consumed across all frames.
        // OOG for state gas is handled in-frame (spendStateGas returns false → frame halts).
        // Pre-Amsterdam: gasUsed = intrinsic + (exec_gas - gas_remaining).
        var total_gas_spent: u64 = undefined;
        if (is_amsterdam) {
            total_gas_spent = tx.gas_limit -| result.gas_remaining -| result.reservoir_remaining;
        } else {
            const exec_gas = tx.gas_limit - initial_gas.initial_gas;
            const gas_spent = exec_gas - result.gas_remaining;
            total_gas_spent = initial_gas.initial_gas + gas_spent;
        }
        // SSTORE clearing refund (exec_refund) only on Success (state was not reverted).
        // EIP-7702 auth_refund applies regardless of execution outcome because authorization
        // processing is committed in preExecution regardless of whether execution succeeds.
        const exec_refund: u64 = if (result.result.status == .Success)
            @as(u64, @intCast(@max(0, result.gas_refunded)))
        else
            0;
        const auth_refund = @as(u64, @intCast(@max(0, initial_gas.auth_refund)));
        // EIP-8037 (Amsterdam+): auth_state_refund (112*cpsb per valid existing auth) bypasses
        // the 1/5 cap — it is a pre-payment correction, not an SSTORE clearing reward.
        const auth_state_refund: u64 = if (is_amsterdam)
            initial_gas.auth_state_refund
        else
            0;
        const raw_refund: u64 = exec_refund + auth_refund;
        const quotient: u64 = if (is_london) 5 else 2;
        // EIP-3529 refund cap: min(refund, gas_used / max_refund_quotient) where gas_used is
        // the TOTAL gas consumed (intrinsic + execution), not just execution gas.
        // Per Yellow Paper: g* = gas_limit - gas_remaining_after_exec = total_gas_spent.
        var capped_refund = @min(raw_refund, total_gas_spent / quotient);
        var final_cost = total_gas_spent - capped_refund;

        if (primitives.isEnabledIn(spec, .prague) and !ctx.cfg.disable_eip7623 and initial_gas.floor_gas > 0) {
            // floor_total = TX_BASE_COST + floor_exec_gas (validated: gas_limit >= floor_total)
            const floor_total = 21000 + initial_gas.floor_gas;
            if (final_cost < floor_total) {
                final_cost = floor_total;
                capped_refund = 0;
            }
        }

        // 3. Effective gas price (EIP-1559 aware)
        const basefee: u128 = @as(u128, block.basefee);
        const effective_gas_price: u128 = if (tx.gas_priority_fee) |tip|
            @min(tx.gas_price, basefee + tip)
        else
            tx.gas_price;

        // 4. Reimburse caller and pay beneficiary — skipped if fee charging is disabled
        //    (e.g. eth_call simulation where no fee was deducted upfront).
        const gas_returned: u64 = tx.gas_limit - final_cost;
        if (!ctx.cfg.disable_fee_charge) {
            // Reimburse caller: gas_returned = gas_limit - final_cost (always >= 0).
            //    Normal case (no floor): gas_returned = gas_remaining + capped_refund.
            //    Floor case: gas_returned = gas_limit - floor_total.
            const reimburse_amount: primitives.U256 = @as(primitives.U256, effective_gas_price) * @as(primitives.U256, gas_returned);
            try js.balanceIncr(tx.caller, reimburse_amount);

            // Pay beneficiary (only tip portion post-London)
            const coinbase_price: u128 = if (is_london) effective_gas_price -| basefee else effective_gas_price;
            const beneficiary_amount: primitives.U256 = @as(primitives.U256, coinbase_price) * @as(primitives.U256, final_cost);
            try js.balanceIncr(block.beneficiary, beneficiary_amount);
        }

        // 6. Extract logs before commitTx destroys them (only on success — reverted state has no logs).
        if (result.result.status == .Success) {
            // EIP-7708 (Amsterdam+): emit deferred burn logs (sorted by address) after coinbase payment.
            if (is_amsterdam) {
                js.emitBurnLogs();
            }
            result.result.logs = js.takeLogs();
        }

        // 7. Commit transaction state.
        // commitTx() records committed-changed storage and flushes per-tx BAL tracking internally.
        js.commitTx();

        // 8. Update ExecutionResult with final accounting.
        // EIP-7778 (Amsterdam+): block gas does NOT deduct refunds.
        //   block_base = final_cost + capped_refund (= total_gas_spent when no floor,
        //   = floor_total when floor applied since capped_refund=0 in that case).
        // EIP-8037 (Amsterdam+):
        //   - receipt cumulativeGasUsed = final_cost (= regular_after_refunds + state)
        //   - block gasUsed = max(regular_before_refunds, state_gas) (no refunds deducted)
        if (is_amsterdam) {
            // block_base = total_gas_spent - auth_state_refund (SSTORE refunds NOT deducted per EIP-7778;
            // auth_state_refund IS deducted as it is a pre-payment correction, not an SSTORE reward).
            const block_base = final_cost + capped_refund;
            if (result.result.status == .Success) {
                const total_state_gross = initial_gas.initial_state_gas + result.result.state_gas_used;
                const total_state = if (total_state_gross > auth_state_refund)
                    total_state_gross - auth_state_refund
                else
                    0;
                const regular_for_block = if (block_base > total_state) block_base - total_state else 0;
                result.result.block_gas_used = @max(regular_for_block, total_state);
            } else {
                // EIP-8037 (Amsterdam+): failed tx block gas capped at TX_MAX_GAS_LIMIT (1<<24).
                // Txs with gas > TX_MAX are allowed but contribute at most TX_MAX to block capacity on failure.
                result.result.block_gas_used = @min(block_base, interpreter_mod.gas_costs.TX_MAX_GAS_LIMIT);
            }
        } else {
            result.result.block_gas_used = final_cost;
        }
        result.result.gas_used = final_cost;
        result.result.gas_refunded = capped_refund;
    }

    /// Handle errors — revert journal, discard tx.
    pub fn catchError(evm: anytype, _: anyerror) void {
        const ctx = evm.getContext();
        // Revert all state changes from this transaction (also clears per-tx BAL pending).
        ctx.journaled_state.discardTx();
    }
};

/// Raw result from the iterative frame runner.
const IterativeResult = struct {
    raw_result: interpreter_mod.InstructionResult,
    gas_remaining: u64,
    gas_refunded: i64,
    return_data: []const u8, // points into return_data_buf; valid until buf is cleared
    /// EIP-8037 (Amsterdam+): total state gas charged across all frames.
    state_gas_used: u64,
    /// EIP-8037 (Amsterdam+): state gas reservoir remaining in the root frame after execution.
    reservoir_remaining: u64,
};

/// One entry on the iterative call stack.
const FrameEntry = struct {
    interp: *interpreter_mod.Interpreter,
    /// What created this sub-frame (null for root).
    cause: ?union(enum) {
        call: interpreter_mod.PendingCallData,
        create: interpreter_mod.PendingCreateData,
    },
};

/// Iterative EVM frame runner. Runs the root interpreter and handles CALL/CREATE
/// sub-frames by pushing/popping FrameEntry items instead of recursing natively.
/// `return_data_buf` is owned by the caller and accumulates return data.
fn executeIterative(
    root_interp: interpreter_mod.Interpreter,
    host: *interpreter_mod.Host,
    return_data_buf: *std.ArrayList(u8),
) !IterativeResult {
    const call_ops = interpreter_mod.opcodes.call_ops;

    var frames = try std.ArrayList(FrameEntry).initCapacity(alloc_mod.get(), 16);
    defer {
        for (frames.items) |f| {
            f.interp.deinit();
            alloc_mod.get().destroy(f.interp);
        }
        frames.deinit(alloc_mod.get());
    }
    const root_ptr = try alloc_mod.get().create(interpreter_mod.Interpreter);
    root_ptr.* = root_interp;
    try frames.append(alloc_mod.get(), .{ .interp = root_ptr, .cause = null });

    // Build instruction table once: spec is constant for the lifetime of a block.
    const schedule = interpreter_mod.protocol_schedule.makeInstructionTable(root_interp.runtime_flags.spec_id);

    while (true) {
        const frame = &frames.items[frames.items.len - 1];
        const spec = frame.interp.runtime_flags.spec_id;

        _ = frame.interp.runWithHost(&schedule, host);

        if (frame.interp.pending != .none) {
            // Sub-frame needed. The opcode already called setupCall/setupCreate and stored
            // checkpoint + new_addr in the pending data. Just build the sub-interpreter.
            const pending = frame.interp.pending;
            frame.interp.pending = .none;
            const sub_depth = frames.items.len; // 0-based: root=0, first sub=1, ...

            switch (pending) {
                .call => |pc| {
                    var sub_interp = interpreter_mod.Interpreter.new(
                        interpreter_mod.Memory.new(),
                        interpreter_mod.ExtBytecode.new(pc.code),
                        interpreter_mod.InputsImpl.new(
                            pc.inputs.caller,
                            pc.inputs.target,
                            pc.inputs.value,
                            @constCast(pc.inputs.data),
                            pc.inputs.gas_limit,
                            pc.inputs.scheme,
                            pc.inputs.is_static,
                            sub_depth,
                        ),
                        pc.inputs.is_static,
                        spec,
                        pc.inputs.gas_limit,
                    );
                    // EIP-8037: forward the reservoir from parent to child.
                    sub_interp.gas.reservoir = pc.inputs.reservoir;
                    const call_ptr = try alloc_mod.get().create(interpreter_mod.Interpreter);
                    call_ptr.* = sub_interp;
                    try frames.append(alloc_mod.get(), .{ .interp = call_ptr, .cause = .{ .call = pc } });
                },
                .create => |pc| {
                    const init_bytecode = bytecode.Bytecode.newRaw(pc.inputs.init_code);
                    var sub_interp = interpreter_mod.Interpreter.new(
                        interpreter_mod.Memory.new(),
                        interpreter_mod.ExtBytecode.newOwned(init_bytecode),
                        interpreter_mod.InputsImpl.new(
                            pc.inputs.caller,
                            pc.new_addr,
                            pc.inputs.value,
                            @constCast(&[_]u8{}),
                            pc.inputs.gas_limit,
                            .call,
                            false,
                            sub_depth,
                        ),
                        false,
                        spec,
                        pc.inputs.gas_limit,
                    );
                    // EIP-8037: forward the reservoir from parent to child.
                    sub_interp.gas.reservoir = pc.inputs.reservoir;
                    const create_ptr = try alloc_mod.get().create(interpreter_mod.Interpreter);
                    create_ptr.* = sub_interp;
                    try frames.append(alloc_mod.get(), .{ .interp = create_ptr, .cause = .{ .create = pc } });
                },
                .none => unreachable,
            }
        } else {
            // Frame completed normally (or halted).
            if (frames.items.len == 1) {
                // Root frame done — extract result before deinit.
                const raw = frame.interp.result;
                const gas_rem = frame.interp.gas.remaining;
                const gas_ref = frame.interp.gas.refunded;
                const root_state_gas = frame.interp.gas.state_gas_used;
                const root_reservoir = frame.interp.gas.reservoir;
                const rd_raw: []const u8 = if (raw.isSuccess() or raw == .revert)
                    frame.interp.return_data.data
                else
                    &[_]u8{};
                // rd_raw may already be return_data_buf.items (parent frame's return_data
                // points into the same buffer). Detect self-copy and skip it.
                if (rd_raw.len == 0 or rd_raw.ptr != return_data_buf.items.ptr) {
                    return_data_buf.clearRetainingCapacity();
                    return_data_buf.appendSlice(alloc_mod.get(), rd_raw) catch {};
                } else {
                    return_data_buf.items.len = rd_raw.len;
                }
                // defer fires here, deiniting frames[0].interp — return_data_buf is safe.
                return IterativeResult{
                    .raw_result = raw,
                    .gas_remaining = gas_rem,
                    .gas_refunded = gas_ref,
                    .return_data = return_data_buf.items,
                    .state_gas_used = root_state_gas,
                    .reservoir_remaining = root_reservoir,
                };
            }

            // Sub-frame done — extract return data, deinit, pop, resume parent.
            const sub_result = frame.interp.result;
            const sub_gas_rem = frame.interp.gas.remaining;
            const sub_gas_ref = frame.interp.gas.refunded;
            const sub_state_gas = frame.interp.gas.state_gas_used;
            const sub_reservoir = frame.interp.gas.reservoir;
            const rd_raw: []const u8 = if (sub_result.isSuccess() or sub_result == .revert)
                frame.interp.return_data.data
            else
                &[_]u8{};
            if (rd_raw.len == 0 or rd_raw.ptr != return_data_buf.items.ptr) {
                return_data_buf.clearRetainingCapacity();
                return_data_buf.appendSlice(alloc_mod.get(), rd_raw) catch {};
            } else {
                return_data_buf.items.len = rd_raw.len;
            }

            const cause = frame.cause orelse unreachable;
            const sub_ptr = frame.interp;
            sub_ptr.deinit();
            _ = frames.pop();
            alloc_mod.get().destroy(sub_ptr);
            const parent = &frames.items[frames.items.len - 1];
            const parent_spec = parent.interp.runtime_flags.spec_id;

            switch (cause) {
                .call => |pc| {
                    var r = host.finalizeCall(pc.checkpoint, sub_result, pc.inputs.gas_limit, sub_gas_rem, sub_gas_ref, return_data_buf.items);
                    // EIP-8037: on success, propagate child's state gas and remaining reservoir.
                    // On any failure, state is rolled back so state gas returns to parent reservoir.
                    // Exception: invalid_static — CREATE charges state gas before the static check
                    // fires, so that state gas is forfeited even though no account was created.
                    if (r.success) {
                        r.state_gas_used = sub_state_gas;
                        r.state_gas_remaining = sub_reservoir;
                    } else if (sub_result == .invalid_static) {
                        r.state_gas_used = 0;
                        r.state_gas_remaining = sub_reservoir;
                    } else {
                        r.state_gas_used = 0;
                        r.state_gas_remaining = sub_state_gas + sub_reservoir;
                    }
                    call_ops.resumeCall(parent.interp, r, pc.ret_off, pc.ret_size);
                },
                .create => |pc| {
                    var r = host.finalizeCreate(pc.checkpoint, pc.new_addr, sub_result, sub_gas_rem, sub_gas_ref, return_data_buf.items, parent_spec, true, sub_reservoir);
                    // EIP-8037: on success, add child's accumulated state gas (from nested ops in initcode).
                    // On failure, finalizeCreate already sets state_gas_remaining = sub_reservoir;
                    // add sub_state_gas so all child state gas is returned to parent's reservoir.
                    if (r.success) {
                        r.state_gas_used += sub_state_gas;
                    } else {
                        r.state_gas_remaining += sub_state_gas;
                    }
                    call_ops.resumeCreate(parent.interp, r);
                },
            }
        }
    }
}

/// Execute EVM — run a full transaction through validate → pre-exec → exec → post-exec.
/// Accepts `*main.Evm` so it works with both heap-allocated `*MainnetEvm` (pass `&mevm.evm`)
/// and stack-allocated test patterns (pass `&evm` directly).
pub const ExecuteEvm = struct {
    pub fn execute(evm: anytype) !main.ExecutionResult {
        var initial_gas = validation.InitialAndFloorGas{ .initial_gas = 0, .floor_gas = 0 };

        // Validate (env checks + caller deduction)
        MainnetHandler.validate(evm, &initial_gas) catch |err| {
            MainnetHandler.catchError(evm, err);
            return main.ExecutionResult.new(.Fail, 0);
        };

        // Pre-execution (warm access lists)
        MainnetHandler.preExecution(evm, &initial_gas) catch |err| {
            MainnetHandler.catchError(evm, err);
            return main.ExecutionResult.new(.Fail, 0);
        };

        // Execute frame
        var frame_result = MainnetHandler.executeFrame(evm, initial_gas) catch |err| {
            MainnetHandler.catchError(evm, err);
            return main.ExecutionResult.new(.Fail, 0);
        };

        // Post-execution: refund capping, floor gas, reimburse caller, reward beneficiary, commit
        MainnetHandler.postExecution(evm, &frame_result, initial_gas) catch |err| {
            MainnetHandler.catchError(evm, err);
            return main.ExecutionResult.new(.Fail, 0);
        };

        return frame_result.result;
    }
};

/// Execute commit EVM — execute then commit state to the underlying database.
/// Note: commitTx() is called inside postExecution; no second commit needed here.
pub const ExecuteCommitEvm = struct {
    pub fn executeAndCommit(evm: anytype) !main.ExecutionResult {
        return ExecuteEvm.execute(evm);
    }
};

// Pull in post-execution tests
test {
    _ = @import("postexecution_tests.zig");
}

// Pull in precompile dispatch tests
test {
    _ = @import("precompile_dispatch_tests.zig");
}

// Pull in call gas accounting / integration tests
test {
    _ = @import("call_integration_tests.zig");
}

// Placeholder for testing
pub const testing = struct {
    pub fn testMainnetBuilder() !void {
        std.log.info("Testing mainnet builder...", .{});

        // Test mainnet context creation
        const ctx = MainContext.mainnet();
        std.debug.assert(ctx.cfg.spec == primitives.SpecId.prague);

        // Test EVM building — buildMainnet returns *MainnetEvm (heap-allocated).
        const evm = MainBuilder.buildMainnet(@constCast(&ctx));
        defer evm.destroy();
        std.debug.assert(evm.getContext() == @constCast(&ctx));
        std.debug.assert(evm.evm.inspector == null);

        std.log.info("Mainnet builder test passed!", .{});
    }

    pub fn testMainnetHandler() !void {
        std.log.info("Testing mainnet handler...", .{});

        // Create test context — buildMainnet returns *MainnetEvm (heap-allocated).
        var ctx = MainContext.mainnet();
        const evm = MainBuilder.buildMainnet(&ctx);
        defer evm.destroy();

        // Test handler in isolation — validate/preExecution are NOOPs when
        // called directly without a properly-populated context, so just test
        // the struct construction.
        const handler = MainnetHandler{};
        _ = handler;

        std.log.info("Mainnet handler test passed!", .{});
    }
};
