const std = @import("std");
const primitives = @import("primitives");
const InstructionContext = @import("../instruction_context.zig").InstructionContext;
const gas_costs = @import("../gas_costs.zig");
const host_module = @import("../host.zig");
const alloc_mod = @import("zesu_allocator");
const CallScheme = @import("../interpreter_action.zig").CallScheme;
const CreateScheme = @import("../interpreter_action.zig").CreateScheme;
const CreateInputs = @import("../interpreter_action.zig").CreateInputs;
const interp_mod = @import("../interpreter.zig");
const Interpreter = interp_mod.Interpreter;
const PendingCallData = interp_mod.PendingCallData;
const PendingCreateData = interp_mod.PendingCreateData;

// ---------------------------------------------------------------------------
// Memory expansion helper
// ---------------------------------------------------------------------------

fn memoryCostWords(num_words: usize) u64 {
    const n: u64 = @intCast(num_words);
    const linear = std.math.mul(u64, n, gas_costs.G_MEMORY) catch return std.math.maxInt(u64);
    const quadratic = (std.math.mul(u64, n, n) catch return std.math.maxInt(u64)) / 512;
    return std.math.add(u64, linear, quadratic) catch std.math.maxInt(u64);
}

fn expandMemory(ctx: *InstructionContext, new_size: usize) bool {
    if (new_size == 0) return true;
    const current = ctx.interpreter.memory.size();
    if (new_size <= current) return true;
    const current_words = (current + 31) / 32;
    const new_words = (std.math.add(usize, new_size, 31) catch return false) / 32;
    if (new_words > current_words) {
        const cost = memoryCostWords(new_words) - memoryCostWords(current_words);
        if (!ctx.interpreter.gas.spend(cost)) return false;
    }
    const aligned_size = new_words * 32;
    const old_size = ctx.interpreter.memory.size();
    ctx.interpreter.memory.buffer.resize(alloc_mod.get(), aligned_size) catch return false;
    @memset(ctx.interpreter.memory.buffer.items[old_size..aligned_size], 0);
    return true;
}

// ---------------------------------------------------------------------------
// Common call dispatch helper
// ---------------------------------------------------------------------------

/// Shared logic for CALL, CALLCODE, DELEGATECALL, STATICCALL.
///
/// Stack layout (from top):
///   CALL/CALLCODE (7 items): gas, addr, value, argsOff, argsSize, retOff, retSize
///   DELEGATECALL/STATICCALL (6 items): gas, addr, argsOff, argsSize, retOff, retSize
fn callImpl(
    ctx: *InstructionContext,
    comptime has_value: bool,
    comptime scheme: CallScheme,
) void {
    const h = ctx.host orelse {
        ctx.interpreter.halt(.invalid_opcode);
        return;
    };
    const stack = &ctx.interpreter.stack;

    const stack_items: usize = if (has_value) 7 else 6;
    if (!stack.hasItems(stack_items)) {
        ctx.interpreter.halt(.stack_underflow);
        return;
    }

    // Pop stack items
    const gas_val = stack.peekUnsafe(0);
    const addr_val = stack.peekUnsafe(1);
    const value: primitives.U256 = if (has_value) stack.peekUnsafe(2) else 0;
    const args_off = if (has_value) stack.peekUnsafe(3) else stack.peekUnsafe(2);
    const args_size = if (has_value) stack.peekUnsafe(4) else stack.peekUnsafe(3);
    const ret_off = if (has_value) stack.peekUnsafe(5) else stack.peekUnsafe(4);
    const ret_size = if (has_value) stack.peekUnsafe(6) else stack.peekUnsafe(5);
    stack.shrinkUnsafe(stack_items);

    const spec = ctx.interpreter.runtime_flags.spec_id;
    const is_static = ctx.interpreter.runtime_flags.is_static;

    // Static call constraint per EIP-214: CALL with non-zero value is forbidden in
    // static context and causes an exception (halt). CALLCODE is NOT in the EIP-214
    // forbidden list because it does not transfer ETH to an external account.
    if (comptime (has_value and scheme == .call)) {
        if (is_static and value > 0) {
            ctx.interpreter.halt(.invalid_static);
            return;
        }
    }

    const target_addr = host_module.u256ToAddress(addr_val);

    // Sizes must always fit in usize (otherwise the memory requirement is impossible).
    // Offsets only need to fit when the corresponding size is non-zero; a giant offset
    // with size=0 is valid (no memory is touched).
    if (args_size > std.math.maxInt(usize) or ret_size > std.math.maxInt(usize)) {
        ctx.interpreter.halt(.memory_limit_oog);
        return;
    }
    const args_size_u: usize = @intCast(args_size);
    const ret_size_u: usize = @intCast(ret_size);
    if ((args_size_u > 0 and args_off > std.math.maxInt(usize)) or
        (ret_size_u > 0 and ret_off > std.math.maxInt(usize)))
    {
        ctx.interpreter.halt(.memory_limit_oog);
        return;
    }
    const args_off_u: usize = if (args_size_u > 0) @intCast(args_off) else 0;
    const ret_off_u: usize = if (ret_size_u > 0) @intCast(ret_off) else 0;

    // Memory expansion for args region
    if (args_size_u > 0) {
        const args_end = std.math.add(usize, args_off_u, args_size_u) catch {
            ctx.interpreter.halt(.memory_limit_oog);
            return;
        };
        if (!expandMemory(ctx, args_end)) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }
    // Memory expansion for return region
    if (ret_size_u > 0) {
        const ret_end = std.math.add(usize, ret_off_u, ret_size_u) catch {
            ctx.interpreter.halt(.memory_limit_oog);
            return;
        };
        if (!expandMemory(ctx, ret_end)) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }

    const pre_is_cold = h.isAddressCold(target_addr);
    // transfers_value only depends on the stack value — no account load needed.
    const transfers_value = has_value and value > 0;
    // Worst-case pre-check (assume account non-existent) before any DB load.
    // getCallGasCost(..., false) >= exact cost, so if this passes the account can never
    // become a phantom BAL entry (the exact-cost check below can never OOG).
    // Gated on Amsterdam: pre-Amsterdam has no BAL and G_NEWACCOUNT makes the worst-case
    // overly conservative for existing accounts, causing false OOG.
    if (primitives.isEnabledIn(spec, .amsterdam)) {
        const worst_case = gas_costs.getCallGasCost(spec, pre_is_cold, transfers_value, false);
        if (ctx.interpreter.gas.remaining < worst_case) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }

    // Load target account info (warm/cold, emptiness) and code (for EIP-7702) in one shot.
    // This replaces the former separate accountInfo + codeInfo calls (two journal lookups).
    const callee_info = h.accountInfoWithCode(target_addr);
    const is_cold = if (callee_info) |info| info.is_cold else pre_is_cold;
    // G_NEWACCOUNT applies to the ETH *recipient*, not the code source.
    // For CALLCODE/DELEGATECALL, ETH goes to self (always exists). Otherwise ETH goes to target_addr.
    const account_exists = switch (scheme) {
        .callcode, .delegatecall => true, // self always exists
        else => if (callee_info) |info| !info.is_empty else false,
    };

    // EIP-7702: pre-compute delegation gas as part of the CALL upfront cost (before the 63/64
    // rule). Per EIP-7702, loading the delegation target incurs a warm/cold access cost that is
    // part of the CALL instruction overhead. Including it in base_cost ensures the 63/64 rule
    // correctly limits forwarded gas (charging it after the sub-call gives the callee too much gas).
    var delegation_gas: u64 = 0;
    if (callee_info) |info| {
        if (info.bytecode.isEip7702()) {
            // Use isAddressCold to determine cold/warm cost WITHOUT loading the delegation
            // target from the DB — avoids tracking it in the BAL during gas calculation.
            // The sub-frame's setupCall will load it properly and track it there.
            const del_addr = info.bytecode.eip7702.address;
            delegation_gas = if (h.isAddressCold(del_addr)) gas_costs.coldAccountAccess(spec) else gas_costs.WARM_ACCOUNT_ACCESS;
        }
    }

    // Base call cost (warm/cold + value transfer + new account + EIP-7702 delegation target access)
    const call_cost_no_delegation = gas_costs.getCallGasCost(spec, is_cold, transfers_value, account_exists);
    const base_cost = call_cost_no_delegation + delegation_gas;

    // Determine forwarded gas (EIP-150 introduces 63/64 rule; pre-EIP-150 uses all remaining).
    // worst_case >= call_cost_no_delegation, so the pre-check above guarantees remaining >= it.
    const remaining = ctx.interpreter.gas.remaining;
    if (remaining < base_cost) {
        // OOG after target access but before delegation (oog_after_target_access /
        // oog_success_minus_1). Per EELS second check_gas: target IS in BAL, delegation NOT loaded.
        ctx.interpreter.halt(.out_of_gas);
        return;
    }

    const after_base = remaining - base_cost;

    // Pre-EIP-150 (Frontier/Homestead): the caller must have gas_remaining >= base_cost + gas_val.
    // If not, the CALL instruction itself causes the parent frame to OOG (unlike EIP-150+ where
    // gas_val is capped at 63/64 of remaining and the sub-call gets less gas).
    // EIP-150 (Tangerine Whistle) replaced this with the 63/64 forwarding rule.
    if (!primitives.isEnabledIn(spec, .tangerine)) {
        const gas_val_u64: u64 = if (gas_val > std.math.maxInt(u64)) std.math.maxInt(u64) else @as(u64, @intCast(gas_val));
        const total_cost = std.math.add(u64, base_cost, gas_val_u64) catch std.math.maxInt(u64);
        if (remaining < total_cost) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }

    // EIP-8037 (Amsterdam+): charge_state_gas in EELS draws from state_gas_left (reservoir) first,
    // then spills any remainder to gas_left BEFORE forwarded gas is computed. We replicate that
    // arithmetic here (without yet touching any counters) so the 63/64 rule operates on the
    // correct budget after state gas.
    const new_account_state_gas: u64 = blk: {
        const MAX_CALL_DEPTH: usize = 1024;
        if (primitives.isEnabledIn(spec, .amsterdam) and transfers_value and !account_exists and
            ctx.interpreter.input.depth < MAX_CALL_DEPTH)
        {
            const cpsb = gas_costs.costPerStateByte(h.block.gas_limit);
            break :blk gas_costs.STATE_BYTES_PER_NEW_ACCOUNT * cpsb;
        }
        break :blk 0;
    };
    const state_gas_spill: u64 = if (new_account_state_gas > 0) blk: {
        const reservoir = ctx.interpreter.gas.reservoir;
        if (new_account_state_gas <= reservoir) break :blk 0;
        break :blk new_account_state_gas - reservoir;
    } else 0;

    if (after_base < state_gas_spill) {
        ctx.interpreter.halt(.out_of_gas);
        return;
    }

    // Budget from which 63/64 forwarded gas is computed (excludes state gas spill).
    const budget = after_base - state_gas_spill;
    // EIP-150: cap forwarded gas to 63/64 of budget. Pre-EIP-150: forward up to all budget.
    const max_forwarded: u64 = if (primitives.isEnabledIn(spec, .tangerine))
        budget - budget / 64
    else
        budget;

    const forwarded: u64 = @min(
        if (gas_val > std.math.maxInt(u64)) max_forwarded else @as(u64, @intCast(gas_val)),
        max_forwarded,
    );

    // The stipend (2300 gas) is gifted to the callee on value-bearing CALL.
    // It is NOT deducted from the caller's gas — the caller only pays `forwarded`.
    const stipend: u64 = if (transfers_value) gas_costs.CALL_STIPEND else 0;
    // Gas limit seen by the sub-interpreter = forwarded amount + free stipend.
    const sub_gas_limit: u64 = forwarded +| stipend;

    // Deduct base cost then the forwarded amount from this frame's gas.
    // regular gas (base + forwarded) must be charged before state gas.
    if (!ctx.interpreter.gas.spend(base_cost)) {
        ctx.interpreter.halt(.out_of_gas);
        return;
    }

    if (!ctx.interpreter.gas.spend(forwarded)) {
        ctx.interpreter.halt(.out_of_gas);
        return;
    }

    // EIP-8037 (Amsterdam+): charge state gas for new account creation via value-bearing CALL.
    // The budget for forwarded gas was already reduced by state_gas_spill above, so this will
    // always succeed (reservoir covers part or all; regular gas covers any spill).
    if (new_account_state_gas > 0) {
        if (!ctx.interpreter.gas.spendStateGas(new_account_state_gas)) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }

    // EIP-8037 (Amsterdam+): pass full reservoir to child; zero parent's reservoir.
    // The reservoir is restored on child failure (via resumeCall below for pre-exec failures,
    // or via the frame runner for normal sub-frames).
    const call_reservoir: u64 = if (primitives.isEnabledIn(spec, .amsterdam)) blk: {
        const r = ctx.interpreter.gas.reservoir;
        ctx.interpreter.gas.reservoir = 0;
        break :blk r;
    } else 0;

    // Build call inputs. For DELEGATECALL, caller and value come from parent frame.
    // For CALLCODE, target (storage context) stays as current contract.
    const call_caller = switch (scheme) {
        .delegatecall => ctx.interpreter.input.caller,
        else => ctx.interpreter.input.target,
    };
    const call_target = switch (scheme) {
        .callcode, .delegatecall => ctx.interpreter.input.target,
        else => target_addr,
    };
    const call_value = switch (scheme) {
        .delegatecall => ctx.interpreter.input.value,
        else => value,
    };
    const call_is_static = is_static or (scheme == .staticcall);

    // Gather call data from memory
    const call_data: []const u8 = if (args_size_u > 0)
        ctx.interpreter.memory.buffer.items[args_off_u .. args_off_u + args_size_u]
    else
        &[_]u8{};

    const inputs = host_module.CallInputs{
        .caller = call_caller,
        .target = call_target,
        .callee = target_addr,
        .value = call_value,
        .data = call_data,
        .gas_limit = sub_gas_limit,
        .scheme = scheme,
        .is_static = call_is_static,
        .reservoir = call_reservoir,
        .preloaded_code = if (callee_info) |info| info.bytecode else null,
        .needs_pre_eip161_touch = !primitives.isEnabledIn(spec, .spurious_dragon) and
            scheme == .call and value == 0 and
            if (callee_info) |info| info.is_empty else false,
    };

    // Dispatch via setupCall. Precompile/failure results are finalized immediately.
    // On success (.ready), suspend this frame by setting interpreter.pending.
    const setup = h.setupCall(inputs, ctx.interpreter.input.depth);
    switch (setup) {
        .failed => |r| {
            // setupCall failed (depth limit, balance, etc.).
            // EIP-8037: return the reservoir (call_reservoir) that was saved+zeroed.
            // resumeCall refunds new_account_state_gas because the call failed (the
            // account was not created) — matching credit_state_gas_refund(NEW_ACCOUNT).
            var result = r;
            result.state_gas_remaining = call_reservoir;
            resumeCall(ctx.interpreter, result, ret_off_u, ret_size_u, new_account_state_gas);
        },
        .precompile => |r| {
            // Precompile ran. It doesn't use state gas, so reservoir comes back intact.
            // state_gas_remaining is already set to inputs.reservoir in setupCall.
            resumeCall(ctx.interpreter, r, ret_off_u, ret_size_u, new_account_state_gas);
        },
        .ready => |s| {
            ctx.interpreter.pending = .{ .call = PendingCallData{
                .inputs = inputs,
                .code = s.code,
                .checkpoint = s.checkpoint,
                .ret_off = ret_off_u,
                .ret_size = ret_size_u,
                .new_account_state_gas = new_account_state_gas,
            } };
        },
    }
}

/// Resume a suspended CALL frame after the sub-frame has completed.
/// Called by the frame runner (or synchronous helper) with the final CallResult.
/// EIP-8037 credit_state_gas_refund for a NEW_ACCOUNT pre-charge that was not consumed
/// (failed value-CALL / CREATE): refund in LIFO order — to regular gas first if the charge
/// spilled out of the reservoir, else the reservoir — and unwind it from the frame's totals.
pub fn refundNewAccountLifo(interp: *Interpreter, amount: u64) void {
    if (amount == 0) return;
    // Shared LIFO routing (regular gas first, then reservoir); the tail differs from
    // refundStateGas — unwind the never-consumed charge from spent, not the refund credit.
    interp.gas.creditStateGasLifo(amount);
    interp.gas.state_gas_spent -|= amount;
}

pub fn resumeCall(interp: *Interpreter, result: host_module.CallResult, ret_off: usize, ret_size: usize, new_account_state_gas: u64) void {
    interp.gas.remaining +|= result.gas_remaining;
    interp.gas.refunded += result.gas_refunded;
    interp.gas.addStateGasFromChild(result.state_gas_used);
    // EIP-8037: restore the reservoir from the child (on success: child's remaining reservoir;
    // on failure: all child state gas + reservoir returned as state_gas_remaining).
    interp.gas.reservoir += result.state_gas_remaining;
    // EIP-8037: a value-bearing CALL that creates a new account pre-charges NEW_ACCOUNT
    // state gas. On failure the account is not created, so refund it (credit_state_gas_refund)
    // in LIFO order — to regular gas first if that charge had spilled, else the reservoir.
    // Routing to regular gas matters: if this frame later halts, that gas is burned (whereas
    // reservoir gas is returned), matching the reference.
    if (!result.success) refundNewAccountLifo(interp, new_account_state_gas);

    const actual = @min(result.return_data.len, ret_size);
    if (actual > 0) {
        const dst = interp.memory.buffer.items[ret_off .. ret_off + actual];
        const src = result.return_data[0..actual];
        if (@intFromPtr(dst.ptr) <= @intFromPtr(src.ptr)) {
            std.mem.copyForwards(u8, dst, src);
        } else {
            std.mem.copyBackwards(u8, dst, src);
        }
    }
    interp.return_data.data = @constCast(result.return_data);

    if (!interp.stack.hasSpace(1)) {
        interp.halt(.stack_overflow);
        return;
    }
    interp.stack.pushUnsafe(if (result.success) 1 else 0);
}

/// Resume a suspended CREATE frame after the sub-frame has completed.
pub fn resumeCreate(interp: *Interpreter, result: host_module.CreateResult) void {
    interp.gas.remaining +|= result.gas_remaining;
    interp.gas.refunded += result.gas_refunded;
    interp.gas.addStateGasFromChild(result.state_gas_used);
    // EIP-8037: code-deposit state gas that spilled from the child's regular gas must be
    // tracked so a later halt/revert refill returns it to regular gas (burned on halt),
    // not the reservoir. Without this the spilled deposit inflates the parent reservoir.
    interp.gas.state_gas_spilled += result.state_gas_spilled;
    // EIP-8037: restore the reservoir from the child (on success: child's remaining reservoir;
    // on failure: all child state gas + reservoir returned as state_gas_remaining).
    interp.gas.reservoir += result.state_gas_remaining;
    interp.return_data.data = @constCast(result.return_data);

    if (!interp.stack.hasSpace(1)) {
        interp.halt(.stack_overflow);
        return;
    }
    interp.stack.pushUnsafe(if (result.success) host_module.addressToU256(result.address) else 0);
}

// ---------------------------------------------------------------------------
// Public opcode handlers
// ---------------------------------------------------------------------------

/// CALL (0xF1): Call a contract.
/// Stack: [gas, addr, value, argsOff, argsSize, retOff, retSize] -> [success]
pub fn opCall(ctx: *InstructionContext) void {
    callImpl(ctx, true, .call);
}

/// CALLCODE (0xF2): Call with current contract's storage context.
/// Stack: [gas, addr, value, argsOff, argsSize, retOff, retSize] -> [success]
pub fn opCallcode(ctx: *InstructionContext) void {
    callImpl(ctx, true, .callcode);
}

/// DELEGATECALL (0xF4): Call with current contract's storage, sender, and value.
/// Stack: [gas, addr, argsOff, argsSize, retOff, retSize] -> [success]
pub fn opDelegatecall(ctx: *InstructionContext) void {
    callImpl(ctx, false, .delegatecall);
}

/// STATICCALL (0xFA): Read-only call (no state modifications allowed).
/// Stack: [gas, addr, argsOff, argsSize, retOff, retSize] -> [success]
pub fn opStaticcall(ctx: *InstructionContext) void {
    callImpl(ctx, false, .staticcall);
}

/// CREATE (0xF0): Create a new contract.
/// Stack: [value, offset, size] -> [addr]
pub fn opCreate(ctx: *InstructionContext) void {
    const h = ctx.host orelse {
        ctx.interpreter.halt(.invalid_opcode);
        return;
    };
    const stack = &ctx.interpreter.stack;
    if (!stack.hasItems(3)) {
        ctx.interpreter.halt(.stack_underflow);
        return;
    }

    const value = stack.peekUnsafe(0);
    const offset = stack.peekUnsafe(1);
    const size = stack.peekUnsafe(2);
    stack.shrinkUnsafe(3);

    const spec = ctx.interpreter.runtime_flags.spec_id;

    // Static-context check first, before any gas is charged — the reference create/create2
    // opcodes raise WriteInStaticContext before init-code cost and the NEW_ACCOUNT state-gas
    // charge, so a create in a static context is charged nothing (not even state gas).
    if (ctx.interpreter.runtime_flags.is_static) {
        ctx.interpreter.halt(.invalid_static);
        return;
    }

    // Base cost: EIP-8037 (Amsterdam+) replaces the 32000 regular CREATE cost with
    // CREATE_ACCESS = ACCOUNT_WRITE(8000) + COLD_STORAGE_ACCESS(3000) = 11000; the
    // NEW_ACCOUNT + code-deposit state gas is charged separately.
    const create_base_cost: u64 = if (primitives.isEnabledIn(spec, .amsterdam)) 11000 else gas_costs.G_CREATE;
    if (!ctx.interpreter.gas.spend(create_base_cost)) {
        ctx.interpreter.halt(.out_of_gas);
        return;
    }

    // Validate and resolve memory region
    const size_u: usize = if (size > std.math.maxInt(usize)) {
        ctx.interpreter.halt(.memory_limit_oog);
        return;
    } else @intCast(size);
    const off_u: usize = if (size_u == 0) 0 else if (offset > std.math.maxInt(usize)) {
        ctx.interpreter.halt(.memory_limit_oog);
        return;
    } else @intCast(offset);

    if (size_u > 0) {
        const create_end = std.math.add(usize, off_u, size_u) catch {
            ctx.interpreter.halt(.memory_limit_oog);
            return;
        };
        if (!expandMemory(ctx, create_end)) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }

    // EIP-3860 (Shanghai+): oversized initcode causes exceptional halt in calling frame.
    // EIP-7954 (Amsterdam+): limit doubled to 65536 (2 * 32768).
    if (primitives.isEnabledIn(spec, .shanghai)) {
        const max_initcode: usize = if (primitives.isEnabledIn(spec, .amsterdam)) primitives.AMSTERDAM_MAX_INITCODE_SIZE else primitives.MAX_INITCODE_SIZE;
        if (size_u > max_initcode) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }

    // EIP-3860 (Shanghai+): initcode word gas
    if (primitives.isEnabledIn(spec, .shanghai)) {
        const word_cost: u64 = 2 * @as(u64, @intCast((size_u + 31) / 32));
        if (!ctx.interpreter.gas.spend(word_cost)) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }

    // EIP-7928 (Amsterdam+): record the create target in the BAL BEFORE the NEW_ACCOUNT
    // charge (reference generic_create accesses the address before charge_state_gas), so an
    // OOG on the charge still leaves the created address in the block access list. The return
    // flags whether the target leaf is already alive, gating the NEW_ACCOUNT charge below.
    // recordCreateTarget returns null when a reference pre-check (depth/balance/nonce) fails —
    // the create returns 0 before accessing the address or charging NEW_ACCOUNT — else the
    // target's aliveness. Charge NEW_ACCOUNT only when it returned a non-null, not-alive result.
    var charge_new_account = false;
    if (primitives.isEnabledIn(spec, .amsterdam)) {
        if (h.recordCreateTarget(ctx.interpreter.input.target, value, &[_]u8{}, false, 0, ctx.interpreter.input.depth)) |alive| {
            charge_new_account = !alive;
        }
    }

    // EIP-8037 (Amsterdam+): charge NEW_ACCOUNT state gas only when the target leaf does not
    // yet exist (reference generic_create: `if not is_account_alive`). Charged BEFORE forwarded
    // gas is computed so `remaining` reflects the state gas cost.
    var new_account_state_gas: u64 = 0;
    if (charge_new_account) {
        const cpsb = gas_costs.costPerStateByte(h.block.gas_limit);
        new_account_state_gas = gas_costs.STATE_BYTES_PER_NEW_ACCOUNT * cpsb;
        if (!ctx.interpreter.gas.spendStateGas(new_account_state_gas)) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }

    // EIP-150 (Tangerine Whistle): forward at most 63/64 of remaining gas.
    // Pre-EIP-150 (Frontier/Homestead): forward all remaining gas.
    const remaining = ctx.interpreter.gas.remaining;
    const forwarded: u64 = if (primitives.isEnabledIn(spec, .tangerine))
        remaining - remaining / 64
    else
        remaining;

    const init_code: []const u8 = if (size_u > 0)
        ctx.interpreter.memory.buffer.items[off_u .. off_u + size_u]
    else
        &[_]u8{};

    // Pre-spend forwarded gas from parent (mirroring callImpl pattern).
    if (!ctx.interpreter.gas.spend(forwarded)) {
        ctx.interpreter.halt(.out_of_gas);
        return;
    }

    // EIP-8037 (Amsterdam+): save+zero parent's reservoir to pass to child.
    const create_reservoir: u64 = if (primitives.isEnabledIn(spec, .amsterdam)) blk: {
        const r = ctx.interpreter.gas.reservoir;
        ctx.interpreter.gas.reservoir = 0;
        break :blk r;
    } else 0;

    const caller = ctx.interpreter.input.target;
    const setup = h.setupCreate(caller, value, init_code, forwarded, false, 0, false, ctx.interpreter.input.depth, true);
    switch (setup) {
        .failed => |r| {
            // EIP-8037: pre-exec failure (e.g. address collision) — restore the parent reservoir
            // and refund new_account_state_gas via credit_state_gas_refund (LIFO): to regular gas
            // first if the charge spilled, else the reservoir. Unwind it from state-gas totals.
            var result = r;
            result.state_gas_remaining = create_reservoir;
            refundNewAccountLifo(ctx.interpreter, new_account_state_gas);
            resumeCreate(ctx.interpreter, result);
        },
        .ready => |s| {
            ctx.interpreter.pending = .{ .create = PendingCreateData{
                .inputs = CreateInputs{
                    .caller = caller,
                    .value = value,
                    .init_code = @constCast(init_code),
                    .gas_limit = forwarded,
                    .scheme = .create,
                    .salt = null,
                    .reservoir = create_reservoir,
                },
                .new_addr = s.new_addr,
                .checkpoint = s.checkpoint,
                .new_account_state_gas = new_account_state_gas,
                .target_alive = s.target_alive,
            } };
        },
    }
}

/// CREATE2 (0xF5): Create a new contract with deterministic address.
/// Stack: [value, offset, size, salt] -> [addr]
pub fn opCreate2(ctx: *InstructionContext) void {
    const h = ctx.host orelse {
        ctx.interpreter.halt(.invalid_opcode);
        return;
    };
    const stack = &ctx.interpreter.stack;
    if (!stack.hasItems(4)) {
        ctx.interpreter.halt(.stack_underflow);
        return;
    }

    const value = stack.peekUnsafe(0);
    const offset = stack.peekUnsafe(1);
    const size = stack.peekUnsafe(2);
    const salt = stack.peekUnsafe(3);
    stack.shrinkUnsafe(4);

    const spec = ctx.interpreter.runtime_flags.spec_id;

    // Static-context check first, before any gas is charged (reference raises
    // WriteInStaticContext before init-code cost and the NEW_ACCOUNT state-gas charge).
    if (ctx.interpreter.runtime_flags.is_static) {
        ctx.interpreter.halt(.invalid_static);
        return;
    }

    // EIP-8037 (Amsterdam+): CREATE_ACCESS = ACCOUNT_WRITE(8000) + COLD_STORAGE_ACCESS(3000).
    const create2_base_cost: u64 = if (primitives.isEnabledIn(spec, .amsterdam)) 11000 else gas_costs.G_CREATE;
    if (!ctx.interpreter.gas.spend(create2_base_cost)) {
        ctx.interpreter.halt(.out_of_gas);
        return;
    }

    const size_u: usize = if (size > std.math.maxInt(usize)) {
        ctx.interpreter.halt(.memory_limit_oog);
        return;
    } else @intCast(size);
    const off_u: usize = if (size_u == 0) 0 else if (offset > std.math.maxInt(usize)) {
        ctx.interpreter.halt(.memory_limit_oog);
        return;
    } else @intCast(offset);

    if (size_u > 0) {
        const create2_end = std.math.add(usize, off_u, size_u) catch {
            ctx.interpreter.halt(.memory_limit_oog);
            return;
        };
        if (!expandMemory(ctx, create2_end)) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }

    // EIP-3860 (Shanghai+): oversized initcode causes exceptional halt in calling frame.
    // EIP-7954 (Amsterdam+): limit doubled to 65536 (2 * 32768).
    if (primitives.isEnabledIn(spec, .shanghai)) {
        const max_initcode: usize = if (primitives.isEnabledIn(spec, .amsterdam)) primitives.AMSTERDAM_MAX_INITCODE_SIZE else primitives.MAX_INITCODE_SIZE;
        if (size_u > max_initcode) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }

    // CREATE2 keccak word cost (charged for the init_code hash)
    {
        const word_cost: u64 = gas_costs.G_KECCAK256WORD * @as(u64, @intCast((size_u + 31) / 32));
        if (!ctx.interpreter.gas.spend(word_cost)) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }
    // EIP-3860 (Shanghai+): additional initcode word gas
    if (primitives.isEnabledIn(spec, .shanghai)) {
        const word_cost: u64 = 2 * @as(u64, @intCast((size_u + 31) / 32));
        if (!ctx.interpreter.gas.spend(word_cost)) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }

    // EIP-7928 (Amsterdam+): record the create2 target in the BAL BEFORE the NEW_ACCOUNT
    // charge, so an OOG on the charge still leaves the created address in the block access list.
    // The return flags whether the target leaf is already alive, gating the charge below.
    // recordCreateTarget returns null when a reference pre-check (depth/balance/nonce) fails,
    // else the target's aliveness. Charge NEW_ACCOUNT only for a non-null, not-alive result.
    var charge_new_account = false;
    if (primitives.isEnabledIn(spec, .amsterdam)) {
        const ic: []const u8 = if (size_u > 0) ctx.interpreter.memory.buffer.items[off_u .. off_u + size_u] else &[_]u8{};
        if (h.recordCreateTarget(ctx.interpreter.input.target, value, ic, true, salt, ctx.interpreter.input.depth)) |alive| {
            charge_new_account = !alive;
        }
    }

    // EIP-8037 (Amsterdam+): charge NEW_ACCOUNT state gas only when the target leaf does not
    // yet exist (reference generic_create: `if not is_account_alive`). Charged BEFORE forwarded
    // gas is computed so `remaining` reflects the state gas cost.
    var new_account_state_gas: u64 = 0;
    if (charge_new_account) {
        const cpsb = gas_costs.costPerStateByte(h.block.gas_limit);
        new_account_state_gas = gas_costs.STATE_BYTES_PER_NEW_ACCOUNT * cpsb;
        if (!ctx.interpreter.gas.spendStateGas(new_account_state_gas)) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }

    // EIP-150 (Tangerine Whistle): forward at most 63/64 of remaining gas.
    // Pre-EIP-150: forward all remaining gas (CREATE2 didn't exist then, but symmetric).
    const remaining = ctx.interpreter.gas.remaining;
    const forwarded: u64 = if (primitives.isEnabledIn(spec, .tangerine))
        remaining - remaining / 64
    else
        remaining;

    const init_code: []const u8 = if (size_u > 0)
        ctx.interpreter.memory.buffer.items[off_u .. off_u + size_u]
    else
        &[_]u8{};

    // Pre-spend forwarded gas from parent.
    if (!ctx.interpreter.gas.spend(forwarded)) {
        ctx.interpreter.halt(.out_of_gas);
        return;
    }

    // EIP-8037 (Amsterdam+): save+zero parent's reservoir to pass to child.
    const create_reservoir: u64 = if (primitives.isEnabledIn(spec, .amsterdam)) blk: {
        const r = ctx.interpreter.gas.reservoir;
        ctx.interpreter.gas.reservoir = 0;
        break :blk r;
    } else 0;

    const caller = ctx.interpreter.input.target;
    const salt_hash = host_module.u256ToHash(salt);
    const setup = h.setupCreate(caller, value, init_code, forwarded, true, salt, false, ctx.interpreter.input.depth, true);
    switch (setup) {
        .failed => |r| {
            // EIP-8037: pre-exec failure (e.g. address collision) — restore the parent reservoir
            // and refund new_account_state_gas via credit_state_gas_refund (LIFO), unwinding it
            // from state-gas totals.
            var result = r;
            result.state_gas_remaining = create_reservoir;
            refundNewAccountLifo(ctx.interpreter, new_account_state_gas);
            resumeCreate(ctx.interpreter, result);
        },
        .ready => |s| {
            ctx.interpreter.pending = .{ .create = PendingCreateData{
                .inputs = CreateInputs{
                    .caller = caller,
                    .value = value,
                    .init_code = @constCast(init_code),
                    .gas_limit = forwarded,
                    .scheme = .create2,
                    .salt = salt_hash,
                    .reservoir = create_reservoir,
                },
                .new_addr = s.new_addr,
                .checkpoint = s.checkpoint,
                .new_account_state_gas = new_account_state_gas,
                .target_alive = s.target_alive,
            } };
        },
    }
}

test {
    _ = @import("create_tests.zig");
}
