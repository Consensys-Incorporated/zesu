const std = @import("std");
const primitives = @import("primitives");

// Base gas costs
pub const G_ZERO = 0;
pub const G_BASE = 2;
pub const G_VERYLOW = 3;
pub const G_LOW = 5;
pub const G_MID = 8;
pub const G_HIGH = 10;

// Special operation costs
pub const G_JUMPDEST = 1;
pub const G_SSET = 20000; // Storage set (from zero to non-zero)
pub const G_SRESET = 5000; // Storage reset (non-zero to non-zero or zero)

// Call costs
pub const G_CALL_FRONTIER = 40; // Frontier/Homestead CALL base gas
pub const G_CALL = 700; // Tangerine+ (EIP-150) through pre-Berlin CALL base gas
pub const COLD_ACCOUNT_ACCESS = 2600;
pub const WARM_ACCOUNT_ACCESS = 100;
pub const COLD_SLOAD = 2100;
pub const WARM_SLOAD = 100;

// EIP-8037 (Amsterdam+): cold access repricing. Both cold account access and
// cold storage access rise to 3000 (from Berlin's 2600 / 2100). Warm access
// stays 100. See execution-specs amsterdam/vm/gas.py GasCosts.
pub const COLD_ACCOUNT_ACCESS_AMSTERDAM = 3000;
pub const COLD_STORAGE_ACCESS_AMSTERDAM = 3000;

/// Cold account-access cost for the active spec (EIP-2929 / EIP-8037).
pub inline fn coldAccountAccess(spec: primitives.SpecId) u64 {
    return if (primitives.isEnabledIn(spec, .amsterdam)) COLD_ACCOUNT_ACCESS_AMSTERDAM else COLD_ACCOUNT_ACCESS;
}

/// Cold storage-access (SLOAD) cost for the active spec (EIP-2929 / EIP-8037).
pub inline fn coldStorageAccess(spec: primitives.SpecId) u64 {
    return if (primitives.isEnabledIn(spec, .amsterdam)) COLD_STORAGE_ACCESS_AMSTERDAM else COLD_SLOAD;
}
pub const CALL_STIPEND = 2300; // Gas gifted to callee on value-bearing CALL (not deducted from caller)

// Storage costs - Pre-Berlin
pub const G_SLOAD_FRONTIER = 50; // Frontier/Homestead SLOAD gas
pub const G_SLOAD_TANGERINE = 200; // Tangerine (EIP-150) through pre-Istanbul SLOAD gas
pub const G_SLOAD_ISTANBUL = 800; // Istanbul (EIP-1884) SLOAD gas

// Storage costs - Berlin and later (EIP-2929)
pub const G_SLOAD_BERLIN_COLD = 2100;
pub const G_SLOAD_BERLIN_WARM = 100;

// SSTORE costs (EIP-2200, EIP-2929, EIP-3529)
pub const SSTORE_SET = 20000;
pub const SSTORE_RESET = 5000;
pub const SSTORE_CLEARS_SCHEDULE = 15000; // Istanbul refund for clearing storage
// EIP-3529 (London): R_sclear reduced from 15000 → 4800 = SSTORE_RESET_GAS + ACCESS_LIST_STORAGE_KEY_COST (2900+1900)
pub const SSTORE_CLEARS_SCHEDULE_LONDON = 4800;

// EIP-8037 (Amsterdam): State creation gas constants
// GAS_STORAGE_UPDATE replaces SSTORE_SET for 0→nonzero writes (regular portion only)
pub const GAS_STORAGE_UPDATE: u64 = 5000;
// EIP-8037 (Amsterdam+): SSTORE regular write cost on first change to a slot.
pub const STORAGE_WRITE_AMSTERDAM: u64 = 10000;
// EIP-8037 (Amsterdam+): storage-clear refund = (STORAGE_WRITE + COLD_STORAGE_ACCESS) * 4800/5000 = 12480.
pub const REFUND_STORAGE_CLEAR_AMSTERDAM: i64 = @intCast((STORAGE_WRITE_AMSTERDAM + COLD_STORAGE_ACCESS_AMSTERDAM) * 4800 / 5000);
// EIP-8037 (Amsterdam+): regular-lane cost to write a new account (CALL_VALUE, CREATE,
// EIP-7702 delegation). Pairs with STATE_BYTES_PER_NEW_ACCOUNT for the state lane.
pub const ACCOUNT_WRITE_COST: u64 = 8000;
// State bytes charged per operation (used with cost_per_state_byte)
pub const STATE_BYTES_PER_STORAGE_SET: u64 = 64;
pub const STATE_BYTES_PER_NEW_ACCOUNT: u64 = 120;
pub const STATE_BYTES_PER_AUTH_BASE: u64 = 23;
// EIP-8037: cap of upfront SSTOREs per system call; used to size system call reservoir.
pub const SYSTEM_MAX_SSTORES_PER_CALL: u64 = 16;
// EIP-7825: TX gas limit boundary for state gas reservoir split
pub const TX_MAX_GAS_LIMIT: u64 = 1 << 24; // 16,777,216

/// EIP-8037: cost_per_state_byte. bal-devnet-7 pins this to a fixed 1530.
pub fn costPerStateByte(block_gas_limit: u64) u64 {
    _ = block_gas_limit;
    return 1530;
}

// Create costs
pub const G_CREATE = 32000;
pub const G_CODEDEPOSIT = 200; // Per byte of deployed code

// Transaction costs
pub const G_TRANSACTION = 21000;
pub const G_TXCREATE = 32000;
pub const G_TXDATAZERO = 4;
pub const G_TXDATANONZERO = 16; // Pre-Istanbul
pub const G_TXDATANONZERO_ISTANBUL = 16; // Actually same
pub const G_TXDATANONZERO_EIP2028 = 16; // After EIP-2028

// Memory expansion cost
pub const G_MEMORY = 3; // Per word

// Copy operations
pub const G_COPY = 3; // Per word

// Log costs
pub const G_LOG = 375;
pub const G_LOGDATA = 8;
pub const G_LOGTOPIC = 375;

// SHA3/Keccak costs
pub const G_KECCAK256 = 30;
pub const G_KECCAK256WORD = 6;

// EXP costs
pub const G_EXP = 10;
pub const G_EXPBYTE = 50; // Post-Spurious Dragon (EIP-160)
pub const G_EXPBYTE_FRONTIER = 10; // Pre-Spurious Dragon

// SELFDESTRUCT
pub const G_SELFDESTRUCT = 5000;
pub const R_SELFDESTRUCT = 24000; // Refund

// Memory expansion cost formula
// cost = memory_size_word * G_MEMORY + (memory_size_word ^ 2) / 512
pub fn memoryExpansionCost(current_words: usize, new_words: usize) u64 {
    if (new_words <= current_words) return 0;

    const new_cost = memoryCost(new_words);
    const current_cost = memoryCost(current_words);

    return new_cost - current_cost;
}

fn memoryCost(num_words: usize) u64 {
    const n: u64 = @intCast(num_words);
    const linear = std.math.mul(u64, n, G_MEMORY) catch return std.math.maxInt(u64);
    const quadratic = (std.math.mul(u64, n, n) catch return std.math.maxInt(u64)) / 512;
    return std.math.add(u64, linear, quadratic) catch std.math.maxInt(u64);
}

// Calculate memory size in words (rounded up).
// Uses divCeil rather than (size + 31) / 32: a huge size must saturate, not
// overflow-panic, on the intermediate +31.
pub fn toWordSize(size: usize) usize {
    return std.math.divCeil(usize, size, 32) catch std.math.maxInt(usize);
}

// Get SLOAD gas cost based on spec and cold/warm access
pub fn getSloadCost(spec: primitives.SpecId, is_cold: bool) u64 {
    return switch (spec) {
        .frontier, .homestead => G_SLOAD_FRONTIER,
        .tangerine, .spurious, .byzantium, .constantinople, .petersburg => G_SLOAD_TANGERINE,
        .istanbul, .muir_glacier => G_SLOAD_ISTANBUL,
        .berlin, .london, .arrow_glacier, .gray_glacier => {
            return if (is_cold) G_SLOAD_BERLIN_COLD else G_SLOAD_BERLIN_WARM;
        },
        .merge, .shanghai, .cancun, .prague, .osaka => {
            return if (is_cold) G_SLOAD_BERLIN_COLD else G_SLOAD_BERLIN_WARM;
        },
        // EIP-8037 (Amsterdam+): cold storage access repriced to 3000.
        .amsterdam => {
            return if (is_cold) COLD_STORAGE_ACCESS_AMSTERDAM else G_SLOAD_BERLIN_WARM;
        },
    };
}

// SSTORE gas cost result
pub const SstoreGas = struct {
    gas_cost: u64,
    gas_refund: i64,
    /// EIP-8037 (Amsterdam+): state gas to charge via spendStateGas. 0 for pre-Amsterdam.
    state_gas: u64 = 0,
    /// EIP-8037 (Amsterdam+): state gas to refund back to reservoir (SSTORE restores zero).
    state_gas_refund: u64 = 0,
};

/// Returns the fork-appropriate SSTORE clearing refund (R_sclear):
///   - London+ (EIP-3529): 4800 = SSTORE_RESET_GAS(2900) + ACCESS_LIST_STORAGE_KEY_COST(1900)
///   - Berlin and earlier (including Istanbul): 15000
///   Note: EIP-2929 (Berlin) does NOT reduce R_sclear. Only EIP-3529 (London) reduces it to 4800.
fn sstoreClearsRefund(spec: primitives.SpecId) i64 {
    if (primitives.isEnabledIn(spec, .london)) return SSTORE_CLEARS_SCHEDULE_LONDON;
    return SSTORE_CLEARS_SCHEDULE;
}

// Calculate SSTORE gas cost based on EIP-2200, EIP-2929, and EIP-8037
pub fn getSstoreCost(
    spec: primitives.SpecId,
    original: primitives.U256,
    current: primitives.U256,
    new: primitives.U256,
    is_cold: bool,
    block_gas_limit: u64,
) SstoreGas {
    // EIP-8037 (Amsterdam+): fully repriced SSTORE model — see execution-specs
    // amsterdam/vm/instructions/storage.py sstore().
    if (primitives.isEnabledIn(spec, .amsterdam)) {
        return getSstoreCostAmsterdam(original, current, new, is_cold, block_gas_limit);
    }

    // Pre-Istanbul: simple gas model based only on current and new values.
    // EIP-2200 "original" tracking did not exist before Istanbul.
    // Every SSTORE is evaluated independently:
    //   current=0 → non-zero: G_SSET (20000)
    //   otherwise:             G_SRESET (5000), with R_sclear (15000) refund if clearing
    if (!primitives.isEnabledIn(spec, .istanbul)) {
        if (current == 0 and new != 0) {
            return .{ .gas_cost = SSTORE_SET, .gas_refund = 0 };
        } else {
            const refund: i64 = if (current != 0 and new == 0) SSTORE_CLEARS_SCHEDULE else 0;
            return .{ .gas_cost = SSTORE_RESET, .gas_refund = refund };
        }
    }

    // EIP-2200 (Istanbul) and EIP-2929 (Berlin) gas model
    const cold_cost: u64 = if (primitives.isEnabledIn(spec, .berlin) and is_cold) COLD_SLOAD else 0;

    // EIP-2929: Berlin+ reduces the base SSTORE_RESET by COLD_SLOAD to avoid
    // double-counting when cold_cost is separately added. Pre-Berlin uses 5000.
    const sstore_reset_cost: u64 = if (primitives.isEnabledIn(spec, .berlin)) SSTORE_RESET - COLD_SLOAD else SSTORE_RESET;

    // Fork-appropriate R_sclear: 4800 (London+), 15000 (Berlin and earlier)
    const clears_refund = sstoreClearsRefund(spec);

    if (current == new) {
        // EIP-2200 no-op: costs 1 SLOAD worth of gas.
        // Istanbul (pre-Berlin): G_sload = G_SLOAD_ISTANBUL = 800 (set by EIP-1884).
        // Berlin+: WARM_STORAGE_READ_COST = 100, plus COLD_SLOAD if the slot is cold.
        const base_no_change: u64 = if (primitives.isEnabledIn(spec, .berlin)) WARM_SLOAD else G_SLOAD_ISTANBUL;
        return .{ .gas_cost = base_no_change + cold_cost, .gas_refund = 0 };
    }

    if (original == current) {
        // First time modification in transaction
        if (original == 0) {
            // Setting from zero: creates new state
            if (primitives.isEnabledIn(spec, .amsterdam)) {
                // EIP-8037: regular gas = GAS_STORAGE_UPDATE (replaces SSTORE_SET),
                // state gas = STATE_BYTES_PER_STORAGE_SET * cost_per_state_byte
                const cpsb = costPerStateByte(block_gas_limit);
                const state_gas = STATE_BYTES_PER_STORAGE_SET * cpsb;
                return .{ .gas_cost = sstore_reset_cost + cold_cost, .gas_refund = 0, .state_gas = state_gas };
            }
            return .{ .gas_cost = SSTORE_SET + cold_cost, .gas_refund = 0 };
        } else {
            // Modifying non-zero value
            if (new == 0) {
                // Clearing storage - provide refund (R_sclear)
                return .{ .gas_cost = sstore_reset_cost + cold_cost, .gas_refund = clears_refund };
            } else {
                // Non-zero to non-zero
                return .{ .gas_cost = sstore_reset_cost + cold_cost, .gas_refund = 0 };
            }
        }
    }

    // Subsequent modification (dirty)
    var refund: i64 = 0;

    if (original != 0) {
        if (current == 0) {
            // Previously cleared, now setting — undo previous R_sclear refund
            refund -= clears_refund;
        } else if (new == 0) {
            // Now clearing — earn R_sclear refund
            refund += clears_refund;
        }
    }

    // Dirty base cost: warm-storage read cost for the current fork.
    // Istanbul (EIP-2200): G_SLOAD_ISTANBUL = 800.
    // Berlin+ (EIP-2929): WARM_STORAGE_READ_COST = 100.
    const dirty_base: u64 = if (primitives.isEnabledIn(spec, .berlin)) WARM_SLOAD else G_SLOAD_ISTANBUL;

    var state_gas_refund: u64 = 0;
    if (original == new) {
        // Restoring original value: refund net cost of the initial modification
        // (making the effective cost of this SSTORE = dirty_base, i.e. one SLOAD).
        if (original == 0) {
            if (primitives.isEnabledIn(spec, .amsterdam)) {
                // EIP-8037: state gas portion returns to reservoir; regular gas refund is
                // GAS_STORAGE_UPDATE - COLD_SLOAD - WARM_SLOAD = 5000 - 2100 - 100 = 2800.
                const cpsb = costPerStateByte(block_gas_limit);
                state_gas_refund = STATE_BYTES_PER_STORAGE_SET * cpsb;
                refund += @as(i64, @intCast(GAS_STORAGE_UPDATE)) -
                    @as(i64, @intCast(COLD_SLOAD)) -
                    @as(i64, @intCast(WARM_SLOAD));
            } else {
                refund += @as(i64, @intCast(SSTORE_SET)) - @as(i64, @intCast(dirty_base));
            }
        } else {
            refund += @as(i64, @intCast(sstore_reset_cost)) - @as(i64, @intCast(dirty_base));
        }
    }

    return .{ .gas_cost = dirty_base + cold_cost, .gas_refund = refund, .state_gas_refund = state_gas_refund };
}

/// EIP-8037 (Amsterdam+) SSTORE gas. Mirrors amsterdam/vm/instructions/storage.py:
///   access:  cold 3000 / warm 100 (always)
///   write:   +STORAGE_WRITE (10000) regular, only on first change this tx
///   set:     +STORAGE_SET state gas (64*cpsb) when creating a slot from zero
///   refunds: REFUND_STORAGE_CLEAR (12480) on clear; STORAGE_WRITE on restore-to-original;
///            STORAGE_SET state-gas credit when a same-tx-set slot is cleared again.
fn getSstoreCostAmsterdam(
    original: primitives.U256,
    current: primitives.U256,
    new: primitives.U256,
    is_cold: bool,
    block_gas_limit: u64,
) SstoreGas {
    const cpsb = costPerStateByte(block_gas_limit);
    const storage_set_state = STATE_BYTES_PER_STORAGE_SET * cpsb;

    var gas_cost: u64 = if (is_cold) COLD_STORAGE_ACCESS_AMSTERDAM else WARM_SLOAD;
    var refund: i64 = 0;
    var state_gas: u64 = 0;
    var state_gas_refund: u64 = 0;

    const first_change = (original == current and current != new);
    if (first_change) gas_cost += STORAGE_WRITE_AMSTERDAM;

    if (current != new) {
        if (original != 0 and current != 0 and new == 0) refund += REFUND_STORAGE_CLEAR_AMSTERDAM;
        if (original != 0 and current == 0) refund -= REFUND_STORAGE_CLEAR_AMSTERDAM;
        if (original == new) refund += @as(i64, @intCast(STORAGE_WRITE_AMSTERDAM));
    }

    if (first_change and original == 0) state_gas = storage_set_state;
    if (current != new and original == new and original == 0) state_gas_refund = storage_set_state;

    return .{ .gas_cost = gas_cost, .gas_refund = refund, .state_gas = state_gas, .state_gas_refund = state_gas_refund };
}

// Calculate call gas cost
pub fn getCallGasCost(
    spec: primitives.SpecId,
    is_cold: bool,
    transfers_value: bool,
    account_exists: bool,
) u64 {
    // Base access cost:
    //   Berlin+ (EIP-2929): cold/warm account access replaces the flat G_CALL
    //   Tangerine+ (EIP-150) through pre-Berlin: flat 700
    //   Frontier/Homestead (pre-Tangerine): flat 40
    var cost: u64 = if (primitives.isEnabledIn(spec, .berlin))
        (if (is_cold) coldAccountAccess(spec) else WARM_ACCOUNT_ACCESS)
    else if (primitives.isEnabledIn(spec, .tangerine))
        G_CALL
    else
        G_CALL_FRONTIER;

    // Value transfer cost. Pre-Amsterdam: G_CALLVALUE = 9000.
    // EIP-8037 (Amsterdam+): CALL_VALUE = ACCOUNT_WRITE(8000) + CALL_STIPEND(2300) = 10300.
    if (transfers_value) {
        cost += if (primitives.isEnabledIn(spec, .amsterdam)) 10300 else 9000;
        // New account creation cost (G_NEWACCOUNT = 25000).
        // EIP-8037 (Amsterdam+): G_NEWACCOUNT regular cost removed; state gas charged separately
        // in opCall via spendStateGas(STATE_BYTES_PER_NEW_ACCOUNT * cost_per_state_byte).
        if (!account_exists and !primitives.isEnabledIn(spec, .amsterdam)) {
            cost += 25000;
        }
    } else if (!primitives.isEnabledIn(spec, .spurious_dragon) and !account_exists) {
        // Pre-EIP-161 (pre-Spurious Dragon): G_NEWACCOUNT is charged for any CALL to a
        // non-existent (dead) account, even with zero value.
        // EIP-161 changed this to only charge G_NEWACCOUNT when value > 0.
        cost += 25000;
    }

    return cost;
}
