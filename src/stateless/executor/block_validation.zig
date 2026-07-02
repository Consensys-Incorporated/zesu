const types = @import("executor_types");
const primitives = @import("primitives");
const bal = @import("./bal.zig");
const accel = @import("accelerators");

// EIP-1559 / gas limit constants
const MIN_GAS_LIMIT: u64 = 5_000;
const MAX_GAS_LIMIT: u64 = 0x7fff_ffff_ffff_ffff;
const GAS_LIMIT_ADJUSTMENT_FACTOR: u64 = 1_024;
const BASE_FEE_MAX_CHANGE_DENOMINATOR: u64 = 8;
const ELASTICITY_MULTIPLIER: u64 = 2;

// EIP-4844 blob gas constants
const GAS_PER_BLOB: u64 = 131_072;
// EIP-7918 blob reserve price constant (2^13)
const BLOB_BASE_COST: u64 = 8_192;
// EIP-7934 max RLP-encoded block size (8 MiB)
const MAX_RLP_BLOCK_SIZE: u64 = 8_388_608;

/// Validates block-level invariants before execution.
/// Returns an error if the block header is invalid.
pub fn validateBlock(env: types.Env, spec: primitives.SpecId) !void {
    // GASLIMIT_TOO_BIG: gas limit must fit in a signed 64-bit integer
    if (env.gas_limit > MAX_GAS_LIMIT) return error.GasLimitTooBig;

    // INVALID_BLOCK_TIMESTAMP_OLDER_THAN_PARENT
    if (env.parent_timestamp) |pt| {
        if (env.timestamp <= pt) return error.InvalidBlockTimestampOlderThanParent;
    }

    // INVALID_GASLIMIT: gas_limit >= MIN_GAS_LIMIT always,
    // and |gas_limit - parent_gas_limit| < parent_gas_limit / 1024 when parent is known
    if (env.gas_limit < MIN_GAS_LIMIT) return error.InvalidGasLimit;

    if (env.parent_gas_limit) |pgl| {
        const max_delta = pgl / GAS_LIMIT_ADJUSTMENT_FACTOR;
        const diff = if (env.gas_limit > pgl) env.gas_limit - pgl else pgl - env.gas_limit;
        if (diff >= max_delta) return error.InvalidGasLimit;
    }

    // INVALID_BASEFEE_PER_GAS (EIP-1559, London+)
    if (primitives.isEnabledIn(spec, .london)) {
        if (env.parent_base_fee) |pbf| if (env.parent_gas_limit) |pgl| if (env.parent_gas_used) |pgu| {
            if (env.base_fee) |actual_base_fee| {
                const gas_target = pgl / ELASTICITY_MULTIPLIER;
                const expected_base_fee: u64 = blk: {
                    if (pgu == gas_target) {
                        break :blk pbf;
                    } else if (pgu > gas_target) {
                        const delta: u128 = pgu - gas_target;
                        const fee_delta: u64 = @intCast(@max(1, @as(u128, pbf) * delta / gas_target / BASE_FEE_MAX_CHANGE_DENOMINATOR));
                        break :blk pbf + fee_delta;
                    } else {
                        const delta: u128 = gas_target - pgu;
                        const fee_delta: u64 = @intCast(@as(u128, pbf) * delta / gas_target / BASE_FEE_MAX_CHANGE_DENOMINATOR);
                        break :blk pbf - fee_delta;
                    }
                };
                if (actual_base_fee != expected_base_fee) return error.InvalidBaseFeePerGas;
            }
        };
    }

    // BLOCK_RLP_TOO_LARGE (EIP-7934, Osaka+)
    if (primitives.isEnabledIn(spec, .osaka)) {
        if (env.block_rlp_size) |sz| {
            if (sz > MAX_RLP_BLOCK_SIZE) return error.BlockRlpTooLarge;
        }
    }

    // PRE_FORK_BLOB_FIELDS: blob header fields must not appear before Cancun
    if (!primitives.isEnabledIn(spec, .cancun)) {
        if (env.excess_blob_gas != null or env.blob_gas_used_header != null)
            return error.UnexpectedBlobFields;
    }

    // INCORRECT_EXCESS_BLOB_GAS (EIP-4844, Cancun+)
    if (primitives.isEnabledIn(spec, .cancun)) {
        if (env.parent_excess_blob_gas) |pebg| if (env.parent_blob_gas_used) |pbgu| {
            const expected: u64 = calcExcessBlobGas(pebg, pbgu, env.parent_base_fee, spec, env.blob_base_fee_update_fraction);
            if (env.excess_blob_gas) |actual| {
                if (actual != expected) return error.IncorrectExcessBlobGas;
            }
        };
    }
}

/// Returns the blob gas TARGET per block for the given spec.
/// - BPO2/Amsterdam+: 14 blobs
/// - BPO1:            10 blobs
/// - Prague/Osaka:     6 blobs
/// - Cancun:           3 blobs
pub fn blobGasTarget(spec: primitives.SpecId) u64 {
    return if (primitives.isEnabledIn(spec, .bpo2))
        14 * GAS_PER_BLOB
    else if (primitives.isEnabledIn(spec, .bpo1))
        10 * GAS_PER_BLOB
    else if (primitives.isEnabledIn(spec, .prague))
        6 * GAS_PER_BLOB
    else
        3 * GAS_PER_BLOB;
}

/// Returns the blob gas MAX per block for the given spec.
/// - BPO2/Amsterdam+: 21 blobs
/// - BPO1:            15 blobs
/// - Prague/Osaka:     9 blobs
/// - Cancun:           6 blobs
pub fn blobGasMax(spec: primitives.SpecId) u64 {
    return if (primitives.isEnabledIn(spec, .bpo2))
        21 * GAS_PER_BLOB
    else if (primitives.isEnabledIn(spec, .bpo1))
        15 * GAS_PER_BLOB
    else if (primitives.isEnabledIn(spec, .prague))
        9 * GAS_PER_BLOB
    else
        6 * GAS_PER_BLOB;
}

/// Computed-vs-declared block commitments, validated by `validatePostExecution`.
/// Pass `null` for paths that don't validate against a claimed header (e.g. the
/// non-stateless executeBlock used by t8n).
pub const RootCommitments = struct {
    computed_state_root: [32]u8,
    expected_state_root: [32]u8,
    computed_receipts_root: [32]u8,
    expected_receipts_root: [32]u8,
};

/// Post-execution block validation.
/// Called after transition() with the actual gas totals.
///   total_gas_used — cumulative gas from all transactions (result.cumulative_gas)
///   blob_gas_used  — total blob gas from type-3 transactions (result.blob_gas_used)
///   roots          — computed/declared state & receipts roots, or null to skip
pub fn validatePostExecution(
    alloc: std.mem.Allocator,
    env: types.Env,
    spec: primitives.SpecId,
    total_gas_used: u64,
    blob_gas_used: u64,
    block_access_list: []const u8,
    accessed: []const types.AccessedEntry,
    roots: ?RootCommitments,
) !void {
    // INVALID_GAS_USED_ABOVE_LIMIT: header gasUsed > gasLimit
    if (env.gas_used_header) |declared| {
        if (declared > env.gas_limit) return error.InvalidGasUsedAboveLimit;
    }

    // GAS_USED_OVERFLOW: actual execution gas > gasLimit (sanity guard)
    if (total_gas_used > env.gas_limit) return error.GasUsedOverflow;

    // INVALID_GAS_USED: computed total ≠ header's declared gasUsed.
    // Gated to pre-Amsterdam: EIP-7778 (Amsterdam+) splits block-header gasUsed
    // (no-refund accounting) from receipt cumulative_gas_used (post-refund).
    // result.cumulative_gas tracks receipt-level gas; once EIP-7778 is
    // implemented in transition(), remove this gate.
    if (!primitives.isEnabledIn(spec, .amsterdam)) {
        if (env.gas_used_header) |declared| {
            if (total_gas_used != declared) return error.InvalidGasUsed;
        }
    }

    if (primitives.isEnabledIn(spec, .cancun)) {
        // BLOB_GAS_USED_ABOVE_LIMIT
        if (blob_gas_used > blobGasMax(spec)) return error.BlobGasUsedAboveLimit;

        // INCORRECT_BLOB_GAS_USED: computed blob gas ≠ header's declared blobGasUsed
        if (env.blob_gas_used_header) |declared| {
            if (blob_gas_used != declared) return error.IncorrectBlobGasUsed;
        }
    }

    // INVALID_BLOCK_ACCESS_LIST (EIP-7928, Amsterdam+)
    if (primitives.isEnabledIn(spec, .amsterdam)) {
        if (block_access_list.len == 0) {
            if (accessed.len != 0) return error.InvalidBlockAccessList;
        } else {
            const declared = bal.decode(alloc, block_access_list) catch {
                return error.InvalidBlockAccessList;
            };

            // Verify declared is strictly ascending by address (canonical BAL order)
            for (1..@max(1, declared.len)) |i| {
                if (std.mem.order(u8, &declared[i - 1].address, &declared[i].address) != .lt) {
                    return error.InvalidBlockAccessList;
                }
            }

            if (declared.len != accessed.len) return error.InvalidBlockAccessList;

            for (declared, accessed) |decl, comp| {
                if (!std.mem.eql(u8, &decl.address, &comp.address)) return error.InvalidBlockAccessList;

                if (comp.pre_nonce != comp.post_nonce) {
                    if (decl.nonce_changes.len == 0) return error.InvalidBlockAccessList;
                    if (decl.nonce_changes[decl.nonce_changes.len - 1] != comp.post_nonce) return error.InvalidBlockAccessList;
                } else {
                    if (decl.nonce_changes.len != 0) return error.InvalidBlockAccessList;
                }

                if (decl.balance_changes.len != 0) {
                    if (decl.balance_changes[decl.balance_changes.len - 1] != comp.post_balance) return error.InvalidBlockAccessList;
                } else if (comp.pre_balance != comp.post_balance) {
                    return error.InvalidBlockAccessList;
                }

                if (decl.code_changes.len != 0) {
                    const last_code = decl.code_changes[decl.code_changes.len - 1];
                    var last_code_hash: primitives.Hash = primitives.KECCAK_EMPTY;
                    if (last_code.len > 0) {
                        accel.keccak256(last_code, &last_code_hash);
                    }
                    if (!std.mem.eql(u8, &last_code_hash, &comp.post_code_hash)) return error.InvalidBlockAccessList;
                } else {
                    if (!std.mem.eql(u8, &comp.pre_code_hash, &comp.post_code_hash)) return error.InvalidBlockAccessList;
                }

                if (decl.storage_changes.len != comp.storage_changes.len) return error.InvalidBlockAccessList;
                for (decl.storage_changes, comp.storage_changes) |ds, cs| {
                    if (!std.mem.eql(u8, &ds.slot, &cs.slot)) return error.InvalidBlockAccessList;
                    if (ds.post_value != cs.post_value) return error.InvalidBlockAccessList;
                }

                if (decl.storage_reads.len != comp.storage_reads.len) return error.InvalidBlockAccessList;
                for (decl.storage_reads, comp.storage_reads) |dr, cr| {
                    if (!std.mem.eql(u8, &dr, &cr)) return error.InvalidBlockAccessList;
                }
            }
        }
    }

    // INVALID_STATE_ROOT / INVALID_RECEIPTS_ROOT: the computed commitments must
    // match the values declared in the block header. Checked last so the more
    // specific gas/blob/BAL errors take precedence.
    if (roots) |r| {
        if (!std.mem.eql(u8, &r.computed_state_root, &r.expected_state_root)) return error.StateRootMismatch;
        if (!std.mem.eql(u8, &r.computed_receipts_root, &r.expected_receipts_root)) return error.ReceiptsRootMismatch;
    }
}

/// Validates blob gas used against the per-block maximum (post-execution check).
/// Deprecated: prefer validatePostExecution. Kept for callers that only need this one check.
pub fn validateBlobGasUsed(blob_gas_used: u64, spec: primitives.SpecId) !void {
    if (!primitives.isEnabledIn(spec, .cancun)) return;
    if (blob_gas_used > blobGasMax(spec)) return error.BlobGasUsedAboveLimit;
}

/// Calculates the expected excess_blob_gas for the next block.
/// For Osaka+ (EIP-7918), applies the reserve price adjustment when active.
/// For Cancun/Prague, uses the standard EIP-4844 formula.
pub fn calcExcessBlobGas(
    parent_excess: u64,
    parent_used: u64,
    parent_base_fee: ?u64,
    spec: primitives.SpecId,
    update_fraction_override: ?u64,
) u64 {
    const target = blobGasTarget(spec);
    const sum = parent_excess + parent_used;

    // Standard EIP-4844 formula applies when sum < target (no excess regardless of EIP-7918)
    if (sum < target) return 0;

    // EIP-7918 reserve price adjustment (Osaka+)
    if (primitives.isEnabledIn(spec, .osaka)) {
        if (parent_base_fee) |pbf| {
            const fraction = update_fraction_override orelse defaultBlobUpdateFraction(spec);
            const current_blob_fee = fakeBlobGasPrice(parent_excess, fraction);
            // Reserve price active when: BLOB_BASE_COST * base_fee > GAS_PER_BLOB * blob_fee
            const lhs: u128 = @as(u128, BLOB_BASE_COST) * @as(u128, pbf);
            const rhs: u128 = @as(u128, GAS_PER_BLOB) * current_blob_fee;
            if (lhs > rhs) {
                // Reserve price active: partial adjustment only
                const max_gas = blobGasMax(spec);
                const adjustment = @as(u128, parent_used) * (max_gas - target) / max_gas;
                return parent_excess + @as(u64, @intCast(adjustment));
            }
        }
    }

    // Standard EIP-4844 formula
    return sum - target;
}

/// Returns the default blob base fee update fraction for the given spec.
fn defaultBlobUpdateFraction(spec: primitives.SpecId) u64 {
    if (primitives.isEnabledIn(spec, .bpo2)) return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_BPO2;
    if (primitives.isEnabledIn(spec, .bpo1)) return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_BPO1;
    if (primitives.isEnabledIn(spec, .prague)) return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE;
    return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN;
}

/// fake_exponential(factor=1, numerator=excess_blob_gas, denominator=update_fraction)
/// Mirrors the EIP-4844 blob gas price formula in zevm/src/context/block.zig.
fn fakeBlobGasPrice(excess_blob_gas: u64, update_fraction: u64) u128 {
    if (update_fraction == 0) return std.math.maxInt(u128);
    const numerator: u128 = excess_blob_gas;
    const denominator: u128 = update_fraction;
    var i: u128 = 1;
    var output: u128 = 0;
    var accum: u128 = denominator; // factor=1 * denominator
    while (accum > 0) {
        output +|= accum;
        accum = (accum *| numerator) / (denominator * i);
        i += 1;
        if (i > 512) break;
    }
    return output / denominator;
}

const std = @import("std");
