//! Header checks in validateBlock, the excess blob gas rule, and the post-execution
//! checks in validatePostExecution. Expected values follow the execution-specs
//! reference (forks/<fork>/fork.py and vm/gas.py).

const std = @import("std");
const types = @import("executor_types");
const SpecId = @import("primitives").SpecId;

const block_validation = @import("./block_validation.zig");
const RootCommitments = block_validation.RootCommitments;
const validatePostExecution = block_validation.validatePostExecution;
const validateBlock = block_validation.validateBlock;
const calcExcessBlobGas = block_validation.calcExcessBlobGas;

const GAS_PER_BLOB: u64 = 131_072;

test "a header logs bloom that differs from the block's logs is rejected" {
    const env: types.Env = .{ .coinbase = @splat(0), .gas_limit = 30_000_000 };
    var roots: RootCommitments = .{
        .computed_state_root = @splat(0x11),
        .expected_state_root = @splat(0x11),
        .computed_receipts_root = @splat(0x22),
        .expected_receipts_root = @splat(0x22),
        .computed_logs_bloom = @splat(0),
        .expected_logs_bloom = @splat(0),
    };
    try validatePostExecution(env, .amsterdam, 0, 0, null, roots);

    roots.expected_logs_bloom[0] = 0x01;
    try std.testing.expectError(error.InvalidLogsBloom, validatePostExecution(env, .amsterdam, 0, 0, null, roots));
}

// fork.py check_gas_limit: LIMIT_MINIMUM = 5000.
test "a gas limit below 5000 is rejected" {
    try validateBlock(.{ .gas_limit = 5_000 }, .osaka);
    try std.testing.expectError(error.InvalidGasLimit, validateBlock(.{ .gas_limit = 4_999 }, .osaka));
}

// fork.py check_gas_limit: the limit must move by less than parent // 1024
// (30_000_000 // 1024 = 29_296) in either direction.
test "a gas limit that moves by parent/1024 or more is rejected" {
    const parent: u64 = 30_000_000;
    try validateBlock(.{ .gas_limit = parent + 29_295, .parent_gas_limit = parent }, .osaka);
    try validateBlock(.{ .gas_limit = parent - 29_295, .parent_gas_limit = parent }, .osaka);
    try std.testing.expectError(
        error.InvalidGasLimit,
        validateBlock(.{ .gas_limit = parent + 29_296, .parent_gas_limit = parent }, .osaka),
    );
    try std.testing.expectError(
        error.InvalidGasLimit,
        validateBlock(.{ .gas_limit = parent - 29_296, .parent_gas_limit = parent }, .osaka),
    );
}

// fork.py validate_header: `header.timestamp <= parent_header.timestamp` is invalid.
test "a timestamp not after the parent's is rejected" {
    try validateBlock(.{ .timestamp = 101, .parent_timestamp = 100 }, .osaka);
    try std.testing.expectError(
        error.InvalidBlockTimestampOlderThanParent,
        validateBlock(.{ .timestamp = 100, .parent_timestamp = 100 }, .osaka),
    );
    try std.testing.expectError(
        error.InvalidBlockTimestampOlderThanParent,
        validateBlock(.{ .timestamp = 99, .parent_timestamp = 100 }, .osaka),
    );
}

fn baseFeeEnv(parent_gas_used: u64, parent_base_fee: u64, base_fee: u64) types.Env {
    return .{
        .gas_limit = 30_000_000,
        .parent_gas_limit = 30_000_000,
        .parent_gas_used = parent_gas_used,
        .parent_base_fee = parent_base_fee,
        .base_fee = base_fee,
    };
}

// fork.py calculate_base_fee_per_gas, parent gas target 15_000_000.
test "the base fee follows the parent's gas usage" {
    const Case = struct { parent_gas_used: u64, parent_base_fee: u64, expected: u64 };
    const cases = [_]Case{
        // At the target the base fee is unchanged.
        .{ .parent_gas_used = 15_000_000, .parent_base_fee = 1_000, .expected = 1_000 },
        // A full parent raises it by 1/8, an empty one lowers it by 1/8.
        .{ .parent_gas_used = 30_000_000, .parent_base_fee = 1_000, .expected = 1_125 },
        .{ .parent_gas_used = 0, .parent_base_fee = 1_000, .expected = 875 },
        // 1_000_000_007 * 5_000_000 // 15_000_000 // 8 = 41_666_666.
        .{ .parent_gas_used = 20_000_000, .parent_base_fee = 1_000_000_007, .expected = 1_041_666_673 },
        .{ .parent_gas_used = 10_000_000, .parent_base_fee = 1_000_000_007, .expected = 958_333_341 },
        // Above the target the increase is at least 1; below it the decrease may be 0.
        .{ .parent_gas_used = 15_000_001, .parent_base_fee = 7, .expected = 8 },
        .{ .parent_gas_used = 14_999_999, .parent_base_fee = 7, .expected = 7 },
    };
    for (cases) |c| {
        try validateBlock(baseFeeEnv(c.parent_gas_used, c.parent_base_fee, c.expected), .osaka);
        try std.testing.expectError(
            error.InvalidBaseFeePerGas,
            validateBlock(baseFeeEnv(c.parent_gas_used, c.parent_base_fee, c.expected + 1), .osaka),
        );
        try std.testing.expectError(
            error.InvalidBaseFeePerGas,
            validateBlock(baseFeeEnv(c.parent_gas_used, c.parent_base_fee, c.expected - 1), .osaka),
        );
    }
}

// fork.py state_transition (EIP-7934): MAX_RLP_BLOCK_SIZE = 10_485_760 - 2_097_152,
// checked from Osaka.
test "a block over the RLP size limit is rejected from Osaka" {
    try validateBlock(.{ .block_rlp_size = 8_388_608 }, .osaka);
    try std.testing.expectError(error.BlockRlpTooLarge, validateBlock(.{ .block_rlp_size = 8_388_609 }, .osaka));
    try std.testing.expectError(error.BlockRlpTooLarge, validateBlock(.{ .block_rlp_size = 8_388_609 }, .amsterdam));
    try validateBlock(.{ .block_rlp_size = 8_388_609 }, .prague);
}

// vm/gas.py calculate_excess_blob_gas, Cancun and Prague: max(0, excess + used - target),
// target 393_216 (Cancun) and 786_432 (Prague). No reserve price before Osaka.
test "excess blob gas before Osaka is the parent's blob gas above the target" {
    try std.testing.expectEqual(0, calcExcessBlobGas(0, 393_215, 1_000_000, .cancun, null));
    try std.testing.expectEqual(0, calcExcessBlobGas(0, 393_216, 1_000_000, .cancun, null));
    try std.testing.expectEqual(1, calcExcessBlobGas(1, 393_216, 1_000_000, .cancun, null));
    try std.testing.expectEqual(393_216, calcExcessBlobGas(0, 786_432, 1_000_000, .cancun, null));

    try std.testing.expectEqual(0, calcExcessBlobGas(393_216, 393_215, 1_000_000, .prague, null));
    try std.testing.expectEqual(1, calcExcessBlobGas(393_216, 393_217, 1_000_000, .prague, null));
    try std.testing.expectEqual(393_216, calcExcessBlobGas(0, 1_179_648, 1_000_000, .prague, null));
}

// vm/gas.py calculate_excess_blob_gas (EIP-7918). With no excess the blob price is 1, so
// the reserve price applies when 8192 * base_fee > 131_072, i.e. base_fee > 16; the
// result is then excess + used * (max - target) // max instead of excess + used - target.
test "excess blob gas from Osaka applies the reserve price above its threshold" {
    const Case = struct { spec: SpecId, used: u64, standard: u64, reserve: u64 };
    const cases = [_]Case{
        // target 6, max 9: 917_504 * 3 // 9
        .{ .spec = .osaka, .used = 7 * GAS_PER_BLOB, .standard = 131_072, .reserve = 305_834 },
        // target 10, max 15: 1_441_792 * 5 // 15
        .{ .spec = .bpo1, .used = 11 * GAS_PER_BLOB, .standard = 131_072, .reserve = 480_597 },
        // target 14, max 21: 1_966_080 * 7 // 21
        .{ .spec = .bpo2, .used = 15 * GAS_PER_BLOB, .standard = 131_072, .reserve = 655_360 },
        .{ .spec = .amsterdam, .used = 15 * GAS_PER_BLOB, .standard = 131_072, .reserve = 655_360 },
    };
    for (cases) |c| {
        try std.testing.expectEqual(c.standard, calcExcessBlobGas(0, c.used, 16, c.spec, null));
        try std.testing.expectEqual(c.reserve, calcExcessBlobGas(0, c.used, 17, c.spec, null));
        // Below the target the result is 0 whatever the base fee.
        try std.testing.expectEqual(0, calcExcessBlobGas(0, c.used - GAS_PER_BLOB - 1, 1_000_000, c.spec, null));
    }
}

// vm/gas.py calculate_blob_gas_price: taylor_exponential(1, excess, BLOB_BASE_FEE_UPDATE_FRACTION).
// At 40_000_000 excess it is 2944 (Osaka, 5_007_716), 120 (BPO1, 8_346_193) and
// 30 (BPO2 and Amsterdam, 11_684_671); the reserve price applies above base_fee = 16 * price.
test "the reserve price threshold uses each fork's blob price" {
    const excess: u64 = 40_000_000;
    const Case = struct { spec: SpecId, used: u64, threshold: u64, standard: u64, reserve: u64 };
    const cases = [_]Case{
        .{ .spec = .osaka, .used = 7 * GAS_PER_BLOB, .threshold = 47_104, .standard = 40_131_072, .reserve = 40_305_834 },
        .{ .spec = .bpo1, .used = 11 * GAS_PER_BLOB, .threshold = 1_920, .standard = 40_131_072, .reserve = 40_480_597 },
        .{ .spec = .bpo2, .used = 15 * GAS_PER_BLOB, .threshold = 480, .standard = 40_131_072, .reserve = 40_655_360 },
        .{ .spec = .amsterdam, .used = 15 * GAS_PER_BLOB, .threshold = 480, .standard = 40_131_072, .reserve = 40_655_360 },
    };
    for (cases) |c| {
        try std.testing.expectEqual(c.standard, calcExcessBlobGas(excess, c.used, c.threshold, c.spec, null));
        try std.testing.expectEqual(c.reserve, calcExcessBlobGas(excess, c.used, c.threshold + 1, c.spec, null));
    }

    // A blob schedule override replaces the fork's update fraction: Osaka with BPO1's.
    try std.testing.expectEqual(40_131_072, calcExcessBlobGas(excess, 7 * GAS_PER_BLOB, 1_920, .osaka, 8_346_193));
    try std.testing.expectEqual(40_305_834, calcExcessBlobGas(excess, 7 * GAS_PER_BLOB, 1_921, .osaka, 8_346_193));
}

// fork.py validate_header: `header.excess_blob_gas != calculate_excess_blob_gas(parent)` is invalid.
test "a header excess blob gas that differs from the parent's result is rejected" {
    var env: types.Env = .{
        .parent_excess_blob_gas = 0,
        .parent_blob_gas_used = 7 * GAS_PER_BLOB,
        .parent_base_fee = 17,
        .excess_blob_gas = 305_834,
    };
    try validateBlock(env, .osaka);
    // 131_072 is the result without the reserve price, which Prague still uses.
    try std.testing.expectError(error.IncorrectExcessBlobGas, validateBlock(env, .prague));
    env.excess_blob_gas = 131_072;
    try validateBlock(env, .prague);
    try std.testing.expectError(error.IncorrectExcessBlobGas, validateBlock(env, .osaka));
}

// fork.py validate_header (`header.gas_used > header.gas_limit`) and state_transition
// (`block_output.block_gas_used != block.header.gas_used`).
test "the header's gas used must fit the limit and match execution" {
    try validatePostExecution(.{ .gas_limit = 1_000_000, .gas_used_header = 1_000_000 }, .osaka, 1_000_000, 0, null, null);
    try std.testing.expectError(
        error.InvalidGasUsedAboveLimit,
        validatePostExecution(.{ .gas_limit = 1_000_000, .gas_used_header = 1_000_001 }, .osaka, 21_000, 0, null, null),
    );
    try std.testing.expectError(
        error.InvalidGasUsed,
        validatePostExecution(.{ .gas_limit = 1_000_000, .gas_used_header = 21_000 }, .osaka, 21_001, 0, null, null),
    );
    try std.testing.expectError(
        error.InvalidGasUsed,
        validatePostExecution(.{ .gas_limit = 1_000_000, .gas_used_header = 21_000 }, .osaka, 20_999, 0, null, null),
    );
}

// fork.py MAX_BLOB_GAS_PER_BLOCK: 6 blobs (Cancun), 9 (Prague, Osaka), 15 (BPO1),
// 21 (BPO2, Amsterdam); check_transaction rejects blob gas beyond it.
test "blob gas used above the fork's maximum is rejected" {
    const Case = struct { spec: SpecId, max_blobs: u64 };
    const cases = [_]Case{
        .{ .spec = .cancun, .max_blobs = 6 },
        .{ .spec = .prague, .max_blobs = 9 },
        .{ .spec = .osaka, .max_blobs = 9 },
        .{ .spec = .bpo1, .max_blobs = 15 },
        .{ .spec = .bpo2, .max_blobs = 21 },
        .{ .spec = .amsterdam, .max_blobs = 21 },
    };
    for (cases) |c| {
        const max = c.max_blobs * GAS_PER_BLOB;
        try validatePostExecution(.{}, c.spec, 0, max, null, null);
        try std.testing.expectError(
            error.BlobGasUsedAboveLimit,
            validatePostExecution(.{}, c.spec, 0, max + GAS_PER_BLOB, null, null),
        );
    }
}

// fork.py state_transition: `block_output.blob_gas_used != block.header.blob_gas_used` is invalid.
test "a header blob gas used that differs from execution is rejected" {
    const env: types.Env = .{ .blob_gas_used_header = 2 * GAS_PER_BLOB };
    try validatePostExecution(env, .osaka, 0, 2 * GAS_PER_BLOB, null, null);
    try std.testing.expectError(error.IncorrectBlobGasUsed, validatePostExecution(env, .osaka, 0, 3 * GAS_PER_BLOB, null, null));
    try std.testing.expectError(error.IncorrectBlobGasUsed, validatePostExecution(env, .osaka, 0, GAS_PER_BLOB, null, null));
}
