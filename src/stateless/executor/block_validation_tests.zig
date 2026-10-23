//! Post-execution commitment checks in validatePostExecution.

const std = @import("std");
const types = @import("executor_types");

const block_validation = @import("./block_validation.zig");
const RootCommitments = block_validation.RootCommitments;
const validatePostExecution = block_validation.validatePostExecution;

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
