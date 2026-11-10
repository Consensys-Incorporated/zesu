//! ProofOutput: the executor's result for a block. This is not what the guest commits; the
//! committed public output is the SSZ validation result built by ssz_output.zig.

const primitives = @import("primitives");

/// Result of executing one transaction.
pub const ReceiptData = struct {
    cumulative_gas_used: u64,
    success: bool,
    logs_bloom: [256]u8,
};

/// Output committed by the guest program.
pub const ProofOutput = struct {
    /// The parent header's state root.
    pre_state_root: primitives.Hash,
    post_state_root: primitives.Hash,
    receipts_root: primitives.Hash,
    receipts: []const ReceiptData,
    /// hardfork.specName of the executed spec (e.g. "Prague").
    fork_name: []const u8,
};
