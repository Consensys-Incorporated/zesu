//! Stateless block execution from SSZ stream input.
//!
//! Reads SSZ input via the injected `zkvm_io` module, executes the block,
//! and returns the serialized SSZ output bytes with a success flag.
//!
//! Used by both the native zesu binary (--ssz stream mode) and zkVM guests.
//! The caller is responsible for writing the output bytes.

const std = @import("std");
const executor = @import("executor");
const ssz_decode = @import("ssz_decode");
const ssz_output = @import("ssz_output");
const zkvm_io = @import("zkvm_io");

pub const Result = struct {
    /// glamsterdam-devnet-6 / zkevm@v0.5.0: SszStatelessValidationResult is now 105 bytes
    /// (32-byte new_payload_request_root + 1-byte success + 72-byte SszChainConfig
    /// trailer). See ssz_output.serialize.
    out: [105]u8,
    success: bool,
};

/// Execute a stateless block from the SSZ input stream.
/// Reads input via `zkvm_io.read_input`, decodes SSZ, executes the block,
/// and serializes the result. Always returns on both success and execution
/// failure — the caller checks `result.success` and commits accordingly.
/// Default-failed sentinel output — written when the SSZ input cannot be decoded.
/// Matches the reference `_default_failed_stateless_output`: root=0, success=0,
/// chain_id=0, fork=Frontier, empty activation and blob-schedule lists.
const DEFAULT_FAILED_OUTPUT: [105]u8 = blk: {
    var b: [105]u8 = .{0} ** 105;
    // [33..37] offset to chain_config = 37 (0x25)
    b[33] = 0x25;
    // [45..49] chain_config.offset_active_fork = 12 (0x0c)
    b[45] = 0x0c;
    // [57..61] active_fork.offset_activation = 16 (0x10)
    b[57] = 0x10;
    // [61..65] active_fork.offset_blob_schedule = 24 (0x18)
    b[61] = 0x18;
    // [65..69] activation.bn_offset = 8 (empty block_number list)
    b[65] = 0x08;
    // [69..73] activation.ts_offset = 8 (empty timestamp list)
    b[69] = 0x08;
    break :blk b;
};

pub fn runStateless(allocator: std.mem.Allocator) !Result {
    var buf_ptr: [*]const u8 = undefined;
    var buf_size: usize = 0;
    zkvm_io.read_input(&buf_ptr, &buf_size);
    std.log.info("input_len={d}", .{buf_size});

    const si = ssz_decode.decode(allocator, buf_ptr[0..buf_size]) catch |err| {
        std.log.err("{s}", .{@errorName(err)});
        return .{ .out = DEFAULT_FAILED_OUTPUT, .success = false };
    };

    const ep = &si.new_payload_request.execution_payload;
    std.log.info("block={d} txns={d}", .{ ep.block_number, ep.transactions.len });

    const exec_result = executor.executeStatelessInput(allocator, si, si.chain_config.fork_name);
    const success = if (exec_result) |_| true else |err| blk: {
        std.log.err("execution failed: {s}", .{@errorName(err)});
        break :blk false;
    };

    const out = try ssz_output.serialize(allocator, si.new_payload_request, si.chain_config.chain_id, success, si.chain_config.activation_timestamp orelse 0);
    std.log.info("root: 0x{x} success={d}", .{ out[0..32].*, @intFromBool(success) });

    return .{ .out = out, .success = success };
}
