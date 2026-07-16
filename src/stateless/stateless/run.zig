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
    /// zkevm@v0.6.2: a successful SszStatelessValidationResult is 69 bytes
    /// (32-byte root + 1-byte success + 36-byte SszChainConfig trailer).
    /// A decode-failure output is 61 bytes (empty default SszChainConfig,
    /// see ssz_output.DEFAULT_FAILED_OUTPUT). Buffer sized for the larger success case.
    out: [69]u8,
    /// Number of valid bytes in `out`: 69 on success, 61 on decode failure. The guest
    /// commits exactly `out[0..len]` — a rejected input must emit 61 bytes, not a
    /// zero-padded 69, to match the reference `_default_failed_stateless_output`.
    len: usize,
    success: bool,
};

/// Execute a stateless block from the SSZ input stream.
/// Reads input via `zkvm_io.read_input`, decodes SSZ, executes the block,
/// and serializes the result. Always returns on both success and execution
/// failure — the caller checks `result.success` and commits `out[0..len]`.
pub fn runStateless(allocator: std.mem.Allocator) !Result {
    var buf_ptr: [*]const u8 = undefined;
    var buf_size: usize = 0;
    zkvm_io.read_input(&buf_ptr, &buf_size);
    std.log.info("input_len={d}", .{buf_size});

    const si = ssz_decode.decode(allocator, buf_ptr[0..buf_size]) catch |err| {
        std.log.err("{s}", .{@errorName(err)});
        var out: [69]u8 = .{0} ** 69;
        @memcpy(out[0..ssz_output.DEFAULT_FAILED_OUTPUT.len], &ssz_output.DEFAULT_FAILED_OUTPUT);
        return .{ .out = out, .len = ssz_output.DEFAULT_FAILED_OUTPUT.len, .success = false };
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

    return .{ .out = out, .len = out.len, .success = success };
}
