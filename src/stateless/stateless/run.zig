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
    /// zkevm@v0.8.0: SszStatelessValidationResult is a fixed-size 43-byte container,
    /// so the decode-failure sentinel and a real result are the same length.
    out: [ssz_output.OUTPUT_SIZE]u8,
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
        return .{ .out = ssz_output.DEFAULT_FAILED_OUTPUT, .success = false };
    };

    const ep = &si.new_payload_request.execution_payload;
    std.log.info("block={d} txns={d}", .{ ep.block_number, ep.transactions.len });

    const exec_result = executor.executeStatelessInput(allocator, si, si.chain_config.fork_name);
    const success = if (exec_result) |_| true else |err| blk: {
        std.log.err("execution failed: {s}", .{@errorName(err)});
        break :blk false;
    };

    const out = try ssz_output.serialize(allocator, si.chain_config, si.new_payload_request, success);
    std.log.info("root: 0x{x} success={d}", .{ out[0..32].*, @intFromBool(success) });

    return .{ .out = out, .success = success };
}
