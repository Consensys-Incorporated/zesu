//! The `runner` module: read SSZ input via `zkvm_io`, execute the block, and return the
//! serialized SSZ output. Used by the zkVM guest entry (src/zkvm/root.zig); the caller writes
//! the output bytes.

const std = @import("std");
const executor = @import("executor");
const ssz_decode = @import("ssz_decode");
const ssz_output = @import("ssz_output");
const zkvm_io = @import("zkvm_io");

pub const Result = struct {
    /// SszStatelessValidationResult is fixed-size, so the decode-failure sentinel and a real
    /// result are the same length.
    out: [ssz_output.OUTPUT_SIZE]u8,
    success: bool,
};

/// Returns a result for decode and execution failures alike (with `success = false`); the
/// caller commits `out` either way. Only an output-serialization error is returned as an error.
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
    std.log.info("block={d} txns={d}", .{ ep.block_number, ep.raw_transactions.len });

    const exec_result = executor.executeStatelessInput(allocator, si, si.chain_config.fork_name);
    const success = if (exec_result) |_| true else |err| blk: {
        std.log.err("execution failed: {s}", .{@errorName(err)});
        break :blk false;
    };

    const out = try ssz_output.serialize(allocator, si.chain_config, si.new_payload_request, success);
    std.log.info("root: 0x{x} success={d}", .{ out[0..32].*, @intFromBool(success) });

    return .{ .out = out, .success = success };
}
