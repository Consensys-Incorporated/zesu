/// Root module for the relocatable rv64im zesu object.
///
/// Provides:
///   - std_options: routes std.log through extern zkvm_log
///   - panic handler: calls zkvm_log then traps (@trap(), a compiler-emitted
///     illegal instruction — not hand-written asm)
///   - export fn main(): called by the zkVM's _start (via libziskos _zisk_main,
///     or a target-specific startup.S). Returns 0/1 in a0 per the RISC-V C ABI;
///     each host's entry point is responsible for turning that into its own
///     halt sequence (ZisK's own _start already does this for free on return).
///
/// External symbols required (resolved at link time from zkVM host object):
///   zkvm_log(level, msg_ptr, msg_len)  — logging sink (e.g. UART)
///   read_input / write_output          — from zkvm-standards io-interface
///   zkvm_keccak256 … zkvm_secp256r1_verify — from zkvm-standards accelerators
///   ZKVM_HEAP_POS / ZKVM_HEAP_TOP — heap region (defined by each host object)
const std = @import("std");
const runner = @import("runner");
const zkvm_io = @import("zkvm_io");
const zesu_allocator = @import("zesu_allocator");

extern fn zkvm_log(level: u8, msg_ptr: [*]const u8, msg_len: usize) void;

pub const std_options: std.Options = .{ .logFn = logFn };

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = scope;
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, format, args) catch format;
    zkvm_log(@intFromEnum(level), msg.ptr, msg.len);
}

pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    zkvm_log(0, msg.ptr, msg.len);
    @trap();
}

export fn main() callconv(.c) c_int {
    guestMain() catch |err| {
        const name = @errorName(err);
        zkvm_log(0, name.ptr, name.len);
        return 1;
    };
    return 0;
}

fn guestMain() !void {
    const allocator = zesu_allocator.get();
    const result = try runner.runStateless(allocator);
    // Commit exactly result.len bytes: 105 on success, 73 for a rejected input.
    zkvm_io.write_output(result.out[0..result.len]);
}
