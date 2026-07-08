/// Root module for the relocatable rv64im zesu object.
///
/// Provides:
///   - std_options: routes std.log through extern zkvm_log
///   - panic handler: calls zkvm_log then zkvm_exit(1)
///   - export fn main(): called by the zkVM's _start (via libziskos _zisk_main)
///
/// External symbols required (resolved at link time from zkVM host object):
///   zkvm_log(level, msg_ptr, msg_len)  — logging sink (e.g. UART)
///   zkvm_exit(code) noreturn           — halt/exit (e.g. ecall a7=93)
///   read_input / write_output          — from zkvm-standards io-interface
///   zkvm_keccak256 … zkvm_secp256r1_verify — from zkvm-standards accelerators
///   ZKVM_HEAP_POS / ZKVM_HEAP_TOP — heap region (defined by each host object)
const std = @import("std");
const runner = @import("runner");
const zkvm_io = @import("zkvm_io");
const zesu_allocator = @import("zesu_allocator");

extern fn zkvm_log(level: u8, msg_ptr: [*]const u8, msg_len: usize) void;
extern fn zkvm_exit(code: i32) noreturn;

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
    zkvm_exit(1);
}

export fn main() void {
    guestMain() catch |err| {
        const name = @errorName(err);
        zkvm_log(0, name.ptr, name.len);
        zkvm_exit(1);
    };
    zkvm_exit(0);
}

fn guestMain() !void {
    const allocator = zesu_allocator.get();
    const result = try runner.runStateless(allocator);
    // Commit exactly result.len bytes: 105 on success, 73 for a rejected input.
    zkvm_io.write_output(result.out[0..result.len]);
}
