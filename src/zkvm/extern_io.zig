const std = @import("std");

/// zkvm_io module for the relocatable rv64im object: read_input / write_output as
/// extern C-ABI symbols per zkvm-standards io-interface, resolved at link time from
/// the zkVM host object. Same pub API as src/io/interface.zig.
///
/// C-ABI: void read_input(const uint8_t** buf_ptr, size_t* buf_size)
pub extern fn read_input(buf_ptr: *[*]const u8, buf_size: *usize) void;

/// C-ABI: void write_output(const uint8_t* output, size_t size)
/// Wrapped to take a []const u8 like src/io/interface.zig.
const _write_output = @extern(
    *const fn ([*]const u8, usize) callconv(std.builtin.CallingConvention.c) void,
    .{ .name = "write_output" },
);

pub fn write_output(output: []const u8) void {
    _write_output(output.ptr, output.len);
}
