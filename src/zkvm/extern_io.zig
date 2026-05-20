const std = @import("std");

/// zkvm_io module for the relocatable rv64im object.
///
/// Declares read_input and write_output as extern C-ABI symbols per
/// zkvm-standards/io-interface. Implementations are resolved at link time
/// from the zkVM host object (e.g. zisk-host.o).
///
/// This module satisfies the `@import("zkvm_io")` in runner.zig with the
/// same pub function signatures as src/io/interface.zig and zkvm_io.zig.
/// C-ABI: void read_input(const uint8_t** buf_ptr, size_t* buf_size)
pub extern fn read_input(buf_ptr: *[*]const u8, buf_size: *usize) void;

/// C-ABI: void write_output(const uint8_t* output, size_t size)
/// Wrapped to match the Zig module API that runner.zig calls ([]const u8).
const _write_output = @extern(
    *const fn ([*]const u8, usize) callconv(std.builtin.CallingConvention.c) void,
    .{ .name = "write_output" },
);

pub fn write_output(output: []const u8) void {
    _write_output(output.ptr, output.len);
}
