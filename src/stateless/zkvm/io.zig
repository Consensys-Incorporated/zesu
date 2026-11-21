//! Allocating stdin/stdout I/O shim. Not wired into any build.zig module and its signatures do
//! not match the `zkvm_io` interface: build.zig binds `zkvm_io` to src/io/interface.zig (native)
//! or src/zkvm/extern_io.zig (guest).

const std = @import("std");

/// Read all private input bytes (stdin in native builds).
pub fn read_input(allocator: std.mem.Allocator) ![]const u8 {
    var list = std.ArrayListUnmanaged(u8).empty;
    errdefer list.deinit(allocator);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = try std.posix.read(std.posix.STDIN_FILENO, &chunk);
        if (n == 0) break;
        try list.appendSlice(allocator, chunk[0..n]);
    }
    return list.items;
}

/// Write public output bytes (stdout in native builds).
pub fn write_output(data: []const u8) void {
    var remaining = data;
    while (remaining.len > 0) {
        const n = std.c.write(std.posix.STDOUT_FILENO, remaining.ptr, remaining.len);
        if (n <= 0) break;
        remaining = remaining[@intCast(n)..];
    }
}
