/// zkVM I/O Interface
///
/// Conforms to zkvm-standards/standards/io-interface/README.md
///
/// Semantics:
///   read_input  — zero-copy, idempotent; sets pointer to private input buffer.
///                 buf_size == 0 means input is invalid / unavailable.
///   write_output — appends to public output; multiple calls concatenate.
///                  Cannot fail.
///
/// Native implementation: reads the file named by the ZESU_INPUT env var (else stdin),
/// writes to stdout. build.zig selects src/zkvm/extern_io.zig instead for the guest
/// object; any replacement `zkvm_io` module must export the same two functions.
const std = @import("std");

var input_buf_done: std.atomic.Value(bool) = .init(false);
var input_buf: ?[]const u8 = null;

/// Read private input.
/// Sets *buf_ptr to the start of the input buffer and *buf_size to its length.
/// Idempotent — calling multiple times returns the same pointer and size.
/// buf_size == 0 means no valid input is available.
pub fn read_input(buf_ptr: *[*]const u8, buf_size: *usize) void {
    if (!input_buf_done.load(.acquire)) {
        const allocator = std.heap.c_allocator;
        const data: ?[]u8 = blk: {
            if (std.c.getenv("ZESU_INPUT")) |path_z| {
                const fd = std.posix.openatZ(std.posix.AT.FDCWD, path_z, .{}, 0) catch break :blk null;
                defer _ = std.c.close(fd);
                break :blk readFd(allocator, fd) catch null;
            } else {
                break :blk readFd(allocator, std.posix.STDIN_FILENO) catch null;
            }
        };
        input_buf = data;
        input_buf_done.store(true, .release);
    }

    if (input_buf) |buf| {
        buf_ptr.* = buf.ptr;
        buf_size.* = buf.len;
    } else {
        buf_ptr.* = @ptrFromInt(1);
        buf_size.* = 0;
    }
}

fn readFd(allocator: std.mem.Allocator, fd: std.posix.fd_t) ![]u8 {
    var list = std.ArrayListUnmanaged(u8).empty;
    errdefer list.deinit(allocator);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = try std.posix.read(fd, &chunk);
        if (n == 0) break;
        try list.appendSlice(allocator, chunk[0..n]);
    }
    return list.items;
}

/// Append bytes to the public output stream.
/// Multiple calls concatenate; the verifier sees the combined output.
pub fn write_output(output: []const u8) void {
    var remaining = output;
    while (remaining.len > 0) {
        const n = std.c.write(std.posix.STDOUT_FILENO, remaining.ptr, remaining.len);
        if (n <= 0) break;
        remaining = remaining[@intCast(n)..];
    }
}
