//! Native c_allocator shim. Not wired into any build.zig module: binaries get their allocator
//! from the `zesu_allocator` singleton (src/evm/allocator.zig).

const std = @import("std");

pub fn get() std.mem.Allocator {
    return std.heap.c_allocator;
}
