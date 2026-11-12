//! Unused: nothing imports this module. Executor allocations come from the caller's
//! allocator or the runtime `zesu_allocator` singleton (src/evm/allocator.zig).
const std = @import("std");

pub fn get() std.mem.Allocator {
    return std.heap.c_allocator;
}
