/// zesu_allocator module for the relocatable rv64im object.
///
/// Bump allocator backed by ZKVM_HEAP_POS / ZKVM_HEAP_TOP extern vars.
/// Each zkVM host object (zisk-host.o, openvm-host.o, linea-host.o) exports
/// these vars and initializes them before calling main(). For ZisK, the vars
/// are aliased onto libziskos.a's ZISK_BUMP_HEAP_POS/TOP via zisk.ld.
///
/// free/resize/remap are no-ops (bump allocator semantics).
///
/// This module satisfies the `@import("zesu_allocator")` interface expected
/// by all EVM modules: pub fn get() std.mem.Allocator.
const std = @import("std");

extern var ZKVM_HEAP_POS: usize;
extern var ZKVM_HEAP_TOP: usize;

fn sysAllocAligned(bytes: usize, alignment: usize) ?[*]u8 {
    const offset = ZKVM_HEAP_POS & (alignment - 1);
    if (offset != 0) {
        ZKVM_HEAP_POS += alignment - offset;
    }
    if (ZKVM_HEAP_POS + bytes > ZKVM_HEAP_TOP) return null;
    const ptr: [*]u8 = @ptrFromInt(ZKVM_HEAP_POS);
    ZKVM_HEAP_POS += bytes;
    return ptr;
}

const vtable = std.mem.Allocator.VTable{
    .alloc = alloc,
    .resize = resize,
    .remap = remap,
    .free = free,
};

var state: u8 = 0;

fn alloc(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
    _ = ctx;
    _ = ret_addr;
    const alignment = @as(usize, 1) << @intFromEnum(ptr_align);
    return sysAllocAligned(len, alignment);
}

fn resize(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
    _ = ctx;
    _ = buf;
    _ = buf_align;
    _ = new_len;
    _ = ret_addr;
    return false;
}

fn remap(ctx: *anyopaque, old_buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
    _ = ctx;
    _ = old_buf;
    _ = buf_align;
    _ = new_len;
    _ = ret_addr;
    return null;
}

fn free(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, ret_addr: usize) void {
    _ = ctx;
    _ = buf;
    _ = buf_align;
    _ = ret_addr;
}

pub fn get() std.mem.Allocator {
    return .{ .ptr = &state, .vtable = &vtable };
}

// ─── Swallowed-allocation-failure channel ─────────────────────────────────────
//
// Part of the zesu_allocator module interface: every implementation must provide
// it, because the swallow sites import the module, not a specific allocator.
// See src/evm/allocator.zig for why the channel exists.
var oom: bool = false;

/// Record that an allocation failed on a path that could not propagate it.
pub fn recordOom() void {
    oom = true;
}

/// Whether any allocation failure has been swallowed since `resetOom()`.
pub fn oomSeen() bool {
    return oom;
}

/// Clear the channel. Call once per block, before execution.
pub fn resetOom() void {
    oom = false;
}
