/// Bump allocator backed by ZKVM_HEAP_POS / ZKVM_HEAP_TOP extern vars; free/resize/remap
/// are no-ops. Not wired into any build: the rv64im object uses alt_fl_alloc.zig.
/// Kept as a drop-in `zesu_allocator` alternative (same `pub fn get()` interface).
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
