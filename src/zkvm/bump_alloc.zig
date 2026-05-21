/// zesu_allocator module for the relocatable rv64im object.
///
/// Bump allocator over the same ZISK_BUMP_HEAP_POS / ZISK_BUMP_HEAP_TOP
/// extern vars shared with libziskos.a. libziskos's init_sys_alloc() (called
/// from _zisk_main before main()) initializes ZISK_BUMP_HEAP_POS to
/// _kernel_heap_bottom and ZISK_BUMP_HEAP_TOP to _kernel_heap_top.
///
/// After this refactor, only zesu's allocator advances ZISK_BUMP_HEAP_POS —
/// the old ZiskAllocator.init() in zisk's main() is gone. free/resize/remap
/// are no-ops (bump allocator semantics).
///
/// This module satisfies the `@import("zesu_allocator")` interface expected
/// by all EVM modules: pub fn get() std.mem.Allocator.
const std = @import("std");

extern var ZISK_BUMP_HEAP_POS: usize;
extern var ZISK_BUMP_HEAP_TOP: usize;

fn sysAllocAligned(bytes: usize, alignment: usize) ?[*]u8 {
    const offset = ZISK_BUMP_HEAP_POS & (alignment - 1);
    if (offset != 0) {
        ZISK_BUMP_HEAP_POS += alignment - offset;
    }
    if (ZISK_BUMP_HEAP_POS + bytes > ZISK_BUMP_HEAP_TOP) return null;
    const ptr: [*]u8 = @ptrFromInt(ZISK_BUMP_HEAP_POS);
    ZISK_BUMP_HEAP_POS += bytes;
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
