/// zesu_allocator module for the relocatable rv64im object.
///
/// Segregated free-list allocator backed by ZKVM_HEAP_POS / ZKVM_HEAP_TOP.
///
/// Replaces the naive bump allocator to avoid OOM on large blocks: freed
/// memory is recycled, so execution with heavy alloc/free churn (EVM memory
/// expansions, return-data buffers, trie node construction) no longer
/// exhausts the heap linearly.
///
/// Design:
///   - 29 size classes: 8, 16, 32, …, 2^31 bytes (power-of-2 buckets).
///   - Each free list is an intrusive singly-linked list; the first 8 bytes
///     of a freed block store the next-pointer (no external metadata).
///   - alloc: pop from the matching free list if non-empty; otherwise
///     bump-allocate a fresh block of classBytes(class) from the heap.
///   - free: push onto the matching free list.
///   - resize: allowed only when new_len falls in the same size class,
///     so free() always recovers the right block.
///   - Oversized allocations (>= 2^32 bytes) fall back to the bump with
///     no recycling — these should never occur in practice.
const std = @import("std");

extern var ZKVM_HEAP_POS: usize;
extern var ZKVM_HEAP_TOP: usize;

/// Minimum block size equals @sizeOf(usize) = 8 on rv64; stores the
/// intrusive next-pointer in freed blocks.
const min_class_bits: usize = 3; // log2(8)
/// Number of size classes: covers 2^3 … 2^(3+28) = 8 bytes … 2 GiB.
const num_classes: usize = 29;

/// Intrusive free-list heads, one per size class (0 == empty).
var free_lists: [num_classes]usize = [_]usize{0} ** num_classes;

/// Ceiling log2 of x, returned as usize.  Requires x > 0.
inline fn ceilLog2(x: usize) usize {
    // @clz(0) == @bitSizeOf(usize), so x==1 → 0, which is correct.
    return @bitSizeOf(usize) - @clz(x - 1);
}

/// Size-class index for a request of `size` bytes with `alignment`.
/// The actual block returned is classBytes(return-value) bytes.
inline fn sizeClass(size: usize, alignment: usize) usize {
    const unit = @max(size, alignment);
    if (unit == 0) return 0;
    const log2_ceil = ceilLog2(unit);
    return if (log2_ceil > min_class_bits) log2_ceil - min_class_bits else 0;
}

/// Bytes in a block of the given class (a power of 2).
inline fn classBytes(class: usize) usize {
    return @as(usize, 1) << @intCast(class + min_class_bits);
}

fn sysAllocAligned(bytes: usize, alignment: usize) ?[*]u8 {
    const offset = ZKVM_HEAP_POS & (alignment - 1);
    if (offset != 0) ZKVM_HEAP_POS += alignment - offset;
    if (ZKVM_HEAP_POS + bytes > ZKVM_HEAP_TOP) return null;
    const ptr: [*]u8 = @ptrFromInt(ZKVM_HEAP_POS);
    ZKVM_HEAP_POS += bytes;
    return ptr;
}

fn alloc(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
    _ = ctx;
    _ = ret_addr;
    const alignment = @as(usize, 1) << @intFromEnum(ptr_align);
    const class = sizeClass(len, alignment);

    if (class < num_classes) {
        const head = free_lists[class];
        if (head != 0) {
            // Pop from free list; next pointer stored at head.
            free_lists[class] = @as(*usize, @ptrFromInt(head)).*;
            return @ptrFromInt(head);
        }
        // Fresh bump-allocation.  classBytes is a power of 2, so it satisfies
        // any alignment <= classBytes naturally; @max guards larger alignments.
        const block_bytes = classBytes(class);
        return sysAllocAligned(block_bytes, @max(alignment, block_bytes));
    }

    // Oversized: bump-allocate with exact size (no free-list recycling).
    return sysAllocAligned(len, alignment);
}

fn resize(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
    _ = ctx;
    _ = ret_addr;
    if (new_len > buf.len) return false;
    const alignment = @as(usize, 1) << @intFromEnum(buf_align);
    // Permit shrink only within the same size class: free() must recover the
    // original block under the new (smaller) buf.len.
    return sizeClass(new_len, alignment) == sizeClass(buf.len, alignment);
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
    _ = ret_addr;
    const alignment = @as(usize, 1) << @intFromEnum(buf_align);
    const class = sizeClass(buf.len, alignment);

    if (class < num_classes) {
        // Push onto free list; store next pointer in the freed block.
        const ptr: usize = @intFromPtr(buf.ptr);
        @as(*usize, @ptrFromInt(ptr)).* = free_lists[class];
        free_lists[class] = ptr;
    }
    // Oversized: leaked back into the bump region (unrecoverable, but
    // allocations >= 2 GiB should not occur in practice).
}

const vtable = std.mem.Allocator.VTable{
    .alloc = alloc,
    .resize = resize,
    .remap = remap,
    .free = free,
};
var state: u8 = 0;

pub fn get() std.mem.Allocator {
    return .{ .ptr = &state, .vtable = &vtable };
}
