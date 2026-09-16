/// zesu_allocator module for the relocatable rv64im object.
///
/// Design & diagrams: see src/zkvm/FREELIST_ALLOC.md
///
/// Segregated free-list allocator backed by ZKVM_HEAP_POS / ZKVM_HEAP_TOP.
/// Functionally identical to fl_alloc.zig, but avoids @clz for size-class
/// classification.
const std = @import("std");

extern var ZKVM_HEAP_POS: usize;
extern var ZKVM_HEAP_TOP: usize;

/// Minimum block size equals @sizeOf(usize) = 8 on rv64; stores the
/// intrusive next-pointer in freed blocks.
const min_class_bits: usize = 3; // log2(8)
/// Number of size classes: covers 2^3 … 2^(3+21) = 8 bytes … 16 MiB.
const num_classes: usize = 22;

/// Intrusive free-list heads, one per size class (0 == empty).
var free_lists: [num_classes]usize = [_]usize{0} ** num_classes;

/// Size class for `size` bytes alone (ignoring alignment), i.e.
/// ceilLog2(size) - min_class_bits clamped to >= 0, computed without @clz
/// as an exact balanced binary search over the fixed power-of-2 thresholds
/// 2^3 .. 2^24. Returns `num_classes` (oversized sentinel) for
/// size > 2^24.
inline fn sizeClassOfBytes(size: usize) usize {
    if (size <= 2048) { // classes 0..8 (thresholds 8..2048)
        if (size <= 64) { // classes 0..3
            if (size <= 16) {
                if (size <= 8) return 0;
                return 1;
            }
            if (size <= 32) return 2;
            return 3;
        }
        if (size <= 512) { // classes 4..6
            if (size <= 128) return 4;
            if (size <= 256) return 5;
            return 6;
        }
        if (size <= 1024) return 7;
        return 8;
    }
    if (size <= 262144) { // classes 9..15 (thresholds 4096..262144)
        if (size <= 16384) { // classes 9..11
            if (size <= 4096) return 9;
            if (size <= 8192) return 10;
            return 11;
        }
        if (size <= 65536) { // classes 12..13
            if (size <= 32768) return 12;
            return 13;
        }
        if (size <= 131072) return 14;
        return 15;
    }
    // classes 16..21 (thresholds 524288..16777216), else oversized
    if (size <= 4194304) {
        if (size <= 1048576) {
            if (size <= 524288) return 16;
            return 17;
        }
        if (size <= 2097152) return 18;
        return 19;
    }
    if (size <= 8388608) return 20;
    if (size <= 16777216) return 21;
    return num_classes; // oversized: caller falls back to bump path
}

/// Size-class index for a request of `size` bytes with alignment
/// `1 << log2_align`. `log2_align` is `std.mem.Alignment`'s raw value,
/// i.e. already log2(alignment) — passed directly by callers, no shift
/// needed here. The actual block returned is classBytes(return-value)
/// bytes.
inline fn sizeClass(size: usize, log2_align: usize) usize {
    const size_class = sizeClassOfBytes(size);
    const align_class = if (log2_align > min_class_bits) log2_align - min_class_bits else 0;
    return @max(size_class, align_class);
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
    const log2_align = @intFromEnum(ptr_align);
    const class = sizeClass(len, log2_align);

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
        const alignment = @as(usize, 1) << @intCast(log2_align);
        return sysAllocAligned(block_bytes, @max(alignment, block_bytes));
    }

    // Oversized: bump-allocate with exact size (no free-list recycling).
    const alignment = @as(usize, 1) << @intCast(log2_align);
    return sysAllocAligned(len, alignment);
}

fn resize(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
    _ = ctx;
    _ = ret_addr;
    if (new_len > buf.len) return false;
    const log2_align = @intFromEnum(buf_align);
    // Permit shrink only within the same size class: free() must recover the
    // original block under the new (smaller) buf.len.
    return sizeClass(new_len, log2_align) == sizeClass(buf.len, log2_align);
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
    const log2_align = @intFromEnum(buf_align);
    const class = sizeClass(buf.len, log2_align);

    if (class < num_classes) {
        // Push onto free list; store next pointer in the freed block.
        const ptr: usize = @intFromPtr(buf.ptr);
        @as(*usize, @ptrFromInt(ptr)).* = free_lists[class];
        free_lists[class] = ptr;
    }
    // Oversized: leaked back into the bump region (unrecoverable, but
    // allocations >= 16 MiB should not occur in practice).
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

/// Reference implementation mirroring fl_alloc.zig's @clz-based formula,
/// used only to cross-check sizeClass() below.
fn referenceSizeClass(size: usize, log2_align: usize) usize {
    const alignment = @as(usize, 1) << @intCast(log2_align);
    const unit = @max(size, alignment);
    const log2_ceil = @bitSizeOf(usize) - @clz(unit - 1);
    return if (log2_ceil > min_class_bits) log2_ceil - min_class_bits else 0;
}

test "sizeClass matches @clz reference at every class boundary and alignment" {
    const sizes = [_]usize{
        0,       1,       7,        8,        9,        15,       16,      17,      31,
        32,      33,      63,       64,       65,       127,      128,     129,     255,
        256,     257,     511,      512,      513,      1023,     1024,    1025,    2047,
        2048,    2049,    4095,     4096,     4097,     8191,     8192,    8193,    16383,
        16384,   16385,   32767,    32768,    32769,    65535,    65536,   65537,   131071,
        131072,  131073,  262143,   262144,   262145,   524287,   524288,  524289,  1048575,
        1048576, 1048577, 2097151,  2097152,  2097153,  4194303,  4194304, 4194305, 8388607,
        8388608, 8388609, 16777215, 16777216, 16777217, 33554432,
    };
    for (sizes) |size| {
        var log2_align: usize = 0;
        while (log2_align <= 12) : (log2_align += 1) {
            const got = sizeClass(size, log2_align);
            const want = referenceSizeClass(size, log2_align);
            try std.testing.expectEqual(want, got);
        }
    }
}

test "sizeClass caps at num_classes for oversized requests" {
    try std.testing.expect(sizeClassOfBytes(16777216) < num_classes);
    try std.testing.expect(sizeClassOfBytes(16777217) >= num_classes);
    try std.testing.expect(sizeClassOfBytes(std.math.maxInt(usize)) >= num_classes);
}

test "classBytes round-trips through sizeClass for every class" {
    var c: usize = 0;
    while (c < num_classes) : (c += 1) {
        const bytes = classBytes(c);
        try std.testing.expectEqual(c, sizeClass(bytes, 0));
    }
}
