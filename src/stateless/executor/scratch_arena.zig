//! Single-threaded scratch arena: bump within a chunk, free every chunk at once.
//!
//! `std.heap.ArenaAllocator` is threadsafe, and the rv64im guest has no atomic
//! instructions (the target drops the A extension), so each of its atomics lowers to
//! an out-of-line libcall there. zesu executes a block on one thread, so this arena
//! is just a bump pointer and a chunk list.
//!
//! Semantics match the part of `ArenaAllocator` callers actually rely on:
//! allocate freely, never free individually, reclaim everything in `deinit`.
//! `free` is a no-op except for the most recent allocation, which is returned
//! to the bump pointer.

const std = @import("std");

const ScratchArena = @This();

/// Chunk header, stored at the front of each child allocation.
const Chunk = struct {
    next: ?*Chunk,
    /// Total bytes of the child allocation, header included — needed to free it.
    cap: usize,
};

/// Chunks are allocated with this alignment and must be freed with it.
const chunk_align: std.mem.Alignment = .fromByteUnits(@alignOf(Chunk));
/// First chunk size; each subsequent chunk doubles until it covers the request.
const first_chunk = 4096;

child: std.mem.Allocator,
chunks: ?*Chunk = null,
/// Size of the most recently allocated chunk, for geometric growth.
last_chunk_size: usize = 0,
/// Bump window of the newest chunk: address of its next free byte, and one past its
/// last byte. Both zero while there is no chunk.
cur: usize = 0,
end: usize = 0,

pub fn init(child: std.mem.Allocator) ScratchArena {
    return .{ .child = child };
}

pub fn deinit(self: *ScratchArena) void {
    var it = self.chunks;
    while (it) |chunk| {
        // Read `next` before freeing: the header lives inside the freed memory.
        const next = chunk.next;
        const raw: [*]u8 = @ptrCast(chunk);
        self.child.rawFree(raw[0..chunk.cap], chunk_align, @returnAddress());
        it = next;
    }
    self.chunks = null;
    self.last_chunk_size = 0;
    self.cur = 0;
    self.end = 0;
}

pub fn allocator(self: *ScratchArena) std.mem.Allocator {
    return .{ .ptr = self, .vtable = &vtable };
}

const vtable: std.mem.Allocator.VTable = .{
    .alloc = alloc,
    .resize = resize,
    .remap = remap,
    .free = free,
};

/// Bump the newest chunk if the request, aligned to `1 << align_log2`, fits; else null.
/// With no chunk the window is empty at address 0: a request with bytes does not fit,
/// and an empty one gets address 0, which is null.
inline fn bump(self: *ScratchArena, len: usize, align_log2: usize) ?[*]u8 {
    const mask = (@as(usize, 1) << @intCast(align_log2)) - 1;
    const start = (self.cur + mask) & ~mask;
    const new_cur = start + len;
    if (new_cur > self.end) return null;
    self.cur = new_cur;
    return @ptrFromInt(start);
}

fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
    const self: *ScratchArena = @ptrCast(@alignCast(ctx));
    const align_log2: usize = @intFromEnum(alignment);
    if (self.bump(len, align_log2)) |p| return p;
    // Out of line, so the bump path above needs no stack frame.
    return @call(.never_inline, allocInNewChunk, .{ self, len, align_log2, ret_addr });
}

fn allocInNewChunk(self: *ScratchArena, len: usize, align_log2: usize, ret_addr: usize) ?[*]u8 {
    // Size the new chunk so the request always fits: header, plus the worst-case
    // alignment padding, plus the request itself.
    const need = @sizeOf(Chunk) + (@as(usize, 1) << @intCast(align_log2)) - 1 + len;
    var size = if (self.last_chunk_size == 0) first_chunk else self.last_chunk_size *| 2;
    if (size < need) size = need;

    const raw = self.child.rawAlloc(size, chunk_align, ret_addr) orelse return null;
    const chunk: *Chunk = @ptrCast(@alignCast(raw));
    chunk.* = .{ .next = self.chunks, .cap = size };
    self.chunks = chunk;
    self.last_chunk_size = size;
    self.cur = @intFromPtr(raw) + @sizeOf(Chunk);
    self.end = @intFromPtr(raw) + size;

    return self.bump(len, align_log2);
}

/// Only the most recent allocation can grow or shrink in place.
fn resize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
    _ = alignment;
    _ = ret_addr;
    const self: *ScratchArena = @ptrCast(@alignCast(ctx));
    const buf_start = @intFromPtr(buf.ptr);
    if (buf_start + buf.len != self.cur) return new_len <= buf.len;

    if (new_len > buf.len and buf_start + new_len > self.end) return false;
    self.cur = buf_start + new_len;
    return true;
}

fn remap(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
    return if (resize(ctx, buf, alignment, new_len, ret_addr)) buf.ptr else null;
}

fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
    _ = alignment;
    _ = ret_addr;
    const self: *ScratchArena = @ptrCast(@alignCast(ctx));
    const buf_start = @intFromPtr(buf.ptr);
    // Reclaim only a trailing free, matching ArenaAllocator's behaviour.
    if (buf_start + buf.len == self.cur) self.cur = buf_start;
}

test "bump, grow across chunks, and reclaim on deinit" {
    var arena = ScratchArena.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var prev: []u8 = try a.alloc(u8, 1);
    prev[0] = 0xAA;
    for (1..2000) |i| {
        const s = try a.alloc(u8, i);
        @memset(s, @truncate(i));
        // Earlier allocations stay valid and untouched.
        try std.testing.expectEqual(@as(u8, 0xAA), prev[0]);
        try std.testing.expectEqual(@as(u8, @truncate(i)), s[i - 1]);
    }
}

test "honours over-aligned requests" {
    var arena = ScratchArena.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (0..64) |_| {
        const p = try a.alignedAlloc(u8, .@"64", 3);
        try std.testing.expect(std.mem.Alignment.@"64".check(@intFromPtr(p.ptr)));
    }
}

test "trailing free and resize reuse the bump pointer" {
    var arena = ScratchArena.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const first = try a.alloc(u8, 64);
    const second = try a.alloc(u8, 64);
    try std.testing.expect(a.resize(second, 32));
    // Runtime-known length so this is a slice, not a *[32]u8.
    var shrunk_len: usize = 32;
    _ = &shrunk_len;
    a.free(second[0..shrunk_len]);
    // The next allocation reuses the space `second` occupied.
    const third = try a.alloc(u8, 64);
    try std.testing.expectEqual(@intFromPtr(second.ptr), @intFromPtr(third.ptr));
    try std.testing.expectEqual(@as(usize, 64), first.len);
}
