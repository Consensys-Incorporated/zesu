//! Single-threaded scratch arena: bump within a chunk, free every chunk at once.
//!
//! `std.heap.ArenaAllocator` is threadsafe by construction — 17 atomic
//! operations for lock-free node lists, ABA avoidance and acquire/release
//! resize pairs. zesu executes one block on one thread, and the rv64im guest
//! has no atomic instructions at all (the target subtracts `.a`/`.zaamo`/
//! `.zalrsc`), so every one of those lowers to an out-of-line libcall there.
//! None of that synchronisation can ever be observed, so this drops it: the
//! arena is a bump pointer and a chunk list, and does strictly less work.
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
    /// Bytes consumed so far, header included.
    used: usize,
};

/// Chunks are allocated with this alignment and must be freed with it.
const chunk_align: std.mem.Alignment = .fromByteUnits(@alignOf(Chunk));
/// First chunk size; each subsequent chunk doubles until it covers the request.
const first_chunk = 4096;

child: std.mem.Allocator,
chunks: ?*Chunk = null,
/// Size of the most recently allocated chunk, for geometric growth.
last_chunk_size: usize = 0,

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

/// Bump `chunk` if the aligned request fits, else null.
fn bump(chunk: *Chunk, len: usize, alignment: std.mem.Alignment) ?[*]u8 {
    const base = @intFromPtr(chunk);
    const start = alignment.forward(base + chunk.used);
    const end = start + len;
    if (end > base + chunk.cap) return null;
    chunk.used = end - base;
    return @ptrFromInt(start);
}

fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
    const self: *ScratchArena = @ptrCast(@alignCast(ctx));

    if (self.chunks) |chunk| {
        if (bump(chunk, len, alignment)) |p| return p;
    }

    // Size the new chunk so the request always fits: header, plus the worst-case
    // alignment padding, plus the request itself.
    const need = @sizeOf(Chunk) + alignment.toByteUnits() - 1 + len;
    var size = if (self.last_chunk_size == 0) first_chunk else self.last_chunk_size *| 2;
    if (size < need) size = need;

    const raw = self.child.rawAlloc(size, chunk_align, ret_addr) orelse return null;
    const chunk: *Chunk = @ptrCast(@alignCast(raw));
    chunk.* = .{ .next = self.chunks, .cap = size, .used = @sizeOf(Chunk) };
    self.chunks = chunk;
    self.last_chunk_size = size;

    return bump(chunk, len, alignment);
}

/// Only the most recent allocation can grow or shrink in place.
fn resize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
    _ = alignment;
    _ = ret_addr;
    const self: *ScratchArena = @ptrCast(@alignCast(ctx));
    const chunk = self.chunks orelse return false;

    const base = @intFromPtr(chunk);
    const buf_start = @intFromPtr(buf.ptr);
    if (buf_start + buf.len != base + chunk.used) return new_len <= buf.len;

    if (new_len <= buf.len) {
        chunk.used = buf_start + new_len - base;
        return true;
    }
    if (buf_start + new_len > base + chunk.cap) return false;
    chunk.used = buf_start + new_len - base;
    return true;
}

fn remap(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
    return if (resize(ctx, buf, alignment, new_len, ret_addr)) buf.ptr else null;
}

fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
    _ = alignment;
    _ = ret_addr;
    const self: *ScratchArena = @ptrCast(@alignCast(ctx));
    const chunk = self.chunks orelse return;
    const base = @intFromPtr(chunk);
    const buf_start = @intFromPtr(buf.ptr);
    // Reclaim only a trailing free, matching ArenaAllocator's behaviour.
    if (buf_start + buf.len == base + chunk.used) chunk.used = buf_start - base;
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
