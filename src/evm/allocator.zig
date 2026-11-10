const std = @import("std");
const builtin = @import("builtin");

/// zesu_allocator for the exposed module graph: a runtime-settable singleton read by
/// every internal `get()` call in the EVM and stateless modules. A consumer installs its
/// allocator once at startup with `set()`, e.g.
///   zesu_allocator.set(fixed_buffer.allocator());   // zkVM guest heap region
///
/// If never set, native targets fall back to std.heap.c_allocator and freestanding
/// targets panic, so a module-consuming zkVM guest MUST call `set()` first. (The turnkey
/// rv64im object roots zesu_allocator on src/zkvm/alt_fl_alloc.zig instead.)
///
/// Lifetime: the backing allocator must outlive every `get()` call.
/// Concurrency: not thread-safe; call `set()` before spawning threads.
var current: ?std.mem.Allocator = null;

/// Install the allocator returned by subsequent `get()` calls.
pub fn set(allocator: std.mem.Allocator) void {
    current = allocator;
}

pub fn get() std.mem.Allocator {
    return current orelse defaultAllocator();
}

fn defaultAllocator() std.mem.Allocator {
    // Explicit if/else so the comptime-known target prunes the untaken branch: on freestanding
    // `std.heap.c_allocator` (which references libc malloc/free) is never analyzed.
    if (builtin.target.os.tag == .freestanding) {
        @panic("zesu allocator not set: call zesu_allocator.set() before use");
    } else {
        return std.heap.c_allocator;
    }
}
