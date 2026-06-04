const std = @import("std");
const builtin = @import("builtin");

/// zesu_allocator — the allocator used for zesu's internal allocations.
///
/// Runtime-injectable singleton. The 268 internal `get()` call sites across the EVM
/// and stateless modules all read this one global, so a consumer installs its
/// allocator once at startup with `set()` and every downstream allocation observes it.
///
/// If never set:
///   - native targets default to std.heap.c_allocator (zesu's own apps/tools/tests),
///   - freestanding targets panic — a zkVM guest MUST install an allocator before use.
///
/// Injection happens at runtime, not build time, so the single exposed `zesu_allocator`
/// module works for every target without rewiring the build graph. Examples:
///   zesu_allocator.set(fixed_buffer.allocator());   // zkVM guest heap region
///   zesu_allocator.set(arena.allocator());          // native tests
///
/// Lifetime: the backing allocator state (FixedBufferAllocator/arena/…) must outlive every
///   `get()` call — in practice for the whole program/guest lifetime.
/// Concurrency: not thread-safe. Call `set()` once at startup before spawning any threads.
///   zkVM guests are single-threaded, so this is a non-issue there.
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
