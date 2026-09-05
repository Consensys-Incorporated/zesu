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

// ─── Swallowed-allocation-failure channel ─────────────────────────────────────
//
// A few call sites cannot return an error: they are on infallible paths whose
// signatures are fixed by callers that have no error to propagate. Historically
// they absorbed an allocation failure and carried on with a degraded value —
// an unanalysed jump table, a dropped log — which turns "out of memory" into
// "this block computed a different answer". A stateless prover must never make
// that trade: a wrong state root is indistinguishable from a consensus failure
// and is far harder to diagnose than an explicit OOM.
//
// Those sites now call `recordOom()` and the block driver rejects the block, in
// the same shape as the swallowed-database-error channel (`Context.ctx_error`).
// Recording rather than wrapping the allocator keeps the success path free of
// any extra indirection — this costs nothing unless an allocation actually
// fails.
//
// Sticky and process-global, so `resetOom()` must run at the start of each
// block; otherwise one failure would poison every later block in a long-lived
// process such as the spec-test runners.
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

