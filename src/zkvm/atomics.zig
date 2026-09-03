//! Single-threaded `__atomic_*` builtins for the rv64im guest.
//!
//! The guest target subtracts `.a`/`.zaamo`/`.zalrsc` (ZisK's ISA is rv64im), so
//! LLVM cannot lower an `@atomicLoad`/`@atomicRmw` natively and instead emits a
//! libcall to `__atomic_<op>_N`. compiler_rt's implementation of those picks
//! between a spinlock and a native atomic on `@sizeOf(T) > largest_atomic_size`
//! — and `largest_atomic_size` is derived from the pointer width (8 on rv64),
//! not from whether the target actually has atomic instructions. So for a u64 it
//! takes the native branch, which lowers right back to a `__atomic_*_8` libcall:
//! the builtin calls itself, unconditionally, and the first invocation burns the
//! whole 4 MiB guest stack (~262k frames at 16 bytes each) and dies as a write
//! below the stack region.
//!
//! Any guest code reaching an atomic hits this — `std.heap.ArenaAllocator` was
//! simply the first to do so. Defining the builtins here makes the linker
//! resolve them from zesu.o and never pull compiler_rt's versions.
//!
//! Plain loads and stores are correct because the guest is strictly
//! single-threaded: there is no other hart, no interrupt handler, and no
//! preemption, so no operation here can be observed partially. The memory-order
//! argument is therefore ignored.

fn Ops(comptime T: type) type {
    return struct {
        fn load(src: *T, model: i32) callconv(.c) T {
            _ = model;
            return src.*;
        }

        fn store(dst: *T, value: T, model: i32) callconv(.c) void {
            _ = model;
            dst.* = value;
        }

        fn exchange(ptr: *T, val: T, model: i32) callconv(.c) T {
            _ = model;
            const old = ptr.*;
            ptr.* = val;
            return old;
        }

        /// Returns 1 on success. On failure `expected` is updated to the current
        /// value, per the GCC builtin contract.
        fn compareExchange(ptr: *T, expected: *T, desired: T, success: i32, failure: i32) callconv(.c) i32 {
            _ = success;
            _ = failure;
            const old = ptr.*;
            if (old == expected.*) {
                ptr.* = desired;
                return 1;
            }
            expected.* = old;
            return 0;
        }

        fn fetchAdd(ptr: *T, val: T, model: i32) callconv(.c) T {
            _ = model;
            const old = ptr.*;
            ptr.* = old +% val;
            return old;
        }

        fn fetchSub(ptr: *T, val: T, model: i32) callconv(.c) T {
            _ = model;
            const old = ptr.*;
            ptr.* = old -% val;
            return old;
        }

        fn fetchAnd(ptr: *T, val: T, model: i32) callconv(.c) T {
            _ = model;
            const old = ptr.*;
            ptr.* = old & val;
            return old;
        }

        fn fetchOr(ptr: *T, val: T, model: i32) callconv(.c) T {
            _ = model;
            const old = ptr.*;
            ptr.* = old | val;
            return old;
        }

        fn fetchXor(ptr: *T, val: T, model: i32) callconv(.c) T {
            _ = model;
            const old = ptr.*;
            ptr.* = old ^ val;
            return old;
        }

        fn fetchNand(ptr: *T, val: T, model: i32) callconv(.c) T {
            _ = model;
            const old = ptr.*;
            ptr.* = ~(old & val);
            return old;
        }
    };
}

comptime {
    // Widths 1/2/4/8 only. The _16 variants already take compiler_rt's spinlock
    // path (16 > largest_atomic_size) and so do not recurse.
    const widths = .{
        .{ u8, "1" },
        .{ u16, "2" },
        .{ u32, "4" },
        .{ u64, "8" },
    };
    for (widths) |w| {
        const O = Ops(w[0]);
        const n: []const u8 = w[1];
        @export(&O.load, .{ .name = "__atomic_load_" ++ n });
        @export(&O.store, .{ .name = "__atomic_store_" ++ n });
        @export(&O.exchange, .{ .name = "__atomic_exchange_" ++ n });
        @export(&O.compareExchange, .{ .name = "__atomic_compare_exchange_" ++ n });
        @export(&O.fetchAdd, .{ .name = "__atomic_fetch_add_" ++ n });
        @export(&O.fetchSub, .{ .name = "__atomic_fetch_sub_" ++ n });
        @export(&O.fetchAnd, .{ .name = "__atomic_fetch_and_" ++ n });
        @export(&O.fetchOr, .{ .name = "__atomic_fetch_or_" ++ n });
        @export(&O.fetchXor, .{ .name = "__atomic_fetch_xor_" ++ n });
        @export(&O.fetchNand, .{ .name = "__atomic_fetch_nand_" ++ n });
    }
}
