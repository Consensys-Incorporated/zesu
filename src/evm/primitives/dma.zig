//! Fixed-size block copy for the ZisK guest.
//!
//! ZisK has a DMA chip with two forms of its copy op, and they differ only in
//! how the byte count reaches it:
//!
//!   csrs 0x813, src ; add  x0, dst, reg(count)  -> dma_memcpy   count via memory
//!   csrs 0x813, src ; addi x0, dst, imm(count)  -> dma_xmemcpy  count in the instruction
//!
//! The extended form costs `DMA_MEMCPY_COST` (46) plus two instructions, with no
//! parameter traffic. A 32-byte copy emitted as four load/store pairs costs eight
//! instructions (~544) and eight memory accesses.
//!
//! An earlier attempt at this used the non-extended op and came out flat: main
//! fell 7.75% but memory rose 5.69%, which was the parameter store and read —
//! two extra accesses against the eight the copy itself needs. The immediate
//! form has neither.
//!
//! Both instructions must be in one `asm` block: the transpiler matches the
//! `csrs`/`addi` pair, and if anything is scheduled between them the marker is
//! not recognised and the destination is read as zero.

const std = @import("std");
const builtin = @import("builtin");

/// True on the ZisK guest. OpenVM's guest is 32-bit, so riscv64-freestanding
/// identifies ZisK.
pub const have_dma = builtin.target.os.tag == .freestanding and
    builtin.target.cpu.arch == .riscv64;

/// Copy exactly `N` bytes. `N` must be comptime-known so the count can be an
/// immediate; the regions must not overlap.
pub inline fn copyFixed(comptime N: usize, dst: *[N]u8, src: *const [N]u8) void {
    // Explicit if/else so the comptime-known target prunes the untaken branch,
    // as in the allocator: the asm is never analysed on a native build.
    if (comptime have_dma) {
        asm volatile (
            \\csrs 0x813, %[src]
            \\addi x0, %[dst], %[n]
            :
            : [src] "r" (@as([*]const u8, src)),
              [dst] "r" (@as([*]u8, dst)),
              [n] "i" (N),
            : .{ .memory = true });
    } else {
        @memcpy(dst, src);
    }
}
