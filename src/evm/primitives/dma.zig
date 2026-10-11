//! Fixed-size block copy through the ZisK DMA chip.
//!
//! ZisK has a DMA chip with two forms of its copy op, differing only in how
//! the byte count reaches it:
//!
//!   csrs 0x813, src ; add  x0, dst, reg(count)  -> dma_memcpy   count via memory
//!   csrs 0x813, src ; addi x0, dst, imm(count)  -> dma_xmemcpy  count in the instruction
//!
//! The extended form needs no parameter store or read, so a 32-byte copy costs
//! `DMA_MEMCPY_COST` plus two instructions, against eight instructions and eight
//! memory accesses for four load/store pairs.
//!
//! Both instructions must be in one `asm` block: the transpiler matches the
//! `csrs`/`addi` pair, and anything scheduled between them breaks recognition.
//! The count must also be a literal (`"i"` constraint): a register count would
//! silently select the slower non-extended op.

const std = @import("std");
const build_options = @import("build_options");

/// True when the ZisK DMA chip is available (set by the build system for the
/// zisk-object target; false for the rv64im baseline and native builds).
pub const has_dma: bool = build_options.has_dma;

/// Copy exactly `N` bytes. `N` must be comptime-known so the count fits in an
/// immediate; the regions must not overlap.
pub inline fn copyFixed(comptime N: usize, dst: *[N]u8, src: *const [N]u8) void {
    if (comptime has_dma) {
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
