//! What the zkVM the guest object is built for provides beyond rv64im: build.zig's
//! `GuestFeatures`, as comptime flags. All false for native builds and the rv64im baseline.

const build_options = @import("build_options");

/// Fixed-size copy accelerator (currently: the ZisK DMA chip; see dma.zig).
pub const has_dma: bool = build_options.has_dma;

/// Hardware-assisted JUMPDEST analysis (currently: ZisK >= 1.3 `jump_dest`, `csrs 0x81C`).
pub const has_jump_dest: bool = build_options.has_jump_dest;

/// 256-bit modular arithmetic linked into the guest as `*_mod256_c` (currently: libziskos).
pub const has_arith256_mod: bool = build_options.has_arith256_mod;
