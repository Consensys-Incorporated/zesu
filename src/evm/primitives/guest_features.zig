//! What the zkVM the guest object is built for provides beyond rv64im: build.zig's
//! `GuestFeatures`, as comptime flags. All false for native builds and the rv64im baseline.

const build_options = @import("build_options");

/// ZisK DMA chip (see dma.zig).
pub const has_dma: bool = build_options.has_dma;

/// ZisK >= 1.3 `jump_dest` precompile (`csrs 0x81C`).
pub const has_jump_dest: bool = build_options.has_jump_dest;

/// libziskos's `*_mod256_c` functions are linked into the guest.
pub const has_arith256_mod: bool = build_options.has_arith256_mod;
