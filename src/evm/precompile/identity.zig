const std = @import("std");
const primitives = @import("primitives");
const main = @import("main.zig");
const alloc_mod = @import("zesu_allocator");

/// Identity precompile
pub const FUN = main.Precompile.new(
    main.PrecompileId.Identity,
    main.u64ToAddress(4),
    identityRun,
);

/// The base cost of the operation
pub const IDENTITY_BASE: u64 = 15;
/// The cost per word
pub const IDENTITY_PER_WORD: u64 = 3;

/// Returns a copy of the input (Yellow Paper, Appendix E).
pub fn identityRun(input: []const u8, gas_limit: u64) main.PrecompileResult {
    const gas_used = main.calcLinearCost(input.len, IDENTITY_BASE, IDENTITY_PER_WORD);
    if (gas_used > gas_limit) {
        return main.PrecompileResult{ .err = main.PrecompileError.OutOfGas };
    }

    // Must copy: `input` is a slice of the caller's memory, which RETURNDATACOPY
    // would otherwise alias.
    const output = alloc_mod.get().dupe(u8, input) catch @panic("out of memory");
    return main.PrecompileResult{ .success = main.PrecompileOutput.new(gas_used, output) };
}
