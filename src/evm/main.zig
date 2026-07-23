const std = @import("std");

// Re-export all modules
pub const primitives = @import("primitives");
pub const bytecode = @import("bytecode");
pub const state = @import("state");
pub const database = @import("database");
pub const context = @import("context");
pub const interpreter = @import("interpreter");
pub const precompile = @import("precompile");
pub const handler = @import("handler");

// Version information
pub const version = @import("version.zig");

// Re-export commonly used types
pub const Address = primitives.Address;
pub const Hash = primitives.Hash;
pub const U256 = primitives.U256;
pub const U128 = primitives.U128;
pub const U64 = primitives.U64;
pub const U32 = primitives.U32;
pub const U16 = primitives.U16;
pub const U8 = primitives.U8;
pub const StorageKey = primitives.StorageKey;
pub const StorageValue = primitives.StorageValue;
pub const SpecId = primitives.SpecId;

// Re-export constants
pub const STACK_LIMIT = primitives.STACK_LIMIT;
pub const CALL_STACK_LIMIT = primitives.CALL_STACK_LIMIT;
pub const BLOCK_HASH_HISTORY = primitives.BLOCK_HASH_HISTORY;
pub const PRECOMPILE3 = primitives.PRECOMPILE3;
pub const KECCAK_EMPTY = primitives.KECCAK_EMPTY;
pub const ONE_ETHER = primitives.ONE_ETHER;
pub const ONE_GWEI = primitives.ONE_GWEI;

/// Main EVM context builder
pub fn createMainnetContext(allocator: std.mem.Allocator) context.DefaultContext {
    const db = database.InMemoryDB.init(allocator);
    return context.DefaultContext.new(db, .prague);
}

/// Execute a transaction in the EVM
pub fn executeTransaction(ctx: *context.DefaultContext, tx: context.Transaction) !context.ExecutionResult {
    return handler.executeTransaction(ctx, tx);
}

/// Test the primitives module
pub fn testPrimitives() !void {
    try primitives.testing.testShortAddress();
    try primitives.testing.testSpecId();
}
