//! Integration tests: a database error surfaced during block execution must mark
//! the block invalid rather than complete as if a failure were legitimate.

const std = @import("std");
const primitives = @import("primitives");
const state_mod = @import("state");
const bytecode_mod = @import("bytecode");
const context_mod = @import("context");
const input = @import("executor_types");

const transition_mod = @import("./transition.zig");
const transitionWithContext = transition_mod.transitionWithContext;
const TransitionResult = transition_mod.TransitionResult;

const TEST_SENDER: input.Address = @splat(0x11);
const TEST_COINBASE: input.Address = @splat(0x22);
const TEST_RECIPIENT: input.Address = @splat(0x33);

// A database that resolves only the accounts a block legitimately needs and fails
// for anything else, standing in for a stateless witness that is missing the
// CREATE target account. Mirrors WitnessDatabase's duck-typed surface.
const PartialWitnessDb = struct {
    fn known(address: input.Address) bool {
        return std.mem.eql(u8, &address, &TEST_SENDER) or
            std.mem.eql(u8, &address, &TEST_COINBASE) or
            std.mem.eql(u8, &address, &TEST_RECIPIENT);
    }

    pub fn basic(_: *@This(), address: input.Address) !?state_mod.AccountInfo {
        if (!known(address)) return error.InvalidWitness;
        var info = state_mod.AccountInfo.default();
        info.balance = 1_000_000_000_000;
        return info;
    }

    pub fn codeByHash(_: *@This(), _: primitives.Hash) !bytecode_mod.Bytecode {
        return bytecode_mod.Bytecode.newLegacy(&.{});
    }

    pub fn storage(_: *@This(), _: primitives.Address, _: primitives.StorageKey) !primitives.StorageValue {
        return 0;
    }

    pub fn blockHash(_: *@This(), _: u64) !primitives.Hash {
        return @splat(0);
    }
};

fn testEnv() input.Env {
    return .{ .coinbase = TEST_COINBASE, .gas_limit = 30_000_000, .base_fee = 0 };
}

fn makeTestCtx() context_mod.Context(PartialWitnessDb) {
    return context_mod.Context(PartialWitnessDb).new(.{}, primitives.SpecId.shanghai);
}

fn runTestBlock(arena: std.mem.Allocator, ctx: anytype, txs: []input.TxInput) !TransitionResult {
    const pre_alloc: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount) = .{};
    return transitionWithContext(
        arena,
        ctx,
        pre_alloc,
        testEnv(),
        txs,
        primitives.SpecId.shanghai,
        1,
        0,
        &.{},
    );
}

// Integration counterpart to the unit tests in db/test.zig and host_tests.zig:
// those prove the database error is raised and that setupCreate marks ctx_error,
// this proves it survives a whole block execution -- the block is rejected
// rather than completing as if the CREATE legitimately failed.
test "a CREATE whose target is absent from the witness marks the block invalid" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    // to == null makes this a CREATE. The target address is derived from the
    // sender and nonce, so it is not one of the addresses the stub DB can resolve.
    var txs = [_]input.TxInput{.{
        .from = TEST_SENDER,
        .to = null,
        .nonce = 0,
        .gas = 200_000,
        .gas_price = 1,
        .data = &[_]u8{ 0x60, 0x00, 0x60, 0x00, 0xf3 }, // RETURN empty
    }};

    var ctx = makeTestCtx();
    // Whether this returns a value or an error is not the contract; the mark is.
    _ = runTestBlock(arena_state.allocator(), &ctx, &txs) catch {};

    try std.testing.expectEqual(
        context_mod.ContextError.database_error,
        ctx.ctx_error,
    );
}

// Control: the same stub DB and block shape, but a plain transfer to an address
// the witness *can* prove. Without this, the test above would also pass if every
// block were marked invalid for an unrelated reason.
test "a block whose accounts are all provable is not marked invalid" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var txs = [_]input.TxInput{.{
        .from = TEST_SENDER,
        .to = TEST_RECIPIENT,
        .nonce = 0,
        .gas = 100_000,
        .gas_price = 1,
        .value = 1,
    }};

    var ctx = makeTestCtx();
    _ = try runTestBlock(arena_state.allocator(), &ctx, &txs);

    try std.testing.expectEqual(context_mod.ContextError.ok, ctx.ctx_error);
}
