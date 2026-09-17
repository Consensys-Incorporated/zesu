//! Regression tests for the Host accessors' ctx_error marking: a stateless witness
//! that cannot answer a database query must not let the interpreter treat the
//! resulting `null`/failure as an ordinary EVM outcome.

const std = @import("std");
const primitives = @import("primitives");
const context_mod = @import("context");
const state_mod = @import("state");
const bytecode_mod = @import("bytecode");
const Host = @import("host.zig").Host;

// A database that can resolve one address and fails for every other, standing in
// for a stateless witness that is missing the CREATE target account.
const MissingTargetDb = struct {
    pub const CALLER: primitives.Address = @splat(0xC0);

    pub fn basic(_: *@This(), address: primitives.Address) !?state_mod.AccountInfo {
        if (std.mem.eql(u8, &address, &CALLER)) {
            var info = state_mod.AccountInfo.default();
            info.balance = 1_000_000;
            return info;
        }
        return error.InvalidWitness;
    }

    pub fn codeByHash(_: *@This(), _: primitives.Hash) !bytecode_mod.Bytecode {
        return bytecode_mod.Bytecode.newLegacy(&.{});
    }

    pub fn storage(_: *@This(), _: primitives.Address, _: primitives.StorageKey) !primitives.StorageValue {
        return error.InvalidWitness;
    }

    pub fn blockHash(_: *@This(), _: u64) !primitives.Hash {
        return error.InvalidWitness;
    }
};

// setupCreate cannot return an error (it yields a plain CreateSetupResult), so
// a database failure while loading the CREATE target can only become "create
// failed". With a stateless witness that outcome is fabricated, so ctx_error must
// be marked -- the block-level driver (stateless/executor/main.zig) turns a
// non-ok ctx_error into InvalidWitness. Note js.loadAccount is a Journal call and
// bypasses the Host accessors that already do this, which is why it needs its own
// marking here.
test "setupCreateCore marks ctx_error when the CREATE target cannot be loaded" {
    var ctx = context_mod.Context(MissingTargetDb).new(.{}, primitives.SpecId.prague);
    defer ctx.journaled_state.deinit();

    var host = Host.init(MissingTargetDb, &ctx, null);

    // The caller is read from evm_state, not the DB, so load it first: we want the
    // CREATE to fail on the *target*, not on its own caller lookup.
    _ = try ctx.journaled_state.loadAccount(MissingTargetDb.CALLER);

    try std.testing.expectEqual(context_mod.ContextError.ok, ctx.ctx_error);

    const setup = host.setupCreate(
        MissingTargetDb.CALLER,
        0,
        &[_]u8{0x00},
        100_000,
        false,
        0,
        false,
        0,
        true,
    );

    switch (setup) {
        .failed => {},
        else => return error.ExpectedCreateToFail,
    }
    // The block must be rejected rather than accepting the fabricated failure.
    try std.testing.expectEqual(context_mod.ContextError.database_error, ctx.ctx_error);
}

// opSload turns a null sload into halt(.invalid_opcode) — an ordinary,
// consensus-visible EVM failure. Without ctx_error, a witness that cannot prove
// the slot would be indistinguishable from a transaction that legitimately
// failed, and the block would be accepted with a fabricated result.
test "Host.sload marks ctx_error when the slot cannot be proven" {
    var ctx = context_mod.Context(MissingTargetDb).new(.{}, primitives.SpecId.prague);
    defer ctx.journaled_state.deinit();
    var host = Host.init(MissingTargetDb, &ctx, null);

    _ = try ctx.journaled_state.loadAccount(MissingTargetDb.CALLER);
    try std.testing.expectEqual(context_mod.ContextError.ok, ctx.ctx_error);

    const result = host.sload(MissingTargetDb.CALLER, 1);

    try std.testing.expect(result == null);
    try std.testing.expectEqual(context_mod.ContextError.database_error, ctx.ctx_error);
}

test "Host.sstore marks ctx_error when the slot cannot be proven" {
    var ctx = context_mod.Context(MissingTargetDb).new(.{}, primitives.SpecId.prague);
    defer ctx.journaled_state.deinit();
    var host = Host.init(MissingTargetDb, &ctx, null);

    _ = try ctx.journaled_state.loadAccount(MissingTargetDb.CALLER);
    try std.testing.expectEqual(context_mod.ContextError.ok, ctx.ctx_error);

    const result = host.sstore(MissingTargetDb.CALLER, 1, 42);

    try std.testing.expect(result == null);
    try std.testing.expectEqual(context_mod.ContextError.database_error, ctx.ctx_error);
}

// Each accessor is pinned separately so a missing ctx_error marking at any one
// site fails exactly its own test.
test "Host.accountInfo marks ctx_error when the account cannot be proven" {
    var ctx = context_mod.Context(MissingTargetDb).new(.{}, primitives.SpecId.prague);
    defer ctx.journaled_state.deinit();
    var host = Host.init(MissingTargetDb, &ctx, null);

    const unknown: primitives.Address = @splat(0xE1);
    try std.testing.expectEqual(context_mod.ContextError.ok, ctx.ctx_error);

    const result = host.accountInfo(unknown);

    try std.testing.expect(result == null);
    try std.testing.expectEqual(context_mod.ContextError.database_error, ctx.ctx_error);
}

test "Host.selfdestruct marks ctx_error when the target cannot be proven" {
    var ctx = context_mod.Context(MissingTargetDb).new(.{}, primitives.SpecId.prague);
    defer ctx.journaled_state.deinit();
    var host = Host.init(MissingTargetDb, &ctx, null);

    _ = try ctx.journaled_state.loadAccount(MissingTargetDb.CALLER);
    const unknown: primitives.Address = @splat(0xE2);
    try std.testing.expectEqual(context_mod.ContextError.ok, ctx.ctx_error);

    const result = host.selfdestruct(MissingTargetDb.CALLER, unknown);

    try std.testing.expect(result == null);
    try std.testing.expectEqual(context_mod.ContextError.database_error, ctx.ctx_error);
}

// recordCreateTarget mirrors setupCreate's pre-checks to decide whether to
// charge NEW_ACCOUNT gas, and loads the CREATE target the same way. It takes
// `js: anytype` internally, so the same stub injection works.
test "recordCreateTargetCore marks ctx_error when the CREATE target cannot be loaded" {
    // Amsterdam: recordCreateTarget returns null immediately on earlier specs
    // because EIP-7928 BAL recording is Amsterdam+ only, so it would never reach
    // the target load and the test would pass for the wrong reason.
    var ctx = context_mod.Context(MissingTargetDb).new(.{}, primitives.SpecId.amsterdam);
    defer ctx.journaled_state.deinit();
    var host = Host.init(MissingTargetDb, &ctx, null);

    _ = try ctx.journaled_state.loadAccount(MissingTargetDb.CALLER);
    try std.testing.expectEqual(context_mod.ContextError.ok, ctx.ctx_error);

    const result = host.recordCreateTarget(
        MissingTargetDb.CALLER,
        0,
        &[_]u8{0x00},
        false,
        0,
        0,
    );

    try std.testing.expect(result == null);
    try std.testing.expectEqual(context_mod.ContextError.database_error, ctx.ctx_error);
}
