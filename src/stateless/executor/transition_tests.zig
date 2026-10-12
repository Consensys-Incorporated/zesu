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

// A witness that proves every account (any other address as absent) and the
// recipient's delegation designator, but not the code of the delegate it points to
// unless `delegate_code_known`.
const DelegationWitnessDb = struct {
    delegate_code_known: bool,

    const DELEGATE: input.Address = @splat(0x55);
    const DESIGNATOR_HASH: primitives.Hash = @splat(0xd1);
    const DELEGATE_CODE_HASH: primitives.Hash = @splat(0xd2);

    pub fn basic(_: *@This(), address: input.Address) !?state_mod.AccountInfo {
        var info = state_mod.AccountInfo.default();
        if (std.mem.eql(u8, &address, &TEST_SENDER) or std.mem.eql(u8, &address, &TEST_COINBASE)) {
            info.balance = 1_000_000_000_000;
        } else if (std.mem.eql(u8, &address, &TEST_RECIPIENT)) {
            info.code_hash = DESIGNATOR_HASH;
            info.code = null; // loaded through codeByHash, as WitnessDatabase does
        } else if (std.mem.eql(u8, &address, &DELEGATE)) {
            info.code_hash = DELEGATE_CODE_HASH;
            info.code = null;
        } else return null;
        return info;
    }

    pub fn codeByHash(self: *@This(), code_hash: primitives.Hash) !bytecode_mod.Bytecode {
        if (std.mem.eql(u8, &code_hash, &DESIGNATOR_HASH)) {
            return .{ .eip7702 = bytecode_mod.Eip7702Bytecode.new(DELEGATE) };
        }
        if (std.mem.eql(u8, &code_hash, &DELEGATE_CODE_HASH) and self.delegate_code_known) {
            return bytecode_mod.Bytecode.newLegacy(&.{0x00}); // STOP
        }
        return error.InvalidWitness;
    }

    pub fn storage(_: *@This(), _: primitives.Address, _: primitives.StorageKey) !primitives.StorageValue {
        return 0;
    }

    pub fn blockHash(_: *@This(), _: u64) !primitives.Hash {
        return @splat(0);
    }
};

fn runDelegatedCall(delegate_code_known: bool) !context_mod.ContextError {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var txs = [_]input.TxInput{.{
        .from = TEST_SENDER,
        .to = TEST_RECIPIENT,
        .nonce = 0,
        .gas = 100_000,
        .gas_price = 1,
    }};
    var ctx = context_mod.Context(DelegationWitnessDb).new(.{ .delegate_code_known = delegate_code_known }, primitives.SpecId.prague);
    const pre_alloc: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount) = .{};
    _ = transitionWithContext(arena_state.allocator(), &ctx, pre_alloc, testEnv(), &txs, primitives.SpecId.prague, 1, 0) catch {};
    return ctx.ctx_error;
}

// A STOP delegate run as empty code gives the same result, so only the witness
// check can reject the block.
test "a transaction to a delegated account whose delegate code is absent from the witness marks the block invalid" {
    try std.testing.expectEqual(context_mod.ContextError.database_error, try runDelegatedCall(false));
}

test "a transaction to a delegated account whose delegate code is in the witness is not marked invalid" {
    try std.testing.expectEqual(context_mod.ContextError.ok, try runDelegatedCall(true));
}

fn depositReceipt(log: *input.Log) input.Receipt {
    return .{
        .type = 2,
        .tx_hash = @splat(0),
        .tx_index = 0,
        .block_hash = @splat(0),
        .block_number = 0,
        .from = TEST_SENDER,
        .to = log.address,
        .cumulative_gas_used = 0,
        .gas_used = 0,
        .contract_address = null,
        .logs = @as(*[1]input.Log, log),
        .logs_bloom = @splat(0),
        .status = 1,
        .effective_gas_price = 0,
    };
}

test "deposit requests come from the chain's own deposit contract" {
    const sepolia: u64 = 11155111;
    var topics = [_]input.Hash{transition_mod.DEPOSIT_EVENT_TOPIC};
    var data: [576]u8 = @splat(0);
    data[192] = 0xaa; // first pubkey byte
    var log = input.Log{
        .address = transition_mod.depositContractAddress(sepolia),
        .topics = &topics,
        .data = &data,
        .block_number = 0,
        .tx_hash = @splat(0),
        .tx_index = 0,
        .block_hash = @splat(0),
        .log_index = 0,
    };
    const receipts = [_]input.Receipt{depositReceipt(&log)};

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const on_sepolia = try transition_mod.collectDeposits(a, &receipts, transition_mod.depositContractAddress(sepolia));
    try std.testing.expectEqual(@as(usize, 192), on_sepolia.len);
    try std.testing.expectEqual(@as(u8, 0xaa), on_sepolia[0]);

    // The same log on mainnet comes from a contract other than mainnet's, so it is no deposit.
    const on_mainnet = try transition_mod.collectDeposits(a, &receipts, transition_mod.depositContractAddress(1));
    try std.testing.expectEqual(@as(usize, 0), on_mainnet.len);
}
