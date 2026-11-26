const std = @import("std");
const primitives = @import("primitives");
const database_mod = @import("database");
const context_mod = @import("context");

const Interpreter = @import("../interpreter.zig").Interpreter;
const InstructionContext = @import("../instruction_context.zig").InstructionContext;
const Host = @import("../host.zig").Host;
const host_module = @import("../host.zig");

const environment = @import("environment.zig");

const expectEqual = std.testing.expectEqual;
const expect = std.testing.expect;

const U = primitives.U256;
const ALLOC = std.heap.page_allocator;

const TARGET: primitives.Address = [_]u8{0xAA} ** 20;
const CALLER_ADDR: primitives.Address = [_]u8{0xBB} ** 20;
const COINBASE_ADDR: primitives.Address = [_]u8{0xCC} ** 20;
const ORIGIN_ADDR: primitives.Address = [_]u8{0xDD} ** 20;

fn makeInterp() Interpreter {
    var interp = Interpreter.defaultExt();
    interp.input.target = TARGET;
    interp.input.caller = CALLER_ADDR;
    return interp;
}

fn makeCtx(db: database_mod.InMemoryDB) context_mod.DefaultContext {
    return context_mod.DefaultContext.new(db, .prague);
}

// ---------------------------------------------------------------------------
// No-host opcodes (read from interpreter.input)
// ---------------------------------------------------------------------------

test "ADDRESS: pushes executing contract address" {
    var interp = makeInterp();
    var ic = InstructionContext{ .interpreter = &interp };

    environment.opAddress(&ic);

    try expect(interp.bytecode.isNotEnd());
    const got = interp.stack.popUnsafe();
    try expectEqual(host_module.addressToU256(TARGET), got);
}

test "CALLER: pushes msg.sender" {
    var interp = makeInterp();
    var ic = InstructionContext{ .interpreter = &interp };

    environment.opCaller(&ic);

    try expect(interp.bytecode.isNotEnd());
    const got = interp.stack.popUnsafe();
    try expectEqual(host_module.addressToU256(CALLER_ADDR), got);
}

test "CALLVALUE: pushes msg.value" {
    var interp = makeInterp();
    interp.input.value = 0xDEADBEEF;
    var ic = InstructionContext{ .interpreter = &interp };

    environment.opCallvalue(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(@as(U, 0xDEADBEEF), interp.stack.popUnsafe());
}

test "CALLVALUE: zero value" {
    var interp = makeInterp();
    interp.input.value = 0;
    var ic = InstructionContext{ .interpreter = &interp };

    environment.opCallvalue(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(@as(U, 0), interp.stack.popUnsafe());
}

test "CALLDATASIZE: empty calldata returns zero" {
    var interp = makeInterp();
    interp.input.data = @as(primitives.Bytes, @constCast(&[_]u8{}));
    var ic = InstructionContext{ .interpreter = &interp };

    environment.opCalldatasize(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(@as(U, 0), interp.stack.popUnsafe());
}

test "CALLDATASIZE: non-empty calldata" {
    const data = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var interp = makeInterp();
    interp.input.data = @as(primitives.Bytes, @constCast(&data));
    var ic = InstructionContext{ .interpreter = &interp };

    environment.opCalldatasize(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(@as(U, 4), interp.stack.popUnsafe());
}

test "CALLDATALOAD: reads 32 bytes from calldata at offset 0" {
    var data: [32]u8 = undefined;
    data[0] = 0xAB;
    @memset(data[1..], 0);
    var interp = makeInterp();
    interp.input.data = @as(primitives.Bytes, @constCast(&data));
    interp.stack.pushUnsafe(0); // offset = 0
    var ic = InstructionContext{ .interpreter = &interp };

    environment.opCalldataload(&ic);

    try expect(interp.bytecode.isNotEnd());
    const expected: U = @as(U, 0xAB) << 248;
    try expectEqual(expected, interp.stack.popUnsafe());
}

test "CALLDATALOAD: offset beyond calldata returns zero" {
    const data = [_]u8{0xFF} ** 4;
    var interp = makeInterp();
    interp.input.data = @as(primitives.Bytes, @constCast(&data));
    interp.stack.pushUnsafe(100); // offset past end
    var ic = InstructionContext{ .interpreter = &interp };

    environment.opCalldataload(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(@as(U, 0), interp.stack.popUnsafe());
}

test "CALLDATALOAD: partial calldata pads with zeros" {
    // 4 bytes of data, offset 0 — result is those 4 bytes left-aligned in 32 bytes
    const data = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var interp = makeInterp();
    interp.input.data = @as(primitives.Bytes, @constCast(&data));
    interp.stack.pushUnsafe(0);
    var ic = InstructionContext{ .interpreter = &interp };

    environment.opCalldataload(&ic);

    try expect(interp.bytecode.isNotEnd());
    const expected: U = (@as(U, 0x01) << 248) | (@as(U, 0x02) << 240) |
        (@as(U, 0x03) << 232) | (@as(U, 0x04) << 224);
    try expectEqual(expected, interp.stack.popUnsafe());
}

// ---------------------------------------------------------------------------
// Host-required opcodes (block/tx environment)
// ---------------------------------------------------------------------------

test "COINBASE: pushes block beneficiary" {
    const db = database_mod.InMemoryDB.init(ALLOC);
    var ctx = makeCtx(db);
    ctx.block.beneficiary = COINBASE_ADDR;

    var interp = makeInterp();
    var host = Host.fromCtx(&ctx, null);
    var ic = InstructionContext{ .interpreter = &interp, .host = &host };

    environment.opCoinbase(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(host_module.addressToU256(COINBASE_ADDR), interp.stack.popUnsafe());
}

test "TIMESTAMP: pushes block timestamp" {
    const db = database_mod.InMemoryDB.init(ALLOC);
    var ctx = makeCtx(db);
    ctx.block.timestamp = 1_700_000_000;

    var interp = makeInterp();
    var host = Host.fromCtx(&ctx, null);
    var ic = InstructionContext{ .interpreter = &interp, .host = &host };

    environment.opTimestamp(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(@as(U, 1_700_000_000), interp.stack.popUnsafe());
}

test "NUMBER: pushes block number" {
    const db = database_mod.InMemoryDB.init(ALLOC);
    var ctx = makeCtx(db);
    ctx.block.number = 19_000_000;

    var interp = makeInterp();
    var host = Host.fromCtx(&ctx, null);
    var ic = InstructionContext{ .interpreter = &interp, .host = &host };

    environment.opNumber(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(@as(U, 19_000_000), interp.stack.popUnsafe());
}

test "GASLIMIT: pushes block gas limit" {
    const db = database_mod.InMemoryDB.init(ALLOC);
    var ctx = makeCtx(db);
    ctx.block.gas_limit = 30_000_000;

    var interp = makeInterp();
    var host = Host.fromCtx(&ctx, null);
    var ic = InstructionContext{ .interpreter = &interp, .host = &host };

    environment.opGaslimit(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(@as(U, 30_000_000), interp.stack.popUnsafe());
}

test "BASEFEE: pushes block base fee" {
    const db = database_mod.InMemoryDB.init(ALLOC);
    var ctx = makeCtx(db);
    ctx.block.basefee = 7;

    var interp = makeInterp();
    var host = Host.fromCtx(&ctx, null);
    var ic = InstructionContext{ .interpreter = &interp, .host = &host };

    environment.opBasefee(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(@as(U, 7), interp.stack.popUnsafe());
}

test "CHAINID: pushes chain id" {
    const db = database_mod.InMemoryDB.init(ALLOC);
    var ctx = makeCtx(db);
    ctx.cfg.chain_id = 137; // Polygon

    var interp = makeInterp();
    var host = Host.fromCtx(&ctx, null);
    var ic = InstructionContext{ .interpreter = &interp, .host = &host };

    environment.opChainid(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(@as(U, 137), interp.stack.popUnsafe());
}

test "ORIGIN: pushes transaction origin" {
    const db = database_mod.InMemoryDB.init(ALLOC);
    var ctx = makeCtx(db);
    ctx.tx.caller = ORIGIN_ADDR;

    var interp = makeInterp();
    var host = Host.fromCtx(&ctx, null);
    var ic = InstructionContext{ .interpreter = &interp, .host = &host };

    environment.opOrigin(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(host_module.addressToU256(ORIGIN_ADDR), interp.stack.popUnsafe());
}

test "GASPRICE: pushes effective gas price for legacy transaction" {
    const db = database_mod.InMemoryDB.init(ALLOC);
    var ctx = makeCtx(db);
    ctx.tx.gas_price = 20_000_000_000; // 20 gwei
    ctx.tx.gas_priority_fee = null; // legacy tx

    var interp = makeInterp();
    var host = Host.fromCtx(&ctx, null);
    var ic = InstructionContext{ .interpreter = &interp, .host = &host };

    environment.opGasprice(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(@as(U, 20_000_000_000), interp.stack.popUnsafe());
}

// ---------------------------------------------------------------------------
// DIFFICULTY / PREVRANDAO
// ---------------------------------------------------------------------------

test "DIFFICULTY: pre-merge returns block difficulty" {
    const db = database_mod.InMemoryDB.init(ALLOC);
    // Use london (pre-merge spec) via withBlock — keep default ctx spec but override interp spec
    var ctx = makeCtx(db);
    ctx.block.difficulty = 0xDEAD;
    ctx.block.prevrandao = null;

    var interp = makeInterp();
    interp.runtime_flags.spec_id = .london; // pre-merge
    var host = Host.fromCtx(&ctx, null);
    var ic = InstructionContext{ .interpreter = &interp, .host = &host };

    environment.opDifficulty(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(@as(U, 0xDEAD), interp.stack.popUnsafe());
}

test "DIFFICULTY: post-merge with prevrandao returns randao value" {
    const RANDAO: primitives.Hash = [_]u8{0x42} ** 32;
    const db = database_mod.InMemoryDB.init(ALLOC);
    var ctx = makeCtx(db); // .prague spec by default (post-merge)
    ctx.block.prevrandao = RANDAO;
    ctx.block.difficulty = 0; // irrelevant post-merge

    var interp = makeInterp();
    // runtime_flags.spec_id defaults to .prague (post-merge) from defaultExt
    var host = Host.fromCtx(&ctx, null);
    var ic = InstructionContext{ .interpreter = &interp, .host = &host };

    environment.opDifficulty(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(host_module.hashToU256(RANDAO), interp.stack.popUnsafe());
}

test "DIFFICULTY: post-merge without prevrandao falls back to difficulty field" {
    const db = database_mod.InMemoryDB.init(ALLOC);
    var ctx = makeCtx(db); // .prague (post-merge)
    ctx.block.prevrandao = null;
    ctx.block.difficulty = 0xABCD;

    var interp = makeInterp();
    var host = Host.fromCtx(&ctx, null);
    var ic = InstructionContext{ .interpreter = &interp, .host = &host };

    environment.opDifficulty(&ic);

    try expect(interp.bytecode.isNotEnd());
    try expectEqual(@as(U, 0xABCD), interp.stack.popUnsafe());
}
