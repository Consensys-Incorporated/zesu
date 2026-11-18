//! `runDispatch` inlines the block/tx environment reads (ORIGIN … SLOTNUM). These
//! tests run them through the dispatch loop and check that a hostless frame, a
//! closed fork gate and a missing slot number still reach the table's handler.

const std = @import("std");
const primitives = @import("primitives");
const bytecode_mod = @import("bytecode");
const database_mod = @import("database");
const context_mod = @import("context");
const interpreter_mod = @import("interpreter.zig");
const protocol_schedule = @import("protocol_schedule.zig");
const host_module = @import("host.zig");
const Host = host_module.Host;
const Interpreter = interpreter_mod.Interpreter;
const ExtBytecode = interpreter_mod.ExtBytecode;
const InputsImpl = interpreter_mod.InputsImpl;
const Memory = @import("memory.zig").Memory;

const expectEqual = std.testing.expectEqual;
const U = primitives.U256;
const GAS: u64 = 1_000_000;

const ORIGIN_ADDR: primitives.Address = [_]u8{0xDD} ** 20;
const COINBASE_ADDR: primitives.Address = [_]u8{0xCC} ** 20;

fn newInterp(code: []const u8, spec: primitives.SpecId) Interpreter {
    return Interpreter.new(
        Memory.new(),
        ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(code)),
        InputsImpl.default(),
        false,
        spec,
        GAS,
    );
}

fn makeCtx(spec: primitives.SpecId) context_mod.DefaultContext {
    var ctx = context_mod.DefaultContext.new(database_mod.InMemoryDB.init(std.heap.page_allocator), spec);
    ctx.tx.caller = ORIGIN_ADDR;
    ctx.tx.gas_price = 50;
    ctx.tx.gas_priority_fee = 3;
    ctx.block.beneficiary = COINBASE_ADDR;
    ctx.block.timestamp = 1_700_000_000;
    ctx.block.number = 19_000_000;
    ctx.block.gas_limit = 30_000_000;
    ctx.block.basefee = 7;
    ctx.block.blob_excess_gas_and_price = .{ .excess_blob_gas = 0, .blob_gasprice = 11 };
    ctx.block.slot_number = 123;
    ctx.cfg.chain_id = 1;
    return ctx;
}

/// Runs a single opcode with a host and returns the interpreter's result.
fn runOne(op: u8, spec: primitives.SpecId, ctx: *context_mod.DefaultContext) !InterpResult {
    var interp = newInterp(&.{op}, spec);
    defer interp.deinit();
    var host = Host.fromCtx(ctx, null);
    const table = protocol_schedule.makeInstructionTable(spec);
    const result = interp.runWithHost(&table, &host);
    return .{
        .result = result,
        .top = if (interp.stack.len() == 1) interp.stack.peekUnsafe(0) else null,
        .gas_used = GAS - interp.gas.remaining,
    };
}

const InterpResult = struct {
    result: @import("instruction_result.zig").InstructionResult,
    top: ?U,
    gas_used: u64,
};

test "dispatch env: each inlined read pushes the host value for G_BASE" {
    var ctx = makeCtx(.amsterdam);
    const cases = [_]struct { op: u8, want: U }{
        .{ .op = 0x32, .want = host_module.addressToU256(ORIGIN_ADDR) },
        .{ .op = 0x3A, .want = 10 }, // min(50, 7 + 3)
        .{ .op = 0x41, .want = host_module.addressToU256(COINBASE_ADDR) },
        .{ .op = 0x42, .want = 1_700_000_000 },
        .{ .op = 0x43, .want = 19_000_000 },
        .{ .op = 0x45, .want = 30_000_000 },
        .{ .op = 0x46, .want = 1 },
        .{ .op = 0x48, .want = 7 },
        .{ .op = 0x4A, .want = 11 },
        .{ .op = 0x4B, .want = 123 },
    };
    for (cases) |c| {
        const got = try runOne(c.op, .amsterdam, &ctx);
        try expectEqual(.stop, got.result);
        try expectEqual(@as(?U, c.want), got.top);
        try expectEqual(@as(u64, 2), got.gas_used);
    }
}

test "dispatch env: a fork gate closed before the opcode's fork is invalid" {
    const cases = [_]struct { op: u8, spec: primitives.SpecId }{
        .{ .op = 0x46, .spec = .petersburg }, // CHAINID, Istanbul
        .{ .op = 0x48, .spec = .berlin }, // BASEFEE, London
        .{ .op = 0x4A, .spec = .shanghai }, // BLOBBASEFEE, Cancun
        .{ .op = 0x4B, .spec = .bpo2 }, // SLOTNUM, Amsterdam
    };
    for (cases) |c| {
        var ctx = makeCtx(c.spec);
        const got = try runOne(c.op, c.spec, &ctx);
        try expectEqual(.invalid_opcode, got.result);
        try expectEqual(@as(?U, null), got.top);
    }
}

test "dispatch env: SLOTNUM without a slot number is invalid" {
    var ctx = makeCtx(.amsterdam);
    ctx.block.slot_number = null;
    const got = try runOne(0x4B, .amsterdam, &ctx);
    try expectEqual(.invalid_opcode, got.result);
    try expectEqual(@as(?U, null), got.top);
}

test "dispatch env: a hostless frame takes the table handler" {
    var interp = newInterp(&.{0x3A}, .amsterdam);
    defer interp.deinit();
    const table = protocol_schedule.makeInstructionTable(.amsterdam);
    try expectEqual(.invalid_opcode, interp.run(&table));
}

test "dispatch env: a push onto a full stack overflows" {
    var ctx = makeCtx(.amsterdam);
    // 1024 PUSH0s fill the stack; the 1025th push is TIMESTAMP.
    var code: [1025]u8 = undefined;
    @memset(code[0..1024], 0x5F);
    code[1024] = 0x42;
    var interp = newInterp(&code, .amsterdam);
    defer interp.deinit();
    var host = Host.fromCtx(&ctx, null);
    const table = protocol_schedule.makeInstructionTable(.amsterdam);
    try expectEqual(.stack_overflow, interp.runWithHost(&table, &host));
}
