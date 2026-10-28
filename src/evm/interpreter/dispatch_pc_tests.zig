//! `runDispatch` holds the program counter in a local and publishes it to
//! `bytecode.pc` only around handlers that read or write it. These tests run
//! real bytecode through the dispatch loop (the per-opcode unit tests call
//! handlers directly and never exercise that sync).
//!
//! Running off the end of the code executes an implicit STOP, which also
//! advances the counter, so a program of length N finishes at pc N + 1.

const std = @import("std");
const primitives = @import("primitives");
const bytecode_mod = @import("bytecode");
const interpreter_mod = @import("interpreter.zig");
const protocol_schedule = @import("protocol_schedule.zig");
const Interpreter = interpreter_mod.Interpreter;
const ExtBytecode = interpreter_mod.ExtBytecode;
const InputsImpl = interpreter_mod.InputsImpl;
const Memory = @import("memory.zig").Memory;
const gas_costs = @import("gas_costs.zig");
const opcodes = @import("opcodes/main.zig");
const InstructionFn = interpreter_mod.InstructionFn;

const expectEqual = std.testing.expectEqual;
const U = primitives.U256;

fn newInterp(code: []const u8, spec: primitives.SpecId) Interpreter {
    return Interpreter.new(
        Memory.new(),
        ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(code)),
        InputsImpl.default(),
        false,
        spec,
        1_000_000,
    );
}

test "dispatch pc: PUSH immediates and PC opcode see the register-held counter" {
    // 0: PUSH2 0x0102   3: PC   4: PUSH1 0x07   6: PC
    var interp = newInterp(&.{ 0x61, 0x01, 0x02, 0x58, 0x60, 0x07, 0x58 }, .amsterdam);
    defer interp.deinit();
    const table = protocol_schedule.makeInstructionTable(.amsterdam);

    try expectEqual(.stop, interp.run(&table));
    try expectEqual(@as(usize, 4), interp.stack.len());
    try expectEqual(@as(U, 6), interp.stack.peekUnsafe(0));
    try expectEqual(@as(U, 7), interp.stack.peekUnsafe(1));
    try expectEqual(@as(U, 3), interp.stack.peekUnsafe(2));
    try expectEqual(@as(U, 0x0102), interp.stack.peekUnsafe(3));
    try expectEqual(@as(usize, 8), interp.bytecode.pc);
}

test "dispatch pc: JUMP moves the register-held counter" {
    // 0: PUSH1 4   2: JUMP   3: INVALID   4: JUMPDEST   5: PC
    var interp = newInterp(&.{ 0x60, 0x04, 0x56, 0xFE, 0x5B, 0x58 }, .amsterdam);
    defer interp.deinit();
    const table = protocol_schedule.makeInstructionTable(.amsterdam);

    try expectEqual(.stop, interp.run(&table));
    try expectEqual(@as(U, 5), interp.stack.peekUnsafe(0));
    try expectEqual(@as(usize, 7), interp.bytecode.pc);
}

test "dispatch pc: JUMPI taken and not taken" {
    // 0: PUSH1 1  2: PUSH1 6  4: JUMPI  5: INVALID  6: JUMPDEST  7: PC
    var taken = newInterp(&.{ 0x60, 0x01, 0x60, 0x06, 0x57, 0xFE, 0x5B, 0x58 }, .amsterdam);
    defer taken.deinit();
    const table = protocol_schedule.makeInstructionTable(.amsterdam);
    try expectEqual(.stop, taken.run(&table));
    try expectEqual(@as(U, 7), taken.stack.peekUnsafe(0));

    // Condition 0: falls through to the INVALID at 5.
    var not_taken = newInterp(&.{ 0x60, 0x00, 0x60, 0x06, 0x57, 0xFE, 0x5B, 0x58 }, .amsterdam);
    defer not_taken.deinit();
    try expectEqual(.invalid_opcode, not_taken.run(&table));
    try expectEqual(@as(usize, 6), not_taken.bytecode.pc);
}

test "dispatch pc: cold path reaches PC through the table with a current counter" {
    // 0: PUSH1 0  2: POP  3: CALLDATASIZE (cold)  4: PC (cold)
    var interp = newInterp(&.{ 0x60, 0x00, 0x50, 0x36, 0x58 }, .amsterdam);
    defer interp.deinit();
    const table = protocol_schedule.makeInstructionTable(.amsterdam);

    try expectEqual(.stop, interp.run(&table));
    try expectEqual(@as(U, 4), interp.stack.peekUnsafe(0));
    try expectEqual(@as(usize, 6), interp.bytecode.pc);
}

test "dispatch pc: pre-Constantinople SHL falls back to the table and publishes the counter" {
    // 0: PUSH1 1  2: PUSH1 1  4: SHL (opUnknown before EIP-145)  5: PC (unreached)
    var interp = newInterp(&.{ 0x60, 0x01, 0x60, 0x01, 0x1B, 0x58 }, .byzantium);
    defer interp.deinit();
    const table = protocol_schedule.makeInstructionTable(.byzantium);

    try expectEqual(.invalid_opcode, interp.run(&table));
    try expectEqual(@as(usize, 5), interp.bytecode.pc);
}

test "dispatch pc: out-of-gas exit still publishes the counter" {
    // 0: PUSH1 1  2: PUSH1 1  4: ADD, with gas for the PUSHes only.
    var interp = newInterp(&.{ 0x60, 0x01, 0x60, 0x01, 0x01 }, .amsterdam);
    defer interp.deinit();
    interp.gas = @TypeOf(interp.gas).new(6);
    const table = protocol_schedule.makeInstructionTable(.amsterdam);

    try expectEqual(.out_of_gas, interp.run(&table));
    try expectEqual(@as(usize, 5), interp.bytecode.pc);
}

// ---------------------------------------------------------------------------
// The inlined environment arm (ADDRESS, CALLER, CALLVALUE, CALLDATASIZE,
// CODESIZE, PC, MSIZE) charges G_BASE and runs the handler body directly,
// where the table path charges `static_gas` and calls the entry's handler.
// These tests pin the assumptions that make the two interchangeable.
// ---------------------------------------------------------------------------

const env_ops = [_]struct { op: u8, handler: InstructionFn }{
    .{ .op = 0x30, .handler = opcodes.opAddress },
    .{ .op = 0x33, .handler = opcodes.opCaller },
    .{ .op = 0x34, .handler = opcodes.opCallvalue },
    .{ .op = 0x36, .handler = opcodes.opCalldatasize },
    .{ .op = 0x38, .handler = opcodes.opCodesize },
    .{ .op = 0x58, .handler = opcodes.opPc },
    .{ .op = 0x59, .handler = opcodes.opMsize },
};

test "inlined env arm: every fork's table still charges G_BASE and runs the shared handler" {
    for (std.enums.values(primitives.SpecId)) |spec| {
        const table = protocol_schedule.makeInstructionTable(spec);
        for (env_ops) |e| {
            errdefer std.debug.print("fork {s}, opcode 0x{x:0>2}\n", .{ primitives.specIdToString(spec), e.op });
            try expectEqual(@as(u64, gas_costs.G_BASE), table[e.op].static_gas);
            try expectEqual(e.handler, table[e.op].func);
        }
    }
}

fn newEnvInterp(code: []const u8, spec: primitives.SpecId, gas_limit: u64, data: []u8) Interpreter {
    const input = InputsImpl.new(
        [_]u8{0xAA} ** 20,
        [_]u8{0xBB} ** 20,
        0x1234,
        data,
        gas_limit,
        .call,
        false,
        0,
    );
    return Interpreter.new(
        Memory.new(),
        ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(code)),
        input,
        false,
        spec,
        gas_limit,
    );
}

/// Run `code` through the dispatch loop and again one `step` at a time (which always goes
/// through the table), and require identical outcomes.
fn expectDispatchMatchesTable(code: []const u8, spec: primitives.SpecId, gas_limit: u64) !void {
    const table = protocol_schedule.makeInstructionTable(spec);
    var data = [_]u8{ 1, 2, 3, 4, 5 };

    var fast = newEnvInterp(code, spec, gas_limit, &data);
    defer fast.deinit();
    var slow = newEnvInterp(code, spec, gas_limit, &data);
    defer slow.deinit();

    const fast_result = fast.run(&table);
    while (slow.bytecode.isNotEnd()) slow.step(&table);

    try expectEqual(slow.result, fast_result);
    try expectEqual(slow.gas.remaining, fast.gas.remaining);
    try expectEqual(slow.bytecode.pc, fast.bytecode.pc);
    try expectEqual(slow.stack.len(), fast.stack.len());
    for (0..slow.stack.len()) |i| {
        try expectEqual(slow.stack.peekUnsafe(i), fast.stack.peekUnsafe(i));
    }
}

test "inlined env arm: dispatch matches the table path on every fork" {
    // 0: PUSH1 1  2: PUSH1 0  4: MSTORE8 (MSIZE becomes 32), then all seven opcodes.
    const code = [_]u8{ 0x60, 0x01, 0x60, 0x00, 0x53 } ++ [_]u8{ 0x30, 0x33, 0x34, 0x36, 0x38, 0x58, 0x59 };
    for (std.enums.values(primitives.SpecId)) |spec| {
        errdefer std.debug.print("fork {s}\n", .{primitives.specIdToString(spec)});
        try expectDispatchMatchesTable(&code, spec, 1_000_000);
    }
}

test "inlined env arm: out of gas and stack overflow match the table path" {
    var flood = [_]u8{0} ** 1025;
    for (env_ops) |e| {
        errdefer std.debug.print("opcode 0x{x:0>2}\n", .{e.op});
        // One unit short of G_BASE.
        try expectDispatchMatchesTable(&.{e.op}, .amsterdam, gas_costs.G_BASE - 1);
        // The 1025th push overflows the 1024-word stack.
        @memset(&flood, e.op);
        try expectDispatchMatchesTable(&flood, .amsterdam, 1_000_000);
    }
}
