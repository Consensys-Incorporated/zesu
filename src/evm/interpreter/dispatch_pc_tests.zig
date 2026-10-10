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
