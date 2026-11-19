//! `runDispatch` inlines DUPN, SWAPN and EXCHANGE (EIP-8024) when the frame's fork has
//! them. These tests run the same code through the dispatch loop and one `step` at a
//! time (which always goes through the instruction table) and require equal outcomes.

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

const expectEqual = std.testing.expectEqual;
const U = primitives.U256;

const DUPN = bytecode_mod.DUPN;
const SWAPN = bytecode_mod.SWAPN;
const EXCHANGE = bytecode_mod.EXCHANGE;
const stack_imm_ops = [_]u8{ DUPN, SWAPN, EXCHANGE };

/// An interpreter over `code` whose stack already holds `depth` distinct words.
fn newInterp(code: []const u8, spec: primitives.SpecId, gas_limit: u64, depth: usize) Interpreter {
    var interp = Interpreter.new(
        Memory.new(),
        ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(code)),
        InputsImpl.default(),
        false,
        spec,
        gas_limit,
    );
    for (0..depth) |i| interp.stack.pushUnsafe((@as(U, 0xABCD) << 128) | i);
    return interp;
}

fn expectDispatchMatchesTable(code: []const u8, spec: primitives.SpecId, gas_limit: u64, depth: usize) !void {
    const table = protocol_schedule.makeInstructionTable(spec);

    var fast = newInterp(code, spec, gas_limit, depth);
    defer fast.deinit();
    var slow = newInterp(code, spec, gas_limit, depth);
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

test "inlined EIP-8024 arm: Amsterdam's table charges G_VERYLOW and runs the handlers" {
    const table = protocol_schedule.makeInstructionTable(.amsterdam);
    for (stack_imm_ops) |op| try expectEqual(@as(u64, gas_costs.G_VERYLOW), table[op].static_gas);
    try expectEqual(opcodes.opDupN, table[DUPN].func);
    try expectEqual(opcodes.opSwapN, table[SWAPN].func);
    try expectEqual(opcodes.opExchange, table[EXCHANGE].func);
}

test "inlined EIP-8024 arm: every immediate at every boundary depth matches the table path" {
    // Depths around each bound: empty, the EXCHANGE range (m + 1 = 3..30), decode_single's
    // 17 and 235 (and one more for SWAPN), and a full stack (DUPN overflows).
    const depths = [_]usize{ 0, 1, 2, 3, 15, 16, 17, 18, 19, 29, 30, 31, 144, 145, 146, 234, 235, 236, 237, 1023, 1024 };
    for (stack_imm_ops) |op| {
        for (0..256) |imm| {
            for (depths) |depth| {
                errdefer std.debug.print("opcode 0x{x:0>2}, immediate {d}, depth {d}\n", .{ op, imm, depth });
                // The trailing PC shows where execution resumes after the immediate.
                try expectDispatchMatchesTable(&.{ op, @intCast(imm), 0x58 }, .amsterdam, 1_000_000, depth);
            }
        }
    }
}

test "inlined EIP-8024 arm: an opcode on the last byte reads a zero immediate" {
    // Immediate 0 is depth 145 for DUPN/SWAPN and the pair (9, 16) for EXCHANGE.
    for (stack_imm_ops) |op| {
        for ([_]usize{ 16, 17, 144, 145, 146 }) |depth| {
            errdefer std.debug.print("opcode 0x{x:0>2}, depth {d}\n", .{ op, depth });
            try expectDispatchMatchesTable(&.{op}, .amsterdam, 1_000_000, depth);
        }
    }
}

test "inlined EIP-8024 arm: out of gas matches the table path" {
    for (stack_imm_ops) |op| {
        for ([_]u64{ 0, gas_costs.G_VERYLOW - 1, gas_costs.G_VERYLOW }) |gas_limit| {
            errdefer std.debug.print("opcode 0x{x:0>2}, gas {d}\n", .{ op, gas_limit });
            // Immediate 128 is valid for all three; 91 is invalid for all three.
            try expectDispatchMatchesTable(&.{ op, 128 }, .amsterdam, gas_limit, 40);
            try expectDispatchMatchesTable(&.{ op, 91 }, .amsterdam, gas_limit, 40);
        }
    }
}

test "inlined EIP-8024 arm: invalid before Amsterdam on every fork" {
    for (std.enums.values(primitives.SpecId)) |spec| {
        if (primitives.isEnabledIn(spec, .amsterdam)) continue;
        for (stack_imm_ops) |op| {
            errdefer std.debug.print("fork {s}, opcode 0x{x:0>2}\n", .{ primitives.specIdToString(spec), op });
            const table = protocol_schedule.makeInstructionTable(spec);
            var interp = newInterp(&.{ op, 128 }, spec, 1_000_000, 40);
            defer interp.deinit();
            try expectEqual(.invalid_opcode, interp.run(&table));
            try expectDispatchMatchesTable(&.{ op, 128 }, spec, 1_000_000, 40);
        }
    }
}

test "inlined EIP-8024 arm: values land where the EIP says" {
    const table = protocol_schedule.makeInstructionTable(.amsterdam);
    const word = struct {
        fn at(i: usize) U {
            return (@as(U, 0xABCD) << 128) | i;
        }
    }.at;

    // DUPN 128: depth 17, i.e. the word pushed 17th from the top.
    var dup = newInterp(&.{ DUPN, 128 }, .amsterdam, 1_000_000, 20);
    defer dup.deinit();
    try expectEqual(.stop, dup.run(&table));
    try expectEqual(@as(usize, 21), dup.stack.len());
    try expectEqual(word(3), dup.stack.peekUnsafe(0));
    try expectEqual(@as(u64, 1_000_000 - gas_costs.G_VERYLOW), dup.gas.remaining);

    // SWAPN 128: top with the word 17 below it.
    var swap = newInterp(&.{ SWAPN, 128 }, .amsterdam, 1_000_000, 20);
    defer swap.deinit();
    try expectEqual(.stop, swap.run(&table));
    try expectEqual(@as(usize, 20), swap.stack.len());
    try expectEqual(word(2), swap.stack.peekUnsafe(0));
    try expectEqual(word(19), swap.stack.peekUnsafe(17));

    // EXCHANGE 129: k = 14, q = 0, r = 14, so depths 1 and 15; the top stays.
    var xchg = newInterp(&.{ EXCHANGE, 129 }, .amsterdam, 1_000_000, 20);
    defer xchg.deinit();
    try expectEqual(.stop, xchg.run(&table));
    try expectEqual(word(19), xchg.stack.peekUnsafe(0));
    try expectEqual(word(4), xchg.stack.peekUnsafe(1));
    try expectEqual(word(18), xchg.stack.peekUnsafe(15));
}
