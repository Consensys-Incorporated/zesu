const std = @import("std");
const primitives = @import("primitives");
const bytecode_mod = @import("bytecode");
const Interpreter = @import("../interpreter.zig").Interpreter;
const ExtBytecode = @import("../interpreter.zig").ExtBytecode;
const InstructionContext = @import("../instruction_context.zig").InstructionContext;
const stack_ops = @import("stack.zig");

const opPop = stack_ops.opPop;
const opPush0 = stack_ops.opPush0;
const makePushFn = stack_ops.makePushFn;
const makeDupFn = stack_ops.makeDupFn;
const makeSwapFn = stack_ops.makeSwapFn;
const opDupN = stack_ops.opDupN;
const opSwapN = stack_ops.opSwapN;
const opExchange = stack_ops.opExchange;

const expectEqual = std.testing.expectEqual;
const expect = std.testing.expect;
const U = primitives.U256;

// --- POP tests ---

test "POP: remove top item" {
    var interp = Interpreter.defaultExt();
    interp.stack.pushUnsafe(@as(U, 42));
    interp.stack.pushUnsafe(@as(U, 100));
    var ctx = InstructionContext{ .interpreter = &interp };
    opPop(&ctx);
    try expect(interp.bytecode.continue_execution);
    try expectEqual(@as(usize, 1), interp.stack.len());
    try expectEqual(@as(U, 42), interp.stack.peekUnsafe(0));
}

test "POP: stack underflow" {
    var interp = Interpreter.defaultExt();
    var ctx = InstructionContext{ .interpreter = &interp };
    opPop(&ctx);
    try expectEqual(.stack_underflow, interp.result);
}

// --- PUSH0 tests ---

test "PUSH0: pushes zero" {
    var interp = Interpreter.defaultExt();
    var ctx = InstructionContext{ .interpreter = &interp };
    opPush0(&ctx);
    try expect(interp.bytecode.continue_execution);
    try expectEqual(@as(usize, 1), interp.stack.len());
    try expectEqual(@as(U, 0), interp.stack.popUnsafe());
}

test "PUSH0: stack overflow" {
    var interp = Interpreter.defaultExt();
    var i: usize = 0;
    while (i < 1024) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    var ctx = InstructionContext{ .interpreter = &interp };
    opPush0(&ctx);
    try expectEqual(.stack_overflow, interp.result);
}

// --- makePushFn tests (PUSH1..PUSH4 spot checks) ---

test "PUSH1: read 1 byte immediate" {
    const opPush1 = makePushFn(1);
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    // Bytecode: PUSH1 0x42 (but step() already consumed the PUSH1 byte; pc points to 0x42)
    const code = [_]u8{ 0x60, 0x42 }; // PUSH1 0x42
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1; // simulates step() having advanced past opcode byte
    var ctx = InstructionContext{ .interpreter = &interp };
    opPush1(&ctx);
    try expect(interp.bytecode.continue_execution);
    try expectEqual(@as(U, 0x42), interp.stack.popUnsafe());
    try expectEqual(@as(usize, 2), interp.bytecode.pc); // advanced by 1
}

test "PUSH2: read 2 byte immediate" {
    const opPush2 = makePushFn(2);
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    const code = [_]u8{ 0x61, 0xAB, 0xCD }; // PUSH2 0xABCD
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opPush2(&ctx);
    try expectEqual(@as(U, 0xABCD), interp.stack.popUnsafe());
    try expectEqual(@as(usize, 3), interp.bytecode.pc);
}

test "PUSH4: 4-byte immediate big-endian" {
    const opPush4 = makePushFn(4);
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    const code = [_]u8{ 0x63, 0xDE, 0xAD, 0xBE, 0xEF };
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opPush4(&ctx);
    try expectEqual(@as(U, 0xDEADBEEF), interp.stack.popUnsafe());
}

test "PUSH1: near end of code (zero padding)" {
    const opPush1 = makePushFn(1);
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    // Only the PUSH1 opcode, no data byte
    const code = [_]u8{0x60};
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1; // past end
    var ctx = InstructionContext{ .interpreter = &interp };
    opPush1(&ctx);
    // Should push 0 (zero-padded)
    try expectEqual(@as(U, 0), interp.stack.popUnsafe());
}

test "PUSH1: stack overflow" {
    const opPush1 = makePushFn(1);
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    const code = [_]u8{ 0x60, 0x01 };
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var i: usize = 0;
    while (i < 1024) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    var ctx = InstructionContext{ .interpreter = &interp };
    opPush1(&ctx);
    try expectEqual(.stack_overflow, interp.result);
}

// --- makeDupFn tests ---

test "DUP1: duplicate top item" {
    const opDup1 = makeDupFn(1);
    var interp = Interpreter.defaultExt();
    interp.stack.pushUnsafe(@as(U, 100));
    interp.stack.pushUnsafe(@as(U, 200));
    var ctx = InstructionContext{ .interpreter = &interp };
    opDup1(&ctx);
    try expect(interp.bytecode.continue_execution);
    try expectEqual(@as(usize, 3), interp.stack.len());
    try expectEqual(@as(U, 200), interp.stack.peekUnsafe(0));
    try expectEqual(@as(U, 200), interp.stack.peekUnsafe(1));
    try expectEqual(@as(U, 100), interp.stack.peekUnsafe(2));
}

test "DUP2: duplicate second item" {
    const opDup2 = makeDupFn(2);
    var interp = Interpreter.defaultExt();
    interp.stack.pushUnsafe(@as(U, 10));
    interp.stack.pushUnsafe(@as(U, 20));
    var ctx = InstructionContext{ .interpreter = &interp };
    opDup2(&ctx);
    try expectEqual(@as(U, 10), interp.stack.peekUnsafe(0));
    try expectEqual(@as(U, 20), interp.stack.peekUnsafe(1));
    try expectEqual(@as(U, 10), interp.stack.peekUnsafe(2));
}

test "DUP1: stack underflow" {
    const opDup1 = makeDupFn(1);
    var interp = Interpreter.defaultExt();
    var ctx = InstructionContext{ .interpreter = &interp };
    opDup1(&ctx);
    try expectEqual(.stack_underflow, interp.result);
}

test "DUP1: stack overflow" {
    const opDup1 = makeDupFn(1);
    var interp = Interpreter.defaultExt();
    var i: usize = 0;
    while (i < 1024) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    var ctx = InstructionContext{ .interpreter = &interp };
    opDup1(&ctx);
    try expectEqual(.stack_overflow, interp.result);
}

// --- makeSwapFn tests ---

test "SWAP1: swap top two items" {
    const opSwap1 = makeSwapFn(1);
    var interp = Interpreter.defaultExt();
    interp.stack.pushUnsafe(@as(U, 10));
    interp.stack.pushUnsafe(@as(U, 20));
    var ctx = InstructionContext{ .interpreter = &interp };
    opSwap1(&ctx);
    try expect(interp.bytecode.continue_execution);
    try expectEqual(@as(U, 10), interp.stack.peekUnsafe(0));
    try expectEqual(@as(U, 20), interp.stack.peekUnsafe(1));
}

test "SWAP2: swap top with third item" {
    const opSwap2 = makeSwapFn(2);
    var interp = Interpreter.defaultExt();
    interp.stack.pushUnsafe(@as(U, 10));
    interp.stack.pushUnsafe(@as(U, 20));
    interp.stack.pushUnsafe(@as(U, 30));
    var ctx = InstructionContext{ .interpreter = &interp };
    opSwap2(&ctx);
    try expectEqual(@as(U, 10), interp.stack.peekUnsafe(0)); // was at depth 2, now top
    try expectEqual(@as(U, 20), interp.stack.peekUnsafe(1));
    try expectEqual(@as(U, 30), interp.stack.peekUnsafe(2)); // was top, now at depth 2
}

test "SWAP1: stack underflow (need 2, have 1)" {
    const opSwap1 = makeSwapFn(1);
    var interp = Interpreter.defaultExt();
    interp.stack.pushUnsafe(@as(U, 1));
    var ctx = InstructionContext{ .interpreter = &interp };
    opSwap1(&ctx);
    try expectEqual(.stack_underflow, interp.result);
}

// --- DUPN tests (EIP-8024) ---

test "DUPN: valid imm=128 (n=17) duplicates item at depth 17" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    // Push 18 items; item at depth 17 (0-indexed from top) has value 99.
    var i: usize = 0;
    while (i < 17) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    interp.stack.pushUnsafe(@as(U, 99)); // depth 17 from the new top after this push: actually push bottom first
    // Let's be precise: push 17 filler items then the target at the bottom.
    // Rebuild: depth n=17 means the 17th item from the top (1-indexed).
    // After dupUnsafe(17) the top becomes a copy of item[top-17+1] in dupUnsafe convention.
    // Easier: push target first, then 16 fillers, then call DUPN imm=128.
    interp.stack.length = 0; // clear; Stack is heap-backed now, so it cannot be re-initialised
    interp.stack.pushUnsafe(@as(U, 0xBEEF)); // will be at depth 17 after 16 more pushes
    var j: usize = 0;
    while (j < 16) : (j += 1) interp.stack.pushUnsafe(@as(U, j + 1));
    // Stack has 17 items; top is 16, depth 17 is 0xBEEF.
    try expectEqual(@as(usize, 17), interp.stack.len());
    const code = [_]u8{ 0xE6, 128 }; // DUPN imm=128
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opDupN(&ctx);
    try expect(interp.bytecode.continue_execution);
    try expectEqual(@as(usize, 18), interp.stack.len());
    try expectEqual(@as(U, 0xBEEF), interp.stack.peekUnsafe(0)); // duplicate at top
}

test "DUPN: invalid imm=91 halts with invalid_opcode (was unchecked: n=236 > 16)" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    // Fill stack so depth check can't trigger — ensures halt is from the byte range check.
    var i: usize = 0;
    while (i < 1024) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    const code = [_]u8{ 0xE6, 91 }; // DUPN imm=91 (first invalid: 90 < 91 < 128)
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opDupN(&ctx);
    try expectEqual(.invalid_opcode, interp.result);
}

test "DUPN: invalid imm=110 halts with invalid_opcode (maps to n=255, old code let this pass)" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    var i: usize = 0;
    while (i < 1024) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    const code = [_]u8{ 0xE6, 110 }; // DUPN imm=110 → n=255, old n<=16 check missed this
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opDupN(&ctx);
    try expectEqual(.invalid_opcode, interp.result);
}

test "DUPN: invalid imm=127 halts with invalid_opcode (last of invalid range, n=16)" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    var i: usize = 0;
    while (i < 1024) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    const code = [_]u8{ 0xE6, 127 }; // DUPN imm=127 → n=16
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opDupN(&ctx);
    try expectEqual(.invalid_opcode, interp.result);
}

test "DUPN: valid boundary imm=0 (n=145) succeeds with sufficient stack" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    interp.stack.pushUnsafe(@as(U, 0xCAFE)); // will be at depth 145 after 144 more pushes
    var i: usize = 0;
    while (i < 144) : (i += 1) interp.stack.pushUnsafe(@as(U, i + 1));
    try expectEqual(@as(usize, 145), interp.stack.len());
    const code = [_]u8{ 0xE6, 0 }; // DUPN imm=0 → n=145
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opDupN(&ctx);
    try expect(interp.bytecode.continue_execution);
    try expectEqual(@as(usize, 146), interp.stack.len());
    try expectEqual(@as(U, 0xCAFE), interp.stack.peekUnsafe(0));
}

test "DUPN: stack underflow" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    // imm=128 → n=17; push only 5 items → underflow
    var i: usize = 0;
    while (i < 5) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    const code = [_]u8{ 0xE6, 128 };
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opDupN(&ctx);
    try expectEqual(.stack_underflow, interp.result);
}

// --- SWAPN tests (EIP-8024) ---

test "SWAPN: valid imm=128 (n=17) swaps top with item at depth 17" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    // Push target at bottom, then 17 fillers so target is at depth 17 from new top.
    interp.stack.pushUnsafe(@as(U, 0xDEAD)); // depth 18 after 17 more pushes
    var i: usize = 0;
    while (i < 17) : (i += 1) interp.stack.pushUnsafe(@as(U, i + 1));
    // Stack: [0xDEAD, 1, 2, ..., 17] (17 is top, 0xDEAD at depth 17, index 0)
    // SWAPN imm=128 → n=17: swap top with stack[top - 17] = 0xDEAD
    const code = [_]u8{ 0xE7, 128 };
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opSwapN(&ctx);
    try expect(interp.bytecode.continue_execution);
    try expectEqual(@as(usize, 18), interp.stack.len());
    try expectEqual(@as(U, 0xDEAD), interp.stack.peekUnsafe(0)); // old depth-17 now on top
    try expectEqual(@as(U, 17), interp.stack.peekUnsafe(17)); // old top now at depth 17
}

test "SWAPN: invalid imm=91 halts with invalid_opcode (was completely unchecked)" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    var i: usize = 0;
    while (i < 1024) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    const code = [_]u8{ 0xE7, 91 }; // SWAPN imm=91: no check existed before fix
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opSwapN(&ctx);
    try expectEqual(.invalid_opcode, interp.result);
}

test "SWAPN: invalid imm=110 halts with invalid_opcode (maps to n=255, was unchecked)" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    var i: usize = 0;
    while (i < 1024) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    const code = [_]u8{ 0xE7, 110 }; // imm=110 → n=255, stack has 1024 items → old code swapped!
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opSwapN(&ctx);
    try expectEqual(.invalid_opcode, interp.result);
}

test "SWAPN: invalid imm=127 halts with invalid_opcode" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    var i: usize = 0;
    while (i < 1024) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    const code = [_]u8{ 0xE7, 127 };
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opSwapN(&ctx);
    try expectEqual(.invalid_opcode, interp.result);
}

test "SWAPN: valid boundary imm=90 (n=235) succeeds with sufficient stack" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    interp.stack.pushUnsafe(@as(U, 0xABCD)); // will be at depth 235 from top
    var i: usize = 0;
    while (i < 235) : (i += 1) interp.stack.pushUnsafe(@as(U, i + 1));
    // top = 235, depth 235 = 0xABCD; SWAPN imm=90 → n=235
    const code = [_]u8{ 0xE7, 90 };
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opSwapN(&ctx);
    try expect(interp.bytecode.continue_execution);
    try expectEqual(@as(U, 0xABCD), interp.stack.peekUnsafe(0));
    try expectEqual(@as(U, 235), interp.stack.peekUnsafe(235));
}

test "SWAPN: stack underflow" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    // imm=128 → n=17, need 18 items; push only 5
    var i: usize = 0;
    while (i < 5) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    const code = [_]u8{ 0xE7, 128 };
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opSwapN(&ctx);
    try expectEqual(.stack_underflow, interp.result);
}

// --- EXCHANGE tests (EIP-8024) ---

test "EXCHANGE: valid imm=0 swaps depths 1 and 2" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    // imm=0: k=0^143=143, q=8, r=15; q<r → n=q+1=9, m=r+1=16
    // Actually let's use a simpler imm. imm=0xBE=190: k=190^143=49, q=3, r=1; q>=r → n=r+1=2, m=29-q=26
    // Use imm=128+1=129: k=129^143=14, q=0, r=14; q<r → n=1, m=15
    // Let's use imm=129: n=1, m=15 → need 16 items.
    interp.stack.pushUnsafe(@as(U, 0xAAAA)); // depth 15 from top
    var i: usize = 0;
    while (i < 14) : (i += 1) interp.stack.pushUnsafe(@as(U, i + 1));
    interp.stack.pushUnsafe(@as(U, 0xBBBB)); // top=0xBBBB, depth1=14, depth15=0xAAAA
    try expectEqual(@as(usize, 16), interp.stack.len());
    const code = [_]u8{ 0xE8, 129 }; // EXCHANGE imm=129 → n=1, m=15
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opExchange(&ctx);
    try expect(interp.bytecode.continue_execution);
    // stack[top-1] and stack[top-15] should be swapped; top unchanged
    try expectEqual(@as(U, 0xBBBB), interp.stack.peekUnsafe(0)); // top unchanged
    try expectEqual(@as(U, 0xAAAA), interp.stack.peekUnsafe(1)); // was depth 15, now depth 1
    try expectEqual(@as(U, 14), interp.stack.peekUnsafe(15)); // was depth 1 (value 14), now depth 15
}

test "EXCHANGE: invalid imm=82 halts with invalid_opcode" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    var i: usize = 0;
    while (i < 1024) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    const code = [_]u8{ 0xE8, 82 }; // first invalid for EXCHANGE (81 < 82 < 128)
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opExchange(&ctx);
    try expectEqual(.invalid_opcode, interp.result);
}

test "EXCHANGE: invalid imm=127 halts with invalid_opcode" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    var i: usize = 0;
    while (i < 1024) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    const code = [_]u8{ 0xE8, 127 };
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opExchange(&ctx);
    try expectEqual(.invalid_opcode, interp.result);
}

test "EXCHANGE: stack underflow" {
    var interp = Interpreter.defaultExt();
    defer interp.deinit();
    // imm=129 → n=1, m=15; need 16 items; push only 5
    var i: usize = 0;
    while (i < 5) : (i += 1) interp.stack.pushUnsafe(@as(U, i));
    const code = [_]u8{ 0xE8, 129 };
    interp.bytecode = ExtBytecode.newOwned(bytecode_mod.Bytecode.newLegacy(&code));
    interp.bytecode.pc = 1;
    var ctx = InstructionContext{ .interpreter = &interp };
    opExchange(&ctx);
    try expectEqual(.stack_underflow, interp.result);
}
