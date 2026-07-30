const std = @import("std");
const primitives = @import("primitives");
const instruction_context = @import("../instruction_context.zig");
const InstructionContext = instruction_context.InstructionContext;
const expandMemory = instruction_context.expandMemory;

// ---------------------------------------------------------------------------
// RETURN / REVERT / INVALID
// ---------------------------------------------------------------------------

/// RETURN (0xF3): Stop execution, return data from memory.
/// Stack: [offset, size] -> []   Gas: 0 static + memory_expansion
pub fn opReturn(ctx: *InstructionContext) void {
    const stack = &ctx.interpreter.stack;
    if (!stack.hasItems(2)) {
        ctx.interpreter.halt(.stack_underflow);
        return;
    }

    const offset = stack.peekUnsafe(0);
    const size = stack.peekUnsafe(1);
    stack.shrinkUnsafe(2);

    if (size == 0) {
        ctx.interpreter.return_data.data = &[_]u8{};
        ctx.interpreter.halt(.@"return");
        return;
    }

    if (offset > std.math.maxInt(usize) or size > std.math.maxInt(usize)) {
        ctx.interpreter.halt(.memory_limit_oog);
        return;
    }

    const offset_u: usize = @intCast(offset);
    const size_u: usize = @intCast(size);

    const return_end = std.math.add(usize, offset_u, size_u) catch {
        ctx.interpreter.halt(.memory_limit_oog);
        return;
    };
    if (!expandMemory(ctx, return_end)) {
        ctx.interpreter.halt(.out_of_gas);
        return;
    }

    ctx.interpreter.return_data.data = ctx.interpreter.memory.buffer.items[offset_u..return_end];
    ctx.interpreter.halt(.@"return");
}

/// REVERT (0xFD): Stop execution and revert state, return data from memory.
/// Stack: [offset, size] -> []   Gas: 0 static + memory_expansion (Byzantium+)
pub fn opRevert(ctx: *InstructionContext) void {
    const stack = &ctx.interpreter.stack;
    if (!stack.hasItems(2)) {
        ctx.interpreter.halt(.stack_underflow);
        return;
    }

    const offset = stack.peekUnsafe(0);
    const size = stack.peekUnsafe(1);
    stack.shrinkUnsafe(2);

    if (size == 0) {
        ctx.interpreter.return_data.data = &[_]u8{};
        ctx.interpreter.halt(.revert);
        return;
    }

    if (offset > std.math.maxInt(usize) or size > std.math.maxInt(usize)) {
        ctx.interpreter.halt(.memory_limit_oog);
        return;
    }

    const offset_u: usize = @intCast(offset);
    const size_u: usize = @intCast(size);

    const revert_end = std.math.add(usize, offset_u, size_u) catch {
        ctx.interpreter.halt(.memory_limit_oog);
        return;
    };
    if (!expandMemory(ctx, revert_end)) {
        ctx.interpreter.halt(.out_of_gas);
        return;
    }

    ctx.interpreter.return_data.data = ctx.interpreter.memory.buffer.items[offset_u..revert_end];
    ctx.interpreter.halt(.revert);
}

/// INVALID (0xFE): Designated invalid instruction. Consumes all remaining gas.
/// Stack: [] -> []   Gas: all remaining
pub fn opInvalid(ctx: *InstructionContext) void {
    ctx.interpreter.gas.spendAll();
    ctx.interpreter.halt(.invalid_opcode);
}
