const std = @import("std");
const primitives = @import("primitives");
const instruction_context = @import("../instruction_context.zig");
const InstructionContext = instruction_context.InstructionContext;
const expandMemory = instruction_context.expandMemory;
const gas_costs = @import("../gas_costs.zig");

/// KECCAK256 opcode (0x20): Compute Keccak-256 hash of memory region
/// Stack: [offset, length] -> [hash]
/// Gas: 30 (G_KECCAK256, dispatch) + 6*ceil(length/32) (word cost) + memory_expansion
pub fn opKeccak256(ctx: *InstructionContext) void {
    const stack = &ctx.interpreter.stack;
    if (!stack.hasItems(2)) {
        ctx.interpreter.halt(.stack_underflow);
        return;
    }

    const offset = stack.peekUnsafe(0);
    const length = stack.peekUnsafe(1);

    if (length > std.math.maxInt(usize)) {
        ctx.interpreter.halt(.memory_limit_oog);
        return;
    }
    const length_usize: usize = @intCast(length);
    // When length == 0, offset is unused — do not halt on huge offset.
    if (length_usize > 0 and offset > std.math.maxInt(usize)) {
        ctx.interpreter.halt(.memory_limit_oog);
        return;
    }
    const offset_usize: usize = if (length_usize == 0) 0 else @intCast(offset);

    // Compute end = offset + length before word-cost so a huge length is caught early.
    const end = if (length_usize > 0)
        std.math.add(usize, offset_usize, length_usize) catch {
            ctx.interpreter.halt(.memory_limit_oog);
            return;
        }
    else
        offset_usize;

    // Dynamic: word cost — std.math.divCeil avoids (length + 31) overflow when
    // length_usize is near maxInt(usize) (e.g. from GASLIMIT with maxInt gas limit).
    const num_words: u64 = @intCast(std.math.divCeil(usize, length_usize, 32) catch unreachable);
    const word_cost = gas_costs.G_KECCAK256WORD * num_words;
    if (!ctx.interpreter.gas.spend(word_cost)) {
        ctx.interpreter.halt(.out_of_gas);
        return;
    }

    // Dynamic: memory expansion
    if (length_usize > 0) {
        if (!expandMemory(ctx, end)) {
            ctx.interpreter.halt(.out_of_gas);
            return;
        }
    }

    const data = if (length_usize > 0)
        ctx.interpreter.memory.buffer.items[offset_usize..end]
    else
        &[_]u8{};

    var hash: [32]u8 = undefined;
    const accel = @import("accelerators");
    accel.keccak256(data, &hash);

    const U = primitives.U256;
    const value: U = (@as(U, std.mem.readInt(u64, hash[0..8], .big)) << 192) |
        (@as(U, std.mem.readInt(u64, hash[8..16], .big)) << 128) |
        (@as(U, std.mem.readInt(u64, hash[16..24], .big)) << 64) |
        @as(U, std.mem.readInt(u64, hash[24..32], .big));

    stack.shrinkUnsafe(1);
    stack.setTopUnsafe().* = value;
}

test {
    _ = @import("keccak_tests.zig");
}
