const std = @import("std");
const bytecode_mod = @import("main.zig");

const JUMPDEST = bytecode_mod.JUMPDEST;
const PUSH1 = bytecode_mod.PUSH1;
const LegacyRawBytecode = bytecode_mod.LegacyRawBytecode;

fn analyzeLegacy(code: []const u8) bytecode_mod.LegacyAnalyzedBytecode {
    return LegacyRawBytecode.init(code).intoAnalyzed();
}

test "analyzeLegacy: jump table agrees with a serial reference" {
    // Reference: the plain byte-serial walk, no word skipping.
    const ref = struct {
        fn jumpdests(alloc: std.mem.Allocator, code: []const u8) ![]bool {
            const out = try alloc.alloc(bool, code.len);
            @memset(out, false);
            var i: usize = 0;
            while (i < code.len) {
                const op = code[i];
                if (op == JUMPDEST) {
                    out[i] = true;
                    i += 1;
                } else {
                    const push_offset = op -% PUSH1;
                    i += if (push_offset < 32) @as(usize, push_offset) + 2 else 1;
                }
            }
            return out;
        }
    };

    const alloc = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xB17C0DE);
    const rand = prng.random();

    for (0..400) |case| {
        // Mix of sizes, including sub-word and word-boundary lengths.
        const len = switch (case % 4) {
            0 => rand.uintLessThan(usize, 9), // 0..8, exercises the tail
            1 => rand.uintLessThan(usize, 64),
            2 => rand.uintLessThan(usize, 600),
            else => rand.uintLessThan(usize, 2000),
        };
        const code = try alloc.alloc(u8, len);
        defer alloc.free(code);
        for (code) |*b| {
            // Bias towards JUMPDEST and PUSH so the fast path is exercised
            // against the interesting bytes rather than mostly skipping.
            b.* = switch (rand.uintLessThan(u8, 4)) {
                0 => JUMPDEST,
                1 => PUSH1 + rand.uintLessThan(u8, 32),
                else => rand.int(u8),
            };
        }

        const expect = try ref.jumpdests(alloc, code);
        defer alloc.free(expect);

        const analyzed = analyzeLegacy(code);
        for (expect, 0..) |want, pc| {
            try std.testing.expectEqual(want, analyzed.jump_table.isValid(pc));
        }
    }

    // Adversarial fixed cases.
    const cases = [_][]const u8{
        &.{},
        &.{JUMPDEST},
        &.{ PUSH1, JUMPDEST }, // JUMPDEST is immediate data, not a target
        &.{ PUSH1 + 31, 0, 0, 0, 0, 0, 0, 0, JUMPDEST }, // inside PUSH32 data
        &([_]u8{PUSH1 + 31} ** 3), // trailing PUSH runs past the end
        &([_]u8{JUMPDEST} ** 8),
        &([_]u8{JUMPDEST} ** 9),
        &([_]u8{0x00} ** 8 ++ [_]u8{JUMPDEST}), // a skippable word then a target
        &([_]u8{0x00} ** 16),
    };
    for (cases) |code| {
        const expect = try ref.jumpdests(alloc, code);
        defer alloc.free(expect);
        const analyzed = analyzeLegacy(code);
        for (expect, 0..) |want, pc| {
            try std.testing.expectEqual(want, analyzed.jump_table.isValid(pc));
        }
    }
}
