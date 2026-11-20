//! Expected values come from the execution-specs reference (`forks/<fork>/vm/gas.py`,
//! `vm/instructions/storage.py`, `vm/instructions/system.py`), not from this implementation.

const std = @import("std");
const primitives = @import("primitives");
const gas_costs = @import("gas_costs.zig");

const expectEqual = std.testing.expectEqual;
const SpecId = primitives.SpecId;

/// One SSTORE on a warm slot: (original, current, new) → charge and refund-counter delta.
const SstoreCase = struct {
    o: u8,
    c: u8,
    n: u8,
    gas: u64,
    refund: i64,
    state_gas: u64 = 0,
    state_refund: u64 = 0,
};

/// `cold_extra` is what a cold slot adds to the charge in these forks.
fn expectSstoreTable(specs: []const SpecId, cases: []const SstoreCase, cold_extra: u64) !void {
    for (specs) |spec| {
        for (cases) |case| {
            for ([_]bool{ false, true }) |is_cold| {
                const got = gas_costs.getSstoreCost(spec, case.o, case.c, case.n, is_cold, 30_000_000);
                const gas = case.gas + if (is_cold) cold_extra else 0;
                errdefer std.debug.print(
                    "spec={s} original={d} current={d} new={d} cold={}\n",
                    .{ @tagName(spec), case.o, case.c, case.n, is_cold },
                );
                try expectEqual(gas, got.gas_cost);
                try expectEqual(case.refund, got.gas_refund);
                try expectEqual(case.state_gas, got.state_gas);
                try expectEqual(case.state_refund, got.state_gas_refund);
            }
        }
    }
}

// frontier … constantinople storage.py sstore: STORAGE_SET 20000 when current == 0 and
// new != 0, else COLD_STORAGE_WRITE 5000; REFUND_STORAGE_CLEAR 15000 when current != 0 and
// new == 0. The original value and slot warmth play no part.
test "SSTORE before Istanbul prices on current and new only" {
    const cases = [_]SstoreCase{
        .{ .o = 0, .c = 0, .n = 1, .gas = 20000, .refund = 0 },
        .{ .o = 1, .c = 0, .n = 1, .gas = 20000, .refund = 0 },
        .{ .o = 0, .c = 0, .n = 0, .gas = 5000, .refund = 0 },
        .{ .o = 1, .c = 1, .n = 1, .gas = 5000, .refund = 0 },
        .{ .o = 1, .c = 1, .n = 2, .gas = 5000, .refund = 0 },
        .{ .o = 1, .c = 1, .n = 0, .gas = 5000, .refund = 15000 },
        .{ .o = 0, .c = 1, .n = 0, .gas = 5000, .refund = 15000 },
        .{ .o = 1, .c = 2, .n = 1, .gas = 5000, .refund = 0 },
    };
    try expectSstoreTable(
        &.{ .frontier, .homestead, .tangerine, .spurious_dragon, .byzantium, .constantinople, .petersburg },
        &cases,
        0,
    );
}

// istanbul storage.py sstore (EIP-2200): SLOAD 800, STORAGE_SET 20000, COLD_STORAGE_WRITE
// 5000, REFUND_STORAGE_CLEAR 15000. Restoring the original refunds 20000 - 800 or 5000 - 800.
test "SSTORE in Istanbul follows EIP-2200 net metering" {
    const cases = [_]SstoreCase{
        .{ .o = 0, .c = 0, .n = 0, .gas = 800, .refund = 0 },
        .{ .o = 1, .c = 1, .n = 1, .gas = 800, .refund = 0 },
        .{ .o = 1, .c = 0, .n = 0, .gas = 800, .refund = 0 },
        .{ .o = 0, .c = 0, .n = 1, .gas = 20000, .refund = 0 },
        .{ .o = 1, .c = 1, .n = 2, .gas = 5000, .refund = 0 },
        .{ .o = 1, .c = 1, .n = 0, .gas = 5000, .refund = 15000 },
        .{ .o = 1, .c = 0, .n = 2, .gas = 800, .refund = -15000 },
        .{ .o = 1, .c = 0, .n = 1, .gas = 800, .refund = -10800 },
        .{ .o = 1, .c = 2, .n = 0, .gas = 800, .refund = 15000 },
        .{ .o = 1, .c = 2, .n = 1, .gas = 800, .refund = 4200 },
        .{ .o = 1, .c = 2, .n = 3, .gas = 800, .refund = 0 },
        .{ .o = 0, .c = 1, .n = 0, .gas = 800, .refund = 19200 },
        .{ .o = 0, .c = 1, .n = 2, .gas = 800, .refund = 0 },
    };
    try expectSstoreTable(&.{ .istanbul, .muir_glacier }, &cases, 0);
}

// berlin storage.py sstore (EIP-2929): WARM_ACCESS 100, COLD_STORAGE_ACCESS 2100 added for a
// cold slot, reset 5000 - 2100, REFUND_STORAGE_CLEAR still 15000. Restoring the original
// refunds 20000 - 100 or 5000 - 2100 - 100.
test "SSTORE in Berlin adds the cold access cost and keeps the 15000 clear refund" {
    const cases = [_]SstoreCase{
        .{ .o = 0, .c = 0, .n = 0, .gas = 100, .refund = 0 },
        .{ .o = 1, .c = 1, .n = 1, .gas = 100, .refund = 0 },
        .{ .o = 1, .c = 0, .n = 0, .gas = 100, .refund = 0 },
        .{ .o = 0, .c = 0, .n = 1, .gas = 20000, .refund = 0 },
        .{ .o = 1, .c = 1, .n = 2, .gas = 2900, .refund = 0 },
        .{ .o = 1, .c = 1, .n = 0, .gas = 2900, .refund = 15000 },
        .{ .o = 1, .c = 0, .n = 2, .gas = 100, .refund = -15000 },
        .{ .o = 1, .c = 0, .n = 1, .gas = 100, .refund = -12200 },
        .{ .o = 1, .c = 2, .n = 0, .gas = 100, .refund = 15000 },
        .{ .o = 1, .c = 2, .n = 1, .gas = 100, .refund = 2800 },
        .{ .o = 1, .c = 2, .n = 3, .gas = 100, .refund = 0 },
        .{ .o = 0, .c = 1, .n = 0, .gas = 100, .refund = 19900 },
        .{ .o = 0, .c = 1, .n = 2, .gas = 100, .refund = 0 },
    };
    try expectSstoreTable(&.{.berlin}, &cases, 2100);
}

// london … osaka storage.py sstore: as Berlin with REFUND_STORAGE_CLEAR 4800 (EIP-3529).
test "SSTORE from London refunds 4800 for a clear" {
    const cases = [_]SstoreCase{
        .{ .o = 0, .c = 0, .n = 0, .gas = 100, .refund = 0 },
        .{ .o = 1, .c = 1, .n = 1, .gas = 100, .refund = 0 },
        .{ .o = 1, .c = 0, .n = 0, .gas = 100, .refund = 0 },
        .{ .o = 0, .c = 0, .n = 1, .gas = 20000, .refund = 0 },
        .{ .o = 1, .c = 1, .n = 2, .gas = 2900, .refund = 0 },
        .{ .o = 1, .c = 1, .n = 0, .gas = 2900, .refund = 4800 },
        .{ .o = 1, .c = 0, .n = 2, .gas = 100, .refund = -4800 },
        .{ .o = 1, .c = 0, .n = 1, .gas = 100, .refund = -2000 },
        .{ .o = 1, .c = 2, .n = 0, .gas = 100, .refund = 4800 },
        .{ .o = 1, .c = 2, .n = 1, .gas = 100, .refund = 2800 },
        .{ .o = 1, .c = 2, .n = 3, .gas = 100, .refund = 0 },
        .{ .o = 0, .c = 1, .n = 0, .gas = 100, .refund = 19900 },
        .{ .o = 0, .c = 1, .n = 2, .gas = 100, .refund = 0 },
    };
    try expectSstoreTable(
        &.{ .london, .arrow_glacier, .gray_glacier, .merge, .shanghai, .cancun, .prague, .osaka, .bpo1, .bpo2 },
        &cases,
        2100,
    );
}

// amsterdam storage.py sstore (EIP-8037): access 100 warm / 2100 cold, STORAGE_WRITE 10000 on
// the first change away from the original, REFUND_STORAGE_CLEAR (10000 + 2100) * 4800 // 5000
// = 11616, restoring the original refunds STORAGE_WRITE, and state gas STORAGE_SET
// 64 * 1530 = 97920 is charged for a first set from zero and credited back when that slot
// returns to zero.
test "SSTORE in Amsterdam splits regular and state gas" {
    const cases = [_]SstoreCase{
        .{ .o = 0, .c = 0, .n = 0, .gas = 100, .refund = 0 },
        .{ .o = 1, .c = 1, .n = 1, .gas = 100, .refund = 0 },
        .{ .o = 1, .c = 0, .n = 0, .gas = 100, .refund = 0 },
        .{ .o = 0, .c = 1, .n = 1, .gas = 100, .refund = 0 },
        .{ .o = 0, .c = 0, .n = 1, .gas = 10100, .refund = 0, .state_gas = 97920 },
        .{ .o = 1, .c = 1, .n = 2, .gas = 10100, .refund = 0 },
        .{ .o = 1, .c = 1, .n = 0, .gas = 10100, .refund = 11616 },
        .{ .o = 1, .c = 0, .n = 2, .gas = 100, .refund = -11616 },
        .{ .o = 1, .c = 0, .n = 1, .gas = 100, .refund = -1616 },
        .{ .o = 1, .c = 2, .n = 0, .gas = 100, .refund = 11616 },
        .{ .o = 1, .c = 2, .n = 1, .gas = 100, .refund = 10000 },
        .{ .o = 1, .c = 2, .n = 3, .gas = 100, .refund = 0 },
        .{ .o = 0, .c = 1, .n = 0, .gas = 100, .refund = 10000, .state_refund = 97920 },
        .{ .o = 0, .c = 1, .n = 2, .gas = 100, .refund = 0 },
    };
    try expectSstoreTable(&.{.amsterdam}, &cases, 2000);
}

// amsterdam vm/gas.py: StateGasCosts.COST_PER_STATE_BYTE = 1530, a constant; GasCosts
// REFUND_STORAGE_CLEAR, CALL_VALUE = ACCOUNT_WRITE 9000 + CALL_STIPEND 2300 and
// CREATE_ACCESS = ACCOUNT_WRITE 9000 + COLD_ACCOUNT_ACCESS 3000.
test "Amsterdam state byte cost and derived constants" {
    for ([_]u64{ 0, 30_000_000, 60_000_000, 300_000_000, std.math.maxInt(u64) }) |gas_limit| {
        try expectEqual(@as(u64, 1530), gas_costs.costPerStateByte(gas_limit));
    }
    try expectEqual(@as(i64, 11616), gas_costs.REFUND_STORAGE_CLEAR_AMSTERDAM);
    try expectEqual(@as(u64, 11300), gas_costs.CALL_VALUE_AMSTERDAM);
    try expectEqual(@as(u64, 12000), gas_costs.CREATE_ACCESS_AMSTERDAM);
    try expectEqual(@as(u64, 3000), gas_costs.coldAccountAccess(.amsterdam));
    try expectEqual(@as(u64, 2600), gas_costs.coldAccountAccess(.osaka));
    try expectEqual(@as(u64, 2100), gas_costs.coldStorageAccess(.amsterdam));
    try expectEqual(@as(u64, 2100), gas_costs.coldStorageAccess(.osaka));
}

// vm/gas.py calculate_memory_gas_cost: words * 3 + words ** 2 // 512, and
// calculate_gas_extend_memory charges the difference between the two totals.
test "memory expansion cost is the difference of the quadratic totals" {
    // Totals: 1 word 3, 22 words 66 + 0, 23 words 69 + 1, 32 words 96 + 2,
    // 724 words 2172 + 1023, 1024 words 3072 + 2048.
    try expectEqual(@as(u64, 3), gas_costs.memoryExpansionCost(0, 1));
    try expectEqual(@as(u64, 66), gas_costs.memoryExpansionCost(0, 22));
    try expectEqual(@as(u64, 70), gas_costs.memoryExpansionCost(0, 23));
    try expectEqual(@as(u64, 98), gas_costs.memoryExpansionCost(0, 32));
    try expectEqual(@as(u64, 3195), gas_costs.memoryExpansionCost(0, 724));
    try expectEqual(@as(u64, 5120), gas_costs.memoryExpansionCost(0, 1024));
    try expectEqual(@as(u64, 4), gas_costs.memoryExpansionCost(22, 23));
    try expectEqual(@as(u64, 3097), gas_costs.memoryExpansionCost(32, 724));
    try expectEqual(@as(u64, 1925), gas_costs.memoryExpansionCost(724, 1024));
}

// vm/gas.py calculate_gas_extend_memory: `if after_size <= before_size: continue`.
test "memory that does not grow costs nothing" {
    try expectEqual(@as(u64, 0), gas_costs.memoryExpansionCost(0, 0));
    try expectEqual(@as(u64, 0), gas_costs.memoryExpansionCost(724, 724));
    try expectEqual(@as(u64, 0), gas_costs.memoryExpansionCost(724, 32));
}

// utils/numeric.py ceil32, then `// 32` in calculate_memory_gas_cost.
test "word size rounds a byte size up to 32" {
    try expectEqual(@as(usize, 0), gas_costs.toWordSize(0));
    try expectEqual(@as(usize, 1), gas_costs.toWordSize(1));
    try expectEqual(@as(usize, 1), gas_costs.toWordSize(32));
    try expectEqual(@as(usize, 2), gas_costs.toWordSize(33));
    try expectEqual(@as(usize, 2), gas_costs.toWordSize(64));
    try expectEqual(@as(usize, 724), gas_costs.toWordSize(23137));
    try expectEqual(@as(usize, 724), gas_costs.toWordSize(23168));
    try expectEqual(@as(usize, 725), gas_costs.toWordSize(23169));
}

// frontier / tangerine_whistle system.py call: NEW_ACCOUNT 25000 whenever the target does
// not exist, value or not, on top of OPCODE_CALL_BASE (40, then 700) and CALL_VALUE 9000.
test "CALL to a missing account before Spurious Dragon pays for the new account without value" {
    try expectEqual(@as(u64, 25040), gas_costs.getCallGasCost(.frontier, false, false, false));
    try expectEqual(@as(u64, 34040), gas_costs.getCallGasCost(.homestead, false, true, false));
    try expectEqual(@as(u64, 9040), gas_costs.getCallGasCost(.homestead, false, true, true));
    try expectEqual(@as(u64, 25700), gas_costs.getCallGasCost(.tangerine, false, false, false));
    try expectEqual(@as(u64, 34700), gas_costs.getCallGasCost(.tangerine, false, true, false));
}

// spurious_dragon system.py call (EIP-161): `create_gas_cost = 0` when value == 0 or the
// target is alive. berlin: access cost 2600 cold / 100 warm replaces the base 700.
test "CALL from Spurious Dragon pays for the new account only with value" {
    try expectEqual(@as(u64, 700), gas_costs.getCallGasCost(.spurious_dragon, false, false, false));
    try expectEqual(@as(u64, 34700), gas_costs.getCallGasCost(.spurious_dragon, false, true, false));
    try expectEqual(@as(u64, 9700), gas_costs.getCallGasCost(.spurious_dragon, false, true, true));
    try expectEqual(@as(u64, 2600), gas_costs.getCallGasCost(.berlin, true, false, false));
    try expectEqual(@as(u64, 36600), gas_costs.getCallGasCost(.berlin, true, true, false));
    try expectEqual(@as(u64, 34100), gas_costs.getCallGasCost(.osaka, false, true, false));
    try expectEqual(@as(u64, 11600), gas_costs.getCallGasCost(.osaka, true, true, true));
}

// amsterdam system.py call: access_gas_cost 3000 cold / 100 warm plus CALL_VALUE 11300; the
// new account is charged as state gas, not here.
test "CALL in Amsterdam has no regular new-account charge" {
    try expectEqual(@as(u64, 100), gas_costs.getCallGasCost(.amsterdam, false, false, true));
    try expectEqual(@as(u64, 3000), gas_costs.getCallGasCost(.amsterdam, true, false, false));
    try expectEqual(@as(u64, 11400), gas_costs.getCallGasCost(.amsterdam, false, true, true));
    try expectEqual(@as(u64, 11400), gas_costs.getCallGasCost(.amsterdam, false, true, false));
    try expectEqual(@as(u64, 14300), gas_costs.getCallGasCost(.amsterdam, true, true, false));
}
