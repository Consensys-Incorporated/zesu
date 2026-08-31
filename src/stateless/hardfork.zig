/// Hardfork schedule — single source of truth for fork names, SpecId mapping,
/// mainnet activation schedule, and block rewards.
///
/// Intentionally outside the executor so that string handling and schedule
/// tables do not pollute the core execution path.
const std = @import("std");
const primitives = @import("primitives");

// ─── Fork name ↔ SpecId ───────────────────────────────────────────────────────

/// Return a human-readable name for a SpecId (e.g. .prague → "Prague").
pub fn specName(spec: primitives.SpecId) []const u8 {
    return switch (spec) {
        .frontier, .frontier_thawing => "Frontier",
        .homestead => "Homestead",
        .dao_fork => "DAO",
        .tangerine => "EIP150",
        .spurious_dragon => "EIP158",
        .byzantium => "Byzantium",
        .constantinople => "Constantinople",
        .petersburg => "Petersburg",
        .istanbul => "Istanbul",
        .muir_glacier => "MuirGlacier",
        .berlin => "Berlin",
        .london => "London",
        .arrow_glacier => "ArrowGlacier",
        .gray_glacier => "GrayGlacier",
        .merge => "Paris",
        .shanghai => "Shanghai",
        .cancun => "Cancun",
        .prague => "Prague",
        .osaka => "Osaka",
        .bpo1 => "BPO1",
        .bpo2 => "BPO2",
        .amsterdam => "Amsterdam",
    };
}

/// Map a fork name string to the corresponding SpecId.
/// Returns null for unknown or transition fork names.
pub fn specFromFork(name: []const u8) ?primitives.SpecId {
    const Entry = struct { k: []const u8, v: primitives.SpecId };
    const table = [_]Entry{
        .{ .k = "Frontier", .v = .frontier },
        .{ .k = "Homestead", .v = .homestead },
        .{ .k = "DAO", .v = .dao_fork },
        .{ .k = "DAOFork", .v = .dao_fork },
        .{ .k = "EIP150", .v = .tangerine },
        .{ .k = "TangerineWhistle", .v = .tangerine },
        .{ .k = "EIP158", .v = .spurious_dragon },
        .{ .k = "SpuriousDragon", .v = .spurious_dragon },
        .{ .k = "Byzantium", .v = .byzantium },
        .{ .k = "Constantinople", .v = .constantinople },
        .{ .k = "ConstantinopleFix", .v = .petersburg },
        .{ .k = "Petersburg", .v = .petersburg },
        .{ .k = "Istanbul", .v = .istanbul },
        .{ .k = "MuirGlacier", .v = .muir_glacier },
        .{ .k = "Berlin", .v = .berlin },
        .{ .k = "London", .v = .london },
        .{ .k = "ArrowGlacier", .v = .arrow_glacier },
        .{ .k = "GrayGlacier", .v = .gray_glacier },
        .{ .k = "Merge", .v = .merge },
        .{ .k = "Paris", .v = .merge },
        .{ .k = "Shanghai", .v = .shanghai },
        .{ .k = "Cancun", .v = .cancun },
        .{ .k = "Prague", .v = .prague },
        .{ .k = "Osaka", .v = .osaka },
        .{ .k = "BPO1", .v = .bpo1 },
        .{ .k = "BPO2", .v = .bpo2 },
        .{ .k = "Amsterdam", .v = .amsterdam },
    };
    for (table) |e| {
        if (std.mem.eql(u8, name, e.k)) return e.v;
    }
    return null;
}

/// Map a `ProtocolFork` index to its SpecId.
///
/// `ProtocolFork` is the stable fork enum the stateless schemas are keyed by
/// (execution-specs `stateless.py`, tests-zkevm@v0.8.2). A stateless input's
/// schema id is `fork_index << 8 | revision`, so this table is what lets the
/// guest execute the fork the input names instead of assuming one.
///
/// Values are the reference enum verbatim. Note 0x07 is `StPetersburg`: the
/// enum merged ConstantinopleFix into it, so there is no separate
/// Constantinople index.
///
/// Returns null for any index the enum does not define — a guest cannot
/// execute a fork it has no rules for, and the input must be rejected.
pub fn specFromProtocolFork(index: u8) ?primitives.SpecId {
    return switch (index) {
        0x01 => .frontier,
        0x02 => .homestead,
        0x03 => .dao_fork,
        0x04 => .tangerine, // TangerineWhistle
        0x05 => .spurious_dragon,
        0x06 => .byzantium,
        0x07 => .petersburg, // StPetersburg
        0x08 => .istanbul,
        0x09 => .muir_glacier,
        0x0A => .berlin,
        0x0B => .london,
        0x0C => .arrow_glacier,
        0x0D => .gray_glacier,
        0x0E => .merge, // Paris
        0x0F => .shanghai,
        0x10 => .cancun,
        0x11 => .prague,
        0x12 => .osaka,
        0x13 => .bpo1,
        0x14 => .bpo2,
        0x15 => .amsterdam,
        else => null,
    };
}

// ─── Transition forks ─────────────────────────────────────────────────────────

const TransitionEntry = struct {
    k: []const u8,
    before: primitives.SpecId,
    after: primitives.SpecId,
};

const transition_table = [_]TransitionEntry{
    .{ .k = "ParisToShanghaiAtTime15k", .before = .merge, .after = .shanghai },
    .{ .k = "ShanghaiToCancunAtTime15k", .before = .shanghai, .after = .cancun },
    .{ .k = "CancunToPragueAtTime15k", .before = .cancun, .after = .prague },
    .{ .k = "PragueToOsakaAtTime15k", .before = .prague, .after = .osaka },
    .{ .k = "OsakaToBPO1AtTime15k", .before = .osaka, .after = .bpo1 },
    .{ .k = "BPO1ToBPO2AtTime15k", .before = .bpo1, .after = .bpo2 },
    .{ .k = "BPO2ToAmsterdamAtTime15k", .before = .bpo2, .after = .amsterdam },
};

/// For transition fork names (e.g. "CancunToPragueAtTime15k"), returns the
/// spec active for a block at the given timestamp (transition activates at 15000).
/// For regular fork names, falls back to specFromFork.
pub fn specForBlock(name: []const u8, timestamp: u64) ?primitives.SpecId {
    for (transition_table) |t| {
        if (std.mem.eql(u8, name, t.k)) {
            return if (timestamp >= 15000) t.after else t.before;
        }
    }
    return specFromFork(name);
}

/// Returns the canonical fork name string active for a given network and block timestamp.
/// For transition forks, resolves to the before or after fork name based on the timestamp.
/// For regular fork names, returns the name unchanged.
pub fn activeForkName(name: []const u8, timestamp: u64) []const u8 {
    for (transition_table) |t| {
        if (std.mem.eql(u8, name, t.k)) {
            return if (timestamp >= 15000) specName(t.after) else specName(t.before);
        }
    }
    return name;
}

// ─── Mainnet activation schedule ──────────────────────────────────────────────

/// Return the SpecId for a mainnet block identified by its block number and timestamp.
/// Timestamp-based forks (post-Merge) take priority over block-based ones.
pub fn mainnetSpec(block_number: u64, timestamp: u64) primitives.SpecId {
    // Timestamp-based (post-Merge)
    if (timestamp >= 1_767_747_671) return .bpo2;
    if (timestamp >= 1_765_290_071) return .bpo1;
    if (timestamp >= 1_764_798_551) return .osaka;
    if (timestamp >= 1_746_612_311) return .prague;
    if (timestamp >= 1_710_338_135) return .cancun;
    if (timestamp >= 1_681_338_455) return .shanghai;
    // Block-based (pre-Merge / Merge itself)
    if (block_number >= 15_537_394) return .merge;
    if (block_number >= 15_050_000) return .gray_glacier;
    if (block_number >= 13_773_000) return .arrow_glacier;
    if (block_number >= 12_965_000) return .london;
    if (block_number >= 12_244_000) return .berlin;
    if (block_number >= 9_200_000) return .muir_glacier;
    if (block_number >= 9_069_000) return .istanbul;
    if (block_number >= 7_280_000) return .petersburg;
    if (block_number >= 4_370_000) return .byzantium;
    if (block_number >= 2_675_000) return .spurious_dragon;
    if (block_number >= 2_463_000) return .tangerine;
    if (block_number >= 1_920_000) return .dao_fork;
    if (block_number >= 1_150_000) return .homestead;
    return .frontier;
}

// ─── Block reward ─────────────────────────────────────────────────────────────

/// Mining reward in wei; -1 means disabled (post-Merge).
pub fn blockReward(spec: primitives.SpecId) i64 {
    return switch (spec) {
        .frontier, .frontier_thawing, .homestead, .dao_fork, .tangerine, .spurious_dragon => 5_000_000_000_000_000_000,
        .byzantium => 3_000_000_000_000_000_000,
        .constantinople, .petersburg, .istanbul, .muir_glacier, .berlin, .london, .arrow_glacier, .gray_glacier => 2_000_000_000_000_000_000,
        else => -1, // post-Merge: no block reward
    };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

test "specFromProtocolFork: reference enum values" {
    const t = std.testing;
    try t.expectEqual(primitives.SpecId.frontier, specFromProtocolFork(0x01).?);
    try t.expectEqual(primitives.SpecId.dao_fork, specFromProtocolFork(0x03).?);
    // ProtocolFork merged ConstantinopleFix into StPetersburg — 0x07 is Petersburg,
    // and no index maps to Constantinople.
    try t.expectEqual(primitives.SpecId.petersburg, specFromProtocolFork(0x07).?);
    try t.expectEqual(primitives.SpecId.merge, specFromProtocolFork(0x0E).?); // Paris
    try t.expectEqual(primitives.SpecId.osaka, specFromProtocolFork(0x12).?);
    try t.expectEqual(primitives.SpecId.bpo2, specFromProtocolFork(0x14).?);
    try t.expectEqual(primitives.SpecId.amsterdam, specFromProtocolFork(0x15).?);
}

test "specFromProtocolFork: undefined indices are rejected" {
    const t = std.testing;
    // 0x00 predates the enum; 0x16 is past Amsterdam, the newest fork zesu has
    // rules for. eip8025's invalid_stateless_input_bytes fixture uses 0x1601 and
    // requires the guest to reject it.
    try t.expectEqual(@as(?primitives.SpecId, null), specFromProtocolFork(0x00));
    try t.expectEqual(@as(?primitives.SpecId, null), specFromProtocolFork(0x16));
    try t.expectEqual(@as(?primitives.SpecId, null), specFromProtocolFork(0xFF));
}

test "specFromProtocolFork: every mapped fork survives the name round-trip" {
    // The decoder stores specName(spec) as the input's fork_name, which
    // executeStatelessInput resolves back through specFromFork. A fork whose
    // name is missing from that table would silently fall back to the mainnet
    // schedule, so every index must round-trip.
    for (1..0x16) |i| {
        const spec = specFromProtocolFork(@intCast(i)) orelse return error.MissingFork;
        const name = specName(spec);
        const back = specFromFork(name) orelse {
            std.debug.print("fork index 0x{x:0>2} → \"{s}\" is not in specFromFork\n", .{ i, name });
            return error.NameNotResolvable;
        };
        try std.testing.expectEqual(spec, back);
    }
}
