/// Parse /genesis.json (geth format) → AllocMap + computed genesis block hash.
const std = @import("std");
const primitives = @import("primitives");
const executor = @import("executor");
const types = executor.executor_types;
const rlp = executor.executor_rlp_encode;
const output = executor.executor_output;

pub const Address = types.Address;
pub const Hash = types.Hash;
pub const AllocMap = std.AutoHashMapUnmanaged(Address, types.AllocAccount);

// keccak256(RLP([])) — the "empty uncle" hash
const EMPTY_UNCLE_HASH: Hash = .{
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a,
    0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc, 0xd4, 0x1a,
    0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13,
    0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
};

// keccak256 of the empty MPT trie
const EMPTY_TRIE_HASH: Hash = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};

pub const GenesisResult = struct {
    alloc: AllocMap,
    hash: Hash,
    timestamp: u64,
    coinbase: Address,
    state_root: Hash,
    gas_limit: u64,
    extra_data: []const u8,
    base_fee: ?u256 = null,
    withdrawals_root: ?Hash = null,
    blob_gas_used: ?u64 = null,
    excess_blob_gas: ?u64 = null,
    parent_beacon_block_root: ?Hash = null,
    requests_hash: ?Hash = null,
    block_access_list_hash: ?Hash = null,
    slot_number: ?u64 = null,
};

/// All fields needed to RLP-encode a block header and compute its hash.
/// Used by both genesis and chain (for imported blocks).
pub const HeaderFields = struct {
    parent_hash: Hash,
    uncle_hash: Hash,
    coinbase: Address,
    state_root: Hash,
    txs_root: Hash,
    receipts_root: Hash,
    logs_bloom: [256]u8,
    difficulty: u256,
    number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8,
    mix_hash: Hash,
    nonce: [8]u8,
    // optional post-London fields
    base_fee: ?u256 = null,
    withdrawals_root: ?Hash = null,
    blob_gas_used: ?u64 = null,
    excess_blob_gas: ?u64 = null,
    parent_beacon_block_root: ?Hash = null,
    requests_hash: ?Hash = null,
    // Amsterdam fields
    block_access_list_hash: ?Hash = null,
    slot_number: ?u64 = null,
};

/// Encode header fields as an RLP list and return keccak256 of the encoding.
pub fn computeBlockHash(arena: std.mem.Allocator, h: HeaderFields) !Hash {
    var fields = std.ArrayListUnmanaged([]const u8).empty;
    try fields.append(arena, try rlp.encodeBytes(arena, &h.parent_hash));
    try fields.append(arena, try rlp.encodeBytes(arena, &h.uncle_hash));
    try fields.append(arena, try rlp.encodeBytes(arena, &h.coinbase));
    try fields.append(arena, try rlp.encodeBytes(arena, &h.state_root));
    try fields.append(arena, try rlp.encodeBytes(arena, &h.txs_root));
    try fields.append(arena, try rlp.encodeBytes(arena, &h.receipts_root));
    try fields.append(arena, try rlp.encodeBytes(arena, &h.logs_bloom));
    try fields.append(arena, try rlp.encodeU256(arena, h.difficulty));
    try fields.append(arena, try rlp.encodeU64(arena, h.number));
    try fields.append(arena, try rlp.encodeU64(arena, h.gas_limit));
    try fields.append(arena, try rlp.encodeU64(arena, h.gas_used));
    try fields.append(arena, try rlp.encodeU64(arena, h.timestamp));
    try fields.append(arena, try rlp.encodeBytes(arena, h.extra_data));
    try fields.append(arena, try rlp.encodeBytes(arena, &h.mix_hash));
    try fields.append(arena, try rlp.encodeBytes(arena, &h.nonce));
    if (h.base_fee) |bf|
        try fields.append(arena, try rlp.encodeU256(arena, bf));
    if (h.withdrawals_root) |wr|
        try fields.append(arena, try rlp.encodeBytes(arena, &wr));
    if (h.blob_gas_used) |bg|
        try fields.append(arena, try rlp.encodeU64(arena, bg));
    if (h.excess_blob_gas) |eg|
        try fields.append(arena, try rlp.encodeU64(arena, eg));
    if (h.parent_beacon_block_root) |pb|
        try fields.append(arena, try rlp.encodeBytes(arena, &pb));
    if (h.requests_hash) |rh|
        try fields.append(arena, try rlp.encodeBytes(arena, &rh));
    if (h.block_access_list_hash) |bh|
        try fields.append(arena, try rlp.encodeBytes(arena, &bh));
    if (h.slot_number) |sn|
        try fields.append(arena, try rlp.encodeU64(arena, sn));
    const encoded = try rlp.encodeList(arena, fields.items);
    return rlp.keccak256(encoded);
}

/// Parse /genesis.json, compute stateRoot and genesis block hash.
pub fn parse(
    arena: std.mem.Allocator,
    json_text: []const u8,
    spec: primitives.SpecId,
) !GenesisResult {
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        arena,
        json_text,
        .{ .duplicate_field_behavior = .use_last },
    );
    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidGenesis,
    };

    // ── Header fields ─────────────────────────────────────────────────────────
    const timestamp = jsonU64(root.get("timestamp") orelse .{ .integer = 0 }) catch 0;
    const gas_limit = jsonU64(root.get("gasLimit") orelse .{ .integer = 0x1388 }) catch 0x1388;
    const difficulty = jsonU256(root.get("difficulty") orelse .{ .integer = 0 }) catch 0;
    const coinbase = hexToAddr(strVal(root, "coinbase") orelse
        "0x0000000000000000000000000000000000000000") catch @as([20]u8, @splat(0));
    const extra_data = hexToSlice(arena, strVal(root, "extraData") orelse "0x") catch &.{};
    const mix_hash = hexToHash(strVal(root, "mixHash") orelse
        "0x0000000000000000000000000000000000000000000000000000000000000000") catch @as([32]u8, @splat(0));

    // nonce: always 8 bytes big-endian
    const nonce_val = jsonU64(root.get("nonce") orelse .{ .integer = 0 }) catch 0;
    var nonce_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &nonce_bytes, nonce_val, .big);

    // London+: baseFeePerGas
    const base_fee: ?u256 = if (primitives.isEnabledIn(spec, .london)) blk: {
        break :blk jsonU256(root.get("baseFeePerGas") orelse .{ .integer = 0 }) catch 0;
    } else null;

    // Shanghai+: withdrawalsRoot
    const withdrawals_root: ?Hash = if (primitives.isEnabledIn(spec, .shanghai)) blk: {
        const v = root.get("withdrawalsRoot") orelse break :blk EMPTY_TRIE_HASH;
        break :blk hexToHash(switch (v) {
            .string => |s| s,
            else => break :blk EMPTY_TRIE_HASH,
        }) catch EMPTY_TRIE_HASH;
    } else null;

    // Cancun+: blobGasUsed, excessBlobGas, parentBeaconBlockRoot
    const blob_gas_used: ?u64 = if (primitives.isEnabledIn(spec, .cancun))
        jsonU64(root.get("blobGasUsed") orelse .{ .integer = 0 }) catch 0
    else
        null;
    const excess_blob_gas: ?u64 = if (primitives.isEnabledIn(spec, .cancun))
        jsonU64(root.get("excessBlobGas") orelse .{ .integer = 0 }) catch 0
    else
        null;
    const parent_beacon_block_root: ?Hash = if (primitives.isEnabledIn(spec, .cancun)) blk: {
        const v = root.get("parentBeaconBlockRoot") orelse break :blk @as([32]u8, @splat(0));
        break :blk hexToHash(switch (v) {
            .string => |s| s,
            else => break :blk @as([32]u8, @splat(0)),
        }) catch @as([32]u8, @splat(0));
    } else null;

    // Prague+: requestsHash
    const requests_hash: ?Hash = if (primitives.isEnabledIn(spec, .prague)) blk: {
        const v = root.get("requestsHash") orelse break :blk null;
        break :blk hexToHash(switch (v) {
            .string => |s| s,
            else => break :blk null,
        }) catch null;
    } else null;

    // Amsterdam+: blockAccessListHash, slotNumber
    const block_access_list_hash: ?Hash = if (primitives.isEnabledIn(spec, .amsterdam)) blk: {
        const v = root.get("blockAccessListHash") orelse break :blk null;
        break :blk hexToHash(switch (v) {
            .string => |s| s,
            else => break :blk null,
        }) catch null;
    } else null;
    const slot_number: ?u64 = if (primitives.isEnabledIn(spec, .amsterdam))
        jsonU64(root.get("slotNumber") orelse .{ .integer = 0 }) catch 0
    else
        null;

    // ── Parse alloc ───────────────────────────────────────────────────────────
    const alloc_map = try parseAlloc(
        arena,
        root.get("alloc") orelse std.json.Value{ .object = std.json.ObjectMap.empty },
    );

    // ── Compute stateRoot from alloc ──────────────────────────────────────────
    const state_root = try output.computeStateRoot(arena, alloc_map, &.{});

    // ── Compute genesis block hash ────────────────────────────────────────────
    const genesis_hash = try computeBlockHash(arena, .{
        .parent_hash = @splat(0),
        .uncle_hash = EMPTY_UNCLE_HASH,
        .coinbase = coinbase,
        .state_root = state_root,
        .txs_root = EMPTY_TRIE_HASH,
        .receipts_root = EMPTY_TRIE_HASH,
        .logs_bloom = @splat(0),
        .difficulty = difficulty,
        .number = 0,
        .gas_limit = gas_limit,
        .gas_used = 0,
        .timestamp = timestamp,
        .extra_data = extra_data,
        .mix_hash = mix_hash,
        .nonce = nonce_bytes,
        .base_fee = base_fee,
        .withdrawals_root = withdrawals_root,
        .blob_gas_used = blob_gas_used,
        .excess_blob_gas = excess_blob_gas,
        .parent_beacon_block_root = parent_beacon_block_root,
        .requests_hash = requests_hash,
        .block_access_list_hash = block_access_list_hash,
        .slot_number = slot_number,
    });

    return GenesisResult{
        .alloc = alloc_map,
        .hash = genesis_hash,
        .timestamp = timestamp,
        .coinbase = coinbase,
        .state_root = state_root,
        .gas_limit = gas_limit,
        .extra_data = extra_data,
        .base_fee = base_fee,
        .withdrawals_root = withdrawals_root,
        .blob_gas_used = blob_gas_used,
        .excess_blob_gas = excess_blob_gas,
        .parent_beacon_block_root = parent_beacon_block_root,
        .requests_hash = requests_hash,
        .block_access_list_hash = block_access_list_hash,
        .slot_number = slot_number,
    };
}

// ─── Alloc parser ─────────────────────────────────────────────────────────────

fn parseAlloc(arena: std.mem.Allocator, val: std.json.Value) !AllocMap {
    var map = AllocMap{};
    const obj = switch (val) {
        .object => |o| o,
        else => return map,
    };
    var it = obj.iterator();
    while (it.next()) |entry| {
        const addr = hexToAddr(entry.key_ptr.*) catch continue;
        const acct_obj = switch (entry.value_ptr.*) {
            .object => |o| o,
            else => continue,
        };
        var acct = types.AllocAccount{};
        if (acct_obj.get("balance")) |v| acct.balance = jsonU256(v) catch 0;
        if (acct_obj.get("nonce")) |v| acct.nonce = jsonU64(v) catch 0;
        if (acct_obj.get("code")) |v| {
            const s = switch (v) {
                .string => |s| s,
                else => "",
            };
            acct.code = hexToSlice(arena, s) catch &.{};
        }
        if (acct_obj.get("storage")) |sv| {
            if (sv == .object) {
                var sit = sv.object.iterator();
                while (sit.next()) |skv| {
                    const key = hexToU256(skv.key_ptr.*) catch continue;
                    const sval = jsonU256(skv.value_ptr.*) catch continue;
                    if (sval != 0) try acct.storage.put(arena, key, sval);
                }
            }
        }
        try map.put(arena, addr, acct);
    }
    return map;
}

// ─── JSON / hex helpers ───────────────────────────────────────────────────────

fn strVal(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn stripHex(s: []const u8) []const u8 {
    if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) return s[2..];
    return s;
}

fn hexToSlice(arena: std.mem.Allocator, hex: []const u8) ![]u8 {
    const s = stripHex(hex);
    if (s.len == 0) return arena.dupe(u8, &.{});
    if (s.len % 2 != 0) return error.OddHexLength;
    const out = try arena.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn hexToAddr(hex: []const u8) ![20]u8 {
    const s = stripHex(hex);
    var padded: [40]u8 = @splat('0');
    if (s.len > 40) return error.InvalidAddress;
    @memcpy(padded[40 - s.len ..], s);
    var out: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, &padded);
    return out;
}

fn hexToHash(hex: []const u8) ![32]u8 {
    const s = stripHex(hex);
    var padded: [64]u8 = @splat('0');
    if (s.len > 64) return error.InvalidHash;
    @memcpy(padded[64 - s.len ..], s);
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, &padded);
    return out;
}

fn hexToU256(hex: []const u8) !u256 {
    const s = stripHex(hex);
    if (s.len == 0) return 0;
    return std.fmt.parseInt(u256, s, 16);
}

fn jsonU64(v: std.json.Value) !u64 {
    return switch (v) {
        .integer => |n| @intCast(n),
        .string => |s| std.fmt.parseInt(u64, stripHex(s), 16) catch
            std.fmt.parseInt(u64, s, 10),
        else => error.InvalidNumeric,
    };
}

fn jsonU256(v: std.json.Value) !u256 {
    return switch (v) {
        .integer => |n| @intCast(n),
        .string => |s| std.fmt.parseInt(u256, stripHex(s), 16) catch
            std.fmt.parseInt(u256, s, 10),
        else => error.InvalidNumeric,
    };
}
