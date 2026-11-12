/// In-memory chain state for Hive consume-rlp.
///
/// Imports RLP-encoded blocks sequentially from genesis, executes them, and
/// commits a block only if it executes and its withdrawals root, state root,
/// receipts root, BAL hash and requests hash all match the header. Invalid
/// blocks are dropped silently. Provides block lookup by number.
const std = @import("std");
const primitives = @import("primitives");
const executor = @import("executor");
const types = executor.executor_types;
const fork_mod = @import("hardfork");
const tx_decode_mod = executor.executor_tx_decode;
const rlp_dec = @import("mpt").rlp;
const mpt_builder = @import("mpt").builder;
const rlp_enc = executor.executor_rlp_encode;
const ForkSchedule = @import("fork_env.zig").ForkSchedule;

const Address = types.Address;
const Hash = types.Hash;
const AllocMap = std.AutoHashMapUnmanaged(Address, types.AllocAccount);

pub const StoredHeader = struct {
    number: u64,
    hash: Hash,
    coinbase: Address,
    state_root: Hash,
    gas_limit: u64,
    gas_used: u64 = 0,
    timestamp: u64,
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

pub const Chain = struct {
    arena: std.heap.ArenaAllocator,
    current_alloc: AllocMap,
    headers: std.ArrayListUnmanaged(StoredHeader),
    fork: ForkSchedule,

    pub fn init(
        backing: std.mem.Allocator,
        genesis_alloc: AllocMap,
        genesis_header: StoredHeader,
        fork: ForkSchedule,
    ) Chain {
        var c = Chain{
            .arena = std.heap.ArenaAllocator.init(backing),
            .current_alloc = .empty,
            .headers = .empty,
            .fork = fork,
        };
        const alloc = c.arena.allocator();
        c.current_alloc = cloneAllocMap(alloc, genesis_alloc) catch .empty;
        var gh = genesis_header;
        gh.extra_data = alloc.dupe(u8, genesis_header.extra_data) catch &.{};
        c.headers.append(alloc, gh) catch {};
        return c;
    }

    pub fn deinit(self: *Chain) void {
        self.arena.deinit();
    }

    /// Import one RLP-encoded block. Silently discards invalid blocks.
    pub fn importBlock(self: *Chain, block_rlp: []const u8) void {
        const alloc = self.arena.allocator();
        self.importBlockInner(alloc, block_rlp) catch {};
    }

    fn importBlockInner(self: *Chain, alloc: std.mem.Allocator, block_rlp: []const u8) !void {
        // ── Outer block list ──────────────────────────────────────────────────
        const outer = try rlp_dec.decodeItem(block_rlp);
        const block_payload = switch (outer.item) {
            .list => |p| p,
            .bytes => return error.InvalidBlock,
        };

        // ── Header ────────────────────────────────────────────────────────────
        const hdr_r = try rlp_dec.decodeItem(block_payload);
        const hdr_payload = switch (hdr_r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBlock,
        };

        // Block hash = keccak256 of the raw header RLP (including its prefix)
        const block_hash = keccak256(block_payload[0..hdr_r.consumed]);

        const hdr = try decodeHeader(hdr_payload);

        // ── Transactions ──────────────────────────────────────────────────────
        const after_hdr = block_payload[hdr_r.consumed..];
        const raw_txs = try decodeTxList(alloc, after_hdr);
        const txs = try tx_decode_mod.decodeTxs(alloc, raw_txs);

        // ── Withdrawals ───────────────────────────────────────────────────────
        const withdrawals_const = decodeWithdrawals(alloc, after_hdr) catch &.{};
        const withdrawals = @constCast(withdrawals_const);

        // ── Fork / spec ───────────────────────────────────────────────────────
        const spec = self.fork.specAt(hdr.number, hdr.timestamp);
        const reward = fork_mod.blockReward(spec);

        // ── Block-hash table (last 256 ancestors) ──────────────────────────────
        const bh_slice = try buildBlockHashes(alloc, self.headers.items);

        // ── Env ───────────────────────────────────────────────────────────────
        var env = types.Env{};
        env.coinbase = hdr.coinbase;
        env.gas_limit = hdr.gas_limit;
        env.number = hdr.number;
        env.timestamp = hdr.timestamp;
        env.block_hashes = bh_slice;
        env.withdrawals = withdrawals;
        env.parent_hash = hdr.parent_hash; // EIP-2935

        if (primitives.isEnabledIn(spec, .merge)) {
            env.random = hdr.mix_hash;
            env.difficulty = 0;
        } else {
            env.difficulty = hdr.difficulty;
        }
        if (hdr.base_fee) |bf| env.base_fee = @as(u64, @intCast(bf));
        if (hdr.excess_blob_gas) |eg| env.excess_blob_gas = eg;
        if (hdr.blob_gas_used) |bgu| env.blob_gas_used_header = bgu;
        if (hdr.parent_beacon_block_root) |pb| env.parent_beacon_block_root = pb;
        env.block_rlp_size = @intCast(block_rlp.len);
        if (hdr.slot_number) |sn| env.slot_number = sn;

        // ── Parent-derived fields for block validation ────────────────────────
        const parent_hdr = self.headers.items[self.headers.items.len - 1];
        env.parent_timestamp = parent_hdr.timestamp;
        env.parent_gas_limit = parent_hdr.gas_limit;
        env.parent_gas_used = parent_hdr.gas_used;
        if (parent_hdr.base_fee) |pbf| env.parent_base_fee = @as(u64, @intCast(pbf));
        if (parent_hdr.excess_blob_gas) |pebg| env.parent_excess_blob_gas = pebg;
        if (parent_hdr.blob_gas_used) |pbgu| env.parent_blob_gas_used = pbgu;

        // ── Validate withdrawals root (EIP-4895, Shanghai+) ──────────────────
        if (hdr.withdrawals_root) |expected_root| {
            const computed_root = try computeWithdrawalsRoot(alloc, withdrawals);
            if (!std.mem.eql(u8, &computed_root, &expected_root)) return;
        }

        // ── Execute (includes validation, transition, and root computation) ────
        const result = executor.executeBlockFromAlloc(
            alloc,
            self.current_alloc,
            env,
            txs,
            spec,
            self.fork.chain_id,
            reward,
        ) catch return; // any error = invalid block, discard

        // ── Verify roots match header ─────────────────────────────────────────
        if (!std.mem.eql(u8, &result.post_state_root, &hdr.state_root)) return;
        if (!std.mem.eql(u8, &result.receipts_root, &hdr.receipts_root)) return;

        // ── BAL hash (EIP-7928, Amsterdam+) ───────────────────────────────────
        if (hdr.block_access_list_hash) |expected_bal_hash| {
            if (result.bal_hash) |computed_bal_hash| {
                if (!std.mem.eql(u8, &computed_bal_hash, &expected_bal_hash)) return;
            } else return;
        }

        // ── Requests hash (EIP-7685, Prague+) ─────────────────────────────────
        if (hdr.requests_hash) |expected_rh| {
            if (!std.mem.eql(u8, &result.requests_hash, &expected_rh)) return;
        }

        // ── Commit ────────────────────────────────────────────────────────────
        self.current_alloc = result.post_alloc;
        const extra_data_copy = alloc.dupe(u8, hdr.extra_data) catch &.{};
        self.headers.append(alloc, .{
            .number = hdr.number,
            .hash = block_hash,
            .coinbase = hdr.coinbase,
            .state_root = hdr.state_root,
            .gas_limit = hdr.gas_limit,
            .gas_used = hdr.gas_used,
            .timestamp = hdr.timestamp,
            .extra_data = extra_data_copy,
            .base_fee = hdr.base_fee,
            .withdrawals_root = hdr.withdrawals_root,
            .blob_gas_used = hdr.blob_gas_used,
            .excess_blob_gas = hdr.excess_blob_gas,
            .parent_beacon_block_root = hdr.parent_beacon_block_root,
            .requests_hash = hdr.requests_hash,
            .block_access_list_hash = hdr.block_access_list_hash,
            .slot_number = hdr.slot_number,
        }) catch {};
    }

    pub fn getByNumber(self: *const Chain, number: u64) ?StoredHeader {
        var i = self.headers.items.len;
        while (i > 0) {
            i -= 1;
            if (self.headers.items[i].number == number) return self.headers.items[i];
        }
        return null;
    }

    pub fn getLatest(self: *const Chain) ?StoredHeader {
        if (self.headers.items.len == 0) return null;
        return self.headers.items[self.headers.items.len - 1];
    }
};

// ─── Block header decoder ─────────────────────────────────────────────────────

const BlockHeader = struct {
    parent_hash: Hash,
    coinbase: Address,
    state_root: Hash,
    receipts_root: Hash,
    difficulty: u256,
    number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8 = &.{},
    mix_hash: Hash,
    base_fee: ?u256 = null,
    withdrawals_root: ?Hash = null,
    blob_gas_used: ?u64 = null,
    excess_blob_gas: ?u64 = null,
    parent_beacon_block_root: ?Hash = null,
    requests_hash: ?Hash = null,
    block_access_list_hash: ?Hash = null,
    slot_number: ?u64 = null,
};

fn decodeHeader(payload: []const u8) !BlockHeader {
    var hdr = BlockHeader{
        .parent_hash = [_]u8{0} ** 32,
        .coinbase = [_]u8{0} ** 20,
        .state_root = [_]u8{0} ** 32,
        .receipts_root = [_]u8{0} ** 32,
        .difficulty = 0,
        .number = 0,
        .gas_limit = 0,
        .gas_used = 0,
        .timestamp = 0,
        .mix_hash = [_]u8{0} ** 32,
    };
    var rest = payload;
    var idx: usize = 0;
    while (rest.len > 0) : (idx += 1) {
        const r = try rlp_dec.decodeItem(rest);
        const b = switch (r.item) {
            .bytes => |v| v,
            .list => &.{},
        };
        switch (idx) {
            0 => hdr.parent_hash = toHash(b),
            // 1 = uncleHash (skip)
            2 => hdr.coinbase = toAddr(b),
            3 => hdr.state_root = toHash(b),
            // 4 = txsRoot (skip)
            5 => hdr.receipts_root = toHash(b),
            // 6 = logsBloom (skip)
            7 => hdr.difficulty = toU256(b),
            8 => hdr.number = toU64(b),
            9 => hdr.gas_limit = toU64(b),
            10 => hdr.gas_used = toU64(b),
            11 => hdr.timestamp = toU64(b),
            12 => hdr.extra_data = b,
            13 => hdr.mix_hash = toHash(b),
            // 14 = nonce (skip)
            15 => hdr.base_fee = toU256(b),
            16 => hdr.withdrawals_root = toHash(b),
            17 => hdr.blob_gas_used = toU64(b),
            18 => hdr.excess_blob_gas = toU64(b),
            19 => hdr.parent_beacon_block_root = toHash(b),
            20 => hdr.requests_hash = toHash(b),
            21 => hdr.block_access_list_hash = toHash(b),
            22 => hdr.slot_number = toU64(b),
            else => {},
        }
        rest = rest[r.consumed..];
    }
    return hdr;
}

// ─── Block payload helpers ────────────────────────────────────────────────────

/// Extract raw tx byte-slices from the transactions list that follows the header.
fn decodeTxList(alloc: std.mem.Allocator, after_hdr: []const u8) ![]const []const u8 {
    const txns_r = try rlp_dec.decodeItem(after_hdr);
    const txns_payload = switch (txns_r.item) {
        .list => |p| p,
        .bytes => return &.{},
    };
    var count: usize = 0;
    var tmp = txns_payload;
    while (tmp.len > 0) {
        const r = try rlp_dec.decodeItem(tmp);
        count += 1;
        tmp = tmp[r.consumed..];
    }
    const txns = try alloc.alloc([]const u8, count);
    var offset: usize = 0;
    for (0..count) |i| {
        const r = try rlp_dec.decodeItem(txns_payload[offset..]);
        txns[i] = switch (r.item) {
            .bytes => |bv| bv,
            .list => txns_payload[offset .. offset + r.consumed],
        };
        offset += r.consumed;
    }
    return txns;
}

/// Decode withdrawals from block outer payload after header.
/// Layout: [txns_list, uncles_list, ?withdrawals_list]
fn decodeWithdrawals(alloc: std.mem.Allocator, after_hdr: []const u8) ![]types.Withdrawal {
    const txns_r = try rlp_dec.decodeItem(after_hdr);
    const uncles_r = try rlp_dec.decodeItem(after_hdr[txns_r.consumed..]);
    const after_uncles = after_hdr[txns_r.consumed + uncles_r.consumed ..];
    if (after_uncles.len == 0) return &.{};

    const wd_r = try rlp_dec.decodeItem(after_uncles);
    const wd_payload = switch (wd_r.item) {
        .list => |p| p,
        .bytes => return &.{},
    };

    var wds = std.ArrayListUnmanaged(types.Withdrawal).empty;
    var rest = wd_payload;
    while (rest.len > 0) {
        const wd_item = try rlp_dec.decodeItem(rest);
        const wd_p = switch (wd_item.item) {
            .list => |p| p,
            .bytes => {
                rest = rest[wd_item.consumed..];
                continue;
            },
        };
        var fields: [4][]const u8 = .{ &.{}, &.{}, &.{}, &.{} };
        var fi: usize = 0;
        var wr = wd_p;
        while (wr.len > 0 and fi < 4) {
            const fr = try rlp_dec.decodeItem(wr);
            fields[fi] = switch (fr.item) {
                .bytes => |bv| bv,
                .list => &.{},
            };
            fi += 1;
            wr = wr[fr.consumed..];
        }
        try wds.append(alloc, types.Withdrawal{
            .index = toU64(fields[0]),
            .validator_index = toU64(fields[1]),
            .address = toAddr(fields[2]),
            .amount = toU64(fields[3]),
        });
        rest = rest[wd_item.consumed..];
    }
    return wds.toOwnedSlice(alloc);
}

fn buildBlockHashes(alloc: std.mem.Allocator, headers: []const StoredHeader) ![]types.BlockHashEntry {
    const n = headers.len;
    const start = if (n > 256) n - 256 else 0;
    const out = try alloc.alloc(types.BlockHashEntry, n - start);
    for (0..n - start) |i|
        out[i] = .{ .number = headers[start + i].number, .hash = headers[start + i].hash };
    return out;
}

fn cloneAllocMap(arena: std.mem.Allocator, src: AllocMap) !AllocMap {
    var dst = AllocMap{};
    var it = src.iterator();
    while (it.next()) |entry| {
        var acct = entry.value_ptr.*;
        acct.code = try arena.dupe(u8, acct.code);
        var new_storage = std.AutoHashMapUnmanaged(u256, u256).empty;
        var sit = acct.storage.iterator();
        while (sit.next()) |se|
            try new_storage.put(arena, se.key_ptr.*, se.value_ptr.*);
        acct.storage = new_storage;
        try dst.put(arena, entry.key_ptr.*, acct);
    }
    return dst;
}

// ─── Withdrawals root ─────────────────────────────────────────────────────────

fn computeWithdrawalsRoot(alloc: std.mem.Allocator, withdrawals: []types.Withdrawal) ![32]u8 {
    if (withdrawals.len == 0) return mpt_builder.EMPTY_TRIE_HASH;
    const items = try alloc.alloc(mpt_builder.KV, withdrawals.len);
    for (withdrawals, 0..) |wd, i| {
        items[i].key = try rlp_enc.encodeU64(alloc, i);
        const fields = [_][]const u8{
            try rlp_enc.encodeU64(alloc, wd.index),
            try rlp_enc.encodeU64(alloc, wd.validator_index),
            try rlp_enc.encodeBytes(alloc, &wd.address),
            try rlp_enc.encodeU64(alloc, wd.amount),
        };
        items[i].value = try rlp_enc.encodeList(alloc, &fields);
    }
    return mpt_builder.trieRoot(alloc, items);
}

// ─── Primitive helpers ────────────────────────────────────────────────────────

fn keccak256(data: []const u8) Hash {
    var h: Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(data, &h, .{});
    return h;
}

fn toU64(b: []const u8) u64 {
    var v: u64 = 0;
    for (b) |byte| v = (v << 8) | byte;
    return v;
}

fn toU256(b: []const u8) u256 {
    var v: u256 = 0;
    for (b) |byte| v = (v << 8) | byte;
    return v;
}

fn toHash(b: []const u8) Hash {
    var h: Hash = [_]u8{0} ** 32;
    if (b.len <= 32) @memcpy(h[32 - b.len ..], b);
    return h;
}

fn toAddr(b: []const u8) Address {
    var a: Address = [_]u8{0} ** 20;
    if (b.len <= 20) @memcpy(a[20 - b.len ..], b);
    return a;
}
