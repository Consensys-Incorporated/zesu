//! Integration tests for WitnessDatabase.
//!
//! Proof vectors are built synthetically using the same RLP construction
//! helpers as the MPT tests.  Each test wires up a minimal StateWitness
//! (flat node pool), initialises a WitnessDatabase and then exercises one
//! interface method.

const std = @import("std");
const primitives = @import("primitives");
const state_mod = @import("state");
const bytecode = @import("bytecode");
const mpt = @import("mpt");
const input = @import("input");
const db_mod = @import("db");

// ─── Known constants ───────────────────────────────────────────────────────────

const KECCAK_EMPTY: primitives.Hash = .{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
};

const EMPTY_TRIE_HASH: primitives.Hash = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};

// ─── Minimal RLP encoder (test-local) ─────────────────────────────────────────

fn encBytes(buf: []u8, off: usize, data: []const u8) usize {
    var o = off;
    if (data.len == 0) {
        buf[o] = 0x80;
        return o + 1;
    } else if (data.len == 1 and data[0] <= 0x7f) {
        buf[o] = data[0];
        return o + 1;
    } else if (data.len <= 55) {
        buf[o] = @intCast(0x80 + data.len);
        o += 1;
        @memcpy(buf[o..][0..data.len], data);
        return o + data.len;
    } else {
        std.debug.assert(data.len <= 255);
        buf[o] = 0xb8;
        buf[o + 1] = @intCast(data.len);
        o += 2;
        @memcpy(buf[o..][0..data.len], data);
        return o + data.len;
    }
}

fn encList(buf: []u8, off: usize, payload: []const u8) usize {
    var o = off;
    if (payload.len <= 55) {
        buf[o] = @intCast(0xc0 + payload.len);
        o += 1;
    } else {
        std.debug.assert(payload.len <= 255);
        buf[o] = 0xf8;
        buf[o + 1] = @intCast(payload.len);
        o += 2;
    }
    @memcpy(buf[o..][0..payload.len], payload);
    return o + payload.len;
}

fn buildAccountRlp(
    buf: []u8,
    nonce: u64,
    balance: u256,
    storage_root: primitives.Hash,
    code_hash: primitives.Hash,
) usize {
    var payload: [200]u8 = undefined;
    var pl: usize = 0;
    // nonce
    if (nonce == 0) {
        payload[pl] = 0x80;
        pl += 1;
    } else {
        var tmp: [8]u8 = undefined;
        var n = nonce;
        var nb: usize = 0;
        while (n > 0) : (nb += 1) {
            tmp[7 - nb] = @intCast(n & 0xff);
            n >>= 8;
        }
        pl = encBytes(&payload, pl, tmp[8 - nb ..]);
    }
    // balance
    if (balance == 0) {
        payload[pl] = 0x80;
        pl += 1;
    } else {
        var tmp: [32]u8 = undefined;
        var b = balance;
        var nb: usize = 0;
        while (b > 0) : (nb += 1) {
            tmp[31 - nb] = @intCast(b & 0xff);
            b >>= 8;
        }
        pl = encBytes(&payload, pl, tmp[32 - nb ..]);
    }
    // storageRoot
    payload[pl] = 0xa0;
    pl += 1;
    @memcpy(payload[pl..][0..32], &storage_root);
    pl += 32;
    // codeHash
    payload[pl] = 0xa0;
    pl += 1;
    @memcpy(payload[pl..][0..32], &code_hash);
    pl += 32;
    return encList(buf, 0, payload[0..pl]);
}

fn buildLeafNode(buf: []u8, key_hash: primitives.Hash, value: []const u8) usize {
    var hp_key: [33]u8 = undefined;
    hp_key[0] = 0x20;
    @memcpy(hp_key[1..33], &key_hash);
    var payload: [512]u8 = undefined;
    var pl: usize = 0;
    pl = encBytes(&payload, pl, &hp_key);
    pl = encBytes(&payload, pl, value);
    return encList(buf, 0, payload[0..pl]);
}

fn buildEmptyBranchNode(buf: []u8) usize {
    buf[0] = 0xd1;
    @memset(buf[1..18], 0x80);
    return 18;
}

// ─── Helper ───────────────────────────────────────────────────────────────────

const ALLOC = std.testing.allocator;

/// Build a NodeIndex from a StateWitness and construct a WitnessDatabase.
/// Caller must call `index.deinit()` when done.
fn makeWdb(w: input.StateWitness, index: *mpt.NodeIndex) !db_mod.WitnessDatabase {
    index.* = try mpt.buildNodeIndex(ALLOC, w.nodes);
    return try db_mod.WitnessDatabase.init(ALLOC, index, w.state_root, w.codes, &.{});
}

// ─── Test 1: basic — account found in pool ────────────────────────────────────

test "basic returns verified AccountInfo" {
    var address: primitives.Address = @splat(0x00);
    address[19] = 0x11;
    const key_hash = mpt.keccak256(&address);

    var account_rlp: [200]u8 = undefined;
    const account_len = buildAccountRlp(&account_rlp, 7, 2000, EMPTY_TRIE_HASH, KECCAK_EMPTY);

    var leaf_node: [512]u8 = undefined;
    const leaf_len = buildLeafNode(&leaf_node, key_hash, account_rlp[0..account_len]);
    const leaf_bytes = leaf_node[0..leaf_len];
    const state_root = mpt.keccak256(leaf_bytes);

    const w = input.StateWitness{
        .state_root = state_root,
        .nodes = &[_][]const u8{leaf_bytes},
        .codes = &.{},
        .keys = &.{},
        .headers = &.{},
    };
    var idx: mpt.NodeIndex = undefined;
    var wdb = try makeWdb(w, &idx);
    defer idx.deinit();
    defer wdb.deinit();
    const info = try wdb.basic(address);
    try std.testing.expect(info != null);
    try std.testing.expectEqual(@as(u64, 7), info.?.nonce);
    try std.testing.expectEqual(@as(u256, 2000), info.?.balance);
    try std.testing.expectEqualSlices(u8, &KECCAK_EMPTY, &info.?.code_hash);
}

// ─── Test 2: basic — non-inclusion via empty branch root ──────────────────────

test "basic returns null for valid non-inclusion proof (empty trie)" {
    var address: primitives.Address = @splat(0x00);
    address[19] = 0x22;

    var branch: [18]u8 = undefined;
    const branch_len = buildEmptyBranchNode(&branch);
    const state_root = mpt.keccak256(branch[0..branch_len]);

    const w = input.StateWitness{
        .state_root = state_root,
        .nodes = &[_][]const u8{branch[0..branch_len]},
        .codes = &.{},
        .keys = &.{},
        .headers = &.{},
    };
    var idx: mpt.NodeIndex = undefined;
    var wdb = try makeWdb(w, &idx);
    defer idx.deinit();
    defer wdb.deinit();
    const info = try wdb.basic(address);
    try std.testing.expect(info == null);
}

// ─── Test 3: basic — non-inclusion via leaf suffix mismatch ───────────────────
//
// The trie contains addr1; we query addr2.  verifyProof decodes the leaf,
// finds the suffix does not match addr2's key nibbles, and returns null.

test "basic returns null when queried address differs from trie leaf" {
    var addr1: primitives.Address = @splat(0x00);
    addr1[19] = 0x01;
    var addr2: primitives.Address = @splat(0x00);
    addr2[19] = 0x02;

    const key_hash1 = mpt.keccak256(&addr1);
    var account_rlp: [200]u8 = undefined;
    const account_len = buildAccountRlp(&account_rlp, 1, 0, EMPTY_TRIE_HASH, KECCAK_EMPTY);
    var leaf_node: [512]u8 = undefined;
    const leaf_len = buildLeafNode(&leaf_node, key_hash1, account_rlp[0..account_len]);
    const leaf_bytes = leaf_node[0..leaf_len];
    const state_root = mpt.keccak256(leaf_bytes);

    const w = input.StateWitness{
        .state_root = state_root,
        .nodes = &[_][]const u8{leaf_bytes},
        .codes = &.{},
        .keys = &.{},
        .headers = &.{},
    };
    var idx: mpt.NodeIndex = undefined;
    var wdb = try makeWdb(w, &idx);
    defer idx.deinit();
    defer wdb.deinit();
    const info = try wdb.basic(addr2);
    try std.testing.expect(info == null);
}

// ─── Test 4: codeByHash — KECCAK_EMPTY fast path ──────────────────────────────

test "codeByHash(KECCAK_EMPTY) returns empty Bytecode" {
    const w = input.StateWitness{
        .state_root = [_]u8{0} ** 32,
        .nodes = &.{},
        .codes = &.{},
        .keys = &.{},
        .headers = &.{},
    };
    var idx: mpt.NodeIndex = undefined;
    var wdb = try makeWdb(w, &idx);
    defer idx.deinit();
    defer wdb.deinit();
    const code = try wdb.codeByHash(KECCAK_EMPTY);
    try std.testing.expect(code.isEmpty());
}

// ─── Test 5: codeByHash — contract code found in witness.codes ────────────────

test "codeByHash returns contract bytecode from witness.codes" {
    const contract_code = &[_]u8{ 0x60, 0x00, 0x56 }; // PUSH1 0x00 JUMP
    const code_hash = mpt.keccak256(contract_code);

    const w = input.StateWitness{
        .state_root = [_]u8{0} ** 32,
        .nodes = &.{},
        .codes = &[_][]const u8{contract_code},
        .keys = &.{},
        .headers = &.{},
    };
    var idx: mpt.NodeIndex = undefined;
    var wdb = try makeWdb(w, &idx);
    defer idx.deinit();
    defer wdb.deinit();
    const code = try wdb.codeByHash(code_hash);
    try std.testing.expect(!code.isEmpty());
    try std.testing.expectEqualSlices(u8, contract_code, code.bytes());
}

// ─── Test 6: storage — slot value found (flat pool) ───────────────────────────
//
// Both the account leaf and the storage leaf go into the same flat node pool.
// WitnessDatabase.storage() resolves the account trie then the storage trie
// using the same pool for both traversals.

test "storage returns verified slot value" {
    var address: primitives.Address = @splat(0x00);
    address[19] = 0x55;
    const slot_key: u256 = 3;

    // Storage leaf: slot 3 → 0xabcd.
    var slot_hash: primitives.Hash = @splat(0);
    {
        var n = slot_key;
        var si: usize = 32;
        while (si > 0) {
            si -= 1;
            slot_hash[si] = @intCast(n & 0xff);
            n >>= 8;
        }
    }
    const storage_key_hash = mpt.keccak256(&slot_hash);
    const rlp_value = &[_]u8{ 0x82, 0xab, 0xcd };
    var storage_leaf: [256]u8 = undefined;
    const storage_leaf_len = buildLeafNode(&storage_leaf, storage_key_hash, rlp_value);
    const storage_leaf_bytes = storage_leaf[0..storage_leaf_len];
    const storage_root = mpt.keccak256(storage_leaf_bytes);

    // Account leaf: account with storage_root above.
    const acc_key_hash = mpt.keccak256(&address);
    var account_rlp: [200]u8 = undefined;
    const account_len = buildAccountRlp(&account_rlp, 0, 0, storage_root, KECCAK_EMPTY);
    var acc_leaf: [512]u8 = undefined;
    const acc_leaf_len = buildLeafNode(&acc_leaf, acc_key_hash, account_rlp[0..account_len]);
    const acc_leaf_bytes = acc_leaf[0..acc_leaf_len];
    const state_root = mpt.keccak256(acc_leaf_bytes);

    // Flat pool contains both leaves.
    const w = input.StateWitness{
        .state_root = state_root,
        .nodes = &[_][]const u8{ acc_leaf_bytes, storage_leaf_bytes },
        .codes = &.{},
        .keys = &.{},
        .headers = &.{},
    };
    var idx: mpt.NodeIndex = undefined;
    var wdb = try makeWdb(w, &idx);
    defer idx.deinit();
    defer wdb.deinit();
    const value = try wdb.storage(address, slot_key);
    try std.testing.expectEqual(@as(u256, 0xabcd), value);
}

// ─── Test 7: storage — EMPTY_TRIE_HASH storage root returns 0 ─────────────────
//
// When an account's storage root is the well-known empty trie hash,
// verifyProof short-circuits to null without requiring any pool nodes.

test "storage returns 0 for account with empty storage trie" {
    var address: primitives.Address = @splat(0x00);
    address[19] = 0x66;
    const key_hash = mpt.keccak256(&address);

    var account_rlp: [200]u8 = undefined;
    const account_len = buildAccountRlp(&account_rlp, 0, 0, EMPTY_TRIE_HASH, KECCAK_EMPTY);
    var leaf_node: [512]u8 = undefined;
    const leaf_len = buildLeafNode(&leaf_node, key_hash, account_rlp[0..account_len]);
    const leaf_bytes = leaf_node[0..leaf_len];
    const state_root = mpt.keccak256(leaf_bytes);

    // Pool contains only the account leaf; no storage nodes needed.
    const w = input.StateWitness{
        .state_root = state_root,
        .nodes = &[_][]const u8{leaf_bytes},
        .codes = &.{},
        .keys = &.{},
        .headers = &.{},
    };
    var idx: mpt.NodeIndex = undefined;
    var wdb = try makeWdb(w, &idx);
    defer idx.deinit();
    defer wdb.deinit();
    const value = try wdb.storage(address, 42);
    try std.testing.expectEqual(@as(u256, 0), value);
}

// ─── Test 8: blockHash — returns zero hash ─────────────────────────────────────

test "blockHash returns InvalidWitness for missing hash" {
    const w = input.StateWitness{
        .state_root = [_]u8{0} ** 32,
        .nodes = &.{},
        .codes = &.{},
        .keys = &.{},
        .headers = &.{},
    };
    var idx: mpt.NodeIndex = undefined;
    var wdb = try makeWdb(w, &idx);
    defer idx.deinit();
    defer wdb.deinit();
    try std.testing.expectError(error.InvalidWitness, wdb.blockHash(12345678));
}
