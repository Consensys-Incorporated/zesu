//! Tests for the MPT module.
//!
//! Integration tests (first half) drive the public API with synthetic vectors built
//! using the same RLP rules the verifier decodes; the flat node pool replaces the old
//! ordered-proof-array: put the node(s) in a slice and the verifier finds them by hash.
//!
//! Internal tests (second half) exercise the private update functions through
//! `mpt.testing`, which re-exports them for this file.

const std = @import("std");
const primitives = @import("primitives");
const input = @import("input");

const mpt = @import("./main.zig");
const builder = mpt.builder;
const nibbles = @import("./nibbles.zig");

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

// ─── Minimal RLP encoder (test-local, allocation-free) ────────────────────────

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
    payload[pl] = 0xa0;
    pl += 1;
    @memcpy(payload[pl..][0..32], &storage_root);
    pl += 32;
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

// ─── Test 1: account inclusion — single-leaf pool ─────────────────────────────

test "verifyAccount inclusion — single-leaf pool" {
    var address: primitives.Address = @splat(0x00);
    address[19] = 0x02;
    const key_hash = mpt.keccak256(&address);

    var account_rlp: [200]u8 = undefined;
    const account_len = buildAccountRlp(&account_rlp, 5, 1000, EMPTY_TRIE_HASH, KECCAK_EMPTY);

    var leaf_node: [512]u8 = undefined;
    const leaf_len = buildLeafNode(&leaf_node, key_hash, account_rlp[0..account_len]);
    const leaf_bytes = leaf_node[0..leaf_len];
    const root = mpt.keccak256(leaf_bytes);

    // Pool contains just the one leaf node.
    const pool = &[_][]const u8{leaf_bytes};
    const result = try mpt.verifyAccount(root, address, pool);

    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u64, 5), result.?.nonce);
    try std.testing.expectEqual(@as(u256, 1000), result.?.balance);
    try std.testing.expectEqualSlices(u8, &KECCAK_EMPTY, &result.?.code_hash);
}

// ─── Test 2: storage inclusion — single-leaf pool ─────────────────────────────

test "verifyStorage inclusion — single-leaf pool" {
    var slot: primitives.Hash = @splat(0x00);
    slot[31] = 0x01;
    const key_hash = mpt.keccak256(&slot);

    const rlp_value = &[_]u8{ 0x84, 0xde, 0xad, 0xbe, 0xef };

    var leaf_node: [256]u8 = undefined;
    const leaf_len = buildLeafNode(&leaf_node, key_hash, rlp_value);
    const leaf_bytes = leaf_node[0..leaf_len];
    const storage_root = mpt.keccak256(leaf_bytes);

    const pool = &[_][]const u8{leaf_bytes};
    const value = try mpt.verifyStorage(storage_root, slot, pool);
    try std.testing.expectEqual(@as(u256, 0xdeadbeef), value);
}

// ─── Test 3: account non-inclusion — empty branch root ────────────────────────

test "verifyAccount non-inclusion — empty branch root" {
    var branch: [18]u8 = undefined;
    const branch_len = buildEmptyBranchNode(&branch);
    const root = mpt.keccak256(branch[0..branch_len]);

    var address: primitives.Address = @splat(0x00);
    address[0] = 0xab;

    const pool = &[_][]const u8{branch[0..branch_len]};
    const result = try mpt.verifyAccount(root, address, pool);
    try std.testing.expect(result == null);
}

// ─── Test 4: storage non-inclusion — empty branch root ────────────────────────

test "verifyStorage non-inclusion — empty branch root" {
    var branch: [18]u8 = undefined;
    const branch_len = buildEmptyBranchNode(&branch);
    const storage_root = mpt.keccak256(branch[0..branch_len]);

    var slot: primitives.Hash = @splat(0x00);
    slot[31] = 0x99;

    const pool = &[_][]const u8{branch[0..branch_len]};
    const value = try mpt.verifyStorage(storage_root, slot, pool);
    try std.testing.expectEqual(@as(u256, 0), value);
}

// ─── Test 5: tampered node — InvalidProof ─────────────────────────────────────

test "verifyProof tampered node — returns InvalidProof" {
    var slot: primitives.Hash = @splat(0x00);
    slot[31] = 0x07;
    const key_hash = mpt.keccak256(&slot);

    var leaf_node: [256]u8 = undefined;
    const leaf_len = buildLeafNode(&leaf_node, key_hash, &[_]u8{0x01});
    const root = mpt.keccak256(leaf_node[0..leaf_len]);

    // Corrupt one byte — keccak256 of the tampered node won't match root.
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..leaf_len], leaf_node[0..leaf_len]);
    tampered[leaf_len / 2] ^= 0xff;

    const pool = &[_][]const u8{tampered[0..leaf_len]};
    const result = mpt.verifyProof(root, key_hash, pool);
    try std.testing.expectError(error.InvalidProof, result);
}

// ─── Test 6: verifyWitness with flat pool ─────────────────────────────────────

test "verifyWitness — single account in pool" {
    var address: primitives.Address = @splat(0x00);
    address[19] = 0x03;
    const key_hash = mpt.keccak256(&address);

    var account_rlp: [200]u8 = undefined;
    const account_len = buildAccountRlp(&account_rlp, 0, 0, EMPTY_TRIE_HASH, KECCAK_EMPTY);

    var leaf_node: [512]u8 = undefined;
    const leaf_len = buildLeafNode(&leaf_node, key_hash, account_rlp[0..account_len]);
    const leaf_bytes = leaf_node[0..leaf_len];
    const state_root = mpt.keccak256(leaf_bytes);

    const w = input.StateWitness{
        .state_root = state_root,
        .nodes = &[_][]const u8{leaf_bytes},
        .codes = &.{},
        .keys = &[_][]const u8{&address},
        .headers = &.{},
    };
    const proven_root = try mpt.verifyWitness(w);
    try std.testing.expectEqualSlices(u8, &state_root, &proven_root);
}

// ─── Test 7: updateStorage no-op delete ──────────────────────────────────────

test "updateStorage: deleting non-existent slot does not change root" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var slot_a: primitives.Hash = @splat(0);
    slot_a[31] = 0x01;
    var slot_b: primitives.Hash = @splat(0);
    slot_b[31] = 0x02; // never inserted

    var extra = std.ArrayListUnmanaged([]const u8).empty;
    var root = EMPTY_TRIE_HASH;
    try mpt.updateStorageChained(alloc, &root, slot_a, 100, &.{}, &extra);
    const root_after_insert = root;

    const new_root = try mpt.updateStorage(alloc, root, slot_b, 0, extra.items);
    try std.testing.expectEqualSlices(u8, &root_after_insert, &new_root);
}

// ─── Test 8: updateStorageChained no-op delete ────────────────────────────────

test "updateStorageChained: deleting non-existent slot does not change root" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var slot_a: primitives.Hash = @splat(0);
    slot_a[31] = 0x01;
    var slot_b: primitives.Hash = @splat(0);
    slot_b[31] = 0x02;
    var slot_c: primitives.Hash = @splat(0);
    slot_c[31] = 0x03; // never inserted

    var extra = std.ArrayListUnmanaged([]const u8).empty;
    var root = EMPTY_TRIE_HASH;
    try mpt.updateStorageChained(alloc, &root, slot_a, 1, &.{}, &extra);
    try mpt.updateStorageChained(alloc, &root, slot_b, 2, extra.items, &extra);
    const root_before = root;

    var extra2 = std.ArrayListUnmanaged([]const u8).empty;
    try mpt.updateStorageChained(alloc, &root, slot_c, 0, extra.items, &extra2);
    try std.testing.expectEqualSlices(u8, &root_before, &root);
}

// ─── Internal tests ────────────────────────────────────────────────────────────

const NodeIndex = mpt.NodeIndex;
const BatchChange = mpt.BatchChange;
const buildNodeIndex = mpt.buildNodeIndex;
const batchUpdateIndexed = mpt.batchUpdateIndexed;
const keccak256 = mpt.keccak256;
const EMPTY_NODE_RLP = mpt.EMPTY_NODE_RLP;
const NodeView = mpt.testing.NodeView;
const updNode = mpt.testing.updNode;
const updNodeEx = mpt.testing.updNodeEx;
const updNodeExRecorded = mpt.testing.updNodeExRecorded;
const updMakeLeaf = mpt.testing.updMakeLeaf;
const updMakeExtension = mpt.testing.updMakeExtension;
const updEncodeBranch = mpt.testing.updEncodeBranch;
const updHashOrEmbed = mpt.testing.updHashOrEmbed;
const updRlpBytes = mpt.testing.updRlpBytes;
const updRlpList = mpt.testing.updRlpList;
const rlpBytesLen = mpt.testing.rlpBytesLen;
const rlpBytesWrite = mpt.testing.rlpBytesWrite;
const rlpListHeaderLen = mpt.testing.rlpListHeaderLen;
const rlpListHeaderWrite = mpt.testing.rlpListHeaderWrite;

//
// These are internal tests that directly exercise the private updNode* functions.
// They cover the extension-node diverge case: deleting a key that doesn't exist
// in the trie (key diverges from the extension prefix before its end) must return
// the trie unchanged rather than incorrectly splitting the extension node.

fn buildTestExtTrie(alloc: std.mem.Allocator) ![]const u8 {
    // Builds: Extension(prefix=[0,0]) → Branch{child[1]:leaf"a", child[2]:leaf"b"}
    // Full key nibbles for "a": [0, 0, 1]
    // Full key nibbles for "b": [0, 0, 2]
    const leaf_a = try updMakeLeaf(alloc, &.{}, "a");
    const leaf_b = try updMakeLeaf(alloc, &.{}, "b");
    var enc: [16][]const u8 = undefined;
    for (0..16) |i| enc[i] = &[_]u8{0x80};
    enc[1] = leaf_a;
    enc[2] = leaf_b;
    const branch = try updEncodeBranch(alloc, &enc, &.{});
    const child_ref = try updHashOrEmbed(alloc, branch);
    return updMakeExtension(alloc, &.{ 0, 0 }, child_ref);
}

test "rlp helpers byte-identical to updRlpBytes/updRlpList" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Byte-string encoding across every branch: empty, single-byte <0x80,
    // single-byte >=0x80, short (<=55) and long (>55, multi-byte length prefix).
    const lens = [_]usize{ 0, 1, 2, 31, 32, 55, 56, 100, 256, 300 };
    for (lens) |n| {
        const data = try alloc.alloc(u8, n);
        for (data, 0..) |*b, i| b.* = @intCast((i * 7 + 1) & 0xff);
        if (n == 1) data[0] = 0x7f; // single-byte <0x80 (raw) path
        const ref = try updRlpBytes(alloc, data);
        try std.testing.expectEqual(ref.len, rlpBytesLen(data));
        const buf = try alloc.alloc(u8, rlpBytesLen(data));
        try std.testing.expectEqual(buf.len, rlpBytesWrite(buf, 0, data));
        try std.testing.expectEqualSlices(u8, ref, buf);
    }
    // single-byte >=0x80 must take the length-prefixed path (0x81, b)
    {
        const data = [_]u8{0xff};
        const ref = try updRlpBytes(alloc, &data);
        try std.testing.expectEqual(ref.len, rlpBytesLen(&data));
        const buf = try alloc.alloc(u8, rlpBytesLen(&data));
        _ = rlpBytesWrite(buf, 0, &data);
        try std.testing.expectEqualSlices(u8, ref, buf);
    }

    // List header across short (<=55) and long (>55) payloads — compared against
    // the prefix of updRlpList of a single payload-sized item.
    const payloads = [_]usize{ 0, 1, 55, 56, 256, 1000 };
    for (payloads) |p| {
        const item = try alloc.alloc(u8, p);
        @memset(item, 0xab);
        const ref = try updRlpList(alloc, &.{item});
        const hlen = rlpListHeaderLen(p);
        try std.testing.expectEqual(ref.len - p, hlen);
        const buf = try alloc.alloc(u8, hlen);
        try std.testing.expectEqual(buf.len, rlpListHeaderWrite(buf, 0, p));
        try std.testing.expectEqualSlices(u8, ref[0..hlen], buf);
    }
}

test "updNode: deleting non-existent key (diverges from extension prefix) is a no-op" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const ext = try buildTestExtTrie(alloc);
    // key[0]=0 matches prefix[0]=0, but key[1]=1 ≠ prefix[1]=0 → cp=1 < prefix.len=2
    const result = try updNode(alloc, ext, &.{ 0, 1, 0, 0 }, null, &.{});
    try std.testing.expectEqualSlices(u8, ext, result);
}

test "updNodeEx: deleting non-existent key (diverges from extension prefix) is a no-op" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const ext = try buildTestExtTrie(alloc);
    var extra = std.ArrayListUnmanaged([]const u8).empty;
    const result = try updNodeEx(alloc, ext, &.{ 0, 1, 0, 0 }, null, &.{}, &extra);
    try std.testing.expectEqualSlices(u8, ext, result);
    try std.testing.expectEqual(@as(usize, 0), extra.items.len);
}

test "updNodeExRecorded: deleting non-existent key (diverges from extension prefix) is a no-op" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const ext = try buildTestExtTrie(alloc);
    var index = NodeIndex.init(alloc);
    var nodes: NodeView = .{ .witness = &index, .created = NodeIndex.init(alloc) };
    const result = try updNodeExRecorded(alloc, ext, &.{ 0, 1, 0, 0 }, null, &nodes);
    try std.testing.expectEqualSlices(u8, ext, result);
}

// ─── Branch-collapse tests ─────────────────────────────────────────────────────
//
// Build: Branch{child[1]:leaf"a", child[2]:leaf"b"}
// Delete child[1] → only child[2] remains → branch collapses to leaf "b" at key [2].
// All three updNode variants must produce the same result.

fn buildTestBranchTrie(alloc: std.mem.Allocator) !struct { branch: []const u8, pool: []const []const u8 } {
    const leaf_a = try updMakeLeaf(alloc, &.{}, "a");
    const leaf_b = try updMakeLeaf(alloc, &.{}, "b");
    var enc: [16][]const u8 = undefined;
    for (0..16) |i| enc[i] = try alloc.dupe(u8, &.{0x80});
    enc[1] = try updHashOrEmbed(alloc, leaf_a);
    enc[2] = try updHashOrEmbed(alloc, leaf_b);
    const branch = try updEncodeBranch(alloc, &enc, &.{});
    // pool contains leaf_a and leaf_b so hash refs can be resolved
    const pool = try alloc.dupe([]const u8, &.{ leaf_a, leaf_b });
    return .{ .branch = branch, .pool = pool };
}

test "updNode: deleting a key collapses branch to leaf" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const t = try buildTestBranchTrie(alloc);
    // Delete key [1] — only child[2] remains → branch must collapse to a leaf at path [2].
    const result = try updNode(alloc, t.branch, &.{1}, null, t.pool);
    const expected = try updMakeLeaf(alloc, &.{2}, "b");
    try std.testing.expectEqualSlices(u8, expected, result);
}

test "updNodeEx: deleting a key collapses branch to leaf" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const t = try buildTestBranchTrie(alloc);
    var extra = std.ArrayListUnmanaged([]const u8).empty;
    const result = try updNodeEx(alloc, t.branch, &.{1}, null, t.pool, &extra);
    const expected = try updMakeLeaf(alloc, &.{2}, "b");
    try std.testing.expectEqualSlices(u8, expected, result);
}

test "updNodeExRecorded: deleting a key collapses branch to leaf" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const t = try buildTestBranchTrie(alloc);
    var index = try buildNodeIndex(alloc, t.pool);
    defer index.deinit();
    var nodes: NodeView = .{ .witness = &index, .created = NodeIndex.init(alloc) };
    const result = try updNodeExRecorded(alloc, t.branch, &.{1}, null, &nodes);
    const expected = try updMakeLeaf(alloc, &.{2}, "b");
    try std.testing.expectEqualSlices(u8, expected, result);
}

// ─── Extension-merge tests ─────────────────────────────────────────────────────
//
// Build: Extension([0]) → Branch{child[1]:leaf"a", child[2]:leaf"b"}
// Delete key [0,1] → branch collapses to leaf"b" at [2] → extension merges with
// that leaf suffix → result is a single leaf at path [0,2].

fn buildTestExtBranchTrie(alloc: std.mem.Allocator) !struct { root: []const u8, pool: []const []const u8 } {
    const leaf_a = try updMakeLeaf(alloc, &.{}, "a");
    const leaf_b = try updMakeLeaf(alloc, &.{}, "b");
    var enc: [16][]const u8 = undefined;
    for (0..16) |i| enc[i] = try alloc.dupe(u8, &.{0x80});
    enc[1] = try updHashOrEmbed(alloc, leaf_a);
    enc[2] = try updHashOrEmbed(alloc, leaf_b);
    const branch = try updEncodeBranch(alloc, &enc, &.{});
    const branch_ref = try updHashOrEmbed(alloc, branch);
    const root = try updMakeExtension(alloc, &.{0}, branch_ref);
    const pool = try alloc.dupe([]const u8, &.{ leaf_a, leaf_b, branch });
    return .{ .root = root, .pool = pool };
}

test "updNode: deleting collapses branch and merges extension" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const t = try buildTestExtBranchTrie(alloc);
    // Delete key [0,1] → extension([0])→branch collapses → result: leaf at [0,2].
    const result = try updNode(alloc, t.root, &.{ 0, 1 }, null, t.pool);
    const expected = try updMakeLeaf(alloc, &.{ 0, 2 }, "b");
    try std.testing.expectEqualSlices(u8, expected, result);
}

test "updNodeEx: deleting collapses branch and merges extension" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const t = try buildTestExtBranchTrie(alloc);
    var extra = std.ArrayListUnmanaged([]const u8).empty;
    const result = try updNodeEx(alloc, t.root, &.{ 0, 1 }, null, t.pool, &extra);
    const expected = try updMakeLeaf(alloc, &.{ 0, 2 }, "b");
    try std.testing.expectEqualSlices(u8, expected, result);
}

test "updNodeExRecorded: deleting collapses branch and merges extension" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const t = try buildTestExtBranchTrie(alloc);
    var index = try buildNodeIndex(alloc, t.pool);
    defer index.deinit();
    var nodes: NodeView = .{ .witness = &index, .created = NodeIndex.init(alloc) };
    const result = try updNodeExRecorded(alloc, t.root, &.{ 0, 1 }, null, &nodes);
    const expected = try updMakeLeaf(alloc, &.{ 0, 2 }, "b");
    try std.testing.expectEqualSlices(u8, expected, result);
}

// Regression for #179: a NodeIndex shared across consecutive blocks must not be
// left pointing into the scratch allocator of an earlier block's root update.
test "batchUpdateIndexed: shared NodeIndex stays valid after scratch is freed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var key_a: [32]u8 = @splat(0x11);
    key_a[0] = 0x10;
    var key_b: [32]u8 = @splat(0x22);
    key_b[0] = 0x20;
    var key_c: [32]u8 = @splat(0x33);
    key_c[0] = 0x30;

    const leafAt = struct {
        fn f(a: std.mem.Allocator, key: [32]u8, val: []const u8) ![]const u8 {
            var nibs: [64]u8 = undefined;
            nibbles.bytesToNibbles(&key, &nibs);
            return updMakeLeaf(a, nibs[1..], val);
        }
    }.f;
    const branchOf = struct {
        fn f(a: std.mem.Allocator, children: []const struct { u8, []const u8 }) ![]const u8 {
            var enc: [16][]const u8 = @splat(&EMPTY_NODE_RLP);
            for (children) |c| enc[c[0]] = try updHashOrEmbed(a, c[1]);
            return updEncodeBranch(a, &enc, &.{});
        }
    }.f;

    // Block 1 pre-state: {a, b, c}. Block 1 deletes a and updates b, so the
    // update creates leaf_b2 and records it for a possible collapse.
    const leaf_a = try leafAt(alloc, key_a, "va");
    const leaf_b1 = try leafAt(alloc, key_b, "vb1");
    const leaf_c = try leafAt(alloc, key_c, "vc");
    const root0 = try branchOf(alloc, &.{ .{ 1, leaf_a }, .{ 2, leaf_b1 }, .{ 3, leaf_c } });

    // Block 2's witness proves block 1's post-state: {b = vb2, c}.
    const leaf_b2 = try leafAt(alloc, key_b, "vb2");
    const root1 = try branchOf(alloc, &.{ .{ 2, leaf_b2 }, .{ 3, leaf_c } });

    const witness = [_][]const u8{ root0, leaf_a, leaf_b1, leaf_c, root1, leaf_b2 };
    var index = try buildNodeIndex(alloc, &witness);
    defer index.deinit();

    var scratch_buf: [16 * 1024]u8 = undefined;
    var scratch_fba = std.heap.FixedBufferAllocator.init(&scratch_buf);
    const block1 = [_]BatchChange{ .{ .key = key_a, .value = null }, .{ .key = key_b, .value = "vb2" } };
    const got1 = try batchUpdateIndexed(scratch_fba.allocator(), keccak256(root0), &block1, &index);
    try std.testing.expectEqual(keccak256(root1), got1);

    // Block 1 left the index exactly as built from the witness.
    try std.testing.expectEqual(@as(u32, witness.len), index.count());
    for (witness) |w| try std.testing.expectEqual(w.ptr, index.get(keccak256(w)).?.ptr);

    // Free block 1's scratch.
    @memset(&scratch_buf, 0xAA);

    const block2 = [_]BatchChange{.{ .key = key_b, .value = "vb3" }};
    const got2 = try batchUpdateIndexed(alloc, got1, &block2, &index);

    var kv = [_]builder.KV{ .{ .key = &key_b, .value = "vb3" }, .{ .key = &key_c, .value = "vc" } };
    try std.testing.expectEqual(try builder.trieRoot(alloc, &kv), got2);
}

// The two tests below cover nodes that a batch update creates and then looks up again
// before it finishes. They are recorded in the update's own NodeView, never in the witness
// index, so a missing record fails the update with InvalidProof instead of giving a wrong
// root. Keys differ in the first nibble (or the last), and the leaf paths are long enough
// that every node is at least 32 bytes and so referenced by hash, not inlined.

fn testLeafBelowFirstNibble(alloc: std.mem.Allocator, key: [32]u8, val: []const u8) ![]const u8 {
    var nibs: [64]u8 = undefined;
    nibbles.bytesToNibbles(&key, &nibs);
    return updMakeLeaf(alloc, nibs[1..], val);
}

test "batchUpdateIndexed: collapse after a delete reads a node the same batch created" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var key_a: [32]u8 = @splat(0x11);
    key_a[0] = 0x30;
    var key_b: [32]u8 = @splat(0x22);
    key_b[0] = 0x50;

    // Pre-state {a, b}: a root branch with a leaf under nibble 3 and one under nibble 5.
    const leaf_a = try testLeafBelowFirstNibble(alloc, key_a, "va");
    const leaf_b = try testLeafBelowFirstNibble(alloc, key_b, "vb");
    var enc: [16][]const u8 = @splat(&EMPTY_NODE_RLP);
    enc[3] = try updHashOrEmbed(alloc, leaf_a);
    enc[5] = try updHashOrEmbed(alloc, leaf_b);
    const root = try updEncodeBranch(alloc, &enc, &.{});

    var index = try buildNodeIndex(alloc, &.{ root, leaf_a, leaf_b });
    defer index.deinit();

    // Updating a creates a new leaf that exists nowhere in the witness; deleting b leaves
    // it as the branch's only child, so collapsing the branch has to decode it by hash.
    const changes = [_]BatchChange{ .{ .key = key_a, .value = "va2" }, .{ .key = key_b, .value = null } };
    const got = try batchUpdateIndexed(alloc, keccak256(root), &changes, &index);

    var kv = [_]builder.KV{.{ .key = &key_a, .value = "va2" }};
    try std.testing.expectEqual(try builder.trieRoot(alloc, &kv), got);
}

test "batchUpdateIndexed: sequential inserts descend into nodes the same batch created" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Three keys that differ only in the last nibble, with 40-byte values so the leaves
    // and the branch that joins them are hashed. Inserted into an empty trie one after
    // another: the second insert splits the first leaf into an extension over a branch,
    // and the third has to descend through that extension into the branch by hash.
    var keys: [3][32]u8 = undefined;
    for (&keys, 0..) |*k, i| {
        k.* = @splat(0x44);
        k[31] = @intCast(i);
    }
    const value: [40]u8 = @splat(0xab);

    var changes: [3]BatchChange = undefined;
    for (&changes, keys) |*c, k| c.* = .{ .key = k, .value = &value };

    var index = try buildNodeIndex(alloc, &.{});
    defer index.deinit();
    const got = try batchUpdateIndexed(alloc, EMPTY_TRIE_HASH, &changes, &index);

    var kv: [3]builder.KV = undefined;
    for (&kv, &keys) |*e, *k| e.* = .{ .key = k, .value = &value };
    try std.testing.expectEqual(try builder.trieRoot(alloc, &kv), got);
}

/// A branch at the root whose children 1 and 2 are leaves with paths of `len_1` and
/// `len_2` nibbles; a valid secured trie has 63 for both. Returns the root hash.
fn buildPathTestTrie(alloc: std.mem.Allocator, index: *NodeIndex, len_1: usize, len_2: usize) ![32]u8 {
    const path: [70]u8 = @splat(0);
    var enc: [16][]const u8 = @splat(&EMPTY_NODE_RLP);
    for ([_]struct { u8, usize }{ .{ 1, len_1 }, .{ 2, len_2 } }) |c| {
        const leaf = try updMakeLeaf(alloc, path[0..c[1]], "value");
        try index.put(keccak256(leaf), leaf);
        enc[c[0]] = try updHashOrEmbed(alloc, leaf);
    }
    const root = try updEncodeBranch(alloc, &enc, &.{});
    try index.put(keccak256(root), root);
    return keccak256(root);
}

test "validateSecuredTriePaths: leaves ending at the key length pass" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var index = NodeIndex.init(arena.allocator());
    const root = try buildPathTestTrie(arena.allocator(), &index, 63, 63);
    try mpt.validateSecuredTriePaths(root, &index, try mpt.NodeFilter.init(arena.allocator(), &index));
}

// The reference checks only that a branch has key nibbles left, not its value slot: a
// 64-nibble lookup always descends into a child, so the value is never read.
test "validateSecuredTriePaths: a branch value is not checked" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var index = NodeIndex.init(alloc);
    const path: [63]u8 = @splat(0);
    var enc: [16][]const u8 = @splat(&EMPTY_NODE_RLP);
    for ([_]u8{ 1, 2 }) |nib| {
        const leaf = try updMakeLeaf(alloc, &path, "value");
        try index.put(keccak256(leaf), leaf);
        enc[nib] = try updHashOrEmbed(alloc, leaf);
    }
    const root = try updEncodeBranch(alloc, &enc, "branch-value");
    try index.put(keccak256(root), root);
    try mpt.validateSecuredTriePaths(keccak256(root), &index, try mpt.NodeFilter.init(arena.allocator(), &index));
}

test "validateSecuredTriePaths: a leaf past or short of the key length is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    for ([_]usize{ 64, 66, 62 }) |len| {
        var index = NodeIndex.init(arena.allocator());
        const root = try buildPathTestTrie(arena.allocator(), &index, 63, len);
        try std.testing.expectError(error.InvalidProof, mpt.validateSecuredTriePaths(root, &index, try mpt.NodeFilter.init(arena.allocator(), &index)));
    }
}

test "validateSecuredTriePaths: an extension reaching the key length is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var index = NodeIndex.init(alloc);
    const branch_hash = try buildPathTestTrie(alloc, &index, 0, 0);
    const path: [64]u8 = @splat(0);
    const ext = try updMakeExtension(alloc, &path, try updRlpBytes(alloc, &branch_hash));
    try index.put(keccak256(ext), ext);
    try std.testing.expectError(error.InvalidProof, mpt.validateSecuredTriePaths(keccak256(ext), &index, try mpt.NodeFilter.init(arena.allocator(), &index)));
}

test "validateSecuredTriePaths: nodes absent from the witness are not walked" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var index = NodeIndex.init(alloc);
    const root = try buildPathTestTrie(alloc, &index, 63, 66);
    // Drop the over-length leaf: only its hash remains, in the root.
    const leaf = try updMakeLeaf(alloc, &(@as([66]u8, @splat(0))), "value");
    try std.testing.expect(index.remove(keccak256(leaf)));
    try mpt.validateSecuredTriePaths(root, &index, try mpt.NodeFilter.init(arena.allocator(), &index));
    // An empty root, or a root absent from the witness, has nothing to walk.
    try mpt.validateSecuredTriePaths(EMPTY_TRIE_HASH, &index, try mpt.NodeFilter.init(arena.allocator(), &index));
    try mpt.validateSecuredTriePaths(@splat(0x11), &index, try mpt.NodeFilter.init(arena.allocator(), &index));
}
