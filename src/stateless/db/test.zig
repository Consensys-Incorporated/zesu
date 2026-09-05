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
    try std.testing.expectEqualSlices(u8, contract_code, code.bytecode());
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

// ─── Regression: storage-root cache must not be silently dropped ──────────────

// `storageRootFor()` is a bare `storage_root_cache.get()`, so a missing entry is
// indistinguishable from "this account was never loaded". The post-execution
// batch trie update relies on that distinction: for a null pre-state root,
// computeStorageRootBatch (src/stateless/executor/output.zig:188) rebuilds the
// storage trie from only the slots execution touched, as if the account had no
// pre-state storage. For an account that *does* have pre-state storage, that
// silently drops every untouched slot and yields a WRONG state root, reported as
// success.
//
// So an allocation failure while caching the root must never be swallowed: the
// three `storage_root_cache.put(...)` sites in db/main.zig must propagate, not
// `catch {}`. This test asserts the invariant that makes the downstream
// assumption safe:
//
//     basic() succeeded  =>  storageRootFor() knows the account's storage root
//
// It drives every allocation index in turn, so it does not depend on how many
// allocations basic() happens to make. A wrong state root returned as success is
// the worst failure mode for a proving system, hence pinning it here.
test "basic must not succeed while silently dropping the storage-root cache entry" {
    var address: primitives.Address = @splat(0x00);
    address[19] = 0x33;
    const key_hash = mpt.keccak256(&address);

    // A non-empty storage root: this is what must not be lost.
    const storage_root: primitives.Hash = @splat(0x5a);

    var account_rlp: [200]u8 = undefined;
    const account_len = buildAccountRlp(&account_rlp, 1, 500, storage_root, KECCAK_EMPTY);
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

    // The node index is built with the real allocator; only the database's own
    // allocations (which include the storage-root cache) are made to fail.
    var idx = try mpt.buildNodeIndex(ALLOC, w.nodes);
    defer idx.deinit();

    var fail_index: usize = 0;
    while (fail_index < 16) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(ALLOC, .{ .fail_index = fail_index });
        var wdb = db_mod.WitnessDatabase.init(
            failing.allocator(),
            &idx,
            w.state_root,
            w.codes,
            &.{},
        ) catch continue; // init itself ran out of memory: nothing to check
        defer wdb.deinit();

        const info = wdb.basic(address) catch continue; // propagated: correct
        if (info == null) continue; // account absent: no root to cache

        // basic() reported success, so the cached root must be present and right.
        const cached = wdb.storageRootFor(address);
        if (cached == null) {
            std.debug.print(
                "\nfail_index={d}: basic() succeeded but storageRootFor() is null;\n" ++
                    "the batch trie update will rebuild storage from scratch and\n" ++
                    "produce a wrong state root with no error raised.\n",
                .{fail_index},
            );
            return error.StorageRootSilentlyDropped;
        }
        try std.testing.expectEqualSlices(u8, &storage_root, &cached.?);
    }
}

// ─── Regression: an unprovable slot must not read as zero ─────────────────────

// The MPT layer distinguishes two outcomes precisely (src/stateless/mpt/main.zig):
// `null` means *proved absent* — the comments there read "valid non-inclusion" —
// whereas `error.InvalidProof` is returned by
// `findNodeInIndex(...) orelse return error.InvalidProof`, i.e. the witness does
// not contain the node needed to prove anything at all.
//
// So InvalidProof means "cannot verify", not "absent". basic() already treats it
// that way (it maps InvalidProof to InvalidWitness, with a documented
// SYSTEM_ADDRESS carve-out), but storage() maps it to `return 0`
// (db/main.zig:186) and the storage-root lookup maps it to EMPTY_TRIE_HASH
// (:175). An incomplete witness therefore reads as "slot is zero" instead of
// failing, which lets a wrong state transition be executed and proved.
//
// Here slot 3 genuinely holds 0xabcd, but its storage leaf is withheld from the
// witness, so a zero result is demonstrably wrong rather than merely unproven.
test "storage must fail, not return 0, when the witness cannot prove the slot" {
    var address: primitives.Address = @splat(0x00);
    address[19] = 0x77;
    const slot_key: u256 = 3;

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
    const rlp_value = &[_]u8{ 0x82, 0xab, 0xcd }; // slot 3 = 0xabcd
    var storage_leaf: [256]u8 = undefined;
    const storage_leaf_len = buildLeafNode(&storage_leaf, storage_key_hash, rlp_value);
    const storage_root = mpt.keccak256(storage_leaf[0..storage_leaf_len]);

    const acc_key_hash = mpt.keccak256(&address);
    var account_rlp: [200]u8 = undefined;
    const account_len = buildAccountRlp(&account_rlp, 0, 0, storage_root, KECCAK_EMPTY);
    var acc_leaf: [512]u8 = undefined;
    const acc_leaf_len = buildLeafNode(&acc_leaf, acc_key_hash, account_rlp[0..account_len]);
    const acc_leaf_bytes = acc_leaf[0..acc_leaf_len];
    const state_root = mpt.keccak256(acc_leaf_bytes);

    // The account leaf is present; the storage leaf is deliberately withheld, so
    // the storage trie cannot be walked at all.
    const w = input.StateWitness{
        .state_root = state_root,
        .nodes = &[_][]const u8{acc_leaf_bytes},
        .codes = &.{},
        .keys = &.{},
        .headers = &.{},
    };
    var idx: mpt.NodeIndex = undefined;
    var wdb = try makeWdb(w, &idx);
    defer idx.deinit();
    defer wdb.deinit();

    const result = wdb.storage(address, slot_key);
    if (result) |value| {
        std.debug.print(
            "\nstorage() returned {d} for an unprovable slot whose true value is 0xabcd;\n" ++
                "an incomplete witness reads as 'slot is zero' instead of failing.\n",
            .{value},
        );
        return error.UnprovableSlotReadAsZero;
    } else |_| {
        // Any error is acceptable here; the point is that it must not succeed.
    }
}

// ─── Regression: CREATE collision check must not guess ────────────────────────

// hasNonZeroStorageForAddress feeds the CREATE collision check
// (src/evm/interpreter/host.zig, setupCreateCore). It used to `catch return
// false`, so a witness that cannot prove the target account read as "no storage
// here" and allowed a CREATE that the reference rejects — a consensus-level wrong
// result. It is now fallible; the journal wrapper records the error so the block
// is rejected after execution, and fails the CREATE closed in the meantime.
//
// Note a genuinely absent account is NOT an error: it resolves via valid
// non-inclusion to false, which the second half of this test pins so the fix
// cannot be "just always return an error".
test "hasNonZeroStorageForAddress must fail when the account cannot be proven" {
    var address: primitives.Address = @splat(0x00);
    address[19] = 0x88;

    // A state root whose account node is absent from the witness: nothing can be
    // proven about this address one way or the other.
    const unprovable_root: primitives.Hash = @splat(0x9e);
    const w = input.StateWitness{
        .state_root = unprovable_root,
        .nodes = &.{},
        .codes = &.{},
        .keys = &.{},
        .headers = &.{},
    };
    var idx: mpt.NodeIndex = undefined;
    var wdb = try makeWdb(w, &idx);
    defer idx.deinit();
    defer wdb.deinit();

    if (wdb.hasNonZeroStorageForAddress(address)) |answer| {
        std.debug.print(
            "\nhasNonZeroStorageForAddress returned {} for an unprovable account;\n" ++
                "the CREATE collision check would proceed on a fabricated answer.\n",
            .{answer},
        );
        return error.UnprovableAccountAnsweredAnyway;
    } else |_| {
        // Correct: the caller is told we cannot determine this.
    }
}

test "hasNonZeroStorageForAddress reports false for a provably absent account" {
    var address: primitives.Address = @splat(0x00);
    address[19] = 0x99;

    // An empty branch root proves non-inclusion for every address, so the answer
    // is knowable and must be `false`, not an error.
    var branch: [18]u8 = undefined;
    const branch_len = buildEmptyBranchNode(&branch);
    const branch_bytes = branch[0..branch_len];
    const state_root = mpt.keccak256(branch_bytes);

    const w = input.StateWitness{
        .state_root = state_root,
        .nodes = &[_][]const u8{branch_bytes},
        .codes = &.{},
        .keys = &.{},
        .headers = &.{},
    };
    var idx: mpt.NodeIndex = undefined;
    var wdb = try makeWdb(w, &idx);
    defer idx.deinit();
    defer wdb.deinit();

    try std.testing.expect(!(try wdb.hasNonZeroStorageForAddress(address)));
}

// Covers the OTHER InvalidProof site in storage(): the storage-root lookup
// (db/main.zig, the verifyAccountIndexed call inside storage()). Here the ACCOUNT
// node is missing, not the storage node, so the account's storage root cannot be
// determined. Defaulting to EMPTY_TRIE_HASH would make every slot on this account
// read as 0. Distinct from the test above, which withholds the storage leaf and
// exercises the verifyStorageIndexed site.
test "storage must fail when the account's storage root cannot be proven" {
    var address: primitives.Address = @splat(0x00);
    address[19] = 0xaa;

    // Empty node pool: the account node behind this root is absent, so nothing
    // about the account (including its storage root) can be proven.
    const unprovable_root: primitives.Hash = @splat(0x7c);
    const w = input.StateWitness{
        .state_root = unprovable_root,
        .nodes = &.{},
        .codes = &.{},
        .keys = &.{},
        .headers = &.{},
    };
    var idx: mpt.NodeIndex = undefined;
    var wdb = try makeWdb(w, &idx);
    defer idx.deinit();
    defer wdb.deinit();

    // Cache is empty, so this goes through the storage-root lookup path.
    if (wdb.storage(address, 3)) |value| {
        std.debug.print(
            "\nstorage() returned {d} for an account whose storage root is unprovable;\n" ++
                "every slot on this account would read as 0.\n",
            .{value},
        );
        return error.UnprovableAccountStorageReadAsZero;
    } else |_| {}
}
