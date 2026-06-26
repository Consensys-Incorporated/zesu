//! Merkle Patricia Trie: proof verification for stateless execution.
//!
//! Verification works against a flat node pool (from debug_executionWitness).
//! For each step, the next node is located by scanning the pool for an entry
//! whose keccak256 hash matches the expected reference — no pre-assembled
//! ordered proof paths are needed.
//!
//! All functions are allocation-free; stack buffers are used for nibble paths.

const std = @import("std");
const primitives = @import("primitives");
const input = @import("input");
const accel = @import("accelerators");

/// RLP decoder — also re-exported so callers (e.g. io.zig) can reuse it.
pub const rlp = @import("rlp.zig");
pub const builder = @import("builder.zig");
const nibbles = @import("nibbles.zig");
const node = @import("node.zig");

// ─── Public types ──────────────────────────────────────────────────────────────

pub const MptError = error{
    /// No node in the pool hashes to the expected value, or pool exhausted.
    InvalidProof,
    /// Malformed node RLP structure (wrong item count, bad types).
    InvalidNode,
    /// Malformed RLP encoding.
    InvalidRlp,
    /// Malformed hex-prefix (compact) encoding.
    InvalidHp,
};

/// Decoded Ethereum account fields.
pub const AccountState = struct {
    nonce: u64,
    balance: u256,
    storage_root: primitives.Hash,
    code_hash: primitives.Hash,
};

/// RLP encoding of an empty node (single byte 0x80). Used as a static sentinel
/// to avoid bump-allocator dupe calls for the common empty-node case in trie updates.
pub const EMPTY_NODE_RLP: [1]u8 = .{0x80};

// ─── keccak256 ─────────────────────────────────────────────────────────────────

/// Delegates to the injected accelerators module.
/// Default: std.crypto pure-Zig.  Zisk build: hardware CSR circuit.
pub fn keccak256(data: []const u8) [32]u8 {
    var hash: [32]u8 = undefined;
    accel.keccak256(data, &hash);
    return hash;
}

// ─── NodeIndex ─────────────────────────────────────────────────────────────────

/// Pre-computed hash → node-bytes map built once from the witness node pool.
/// Use buildNodeIndex() to populate, then pass to the *Indexed verification
/// functions for O(1) node lookups instead of O(N·keccak) linear scans.
pub const NodeIndex = std.HashMap([32]u8, []const u8, primitives.HashContext, 80);

/// Build a NodeIndex from a flat node pool.
/// Each entry maps keccak256(node_bytes) → node_bytes.
/// The returned map is owned by the caller; call deinit() when done.
pub fn buildNodeIndex(allocator: std.mem.Allocator, pool: []const []const u8) !NodeIndex {
    var index = NodeIndex.init(allocator);
    try index.ensureTotalCapacity(@intCast(pool.len));
    for (pool) |node_bytes| {
        const h = keccak256(node_bytes);
        index.putAssumeCapacity(h, node_bytes);
    }
    return index;
}

/// O(1) index lookup — used by the indexed API for large witness pools.
fn findNodeInIndex(index: *const NodeIndex, hash: primitives.Hash) ?[]const u8 {
    return index.get(hash);
}

// ─── findNode ──────────────────────────────────────────────────────────────────

/// Linear scan of the node pool for an entry whose keccak256 equals `hash`.
/// Returns the raw node bytes, or null if no match is found.
fn findNode(pool: []const []const u8, hash: primitives.Hash) ?[]const u8 {
    for (pool) |node_bytes| {
        if (std.mem.eql(u8, &keccak256(node_bytes), &hash)) return node_bytes;
    }
    return null;
}

// ─── verifyProof ───────────────────────────────────────────────────────────────

/// Traverse the trie for `key_hash` starting from `root_hash`, using the
/// flat `pool` of node preimages to resolve each hash reference.
///
/// Returns the leaf value bytes on inclusion, or null for a valid
/// non-inclusion proof (empty branch child or mismatched leaf suffix).
pub fn verifyProof(
    root_hash: primitives.Hash,
    key_hash: primitives.Hash,
    pool: []const []const u8,
) MptError!?[]const u8 {
    // Empty trie root: non-inclusion is provable without any pool nodes.
    if (std.mem.eql(u8, &root_hash, &EMPTY_TRIE_HASH)) return null;

    var key_nibbles: [64]u8 = undefined;
    nibbles.bytesToNibbles(&key_hash, &key_nibbles);

    // Tracks the next expected node: either a 32-byte hash (pool lookup)
    // or an inline RLP encoding (embedded directly in the parent node).
    const ExpectedRef = union(enum) {
        hash: *const [32]u8,
        inline_node: []const u8,
    };
    var expected: ExpectedRef = .{ .hash = &root_hash };
    var pos: usize = 0;

    while (true) {
        // Resolve the current node.
        const node_rlp: []const u8 = switch (expected) {
            .hash => |h| findNode(pool, h.*) orelse return error.InvalidProof,
            .inline_node => |inl| inl,
        };

        const decoded = node.decodeNode(node_rlp) catch |err| switch (err) {
            error.InvalidRlp => return error.InvalidRlp,
            error.InvalidNode => return error.InvalidNode,
        };

        switch (decoded) {
            .branch => |b| {
                if (pos >= 64) return error.InvalidProof;
                const nibble = key_nibbles[pos];
                pos += 1;
                switch (b.children[nibble]) {
                    .empty => return null, // valid non-inclusion
                    .hash => |h| expected = .{ .hash = h },
                    .inline_node => |inl| expected = .{ .inline_node = inl },
                }
            },

            .extension => |e| {
                var path_buf: [128]u8 = undefined;
                const hp = nibbles.hpDecode(e.prefix, &path_buf) catch return error.InvalidHp;
                if (hp.is_leaf) return error.InvalidNode;
                const prefix_nibs = path_buf[0..hp.len];
                if (pos + prefix_nibs.len > 64) return error.InvalidProof;
                if (!std.mem.eql(u8, prefix_nibs, key_nibbles[pos .. pos + prefix_nibs.len]))
                    return null; // prefix diverges → valid non-inclusion
                pos += prefix_nibs.len;
                switch (e.child) {
                    .empty => return error.InvalidNode,
                    .hash => |h| expected = .{ .hash = h },
                    .inline_node => |inl| expected = .{ .inline_node = inl },
                }
            },

            .leaf => |lf| {
                var path_buf: [128]u8 = undefined;
                const hp = nibbles.hpDecode(lf.key_end, &path_buf) catch return error.InvalidHp;
                if (!hp.is_leaf) return error.InvalidNode;
                const suffix_nibs = path_buf[0..hp.len];
                // Suffix must exactly match the remaining key nibbles.
                if (suffix_nibs.len != 64 - pos) return null;
                if (!std.mem.eql(u8, suffix_nibs, key_nibbles[pos..])) return null;
                return lf.value;
            },
        }
    }
}

// ─── verifyProofVerbose ────────────────────────────────────────────────────────

/// Like verifyProof but writes a one-line trace per trie node to `writer`.
///
/// Each line shows: node type, the hash used to locate it (or "(inline)" for
/// embedded nodes), and what was consumed — nibble index for branches,
/// number of skipped nibbles for extensions.
pub fn verifyProofVerbose(
    root_hash: primitives.Hash,
    key_hash: primitives.Hash,
    pool: []const []const u8,
    writer: anytype,
) MptError!?[]const u8 {
    if (std.mem.eql(u8, &root_hash, &EMPTY_TRIE_HASH)) return null;

    var key_nibbles: [64]u8 = undefined;
    nibbles.bytesToNibbles(&key_hash, &key_nibbles);

    const ExpectedRef = union(enum) {
        hash: *const [32]u8,
        inline_node: []const u8,
    };
    var expected: ExpectedRef = .{ .hash = &root_hash };
    var pos: usize = 0;

    while (true) {
        const node_rlp: []const u8 = switch (expected) {
            .hash => |h| findNode(pool, h.*) orelse return error.InvalidProof,
            .inline_node => |inl| inl,
        };

        const decoded = node.decodeNode(node_rlp) catch |err| switch (err) {
            error.InvalidRlp => return error.InvalidRlp,
            error.InvalidNode => return error.InvalidNode,
        };

        switch (decoded) {
            .branch => |b| {
                if (pos >= 64) return error.InvalidProof;
                const nibble = key_nibbles[pos];
                pos += 1;
                switch (expected) {
                    .hash => |h| writer.print("        branch    0x{x}  nibble={x}\n", .{ h.*, nibble }) catch {},
                    .inline_node => writer.print("        branch    (inline)  nibble={x}\n", .{nibble}) catch {},
                }
                switch (b.children[nibble]) {
                    .empty => return null,
                    .hash => |h| expected = .{ .hash = h },
                    .inline_node => |inl| expected = .{ .inline_node = inl },
                }
            },

            .extension => |e| {
                var path_buf: [128]u8 = undefined;
                const hp = nibbles.hpDecode(e.prefix, &path_buf) catch return error.InvalidHp;
                if (hp.is_leaf) return error.InvalidNode;
                const prefix_nibs = path_buf[0..hp.len];
                if (pos + prefix_nibs.len > 64) return error.InvalidProof;
                switch (expected) {
                    .hash => |h| writer.print("        extension 0x{x}  skip={d}\n", .{ h.*, hp.len }) catch {},
                    .inline_node => writer.print("        extension (inline)  skip={d}\n", .{hp.len}) catch {},
                }
                if (!std.mem.eql(u8, prefix_nibs, key_nibbles[pos .. pos + prefix_nibs.len]))
                    return null;
                pos += prefix_nibs.len;
                switch (e.child) {
                    .empty => return error.InvalidNode,
                    .hash => |h| expected = .{ .hash = h },
                    .inline_node => |inl| expected = .{ .inline_node = inl },
                }
            },

            .leaf => |lf| {
                var path_buf: [128]u8 = undefined;
                const hp = nibbles.hpDecode(lf.key_end, &path_buf) catch return error.InvalidHp;
                if (!hp.is_leaf) return error.InvalidNode;
                const suffix_nibs = path_buf[0..hp.len];
                if (suffix_nibs.len != 64 - pos) return null;
                if (!std.mem.eql(u8, suffix_nibs, key_nibbles[pos..])) return null;
                switch (expected) {
                    .hash => |h| writer.print("        leaf      0x{x}\n", .{h.*}) catch {},
                    .inline_node => writer.print("        leaf      (inline)\n", .{}) catch {},
                }
                return lf.value;
            },
        }
    }
}

// ─── verifyAccount ─────────────────────────────────────────────────────────────

/// Verify that `address` is (or isn't) in the state trie at `state_root`,
/// using the flat `pool` of node preimages from the witness.
///
/// Returns the decoded AccountState on inclusion, or null on valid
/// non-inclusion (address provably absent from the trie).
pub fn verifyAccount(
    state_root: primitives.Hash,
    address: primitives.Address,
    pool: []const []const u8,
) MptError!?AccountState {
    const key_hash = keccak256(&address);
    const value = try verifyProof(state_root, key_hash, pool) orelse return null;

    // Account value is RLP list: [nonce, balance, storageRoot, codeHash]
    const outer = rlp.decodeItem(value) catch return error.InvalidRlp;
    const payload = switch (outer.item) {
        .list => |p| p,
        .bytes => return error.InvalidRlp,
    };
    var rest = payload;

    const nonce_r = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const nonce = decodeUint64(itemBytes(nonce_r.item) orelse return error.InvalidRlp) catch return error.InvalidRlp;
    rest = rest[nonce_r.consumed..];

    const balance_r = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const balance = decodeUint256(itemBytes(balance_r.item) orelse return error.InvalidRlp) catch return error.InvalidRlp;
    rest = rest[balance_r.consumed..];

    const storage_r = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const sbytes = itemBytes(storage_r.item) orelse return error.InvalidRlp;
    if (sbytes.len != 32) return error.InvalidRlp;
    var storage_root: primitives.Hash = undefined;
    @memcpy(&storage_root, sbytes);
    rest = rest[storage_r.consumed..];

    const code_r = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const cbytes = itemBytes(code_r.item) orelse return error.InvalidRlp;
    if (cbytes.len != 32) return error.InvalidRlp;
    var code_hash: primitives.Hash = undefined;
    @memcpy(&code_hash, cbytes);

    return AccountState{
        .nonce = nonce,
        .balance = balance,
        .storage_root = storage_root,
        .code_hash = code_hash,
    };
}

// ─── verifyStorage ─────────────────────────────────────────────────────────────

/// Verify that `slot` is (or isn't) in the storage trie at `storage_root`,
/// using the flat `pool` of node preimages.
///
/// Returns the decoded u256 value, or 0 for a valid non-inclusion proof.
pub fn verifyStorage(
    storage_root: primitives.Hash,
    slot: primitives.Hash,
    pool: []const []const u8,
) MptError!u256 {
    const key_hash = keccak256(&slot);
    const value = try verifyProof(storage_root, key_hash, pool) orelse return 0;

    const r = rlp.decodeItem(value) catch return error.InvalidRlp;
    const bytes = itemBytes(r.item) orelse return error.InvalidRlp;
    if (bytes.len > 32) return error.InvalidRlp;
    return decodeUint256(bytes) catch return error.InvalidRlp;
}

// ─── Indexed verification (O(1) node lookup) ───────────────────────────────────

/// Like verifyProof but uses a pre-built NodeIndex for O(1) lookups.
/// Build the index once with buildNodeIndex() and reuse across all keys.
pub fn verifyProofIndexed(
    root_hash: primitives.Hash,
    key_hash: primitives.Hash,
    index: *const NodeIndex,
) MptError!?[]const u8 {
    if (std.mem.eql(u8, &root_hash, &EMPTY_TRIE_HASH)) return null;

    var key_nibbles: [64]u8 = undefined;
    nibbles.bytesToNibbles(&key_hash, &key_nibbles);

    const ExpectedRef = union(enum) {
        hash: *const [32]u8,
        inline_node: []const u8,
    };
    var expected: ExpectedRef = .{ .hash = &root_hash };
    var pos: usize = 0;

    while (true) {
        const node_rlp: []const u8 = switch (expected) {
            .hash => |h| findNodeInIndex(index, h.*) orelse return error.InvalidProof,
            .inline_node => |inl| inl,
        };

        // Fast path for branch nodes: decode only the child we need (O(nibble)
        // instead of O(17)). decodeNibble returns null for leaf/extension nodes,
        // in which case we fall through to the full decodeNode path below.
        if (pos < 64) {
            const nibble = key_nibbles[pos];
            if (try node.decodeNibble(node_rlp, nibble)) |child_ref| {
                pos += 1;
                switch (child_ref) {
                    .empty => return null,
                    .hash => |h| expected = .{ .hash = h },
                    .inline_node => |inl| expected = .{ .inline_node = inl },
                }
                continue;
            }
        }

        const decoded = node.decodeNode(node_rlp) catch |err| switch (err) {
            error.InvalidRlp => return error.InvalidRlp,
            error.InvalidNode => return error.InvalidNode,
        };

        switch (decoded) {
            .branch => |b| {
                if (pos >= 64) return error.InvalidProof;
                const nibble = key_nibbles[pos];
                pos += 1;
                switch (b.children[nibble]) {
                    .empty => return null,
                    .hash => |h| expected = .{ .hash = h },
                    .inline_node => |inl| expected = .{ .inline_node = inl },
                }
            },
            .extension => |e| {
                var path_buf: [128]u8 = undefined;
                const hp = nibbles.hpDecode(e.prefix, &path_buf) catch return error.InvalidHp;
                if (hp.is_leaf) return error.InvalidNode;
                const prefix_nibs = path_buf[0..hp.len];
                if (pos + prefix_nibs.len > 64) return error.InvalidProof;
                if (!std.mem.eql(u8, prefix_nibs, key_nibbles[pos .. pos + prefix_nibs.len]))
                    return null;
                pos += prefix_nibs.len;
                switch (e.child) {
                    .empty => return error.InvalidNode,
                    .hash => |h| expected = .{ .hash = h },
                    .inline_node => |inl| expected = .{ .inline_node = inl },
                }
            },
            .leaf => |lf| {
                var path_buf: [128]u8 = undefined;
                const hp = nibbles.hpDecode(lf.key_end, &path_buf) catch return error.InvalidHp;
                if (!hp.is_leaf) return error.InvalidNode;
                const suffix_nibs = path_buf[0..hp.len];
                if (suffix_nibs.len != 64 - pos) return null;
                if (!std.mem.eql(u8, suffix_nibs, key_nibbles[pos..])) return null;
                return lf.value;
            },
        }
    }
}

/// Like verifyAccount but uses a pre-built NodeIndex for O(1) node lookups.
pub fn verifyAccountIndexed(
    state_root: primitives.Hash,
    address: primitives.Address,
    index: *const NodeIndex,
) MptError!?AccountState {
    const key_hash = keccak256(&address);
    const value = try verifyProofIndexed(state_root, key_hash, index) orelse return null;

    const outer = rlp.decodeItem(value) catch return error.InvalidRlp;
    const payload = switch (outer.item) {
        .list => |p| p,
        .bytes => return error.InvalidRlp,
    };
    var rest = payload;

    const nonce_r = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const nonce = decodeUint64(itemBytes(nonce_r.item) orelse return error.InvalidRlp) catch return error.InvalidRlp;
    rest = rest[nonce_r.consumed..];

    const balance_r = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const balance = decodeUint256(itemBytes(balance_r.item) orelse return error.InvalidRlp) catch return error.InvalidRlp;
    rest = rest[balance_r.consumed..];

    const storage_r = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const sbytes = itemBytes(storage_r.item) orelse return error.InvalidRlp;
    if (sbytes.len != 32) return error.InvalidRlp;
    var storage_root: primitives.Hash = undefined;
    @memcpy(&storage_root, sbytes);
    rest = rest[storage_r.consumed..];

    const code_r = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const cbytes = itemBytes(code_r.item) orelse return error.InvalidRlp;
    if (cbytes.len != 32) return error.InvalidRlp;
    var code_hash: primitives.Hash = undefined;
    @memcpy(&code_hash, cbytes);

    return AccountState{
        .nonce = nonce,
        .balance = balance,
        .storage_root = storage_root,
        .code_hash = code_hash,
    };
}

/// Like verifyStorage but uses a pre-built NodeIndex for O(1) node lookups.
pub fn verifyStorageIndexed(
    storage_root: primitives.Hash,
    slot: primitives.Hash,
    index: *const NodeIndex,
) MptError!u256 {
    const key_hash = keccak256(&slot);
    const value = try verifyProofIndexed(storage_root, key_hash, index) orelse return 0;

    const r = rlp.decodeItem(value) catch return error.InvalidRlp;
    const bytes = itemBytes(r.item) orelse return error.InvalidRlp;
    if (bytes.len > 32) return error.InvalidRlp;
    return decodeUint256(bytes) catch return error.InvalidRlp;
}

// ─── verifyWitness ─────────────────────────────────────────────────────────────

/// Verify all account and storage proofs in the witness.
/// Returns the proven pre-state root (== witness.state_root).
///
/// Keys with length 20 are account addresses.
/// Keys with length 52 are address (20) + storage slot (32).
/// Keys with length 32 are standalone storage slots that belong to the
/// nearest preceding account address (20-byte key) in the array.
pub fn verifyWitness(witness: input.StateWitness) MptError!primitives.Hash {
    var current_addr: ?primitives.Address = null;

    for (witness.keys) |key| {
        if (key.len == 20) {
            var addr: primitives.Address = undefined;
            @memcpy(&addr, key[0..20]);
            current_addr = addr;
            _ = try verifyAccount(witness.state_root, addr, witness.nodes);
        } else if (key.len == 52) {
            var addr: primitives.Address = undefined;
            @memcpy(&addr, key[0..20]);
            current_addr = addr;
            var raw_slot: primitives.Hash = undefined;
            @memcpy(&raw_slot, key[20..52]);

            // Must verify the account first to get its storage_root.
            const account_state = try verifyAccount(witness.state_root, addr, witness.nodes);
            const storage_root = if (account_state) |as| as.storage_root else EMPTY_TRIE_HASH;
            _ = try verifyStorage(storage_root, raw_slot, witness.nodes);
        } else if (key.len == 32) {
            // Standalone slot: context account is the nearest preceding address key.
            if (current_addr) |addr| {
                var raw_slot: primitives.Hash = undefined;
                @memcpy(&raw_slot, key[0..32]);

                const account_state = try verifyAccount(witness.state_root, addr, witness.nodes);
                const storage_root = if (account_state) |as| as.storage_root else EMPTY_TRIE_HASH;
                _ = try verifyStorage(storage_root, raw_slot, witness.nodes);
            }
        }
    }
    return witness.state_root;
}

/// Apply a state account write to an existing state trie rooted at `root`,
/// using combined pool+extra lookups for chained updates.
///
/// `addr_key` is keccak256(address) — the 32-byte trie key.
/// `account_rlp` is the RLP-encoded account; pass null to delete the account.
pub fn updateAccountChained(
    alloc: std.mem.Allocator,
    root: *[32]u8,
    addr_key: [32]u8,
    account_rlp: ?[]const u8,
    pool: []const []const u8,
    extra: *std.ArrayListUnmanaged([]const u8),
) (MptError || error{OutOfMemory})!void {
    var key_nibs: [64]u8 = undefined;
    nibbles.bytesToNibbles(&addr_key, &key_nibs);

    if (std.mem.eql(u8, root, &EMPTY_TRIE_HASH)) {
        if (account_rlp) |val| {
            const leaf_rlp = try updMakeLeaf(alloc, &key_nibs, val);
            try extra.append(alloc, leaf_rlp);
            root.* = keccak256(leaf_rlp);
        }
        return;
    }

    const root_bytes = findNode(pool, root.*) orelse
        findNode(extra.items, root.*) orelse
        return error.InvalidProof;
    const new_root_rlp = try updNodeEx(alloc, root_bytes, &key_nibs, account_rlp, pool, extra);
    try extra.append(alloc, new_root_rlp);
    root.* = if (new_root_rlp.len == 1 and new_root_rlp[0] == 0x80)
        EMPTY_TRIE_HASH
    else
        keccak256(new_root_rlp);
}

// ─── Private helpers ───────────────────────────────────────────────────────────

const EMPTY_TRIE_HASH: primitives.Hash = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};

fn itemBytes(item: rlp.RlpItem) ?[]const u8 {
    return switch (item) {
        .bytes => |b| b,
        .list => null,
    };
}

fn decodeUint64(bytes: []const u8) error{InvalidRlp}!u64 {
    if (bytes.len == 0) return 0;
    if (bytes.len > 8) return error.InvalidRlp;
    var result: u64 = 0;
    for (bytes) |b| result = (result << 8) | b;
    return result;
}

fn decodeUint256(bytes: []const u8) error{InvalidRlp}!u256 {
    if (bytes.len == 0) return 0;
    if (bytes.len > 32) return error.InvalidRlp;
    var result: u256 = 0;
    for (bytes) |b| result = (result << 8) | b;
    return result;
}

// ─── MPT Update (stateless storage root computation) ─────────────────────────

/// Apply a single storage slot write to an existing storage trie rooted at
/// `old_root`, resolving existing nodes via the witness `pool`.
///
/// `slot` is the raw 32-byte storage key (keccak256'd internally).
/// `new_value` = 0 means delete the slot from the trie.
///
/// Returns the new trie root hash.
pub fn updateStorage(
    alloc: std.mem.Allocator,
    old_root: [32]u8,
    slot: [32]u8,
    new_value: u256,
    pool: []const []const u8,
) (MptError || error{OutOfMemory})![32]u8 {
    const key_hash = keccak256(&slot);
    var key_nibs: [64]u8 = undefined;
    nibbles.bytesToNibbles(&key_hash, &key_nibs);

    const new_val_enc: ?[]const u8 = if (new_value == 0) null else blk: {
        break :blk try updRlpU256(alloc, new_value);
    };

    if (std.mem.eql(u8, &old_root, &EMPTY_TRIE_HASH)) {
        if (new_val_enc) |val| {
            const leaf_rlp = try updMakeLeaf(alloc, &key_nibs, val);
            return keccak256(leaf_rlp);
        }
        return EMPTY_TRIE_HASH;
    }

    const root_bytes = findNode(pool, old_root) orelse return error.InvalidProof;
    const new_root_rlp = try updNode(alloc, root_bytes, &key_nibs, new_val_enc, pool);
    if (new_root_rlp.len == 1 and new_root_rlp[0] == 0x80) return EMPTY_TRIE_HASH;
    return keccak256(new_root_rlp);
}

/// Apply a storage slot write, accumulating new trie nodes in `extra` so that
/// multiple chained updates work correctly.  Pass the SAME `extra` for all
/// updates on one account; it accumulates new node bytes across calls so that
/// each subsequent update can resolve the new root and intermediate nodes that
/// were produced by previous updates.
pub fn updateStorageChained(
    alloc: std.mem.Allocator,
    root: *[32]u8,
    slot: [32]u8,
    new_value: u256,
    pool: []const []const u8,
    extra: *std.ArrayListUnmanaged([]const u8),
) (MptError || error{OutOfMemory})!void {
    const key_hash = keccak256(&slot);
    var key_nibs: [64]u8 = undefined;
    nibbles.bytesToNibbles(&key_hash, &key_nibs);

    const new_val_enc: ?[]const u8 = if (new_value == 0) null else blk: {
        break :blk try updRlpU256(alloc, new_value);
    };

    if (std.mem.eql(u8, root, &EMPTY_TRIE_HASH)) {
        if (new_val_enc) |val| {
            const leaf_rlp = try updMakeLeaf(alloc, &key_nibs, val);
            try extra.append(alloc, leaf_rlp);
            root.* = keccak256(leaf_rlp);
        }
        return;
    }

    // Find root in combined pool (original witness nodes + nodes produced by prior updates)
    const root_bytes = findNode(pool, root.*) orelse
        findNode(extra.items, root.*) orelse
        return error.InvalidProof;
    const new_root_rlp = try updNodeEx(alloc, root_bytes, &key_nibs, new_val_enc, pool, extra);
    // Store new root in extra so the next update can find it
    try extra.append(alloc, new_root_rlp);
    root.* = if (new_root_rlp.len == 1 and new_root_rlp[0] == 0x80)
        EMPTY_TRIE_HASH
    else
        keccak256(new_root_rlp);
}

// ─── Indexed variants of verifyWitness and chained update functions ────────────
//
// These accept a pre-built NodeIndex (hash→node map) produced by buildNodeIndex().
// All pool lookups are O(1) hashmap lookups. New intermediate nodes created during
// updates are inserted into the same index so subsequent lookups remain O(1).

/// Like updateAccountChained but uses a mutable NodeIndex for O(1) lookups.
/// New intermediate nodes are inserted into `index` so subsequent chained updates find them.
pub fn updateAccountChainedIndexed(
    alloc: std.mem.Allocator,
    root: *[32]u8,
    addr_key: [32]u8,
    account_rlp: ?[]const u8,
    index: *NodeIndex,
) (MptError || error{OutOfMemory})!void {
    var key_nibs: [64]u8 = undefined;
    nibbles.bytesToNibbles(&addr_key, &key_nibs);

    if (std.mem.eql(u8, root, &EMPTY_TRIE_HASH)) {
        if (account_rlp) |val| {
            const leaf_rlp = try updMakeLeaf(alloc, &key_nibs, val);
            const h = keccak256(leaf_rlp);
            try index.put(h, leaf_rlp);
            root.* = h;
        }
        return;
    }

    const root_bytes = findNodeInIndex(index, root.*) orelse return error.InvalidProof;
    const new_root_rlp = try updNodeExIndexed(alloc, root_bytes, &key_nibs, account_rlp, index);
    root.* = if (new_root_rlp.len == 1 and new_root_rlp[0] == 0x80)
        EMPTY_TRIE_HASH
    else blk: {
        const h = keccak256(new_root_rlp);
        try index.put(h, new_root_rlp);
        break :blk h;
    };
}

/// Like updateStorageChained but uses a mutable NodeIndex for O(1) lookups.
/// New intermediate nodes are inserted into `index` so subsequent chained updates find them.
pub fn updateStorageChainedIndexed(
    alloc: std.mem.Allocator,
    root: *[32]u8,
    slot: [32]u8,
    new_value: u256,
    index: *NodeIndex,
) (MptError || error{OutOfMemory})!void {
    const key_hash = keccak256(&slot);
    var key_nibs: [64]u8 = undefined;
    nibbles.bytesToNibbles(&key_hash, &key_nibs);

    const new_val_enc: ?[]const u8 = if (new_value == 0) null else blk: {
        break :blk try updRlpU256(alloc, new_value);
    };

    if (std.mem.eql(u8, root, &EMPTY_TRIE_HASH)) {
        if (new_val_enc) |val| {
            const leaf_rlp = try updMakeLeaf(alloc, &key_nibs, val);
            const h = keccak256(leaf_rlp);
            try index.put(h, leaf_rlp);
            root.* = h;
        }
        return;
    }

    const root_bytes = findNodeInIndex(index, root.*) orelse return error.InvalidProof;
    const new_root_rlp = try updNodeExIndexed(alloc, root_bytes, &key_nibs, new_val_enc, index);
    root.* = if (new_root_rlp.len == 1 and new_root_rlp[0] == 0x80)
        EMPTY_TRIE_HASH
    else blk: {
        const h = keccak256(new_root_rlp);
        try index.put(h, new_root_rlp);
        break :blk h;
    };
}

// ─── Batch trie update ─────────────────────────────────────────────────────────

/// A single keyed change for a batch trie update.
/// `key` is the 32-byte trie key (keccak256(address) for state, keccak256(slot) for storage).
/// `value` is the RLP-encoded value to insert, or null to delete.
pub const BatchChange = struct {
    key: [32]u8,
    value: ?[]const u8,
};

/// Batch-update a trie with multiple pre-sorted changes, visiting each branch node once.
/// `sorted_changes` must be sorted ascending by `key`.
/// Returns the new root hash.
pub fn batchUpdateIndexed(
    alloc: std.mem.Allocator,
    root: [32]u8,
    sorted_changes: []const BatchChange,
    index: *NodeIndex,
) (MptError || error{OutOfMemory})![32]u8 {
    if (sorted_changes.len == 0) return root;
    const root_rlp: []const u8 = if (std.mem.eql(u8, &root, &EMPTY_TRIE_HASH))
        &.{0x80}
    else
        findNodeInIndex(index, root) orelse return error.InvalidProof;
    const new_root_rlp = try batchUpdateNodeIndexed(alloc, root_rlp, sorted_changes, 0, index);
    return commitRoot(new_root_rlp);
}

fn commitRoot(new_root_rlp: []const u8) [32]u8 {
    if (new_root_rlp.len == 1 and new_root_rlp[0] == 0x80) return EMPTY_TRIE_HASH;
    return keccak256(new_root_rlp);
}

inline fn nibbleAt(key: *const [32]u8, depth: u8) u8 {
    return if (depth & 1 == 0) key[depth / 2] >> 4 else key[depth / 2] & 0x0f;
}

fn batchUpdateNodeIndexed(
    alloc: std.mem.Allocator,
    node_rlp: []const u8,
    changes: []const BatchChange,
    depth: u8,
    index: *NodeIndex,
) (MptError || error{OutOfMemory})![]const u8 {
    if (changes.len == 1) {
        var key_nibs: [64]u8 = undefined;
        nibbles.bytesToNibbles(&changes[0].key, &key_nibs);
        // Insertion (value != null): no collapse possible, skip index.put for new nodes.
        // Deletion (value == null): collapseIndexed may look up a sole remaining child
        //   by hash — must use the put variant so the child is findable.
        return if (changes[0].value != null)
            updNodeExBatch(alloc, node_rlp, key_nibs[depth..], changes[0].value, index)
        else
            updNodeExIndexed(alloc, node_rlp, key_nibs[depth..], changes[0].value, index);
    }

    // Empty subtree with multiple inserts: build sequentially.
    // Each iteration may create hashed intermediate nodes that subsequent iterations
    // resolve via findNodeInIndex — index.put is required here.
    if (node_rlp.len == 1 and node_rlp[0] == 0x80) {
        var current = node_rlp;
        for (changes) |ch| {
            var key_nibs: [64]u8 = undefined;
            nibbles.bytesToNibbles(&ch.key, &key_nibs);
            current = try updNodeExIndexed(alloc, current, key_nibs[depth..], ch.value, index);
        }
        return current;
    }

    const decoded = node.decodeNode(node_rlp) catch |err| switch (err) {
        error.InvalidRlp => return error.InvalidRlp,
        error.InvalidNode => return error.InvalidNode,
    };

    switch (decoded) {
        .branch => |b| {
            var enc: [16][]const u8 = undefined;
            for (b.children, 0..) |child, i| enc[i] = refEncSlice(node_rlp, child);

            // Collapse is only possible when at least one change is a deletion.
            // When has_deletion=false, collapseIndexed is never called, so new child nodes
            // need not be inserted into the index — callers receive them via return values.
            const has_deletion = for (changes) |ch| {
                if (ch.value == null) break true;
            } else false;

            // Partition sorted changes by nibble at this depth; each run is contiguous.
            var i: usize = 0;
            while (i < changes.len) {
                const nib = nibbleAt(&changes[i].key, depth);
                var j = i + 1;
                while (j < changes.len and nibbleAt(&changes[j].key, depth) == nib) j += 1;

                const child_rlp: []const u8 = switch (b.children[nib]) {
                    .empty => &.{0x80},
                    .hash => |h| findNodeInIndex(index, h.*) orelse return error.InvalidProof,
                    .inline_node => |il| il,
                };
                const new_child_rlp = try batchUpdateNodeIndexed(alloc, child_rlp, changes[i..j], depth + 1, index);
                enc[nib] = if (has_deletion)
                    try updHashOrEmbedExIndexed(alloc, new_child_rlp, index)
                else
                    try updHashOrEmbed(alloc, new_child_rlp);
                i = j;
            }

            // Collapse branch if a deletion leaves exactly one non-empty child with no value.
            // Only possible when at least one change is a deletion (value == null).

            if (has_deletion and b.value.len == 0) {
                var sole: i32 = -1;
                for (enc, 0..) |ce, ci| {
                    if (ce.len == 1 and ce[0] == 0x80) continue;
                    if (sole >= 0) {
                        sole = -2;
                        break;
                    }
                    sole = @intCast(ci);
                }
                if (sole >= 0) return collapseIndexed(alloc, @intCast(sole), enc[@intCast(sole)], index);
                if (sole == -1) return &EMPTY_NODE_RLP;
            }

            return updEncodeBranch(alloc, &enc, b.value);
        },

        // Extension and leaf: fall back to sequential single-change updates.
        // These cases are rare for multi-change batches (most shared ancestors are branches).
        // Each iteration may look up children created by the previous one via findNodeInIndex —
        // index.put is required here.
        else => {
            var current = node_rlp;
            for (changes) |ch| {
                var key_nibs: [64]u8 = undefined;
                nibbles.bytesToNibbles(&ch.key, &key_nibs);
                current = try updNodeExIndexed(alloc, current, key_nibs[depth..], ch.value, index);
            }
            return current;
        },
    }
}

/// Like updResolveRefEx but uses NodeIndex for O(1) lookups.
/// New nodes created during updates are inserted into the same index, so a single lookup suffices.
fn updResolveRefExIndexed(ref: node.NodeRef, index: *const NodeIndex) MptError![]const u8 {
    return switch (ref) {
        .empty => &.{0x80},
        .hash => |h| findNodeInIndex(index, h.*) orelse return error.InvalidProof,
        .inline_node => |b| b,
    };
}

/// Like updNodeEx but uses a single mutable NodeIndex for O(1) pool lookups.
/// New intermediate nodes are inserted into `index` so subsequent chained updates find them.
/// Single-change indexed trie update. `store_in_index` controls whether newly
/// created intermediate nodes are inserted into `index`.
///
///   store_in_index = true  → chained update path (updateAccountChainedIndexed /
///                             updateStorageChainedIndexed): subsequent calls need
///                             to find nodes created by earlier calls.
///   store_in_index = false → batch update path (batchUpdateIndexed): all lookups
///                             use pre-existing witness nodes; newly created nodes
///                             are returned directly up the call stack and never
///                             looked up via the index within the same traversal.
fn updNodeExImpl(
    comptime store_in_index: bool,
    alloc: std.mem.Allocator,
    node_rlp: []const u8,
    remaining: []const u8,
    new_val: ?[]const u8,
    index: *NodeIndex,
) (MptError || error{OutOfMemory})![]const u8 {
    if (node_rlp.len == 1 and node_rlp[0] == 0x80) {
        if (new_val) |val| return updMakeLeaf(alloc, remaining, val);
        return &EMPTY_NODE_RLP;
    }

    const decoded = node.decodeNode(node_rlp) catch |err| switch (err) {
        error.InvalidRlp => return error.InvalidRlp,
        error.InvalidNode => return error.InvalidNode,
    };

    switch (decoded) {
        .branch => |b| {
            if (remaining.len == 0) {
                var enc: [16][]const u8 = undefined;
                for (b.children, 0..) |child, i| enc[i] = refEncSlice(node_rlp, child);
                return updEncodeBranch(alloc, &enc, new_val orelse &.{});
            }
            const nib = remaining[0];
            const child_rlp = try updResolveRefExIndexed(b.children[nib], index);
            const new_child_rlp = try updNodeExImpl(store_in_index, alloc, child_rlp, remaining[1..], new_val, index);
            const new_child_enc = if (comptime store_in_index) try updHashOrEmbedExIndexed(alloc, new_child_rlp, index) else try updHashOrEmbed(alloc, new_child_rlp);
            var enc: [16][]const u8 = undefined;
            for (b.children, 0..) |child, i| enc[i] = refEncSlice(node_rlp, child);
            enc[nib] = new_child_enc;

            // Collapse branch if deletion leaves only one non-empty child with no value.
            // Canonical MPT requires replacing such a branch with an extension or leaf.
            if (new_val == null and b.value.len == 0) {
                var sole: i32 = -1;
                for (enc, 0..) |ce, i| {
                    const empty = ce.len == 1 and ce[0] == 0x80;
                    if (!empty) {
                        if (sole >= 0) {
                            sole = -2;
                            break;
                        }
                        sole = @intCast(i);
                    }
                }
                if (sole >= 0) return collapseIndexed(alloc, @intCast(sole), enc[@intCast(sole)], index);
                if (sole == -1) return &EMPTY_NODE_RLP; // all children empty
            }

            return updEncodeBranch(alloc, &enc, b.value);
        },

        .extension => |e| {
            var path_buf: [128]u8 = undefined;
            const hp = nibbles.hpDecode(e.prefix, &path_buf) catch return error.InvalidHp;
            if (hp.is_leaf) return error.InvalidNode;
            const prefix = path_buf[0..hp.len];
            const cp = nibbles.commonPrefixLen(prefix, remaining);

            if (cp == prefix.len) {
                const child_rlp = try updResolveRefExIndexed(e.child, index);
                const new_child_rlp = try updNodeExImpl(store_in_index, alloc, child_rlp, remaining[cp..], new_val, index);
                if (new_child_rlp.len == 1 and new_child_rlp[0] == 0x80)
                    return &EMPTY_NODE_RLP;

                // When a deletion collapses a descendant branch into a short node,
                // merge the extension path with the child's path (canonical form).
                if (new_val == null) {
                    const cd = node.decodeNode(new_child_rlp) catch null;
                    if (cd) |decoded_child| {
                        var cpb: [128]u8 = undefined;
                        var merged: [64]u8 = undefined;
                        @memcpy(merged[0..prefix.len], prefix);
                        switch (decoded_child) {
                            .leaf => |lf| {
                                const chp = nibbles.hpDecode(lf.key_end, &cpb) catch return error.InvalidHp;
                                @memcpy(merged[prefix.len .. prefix.len + chp.len], cpb[0..chp.len]);
                                return updMakeLeaf(alloc, merged[0 .. prefix.len + chp.len], lf.value);
                            },
                            .extension => |ee| {
                                const chp = nibbles.hpDecode(ee.prefix, &cpb) catch return error.InvalidHp;
                                @memcpy(merged[prefix.len .. prefix.len + chp.len], cpb[0..chp.len]);
                                const child_ref = try updRefEnc(alloc, ee.child);
                                return updMakeExtension(alloc, merged[0 .. prefix.len + chp.len], child_ref);
                            },
                            .branch => {},
                        }
                    }
                }

                const new_child_ref = if (comptime store_in_index) try updHashOrEmbedExIndexed(alloc, new_child_rlp, index) else try updHashOrEmbed(alloc, new_child_rlp);
                return updMakeExtension(alloc, prefix, new_child_ref);
            }

            // Key diverges from extension prefix → key doesn't exist → return unchanged.
            if (new_val == null) {
                const child_ref = try updRefEnc(alloc, e.child);
                return updMakeExtension(alloc, prefix, child_ref);
            }

            // Partial prefix match: split extension at position `cp`
            var children_enc: [16][]const u8 = undefined;
            for (&children_enc) |*enc| enc.* = &EMPTY_NODE_RLP;
            var branch_val: []const u8 = &.{};

            const old_nib = prefix[cp];
            if (cp + 1 < prefix.len) {
                const ext_rlp = try updMakeExtension(alloc, prefix[cp + 1 ..], try updRefEnc(alloc, e.child));
                children_enc[old_nib] = if (comptime store_in_index) try updHashOrEmbedExIndexed(alloc, ext_rlp, index) else try updHashOrEmbed(alloc, ext_rlp);
            } else {
                children_enc[old_nib] = try updRefEnc(alloc, e.child);
            }
            if (new_val) |val| {
                if (cp < remaining.len) {
                    const new_nib = remaining[cp];
                    const leaf_rlp = try updMakeLeaf(alloc, remaining[cp + 1 ..], val);
                    children_enc[new_nib] = if (comptime store_in_index) try updHashOrEmbedExIndexed(alloc, leaf_rlp, index) else try updHashOrEmbed(alloc, leaf_rlp);
                } else {
                    branch_val = val;
                }
            }
            const branch_rlp = try updEncodeBranch(alloc, &children_enc, branch_val);
            if (cp == 0) return branch_rlp;
            const branch_ref = if (comptime store_in_index) try updHashOrEmbedExIndexed(alloc, branch_rlp, index) else try updHashOrEmbed(alloc, branch_rlp);
            return updMakeExtension(alloc, prefix[0..cp], branch_ref);
        },

        .leaf => |lf| {
            var path_buf: [128]u8 = undefined;
            const hp = nibbles.hpDecode(lf.key_end, &path_buf) catch return error.InvalidHp;
            if (!hp.is_leaf) return error.InvalidNode;
            const suffix = path_buf[0..hp.len];
            const cp = nibbles.commonPrefixLen(suffix, remaining);

            if (cp == suffix.len and cp == remaining.len) {
                if (new_val) |val| return updMakeLeaf(alloc, suffix, val);
                return &EMPTY_NODE_RLP;
            }

            if (new_val == null) {
                return updMakeLeaf(alloc, suffix, lf.value);
            }

            var children_enc: [16][]const u8 = undefined;
            for (&children_enc) |*enc| enc.* = &EMPTY_NODE_RLP;
            var branch_val: []const u8 = &.{};

            if (cp < suffix.len) {
                const old_nib = suffix[cp];
                const old_leaf_rlp = try updMakeLeaf(alloc, suffix[cp + 1 ..], lf.value);
                children_enc[old_nib] = if (comptime store_in_index) try updHashOrEmbedExIndexed(alloc, old_leaf_rlp, index) else try updHashOrEmbed(alloc, old_leaf_rlp);
            } else {
                branch_val = lf.value;
            }
            if (cp < remaining.len) {
                const new_nib = remaining[cp];
                const new_leaf_rlp = try updMakeLeaf(alloc, remaining[cp + 1 ..], new_val.?);
                children_enc[new_nib] = if (comptime store_in_index) try updHashOrEmbedExIndexed(alloc, new_leaf_rlp, index) else try updHashOrEmbed(alloc, new_leaf_rlp);
            } else {
                branch_val = new_val.?;
            }
            const branch_rlp = try updEncodeBranch(alloc, &children_enc, branch_val);
            if (cp == 0) return branch_rlp;
            const branch_ref = if (comptime store_in_index) try updHashOrEmbedExIndexed(alloc, branch_rlp, index) else try updHashOrEmbed(alloc, branch_rlp);
            return updMakeExtension(alloc, suffix[0..cp], branch_ref);
        },
    }
}

fn updNodeExIndexed(
    alloc: std.mem.Allocator,
    node_rlp: []const u8,
    remaining: []const u8,
    new_val: ?[]const u8,
    index: *NodeIndex,
) (MptError || error{OutOfMemory})![]const u8 {
    return updNodeExImpl(true, alloc, node_rlp, remaining, new_val, index);
}

fn updNodeExBatch(
    alloc: std.mem.Allocator,
    node_rlp: []const u8,
    remaining: []const u8,
    new_val: ?[]const u8,
    index: *NodeIndex,
) (MptError || error{OutOfMemory})![]const u8 {
    return updNodeExImpl(false, alloc, node_rlp, remaining, new_val, index);
}

/// Recursively update a node and return its new RLP bytes.
/// Returns `&.{0x80}` (empty node) when the subtree becomes empty.
fn updNode(
    alloc: std.mem.Allocator,
    node_rlp: []const u8,
    remaining: []const u8,
    new_val: ?[]const u8,
    pool: []const []const u8,
) (MptError || error{OutOfMemory})![]const u8 {
    // Empty node
    if (node_rlp.len == 1 and node_rlp[0] == 0x80) {
        if (new_val) |val| return updMakeLeaf(alloc, remaining, val);
        return &EMPTY_NODE_RLP;
    }

    const decoded = node.decodeNode(node_rlp) catch |err| switch (err) {
        error.InvalidRlp => return error.InvalidRlp,
        error.InvalidNode => return error.InvalidNode,
    };

    switch (decoded) {
        .branch => |b| {
            if (remaining.len == 0) {
                // Update branch value slot (rare in Ethereum storage tries)
                var enc: [16][]const u8 = undefined;
                for (b.children, 0..) |child, i| enc[i] = refEncSlice(node_rlp, child);
                return updEncodeBranch(alloc, &enc, new_val orelse &.{});
            }
            const nib = remaining[0];
            const child_rlp = try updResolveRef(b.children[nib], pool);
            const new_child_rlp = try updNode(alloc, child_rlp, remaining[1..], new_val, pool);
            const new_child_enc = try updHashOrEmbed(alloc, new_child_rlp);
            var enc: [16][]const u8 = undefined;
            for (b.children, 0..) |child, i| enc[i] = refEncSlice(node_rlp, child);
            enc[nib] = new_child_enc;

            // Collapse branch if deletion leaves only one non-empty child with no value.
            if (new_val == null and b.value.len == 0) {
                var sole: i32 = -1;
                for (enc, 0..) |ce, i| {
                    const empty = ce.len == 1 and ce[0] == 0x80;
                    if (!empty) {
                        if (sole >= 0) {
                            sole = -2;
                            break;
                        }
                        sole = @intCast(i);
                    }
                }
                if (sole >= 0) return collapseNode(alloc, @intCast(sole), enc[@intCast(sole)], pool);
                if (sole == -1) return &EMPTY_NODE_RLP;
            }

            return updEncodeBranch(alloc, &enc, b.value);
        },

        .extension => |e| {
            var path_buf: [128]u8 = undefined;
            const hp = nibbles.hpDecode(e.prefix, &path_buf) catch return error.InvalidHp;
            if (hp.is_leaf) return error.InvalidNode;
            const prefix = path_buf[0..hp.len];
            const cp = nibbles.commonPrefixLen(prefix, remaining);

            if (cp == prefix.len) {
                // Full prefix match: recurse into child
                const child_rlp = try updResolveRef(e.child, pool);
                const new_child_rlp = try updNode(alloc, child_rlp, remaining[cp..], new_val, pool);
                if (new_child_rlp.len == 1 and new_child_rlp[0] == 0x80)
                    return &EMPTY_NODE_RLP;

                // Merge extension path with a collapsed child (canonical form).
                if (new_val == null) {
                    const cd = node.decodeNode(new_child_rlp) catch null;
                    if (cd) |decoded_child| {
                        var cpb: [128]u8 = undefined;
                        var merged: [64]u8 = undefined;
                        @memcpy(merged[0..prefix.len], prefix);
                        switch (decoded_child) {
                            .leaf => |lf| {
                                const chp = nibbles.hpDecode(lf.key_end, &cpb) catch return error.InvalidHp;
                                @memcpy(merged[prefix.len .. prefix.len + chp.len], cpb[0..chp.len]);
                                return updMakeLeaf(alloc, merged[0 .. prefix.len + chp.len], lf.value);
                            },
                            .extension => |ee| {
                                const chp = nibbles.hpDecode(ee.prefix, &cpb) catch return error.InvalidHp;
                                @memcpy(merged[prefix.len .. prefix.len + chp.len], cpb[0..chp.len]);
                                const child_ref = try updRefEnc(alloc, ee.child);
                                return updMakeExtension(alloc, merged[0 .. prefix.len + chp.len], child_ref);
                            },
                            .branch => {},
                        }
                    }
                }

                const new_child_ref = try updHashOrEmbed(alloc, new_child_rlp);
                return updMakeExtension(alloc, prefix, new_child_ref);
            }

            // Key diverges from extension prefix → key doesn't exist → return unchanged.
            if (new_val == null) {
                const child_ref = try updRefEnc(alloc, e.child);
                return updMakeExtension(alloc, prefix, child_ref);
            }

            // Partial prefix match: split extension at position `cp`
            var children_enc: [16][]const u8 = undefined;
            for (&children_enc) |*enc| enc.* = &EMPTY_NODE_RLP;
            var branch_val: []const u8 = &.{};

            // Old extension tail goes into branch
            const old_nib = prefix[cp];
            if (cp + 1 < prefix.len) {
                const ext_rlp = try updMakeExtension(alloc, prefix[cp + 1 ..], try updRefEnc(alloc, e.child));
                children_enc[old_nib] = try updHashOrEmbed(alloc, ext_rlp);
            } else {
                children_enc[old_nib] = try updRefEnc(alloc, e.child);
            }
            // New key tail
            if (new_val) |val| {
                if (cp < remaining.len) {
                    const new_nib = remaining[cp];
                    const leaf_rlp = try updMakeLeaf(alloc, remaining[cp + 1 ..], val);
                    children_enc[new_nib] = try updHashOrEmbed(alloc, leaf_rlp);
                } else {
                    branch_val = val;
                }
            }
            const branch_rlp = try updEncodeBranch(alloc, &children_enc, branch_val);
            if (cp == 0) return branch_rlp;
            const branch_ref = try updHashOrEmbed(alloc, branch_rlp);
            return updMakeExtension(alloc, prefix[0..cp], branch_ref);
        },

        .leaf => |lf| {
            var path_buf: [128]u8 = undefined;
            const hp = nibbles.hpDecode(lf.key_end, &path_buf) catch return error.InvalidHp;
            if (!hp.is_leaf) return error.InvalidNode;
            const suffix = path_buf[0..hp.len];
            const cp = nibbles.commonPrefixLen(suffix, remaining);

            if (cp == suffix.len and cp == remaining.len) {
                // Full key match: update or delete
                if (new_val) |val| return updMakeLeaf(alloc, suffix, val);
                return &EMPTY_NODE_RLP;
            }

            if (new_val == null) {
                // Deleting a non-existent key: return leaf unchanged
                return updMakeLeaf(alloc, suffix, lf.value);
            }

            // Divergence: split into branch (+ optional extension)
            var children_enc: [16][]const u8 = undefined;
            for (&children_enc) |*enc| enc.* = &EMPTY_NODE_RLP;
            var branch_val: []const u8 = &.{};

            if (cp < suffix.len) {
                const old_nib = suffix[cp];
                const old_leaf_rlp = try updMakeLeaf(alloc, suffix[cp + 1 ..], lf.value);
                children_enc[old_nib] = try updHashOrEmbed(alloc, old_leaf_rlp);
            } else {
                branch_val = lf.value; // existing leaf ends exactly at the branch
            }
            if (cp < remaining.len) {
                const new_nib = remaining[cp];
                const new_leaf_rlp = try updMakeLeaf(alloc, remaining[cp + 1 ..], new_val.?);
                children_enc[new_nib] = try updHashOrEmbed(alloc, new_leaf_rlp);
            } else {
                branch_val = new_val.?; // new key ends exactly at the branch
            }
            const branch_rlp = try updEncodeBranch(alloc, &children_enc, branch_val);
            if (cp == 0) return branch_rlp;
            const branch_ref = try updHashOrEmbed(alloc, branch_rlp);
            return updMakeExtension(alloc, suffix[0..cp], branch_ref);
        },
    }
}

/// Like updNode but uses combined pool+extra lookups and deposits new nodes into extra.
fn updNodeEx(
    alloc: std.mem.Allocator,
    node_rlp: []const u8,
    remaining: []const u8,
    new_val: ?[]const u8,
    pool: []const []const u8,
    extra: *std.ArrayListUnmanaged([]const u8),
) (MptError || error{OutOfMemory})![]const u8 {
    if (node_rlp.len == 1 and node_rlp[0] == 0x80) {
        if (new_val) |val| return updMakeLeaf(alloc, remaining, val);
        return &EMPTY_NODE_RLP;
    }

    const decoded = node.decodeNode(node_rlp) catch |err| switch (err) {
        error.InvalidRlp => return error.InvalidRlp,
        error.InvalidNode => return error.InvalidNode,
    };

    switch (decoded) {
        .branch => |b| {
            if (remaining.len == 0) {
                var enc: [16][]const u8 = undefined;
                for (b.children, 0..) |child, i| enc[i] = refEncSlice(node_rlp, child);
                return updEncodeBranch(alloc, &enc, new_val orelse &.{});
            }
            const nib = remaining[0];
            const child_rlp = try updResolveRefEx(b.children[nib], pool, extra.items);
            const new_child_rlp = try updNodeEx(alloc, child_rlp, remaining[1..], new_val, pool, extra);
            const new_child_enc = try updHashOrEmbedEx(alloc, new_child_rlp, extra);
            var enc: [16][]const u8 = undefined;
            for (b.children, 0..) |child, i| enc[i] = refEncSlice(node_rlp, child);
            enc[nib] = new_child_enc;

            // Collapse branch if deletion leaves only one non-empty child with no value.
            if (new_val == null and b.value.len == 0) {
                var sole: i32 = -1;
                for (enc, 0..) |ce, i| {
                    const empty = ce.len == 1 and ce[0] == 0x80;
                    if (!empty) {
                        if (sole >= 0) {
                            sole = -2;
                            break;
                        }
                        sole = @intCast(i);
                    }
                }
                if (sole >= 0) return collapseNodeEx(alloc, @intCast(sole), enc[@intCast(sole)], pool, extra);
                if (sole == -1) return &EMPTY_NODE_RLP;
            }

            return updEncodeBranch(alloc, &enc, b.value);
        },

        .extension => |e| {
            var path_buf: [128]u8 = undefined;
            const hp = nibbles.hpDecode(e.prefix, &path_buf) catch return error.InvalidHp;
            if (hp.is_leaf) return error.InvalidNode;
            const prefix = path_buf[0..hp.len];
            const cp = nibbles.commonPrefixLen(prefix, remaining);

            if (cp == prefix.len) {
                const child_rlp = try updResolveRefEx(e.child, pool, extra.items);
                const new_child_rlp = try updNodeEx(alloc, child_rlp, remaining[cp..], new_val, pool, extra);
                if (new_child_rlp.len == 1 and new_child_rlp[0] == 0x80)
                    return &EMPTY_NODE_RLP;

                // Merge extension path with a collapsed child (canonical form).
                if (new_val == null) {
                    const cd = node.decodeNode(new_child_rlp) catch null;
                    if (cd) |decoded_child| {
                        var cpb: [128]u8 = undefined;
                        var merged: [64]u8 = undefined;
                        @memcpy(merged[0..prefix.len], prefix);
                        switch (decoded_child) {
                            .leaf => |lf| {
                                const chp = nibbles.hpDecode(lf.key_end, &cpb) catch return error.InvalidHp;
                                @memcpy(merged[prefix.len .. prefix.len + chp.len], cpb[0..chp.len]);
                                return updMakeLeaf(alloc, merged[0 .. prefix.len + chp.len], lf.value);
                            },
                            .extension => |ee| {
                                const chp = nibbles.hpDecode(ee.prefix, &cpb) catch return error.InvalidHp;
                                @memcpy(merged[prefix.len .. prefix.len + chp.len], cpb[0..chp.len]);
                                const child_ref = try updRefEnc(alloc, ee.child);
                                return updMakeExtension(alloc, merged[0 .. prefix.len + chp.len], child_ref);
                            },
                            .branch => {},
                        }
                    }
                }

                const new_child_ref = try updHashOrEmbedEx(alloc, new_child_rlp, extra);
                return updMakeExtension(alloc, prefix, new_child_ref);
            }

            // Key diverges from extension prefix → key doesn't exist → return unchanged.
            if (new_val == null) {
                const child_ref = try updRefEnc(alloc, e.child);
                return updMakeExtension(alloc, prefix, child_ref);
            }

            var children_enc: [16][]const u8 = undefined;
            for (&children_enc) |*enc| enc.* = &EMPTY_NODE_RLP;
            var branch_val: []const u8 = &.{};

            const old_nib = prefix[cp];
            if (cp + 1 < prefix.len) {
                const ext_rlp = try updMakeExtension(alloc, prefix[cp + 1 ..], try updRefEnc(alloc, e.child));
                children_enc[old_nib] = try updHashOrEmbedEx(alloc, ext_rlp, extra);
            } else {
                children_enc[old_nib] = try updRefEnc(alloc, e.child);
            }
            if (new_val) |val| {
                if (cp < remaining.len) {
                    const new_nib = remaining[cp];
                    const leaf_rlp = try updMakeLeaf(alloc, remaining[cp + 1 ..], val);
                    children_enc[new_nib] = try updHashOrEmbedEx(alloc, leaf_rlp, extra);
                } else {
                    branch_val = val;
                }
            }
            const branch_rlp = try updEncodeBranch(alloc, &children_enc, branch_val);
            if (cp == 0) return branch_rlp;
            const branch_ref = try updHashOrEmbedEx(alloc, branch_rlp, extra);
            return updMakeExtension(alloc, prefix[0..cp], branch_ref);
        },

        .leaf => |lf| {
            var path_buf: [128]u8 = undefined;
            const hp = nibbles.hpDecode(lf.key_end, &path_buf) catch return error.InvalidHp;
            if (!hp.is_leaf) return error.InvalidNode;
            const suffix = path_buf[0..hp.len];
            const cp = nibbles.commonPrefixLen(suffix, remaining);

            if (cp == suffix.len and cp == remaining.len) {
                if (new_val) |val| return updMakeLeaf(alloc, suffix, val);
                return &EMPTY_NODE_RLP;
            }

            if (new_val == null) {
                return updMakeLeaf(alloc, suffix, lf.value);
            }

            var children_enc: [16][]const u8 = undefined;
            for (&children_enc) |*enc| enc.* = &EMPTY_NODE_RLP;
            var branch_val: []const u8 = &.{};

            if (cp < suffix.len) {
                const old_nib = suffix[cp];
                const old_leaf_rlp = try updMakeLeaf(alloc, suffix[cp + 1 ..], lf.value);
                children_enc[old_nib] = try updHashOrEmbedEx(alloc, old_leaf_rlp, extra);
            } else {
                branch_val = lf.value;
            }
            if (cp < remaining.len) {
                const new_nib = remaining[cp];
                const new_leaf_rlp = try updMakeLeaf(alloc, remaining[cp + 1 ..], new_val.?);
                children_enc[new_nib] = try updHashOrEmbedEx(alloc, new_leaf_rlp, extra);
            } else {
                branch_val = new_val.?;
            }
            const branch_rlp = try updEncodeBranch(alloc, &children_enc, branch_val);
            if (cp == 0) return branch_rlp;
            const branch_ref = try updHashOrEmbedEx(alloc, branch_rlp, extra);
            return updMakeExtension(alloc, suffix[0..cp], branch_ref);
        },
    }
}

// ─── Update helpers ───────────────────────────────────────────────────────────

fn updResolveRef(ref: node.NodeRef, pool: []const []const u8) MptError![]const u8 {
    return switch (ref) {
        .empty => &.{0x80},
        .hash => |h| findNode(pool, h.*) orelse return error.InvalidProof,
        .inline_node => |b| b,
    };
}

fn updResolveRefEx(ref: node.NodeRef, pool: []const []const u8, extra_items: []const []const u8) MptError![]const u8 {
    return switch (ref) {
        .empty => &.{0x80},
        .hash => |h| findNode(pool, h.*) orelse findNode(extra_items, h.*) orelse return error.InvalidProof,
        .inline_node => |b| b,
    };
}

fn updRefEnc(alloc: std.mem.Allocator, ref: node.NodeRef) ![]const u8 {
    return switch (ref) {
        .empty => &EMPTY_NODE_RLP,
        .hash => |h| updRlpBytes(alloc, h),
        .inline_node => |b| b,
    };
}

/// Zero-copy variant of updRefEnc for unchanged branch children.
/// Returns a slice directly into parent_rlp (hash/inline cases) or a static literal (empty).
/// Caller must ensure parent_rlp is the exact node bytes from which `ref` was decoded.
inline fn refEncSlice(parent_rlp: []const u8, ref: node.NodeRef) []const u8 {
    return switch (ref) {
        .empty => &.{0x80},
        .inline_node => |b| b,
        .hash => |h| blk: {
            // h points 1 byte past the 0xa0 RLP prefix inside parent_rlp.
            const off = @intFromPtr(h) - @intFromPtr(parent_rlp.ptr);
            break :blk parent_rlp[off - 1 .. off + 32];
        },
    };
}

/// Collapse a branch's sole remaining child into the canonical short-node form.
///
/// After a deletion leaves a branch with exactly one non-empty child (no value),
/// Ethereum's MPT requires replacing the branch with either a leaf or extension
/// whose path has the child's nibble prepended. This mirrors go-ethereum's
/// "fold back into a short node" logic.
///
/// `child_enc` is the parent-encoded reference already in `enc[sole_nib]`:
///   - hash ref: 33 bytes, child_enc[0] == 0xa0
///   - inline node: raw RLP bytes (< 32 bytes)
fn collapseIndexed(
    alloc: std.mem.Allocator,
    sole_nib: u8,
    child_enc: []const u8,
    index: *NodeIndex,
) (MptError || error{OutOfMemory})![]const u8 {
    // Resolve the child's actual RLP bytes.
    const child_bytes: []const u8 = blk: {
        if (child_enc.len == 33 and child_enc[0] == 0xa0) {
            var h: [32]u8 = undefined;
            @memcpy(&h, child_enc[1..33]);
            break :blk findNodeInIndex(index, h) orelse return error.InvalidProof;
        }
        break :blk child_enc;
    };

    const decoded = node.decodeNode(child_bytes) catch |err| switch (err) {
        error.InvalidRlp => return error.InvalidRlp,
        error.InvalidNode => return error.InvalidNode,
    };

    var path_buf: [128]u8 = undefined;
    var merged: [64]u8 = undefined;
    merged[0] = sole_nib;

    switch (decoded) {
        .leaf => |lf| {
            const hp = nibbles.hpDecode(lf.key_end, &path_buf) catch return error.InvalidHp;
            @memcpy(merged[1 .. 1 + hp.len], path_buf[0..hp.len]);
            return updMakeLeaf(alloc, merged[0 .. 1 + hp.len], lf.value);
        },
        .extension => |e| {
            const hp = nibbles.hpDecode(e.prefix, &path_buf) catch return error.InvalidHp;
            @memcpy(merged[1 .. 1 + hp.len], path_buf[0..hp.len]);
            const child_ref = try updRefEnc(alloc, e.child);
            return updMakeExtension(alloc, merged[0 .. 1 + hp.len], child_ref);
        },
        .branch => {
            // Child is itself a branch: 1-nibble extension pointing to it.
            return updMakeExtension(alloc, merged[0..1], child_enc);
        },
    }
}

/// Like collapseIndexed but resolves child bytes from the witness pool.
fn collapseNode(
    alloc: std.mem.Allocator,
    sole_nib: u8,
    child_enc: []const u8,
    pool: []const []const u8,
) (MptError || error{OutOfMemory})![]const u8 {
    const child_bytes: []const u8 = blk: {
        if (child_enc.len == 33 and child_enc[0] == 0xa0) {
            var h: [32]u8 = undefined;
            @memcpy(&h, child_enc[1..33]);
            break :blk findNode(pool, h) orelse return error.InvalidProof;
        }
        break :blk child_enc;
    };

    const decoded = node.decodeNode(child_bytes) catch |err| switch (err) {
        error.InvalidRlp => return error.InvalidRlp,
        error.InvalidNode => return error.InvalidNode,
    };

    var path_buf: [128]u8 = undefined;
    var merged: [64]u8 = undefined;
    merged[0] = sole_nib;

    switch (decoded) {
        .leaf => |lf| {
            const hp = nibbles.hpDecode(lf.key_end, &path_buf) catch return error.InvalidHp;
            @memcpy(merged[1 .. 1 + hp.len], path_buf[0..hp.len]);
            return updMakeLeaf(alloc, merged[0 .. 1 + hp.len], lf.value);
        },
        .extension => |e| {
            const hp = nibbles.hpDecode(e.prefix, &path_buf) catch return error.InvalidHp;
            @memcpy(merged[1 .. 1 + hp.len], path_buf[0..hp.len]);
            const child_ref = try updRefEnc(alloc, e.child);
            return updMakeExtension(alloc, merged[0 .. 1 + hp.len], child_ref);
        },
        .branch => {
            return updMakeExtension(alloc, merged[0..1], child_enc);
        },
    }
}

/// Like collapseIndexed but resolves child bytes from the combined pool+extra.
fn collapseNodeEx(
    alloc: std.mem.Allocator,
    sole_nib: u8,
    child_enc: []const u8,
    pool: []const []const u8,
    extra: *std.ArrayListUnmanaged([]const u8),
) (MptError || error{OutOfMemory})![]const u8 {
    const child_bytes: []const u8 = blk: {
        if (child_enc.len == 33 and child_enc[0] == 0xa0) {
            var h: [32]u8 = undefined;
            @memcpy(&h, child_enc[1..33]);
            break :blk findNode(pool, h) orelse findNode(extra.items, h) orelse return error.InvalidProof;
        }
        break :blk child_enc;
    };

    const decoded = node.decodeNode(child_bytes) catch |err| switch (err) {
        error.InvalidRlp => return error.InvalidRlp,
        error.InvalidNode => return error.InvalidNode,
    };

    var path_buf: [128]u8 = undefined;
    var merged: [64]u8 = undefined;
    merged[0] = sole_nib;

    switch (decoded) {
        .leaf => |lf| {
            const hp = nibbles.hpDecode(lf.key_end, &path_buf) catch return error.InvalidHp;
            @memcpy(merged[1 .. 1 + hp.len], path_buf[0..hp.len]);
            return updMakeLeaf(alloc, merged[0 .. 1 + hp.len], lf.value);
        },
        .extension => |e| {
            const hp = nibbles.hpDecode(e.prefix, &path_buf) catch return error.InvalidHp;
            @memcpy(merged[1 .. 1 + hp.len], path_buf[0..hp.len]);
            const child_ref = try updRefEnc(alloc, e.child);
            return updMakeExtension(alloc, merged[0 .. 1 + hp.len], child_ref);
        },
        .branch => {
            return updMakeExtension(alloc, merged[0..1], child_enc);
        },
    }
}

/// Compute the parent-node reference encoding for a child node.
/// If the child RLP is < 32 bytes: embed inline (return as-is).
/// If >= 32 bytes: return RLP-encoded keccak256 hash.
fn updHashOrEmbed(alloc: std.mem.Allocator, node_rlp: []const u8) ![]const u8 {
    if (node_rlp.len < 32) return node_rlp;
    const h = keccak256(node_rlp);
    return updRlpBytes(alloc, &h);
}

/// Like updHashOrEmbed but also deposits the hashed node into `extra` so
/// subsequent chained updates can resolve it.
fn updHashOrEmbedEx(alloc: std.mem.Allocator, node_rlp: []const u8, extra: *std.ArrayListUnmanaged([]const u8)) ![]const u8 {
    if (node_rlp.len < 32) return node_rlp;
    try extra.append(alloc, node_rlp);
    const h = keccak256(node_rlp);
    return updRlpBytes(alloc, &h);
}

/// Like updHashOrEmbedEx but inserts the new node directly into the shared NodeIndex.
fn updHashOrEmbedExIndexed(alloc: std.mem.Allocator, node_rlp: []const u8, index: *NodeIndex) ![]const u8 {
    if (node_rlp.len < 32) return node_rlp;
    const h = keccak256(node_rlp);
    try index.put(h, node_rlp);
    return updRlpBytes(alloc, &h);
}

/// Number of bytes required to RLP-encode `data` as a byte string (mirrors updRlpBytes logic).
fn rlpBytesLen(data: []const u8) usize {
    if (data.len == 0) return 1;
    if (data.len == 1 and data[0] < 0x80) return 1;
    if (data.len <= 55) return 1 + data.len;
    var lc: usize = 0;
    var lv = data.len;
    while (lv > 0) : (lv >>= 8) lc += 1;
    return 1 + lc + data.len;
}

/// Write `data` as an RLP byte string into `buf[pos..]`. Returns updated position.
fn rlpBytesWrite(buf: []u8, pos: usize, data: []const u8) usize {
    if (data.len == 0) {
        buf[pos] = 0x80;
        return pos + 1;
    }
    if (data.len == 1 and data[0] < 0x80) {
        buf[pos] = data[0];
        return pos + 1;
    }
    if (data.len <= 55) {
        buf[pos] = @intCast(0x80 + data.len);
        @memcpy(buf[pos + 1 ..][0..data.len], data);
        return pos + 1 + data.len;
    }
    var len_buf: [8]u8 = undefined;
    var lv = data.len;
    var lc: usize = 0;
    while (lv > 0) : (lv >>= 8) lc += 1;
    lv = data.len;
    var li = lc;
    while (li > 0) : (li -= 1) {
        len_buf[li - 1] = @intCast(lv & 0xff);
        lv >>= 8;
    }
    buf[pos] = @intCast(0xb7 + lc);
    @memcpy(buf[pos + 1 ..][0..lc], len_buf[0..lc]);
    @memcpy(buf[pos + 1 + lc ..][0..data.len], data);
    return pos + 1 + lc + data.len;
}

/// Write an RLP list header for a payload of `payload` bytes into `buf[pos..]`.
/// Returns updated position (i.e. start of payload region).
fn rlpListHeaderWrite(buf: []u8, pos: usize, payload: usize) usize {
    if (payload <= 55) {
        buf[pos] = @intCast(0xc0 + payload);
        return pos + 1;
    }
    var len_buf: [8]u8 = undefined;
    var lv = payload;
    var lc: usize = 0;
    while (lv > 0) : (lv >>= 8) lc += 1;
    lv = payload;
    var li = lc;
    while (li > 0) : (li -= 1) {
        len_buf[li - 1] = @intCast(lv & 0xff);
        lv >>= 8;
    }
    buf[pos] = @intCast(0xf7 + lc);
    @memcpy(buf[pos + 1 ..][0..lc], len_buf[0..lc]);
    return pos + 1 + lc;
}

/// Returns the number of bytes in an RLP list header for `payload` content bytes.
fn rlpListHeaderLen(payload: usize) usize {
    if (payload <= 55) return 1;
    var lc: usize = 0;
    var lv = payload;
    while (lv > 0) : (lv >>= 8) lc += 1;
    return 1 + lc;
}

fn updMakeLeaf(alloc: std.mem.Allocator, path_nibs: []const u8, value: []const u8) ![]const u8 {
    var hp_buf: [65]u8 = undefined;
    const hp = nibbles.hpEncode(path_nibs, true, &hp_buf);
    const payload = rlpBytesLen(hp) + rlpBytesLen(value);
    const out = try alloc.alloc(u8, rlpListHeaderLen(payload) + payload);
    var pos = rlpListHeaderWrite(out, 0, payload);
    pos = rlpBytesWrite(out, pos, hp);
    _ = rlpBytesWrite(out, pos, value);
    return out;
}

fn updMakeExtension(alloc: std.mem.Allocator, path_nibs: []const u8, child_ref: []const u8) ![]const u8 {
    var hp_buf: [65]u8 = undefined;
    const hp = nibbles.hpEncode(path_nibs, false, &hp_buf);
    // child_ref is already an RLP-encoded list item (either an inline node or rlp(hash)),
    // so it contributes its raw bytes directly to the list payload.
    const payload = rlpBytesLen(hp) + child_ref.len;
    const out = try alloc.alloc(u8, rlpListHeaderLen(payload) + payload);
    var pos = rlpListHeaderWrite(out, 0, payload);
    pos = rlpBytesWrite(out, pos, hp);
    @memcpy(out[pos..][0..child_ref.len], child_ref);
    return out;
}

fn updEncodeBranch(
    alloc: std.mem.Allocator,
    children_enc: *const [16][]const u8,
    value: []const u8,
) ![]const u8 {
    var items: [17][]const u8 = undefined;
    for (children_enc, 0..) |enc, i| items[i] = enc;
    //items[16] = try updRlpBytes(alloc, value);
    items[16] = if (value.len == 0) &EMPTY_NODE_RLP else try updRlpBytes(alloc, value);
    return updRlpList(alloc, &items);
}

fn updRlpU256(alloc: std.mem.Allocator, v: u256) ![]const u8 {
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &buf, v, .big);
    var start: usize = 0;
    while (start < 32 and buf[start] == 0) start += 1;
    return updRlpBytes(alloc, buf[start..]);
}

fn updRlpBytes(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    if (data.len == 1 and data[0] < 0x80) return alloc.dupe(u8, data);
    if (data.len == 0) return alloc.dupe(u8, &EMPTY_NODE_RLP);
    if (data.len <= 55) {
        const out = try alloc.alloc(u8, 1 + data.len);
        out[0] = @intCast(0x80 + data.len);
        @memcpy(out[1..], data);
        return out;
    }
    var len_buf: [8]u8 = undefined;
    var lv = data.len;
    var lc: usize = 0;
    while (lv > 0) : (lv >>= 8) lc += 1;
    lv = data.len;
    var li = lc;
    while (li > 0) : (li -= 1) {
        len_buf[li - 1] = @intCast(lv & 0xff);
        lv >>= 8;
    }
    const out = try alloc.alloc(u8, 1 + lc + data.len);
    out[0] = @intCast(0xb7 + lc);
    @memcpy(out[1..][0..lc], len_buf[0..lc]);
    @memcpy(out[1 + lc ..], data);
    return out;
}

// ─── Tests ─────────────────────────────────────────────────────────────────────
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

test "updNodeExIndexed: deleting non-existent key (diverges from extension prefix) is a no-op" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const ext = try buildTestExtTrie(alloc);
    var index = NodeIndex.init(alloc);
    const result = try updNodeExIndexed(alloc, ext, &.{ 0, 1, 0, 0 }, null, &index);
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

test "updNodeExIndexed: deleting a key collapses branch to leaf" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const t = try buildTestBranchTrie(alloc);
    var index = try buildNodeIndex(alloc, t.pool);
    defer index.deinit();
    const result = try updNodeExIndexed(alloc, t.branch, &.{1}, null, &index);
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

test "updNodeExIndexed: deleting collapses branch and merges extension" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const t = try buildTestExtBranchTrie(alloc);
    var index = try buildNodeIndex(alloc, t.pool);
    defer index.deinit();
    const result = try updNodeExIndexed(alloc, t.root, &.{ 0, 1 }, null, &index);
    const expected = try updMakeLeaf(alloc, &.{ 0, 2 }, "b");
    try std.testing.expectEqualSlices(u8, expected, result);
}

fn updRlpList(alloc: std.mem.Allocator, items: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (items) |item| total += item.len;
    if (total <= 55) {
        const out = try alloc.alloc(u8, 1 + total);
        out[0] = @intCast(0xc0 + total);
        var pos: usize = 1;
        for (items) |item| {
            @memcpy(out[pos..][0..item.len], item);
            pos += item.len;
        }
        return out;
    }
    var len_buf: [8]u8 = undefined;
    var lv = total;
    var lc: usize = 0;
    while (lv > 0) : (lv >>= 8) lc += 1;
    lv = total;
    var li = lc;
    while (li > 0) : (li -= 1) {
        len_buf[li - 1] = @intCast(lv & 0xff);
        lv >>= 8;
    }
    const out = try alloc.alloc(u8, 1 + lc + total);
    out[0] = @intCast(0xf7 + lc);
    @memcpy(out[1..][0..lc], len_buf[0..lc]);
    var pos: usize = 1 + lc;
    for (items) |item| {
        @memcpy(out[pos..][0..item.len], item);
        pos += item.len;
    }
    return out;
}
