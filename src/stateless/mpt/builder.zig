//! Merkle Patricia Trie builder.
//!
//! Builds a trie from a set of key-value pairs and returns the root hash.
//! Keys are raw bytes; they are hashed/nibble-expanded internally.
//!
//! Reference: Ethereum Yellow Paper Appendix C.
const std = @import("std");
const nibbles = @import("nibbles.zig");
const accel = @import("accelerators");
const mpt = @import("main.zig");

pub const EMPTY_TRIE_HASH: [32]u8 = [_]u8{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};

pub const KV = struct {
    key: []const u8,
    value: []const u8,
};

/// Compute the MPT root hash for a set of key-value pairs.
/// Keys are used as-is (caller is responsible for pre-hashing if needed).
/// Returns EMPTY_TRIE_HASH if items is empty.
pub fn trieRoot(alloc: std.mem.Allocator, items: []KV) ![32]u8 {
    if (items.len == 0) return EMPTY_TRIE_HASH;

    // Convert each key to nibbles, sort by nibble path
    const NibbleKV = struct {
        nibs: []u8,
        value: []const u8,
    };
    var nkvs = try alloc.alloc(NibbleKV, items.len);
    for (items, 0..) |kv, i| {
        const nibs = try alloc.alloc(u8, kv.key.len * 2);
        nibbles.bytesToNibbles(kv.key, nibs);
        nkvs[i] = .{ .nibs = nibs, .value = kv.value };
    }

    // Sort by nibble path (lexicographic)
    std.mem.sort(NibbleKV, nkvs, {}, struct {
        fn lt(_: void, a: NibbleKV, b: NibbleKV) bool {
            return std.mem.lessThan(u8, a.nibs, b.nibs);
        }
    }.lt);

    const encoded = try buildNode(alloc, nkvs, 0);
    if (encoded.len < 32) {
        // Root is always hashed, even if small
        return keccak256(encoded);
    }
    return keccak256(encoded);
}

// ─── Internal node builder ────────────────────────────────────────────────────

/// Recursively build and RLP-encode a trie node for the given items,
/// all sharing the same path prefix up to `depth` nibbles.
/// Returns the raw RLP bytes of the node (NOT yet hashed).
fn buildNode(alloc: std.mem.Allocator, items: anytype, depth: usize) ![]const u8 {
    if (items.len == 0) {
        // Empty node: RLP of empty string
        return &mpt.EMPTY_NODE_RLP;
    }

    if (items.len == 1) {
        // Leaf node: remaining path + value
        return encodeLeaf(alloc, items[0].nibs[depth..], items[0].value);
    }

    // Find common prefix among all items starting at depth
    var prefix_len: usize = items[0].nibs.len - depth;
    for (items[1..]) |item| {
        const cp = nibbles.commonPrefixLen(items[0].nibs[depth..], item.nibs[depth..]);
        if (cp < prefix_len) prefix_len = cp;
    }

    if (prefix_len > 0) {
        // Extension node: shared prefix leads to a child node
        const shared = items[0].nibs[depth .. depth + prefix_len];
        const child_enc = try buildNode(alloc, items, depth + prefix_len);
        const child_ref = try hashOrEmbed(alloc, child_enc);
        return encodeExtension(alloc, shared, child_ref);
    }

    // Branch node: split items by next nibble (0..15), optional value at this path
    var children: [16]?[]const u8 = [_]?[]const u8{null} ** 16;
    var branch_value: ?[]const u8 = null;

    // Group items by their nibble at `depth`
    var start: usize = 0;
    while (start < items.len) {
        if (items[start].nibs.len == depth) {
            // This item's key ends exactly here — it's the branch value
            branch_value = items[start].value;
            start += 1;
            continue;
        }
        const nib = items[start].nibs[depth];
        var end = start + 1;
        while (end < items.len and items[end].nibs.len > depth and items[end].nibs[depth] == nib) {
            end += 1;
        }
        const child_enc = try buildNode(alloc, items[start..end], depth + 1);
        children[nib] = try hashOrEmbed(alloc, child_enc);
        start = end;
    }

    return encodeBranch(alloc, children, branch_value);
}

// ─── Node encoding ────────────────────────────────────────────────────────────

fn encodeLeaf(alloc: std.mem.Allocator, path: []const u8, value: []const u8) ![]const u8 {
    var hp_buf: [65]u8 = undefined;
    const hp = nibbles.hpEncode(path, true, &hp_buf);
    const items = [_][]const u8{
        try encodeRlpBytes(alloc, hp),
        try encodeRlpBytes(alloc, value),
    };
    return encodeRlpList(alloc, &items);
}

fn encodeExtension(alloc: std.mem.Allocator, path: []const u8, child_ref: []const u8) ![]const u8 {
    var hp_buf: [65]u8 = undefined;
    const hp = nibbles.hpEncode(path, false, &hp_buf);
    const items = [_][]const u8{
        try encodeRlpBytes(alloc, hp),
        child_ref,
    };
    return encodeRlpList(alloc, &items);
}

fn encodeBranch(
    alloc: std.mem.Allocator,
    children: [16]?[]const u8,
    value: ?[]const u8,
) ![]const u8 {
    var items: [17][]const u8 = undefined;
    for (children, 0..) |child, i| {
        items[i] = child orelse try alloc.dupe(u8, &.{0x80}); // empty node ref
    }
    items[16] = try encodeRlpBytes(alloc, value orelse &.{});
    return encodeRlpList(alloc, &items);
}

/// If node is < 32 bytes: return as-is (embed inline).
/// If node is >= 32 bytes: return RLP-encoded keccak256 hash (33 bytes).
fn hashOrEmbed(alloc: std.mem.Allocator, node: []const u8) ![]const u8 {
    if (node.len < 32) return node;
    const h = keccak256(node);
    return encodeRlpBytes(alloc, &h);
}

// ─── Minimal RLP encoding (no external dependency) ───────────────────────────

fn encodeRlpBytes(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    if (data.len == 1 and data[0] < 0x80) {
        return alloc.dupe(u8, data);
    } else if (data.len == 0) {
        return alloc.dupe(u8, &.{0x80});
    } else if (data.len <= 55) {
        const out = try alloc.alloc(u8, 1 + data.len);
        out[0] = @intCast(0x80 + data.len);
        @memcpy(out[1..], data);
        return out;
    } else {
        var len_buf: [8]u8 = undefined;
        const len_bytes = bigEndianMinimal(data.len, &len_buf);
        const out = try alloc.alloc(u8, 1 + len_bytes.len + data.len);
        out[0] = @intCast(0xb7 + len_bytes.len);
        @memcpy(out[1..][0..len_bytes.len], len_bytes);
        @memcpy(out[1 + len_bytes.len ..], data);
        return out;
    }
}

fn encodeRlpList(alloc: std.mem.Allocator, items: []const []const u8) ![]u8 {
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
    } else {
        var len_buf: [8]u8 = undefined;
        const len_bytes = bigEndianMinimal(total, &len_buf);
        const out = try alloc.alloc(u8, 1 + len_bytes.len + total);
        out[0] = @intCast(0xf7 + len_bytes.len);
        @memcpy(out[1..][0..len_bytes.len], len_bytes);
        var pos: usize = 1 + len_bytes.len;
        for (items) |item| {
            @memcpy(out[pos..][0..item.len], item);
            pos += item.len;
        }
        return out;
    }
}

fn bigEndianMinimal(n: usize, buf: *[8]u8) []const u8 {
    var v = n;
    var len: usize = 0;
    while (v > 0) : (v >>= 8) len += 1;
    if (len == 0) len = 1;
    var i: usize = len;
    v = n;
    while (i > 0) : (i -= 1) {
        buf[i - 1] = @intCast(v & 0xff);
        v >>= 8;
    }
    return buf[0..len];
}

pub fn keccak256(data: []const u8) [32]u8 {
    var hash: [32]u8 = undefined;
    accel.keccak256(data, &hash);
    return hash;
}
