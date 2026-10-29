//! Decode RLP-encoded raw trie nodes into typed discriminated unions.
//!
//! These are the nodes that appear in an MPT Merkle proof — not the in-memory
//! tree nodes used by a trie builder. All slices point into the original proof
//! bytes; no heap allocation occurs.

const std = @import("std");
const rlp = @import("rlp.zig");

/// A reference to a child node within a proof.
pub const NodeRef = union(enum) {
    /// 32-byte keccak256 hash of the child node (linked to next proof element).
    hash: *const [32]u8,
    /// Short (< 32 byte) child node inlined directly in the parent.
    inline_node: []const u8,
    /// Empty / null slot (branch child absent).
    empty: void,
};

/// A decoded trie node. All slices are views into the original proof bytes.
pub const DecodedNode = union(enum) {
    leaf: struct {
        /// HP-encoded remaining key path (compact / hex-prefix bytes).
        key_end: []const u8,
        /// Leaf value (e.g. RLP-encoded account or storage integer).
        value: []const u8,
    },
    extension: struct {
        /// HP-encoded shared prefix path.
        prefix: []const u8,
        /// Reference to the next node.
        child: NodeRef,
    },
    branch: struct {
        /// 16 child slots indexed by nibble (0–15).
        children: [16]NodeRef,
        /// Value stored at this branch (almost always empty in Ethereum tries).
        value: []const u8,
    },
};

/// Decode one RLP-encoded trie node from `bytes`.
///
/// Dispatches on the item count in the outer RLP list:
///   2  items → leaf or extension (HP flag bit of item[0] distinguishes them)
///   17 items → branch
///   other   → error.InvalidNode
pub fn decodeNode(bytes: []const u8) error{ InvalidRlp, InvalidNode }!DecodedNode {
    const outer = try rlp.decodeItem(bytes);
    const payload = switch (outer.item) {
        .list => |p| p,
        .bytes => return error.InvalidNode,
    };

    // One pass over the items: each of the first 16 becomes a child ref as a branch would
    // read it, the 17th the branch value, and the first two are kept for a leaf or extension.
    // Most branch slots are an empty string or a 32-byte hash, read from the prefix byte.
    var children: [16]NodeRef = undefined;
    var value: []const u8 = &.{};
    var first: [2]rlp.RlpItem = undefined;
    var second_raw: []const u8 = undefined;
    var count: usize = 0;
    var rest = payload;
    while (rest.len > 0) : (count += 1) {
        if (count >= 17) return error.InvalidNode;
        var item: rlp.RlpItem = undefined;
        var consumed: usize = undefined;
        if (rest[0] == 0x80) {
            item = .{ .bytes = &.{} };
            consumed = 1;
        } else if (rest[0] == 0xa0 and rest.len >= 33) {
            item = .{ .bytes = rest[1..33] };
            consumed = 33;
        } else {
            const r = try rlp.decodeItem(rest);
            item = r.item;
            consumed = r.consumed;
        }
        const raw = rest[0..consumed];
        if (count < 2) first[count] = item;
        if (count == 1) second_raw = raw;
        if (count < 16) {
            children[count] = try decodeNodeRef(item, raw);
        } else value = switch (item) {
            .bytes => |b| b,
            .list => &.{},
        };
        rest = rest[consumed..];
    }

    switch (count) {
        2 => {
            // 2-item node: leaf or extension distinguished by the HP flag bit.
            const key_bytes = switch (first[0]) {
                .bytes => |b| b,
                .list => return error.InvalidNode,
            };
            if (key_bytes.len == 0) return error.InvalidNode;

            // Bit 5 of the first byte signals leaf (1) vs extension (0).
            const is_leaf = (key_bytes[0] & 0x20) != 0;

            if (is_leaf) {
                const val_bytes: []const u8 = switch (first[1]) {
                    .bytes => |b| b,
                    .list => |l| l,
                };
                return .{ .leaf = .{ .key_end = key_bytes, .value = val_bytes } };
            } else {
                return .{ .extension = .{
                    .prefix = key_bytes,
                    .child = try decodeNodeRef(first[1], second_raw),
                } };
            }
        },
        17 => return .{ .branch = .{ .children = children, .value = value } },
        else => return error.InvalidNode,
    }
}

/// Convert an RLP item into a NodeRef.
/// `raw` is the full RLP bytes of the item (including any list header), used
/// when the item is an inline list node (a short branch/extension < 32 bytes
/// embedded directly rather than hash-referenced).
fn decodeNodeRef(item: rlp.RlpItem, raw: []const u8) error{InvalidNode}!NodeRef {
    switch (item) {
        .bytes => |b| {
            if (b.len == 0) return .{ .empty = {} };
            if (b.len == 32) {
                return .{ .hash = b[0..32] };
            }
            // Short encoding: inline node (< 32 bytes of raw RLP).
            return .{ .inline_node = b };
        },
        .list => {
            // Inline node embedded as a list: a short branch or extension
            // (< 32 bytes) whose full RLP is included directly in the parent.
            return .{ .inline_node = raw };
        },
    }
}

/// Decode only the child at `nibble` (0–15) from a branch node, stopping iteration
/// as soon as the target slot is reached instead of parsing all 17 children.
///
/// Returns null when `bytes` is a leaf or extension node (2-item list), allowing the
/// caller to fall through to full decoding. Returns error for malformed RLP.
pub fn decodeNibble(bytes: []const u8, nibble: u8) error{ InvalidRlp, InvalidNode }!?NodeRef {
    // A branch is almost always a long list with a two-byte length: read it as decodeItem would.
    const payload = if (bytes.len >= 3 and bytes[0] == 0xf9) blk: {
        const len = @as(usize, bytes[1]) << 8 | bytes[2];
        if (3 + len > bytes.len) return error.InvalidRlp;
        break :blk bytes[3..][0..len];
    } else switch ((try rlp.decodeItem(bytes)).item) {
        .list => |p| p,
        .bytes => return error.InvalidNode,
    };
    var rest = payload;

    // Skip items 0..nibble-1. A branch's children are almost all 0x80 (empty) or 0xa0 plus a
    // 32-byte hash, whose lengths the prefix byte alone fixes; anything else is decoded.
    for (0..nibble) |_| {
        if (rest.len == 0) return null; // fewer than nibble+1 items → leaf/extension
        const n: usize = switch (rest[0]) {
            0x80 => 1,
            0xa0 => 33,
            else => (try rlp.decodeItem(rest)).consumed,
        };
        if (n > rest.len) return error.InvalidRlp;
        rest = rest[n..];
    }
    // Capture the target child, reading an empty or hashed slot from its prefix byte.
    if (rest.len == 0) return null;
    var result: NodeRef = undefined;
    if (rest[0] == 0x80) {
        result = .{ .empty = {} };
        rest = rest[1..];
    } else if (rest[0] == 0xa0 and rest.len >= 33) {
        result = .{ .hash = rest[1..33] };
        rest = rest[33..];
    } else {
        const r = try rlp.decodeItem(rest);
        result = try decodeNodeRef(r.item, rest[0..r.consumed]);
        rest = rest[r.consumed..];
    }

    // Disambiguate leaf/extension (2 items) from branch (17 items).
    // After consuming nibble+1 items:
    //   nibble >= 2: a 2-item node is exhausted by item 1, so reaching here guarantees branch.
    //   nibble == 1: if rest is empty we consumed exactly 2 items → leaf/extension.
    //   nibble == 0: consume item 1 to check if the list is exactly 2 items long.
    if (nibble == 1 and rest.len == 0) return null;
    if (nibble == 0) {
        if (rest.len == 0) return null; // degenerate 1-item list
        const r1 = try rlp.decodeItem(rest);
        rest = rest[r1.consumed..];
        if (rest.len == 0) return null; // exactly 2 items → leaf/extension
    }

    return result;
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

test "decodeNode leaf" {
    // Leaf node: [HP_key, value]
    // HP key = 0x20 (leaf, even, empty path) → RLP 0x81 0x20
    // value  = 0x42 (single byte < 0x80)
    // list payload = [0x81, 0x20, 0x42] = 3 bytes → 0xc3 0x81 0x20 0x42
    const bytes = &[_]u8{ 0xc3, 0x81, 0x20, 0x42 };
    const node = try decodeNode(bytes);
    try std.testing.expect(node == .leaf);
    try std.testing.expectEqualSlices(u8, &.{0x20}, node.leaf.key_end);
    try std.testing.expectEqualSlices(u8, &.{0x42}, node.leaf.value);
}

test "decodeNode extension with hash child" {
    // Extension node: [HP_key, child_hash]
    // HP key = 0x00 (extension, even, empty path) → RLP 0x81 0x00
    // child  = 32-byte hash (all 0xaa) → RLP 0xa0 followed by 32 bytes
    var buf: [37]u8 = undefined;
    buf[0] = 0x81; // short string, len=1
    buf[1] = 0x00; // HP: extension, even
    buf[2] = 0xa0; // short string, len=32
    @memset(buf[3..35], 0xaa);
    // payload = 35 bytes → list: 0xf8 0x23 + 35 bytes = 37 bytes total
    var node_buf: [37]u8 = undefined;
    node_buf[0] = 0xf8;
    node_buf[1] = 35;
    @memcpy(node_buf[2..37], buf[0..35]);
    const node = try decodeNode(&node_buf);
    try std.testing.expect(node == .extension);
    try std.testing.expectEqualSlices(u8, &.{0x00}, node.extension.prefix);
    try std.testing.expect(node.extension.child == .hash);
    var expected_hash: [32]u8 = undefined;
    @memset(&expected_hash, 0xaa);
    try std.testing.expectEqualSlices(u8, &expected_hash, node.extension.child.hash);
}

test "decodeNode branch all empty" {
    // Branch: 17 × 0x80 (empty string) = 17 bytes payload
    // list: 0xd1 (0xc0 + 17) + 17 bytes
    var buf: [18]u8 = undefined;
    buf[0] = 0xd1;
    @memset(buf[1..18], 0x80);
    const node = try decodeNode(&buf);
    try std.testing.expect(node == .branch);
    for (node.branch.children) |child| {
        try std.testing.expect(child == .empty);
    }
    try std.testing.expectEqualSlices(u8, &.{}, node.branch.value);
}

test "decodeNode branch with hash child at slot 0" {
    // 17-item branch: children[0] = 32-byte hash, children[1..15] = empty, value = empty.
    // Byte layout:
    //   children[0]:  0xa0 + 32 bytes = 33 bytes (1 RLP item)
    //   children[1..15]: 15 × 0x80    = 15 bytes (15 RLP items)
    //   value (slot 16): 0x80          =  1 byte  (1 RLP item)
    //   Total payload: 49 bytes, 17 items; 49 < 56 → list prefix 0xc0 + 49 = 0xf1
    var payload: [49]u8 = undefined;
    payload[0] = 0xa0; // RLP prefix for 32-byte string
    @memset(payload[1..33], 0xbb); // hash bytes
    @memset(payload[33..], 0x80); // remaining 16 slots: children[1..15] + value
    var buf: [50]u8 = undefined;
    buf[0] = 0xc0 + 49; // = 0xf1
    @memcpy(buf[1..50], &payload);
    const node = try decodeNode(&buf);
    try std.testing.expect(node == .branch);
    try std.testing.expect(node.branch.children[0] == .hash);
    var expected: [32]u8 = undefined;
    @memset(&expected, 0xbb);
    try std.testing.expectEqualSlices(u8, &expected, node.branch.children[0].hash);
    for (node.branch.children[1..]) |child| {
        try std.testing.expect(child == .empty);
    }
}

test "decodeNode inline child" {
    // Extension with a short (< 32 byte) inline child.
    // HP key = 0x00 → 0x81 0x00 (2 bytes)
    // inline child = 4-byte string: 0x84 0x01 0x02 0x03 0x04 (5 bytes)
    // payload = 7 bytes → list 0xc7 + 7 bytes = 8 bytes total
    const bytes = &[_]u8{ 0xc7, 0x81, 0x00, 0x84, 0x01, 0x02, 0x03, 0x04 };
    const node = try decodeNode(bytes);
    try std.testing.expect(node == .extension);
    try std.testing.expect(node.extension.child == .inline_node);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, node.extension.child.inline_node);
}

test "decodeNode invalid: wrong item count" {
    // 3 items → error.InvalidNode
    const bytes = &[_]u8{ 0xc3, 0x80, 0x80, 0x80 };
    try std.testing.expectError(error.InvalidNode, decodeNode(bytes));
}

test "decodeNode invalid: not a list" {
    // Top-level bytes item → error.InvalidNode
    const bytes = &[_]u8{ 0x83, 0x01, 0x02, 0x03 };
    try std.testing.expectError(error.InvalidNode, decodeNode(bytes));
}

test "decodeNode invalid: leaf with empty HP key" {
    // [0x80, 0x80] = [empty string, empty string] → key_end is empty → InvalidNode
    const bytes = &[_]u8{ 0xc2, 0x80, 0x80 };
    try std.testing.expectError(error.InvalidNode, decodeNode(bytes));
}
