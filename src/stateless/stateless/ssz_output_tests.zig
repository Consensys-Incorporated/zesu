//! Merkleization tests: the in-place `sparseRoot` and `progressiveRoot` against a
//! recursive reference that copies nothing in place and derives its own zero subtrees.

const std = @import("std");
const ssz_output = @import("ssz_output.zig");

const Node = [32]u8;
const ZERO: Node = @splat(0);

fn hashPair(a: Node, b: Node) Node {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&a);
    h.update(&b);
    var out: Node = undefined;
    h.final(&out);
    return out;
}

fn refZero(depth: u8) Node {
    var z = ZERO;
    for (0..depth) |_| z = hashPair(z, z);
    return z;
}

// SSZ merkleize(chunks, limit = 2^depth): missing leaves are zero chunks.
fn refSparse(leaves: []const Node, depth: u8) Node {
    if (leaves.len == 0) return refZero(depth);
    if (depth == 0) return leaves[0];
    const half = @as(usize, 1) << @intCast(depth - 1);
    const split = @min(half, leaves.len);
    return hashPair(refSparse(leaves[0..split], depth - 1), refSparse(leaves[split..], depth - 1));
}

// EIP-7916 progressive merkleization: subtrees of 1, 4, 16, ... leaves along a
// right-leaning spine that ends in one zero chunk.
fn refProgressive(nodes: []const Node, depth: u8) Node {
    if (nodes.len == 0) return ZERO;
    const n = @min(@as(usize, 1) << @intCast(depth), nodes.len);
    return hashPair(refSparse(nodes[0..n], depth), refProgressive(nodes[n..], depth + 2));
}

fn randomNodes(random: std.Random, n: usize) ![]Node {
    const nodes = try std.testing.allocator.alloc(Node, n);
    random.bytes(std.mem.sliceAsBytes(nodes));
    return nodes;
}

fn expectSparse(random: std.Random, n: usize, depth: u8) !void {
    const leaves = try randomNodes(random, n);
    defer std.testing.allocator.free(leaves);
    const expected = refSparse(leaves, depth);
    try std.testing.expectEqualSlices(u8, &expected, &ssz_output.sparseRoot(leaves, depth));
}

fn expectProgressive(random: std.Random, n: usize) !void {
    const nodes = try randomNodes(random, n);
    defer std.testing.allocator.free(nodes);
    const expected = refProgressive(nodes, 0);
    try std.testing.expectEqualSlices(u8, &expected, &ssz_output.progressiveRoot(nodes));
}

test "sparseRoot matches recursive merkleization for every leaf count up to the limit" {
    var prng = std.Random.DefaultPrng.init(0x5a);
    const random = prng.random();
    for ([_]u8{ 0, 1, 2, 3, 5 }) |depth| {
        const limit = @as(usize, 1) << @intCast(depth);
        for (0..limit + 1) |n| try expectSparse(random, n, depth);
    }
}

// Depth 12 is the versioned-hash list limit; counts sit either side of a power of two.
test "sparseRoot pads odd levels with the zero subtree of that level at depth 12" {
    var prng = std.Random.DefaultPrng.init(0x5b);
    const random = prng.random();
    for ([_]usize{ 0, 1, 2, 3, 5, 6, 7, 9, 255, 256, 257, 1023, 1025, 2047, 2049, 4095, 4096 }) |n| {
        try expectSparse(random, n, 12);
    }
}

test "progressiveRoot matches the recursive spine for every node count up to 400" {
    var prng = std.Random.DefaultPrng.init(0x5c);
    const random = prng.random();
    for (0..401) |n| try expectProgressive(random, n);
}

// Subtree boundaries: 1, 5, 21, 85, 341, 1365, 5461 nodes fill a whole number of subtrees.
test "progressiveRoot at and around each subtree boundary" {
    var prng = std.Random.DefaultPrng.init(0x5d);
    const random = prng.random();
    for ([_]usize{ 1364, 1365, 1366, 4095, 4096, 4097, 5460, 5461, 5462, 7000 }) |n| {
        try expectProgressive(random, n);
    }
}
