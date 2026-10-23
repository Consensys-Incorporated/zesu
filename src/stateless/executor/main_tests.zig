//! Witness header validation: the headers must form a hash-linked chain ending at the
//! payload's parent, and the parent supplies the pre-state root and parent fields.

const std = @import("std");
const mpt = @import("mpt");

const main = @import("./main.zig");
const enc = @import("./rlp_encode.zig");
const exceptions = @import("./exceptions.zig");
const decodeWitnessHeaders = main.decodeWitnessHeaders;

const ZERO: [32]u8 = @splat(0);

/// A header with the fields decodeMinimalHeader and decodeParentHeader read.
fn testHeader(alloc: std.mem.Allocator, parent_hash: [32]u8, state_root: [32]u8, number: u64) ![]u8 {
    return enc.encodeList(alloc, &.{
        try enc.encodeBytes(alloc, &parent_hash),
        try enc.encodeBytes(alloc, &ZERO), // ommers_hash
        try enc.encodeBytes(alloc, &([_]u8{0} ** 20)), // beneficiary
        try enc.encodeBytes(alloc, &state_root),
        try enc.encodeBytes(alloc, &ZERO), // transactions_root
        try enc.encodeBytes(alloc, &ZERO), // receipts_root
        try enc.encodeBytes(alloc, &([_]u8{0} ** 256)), // logs_bloom
        try enc.encodeU64(alloc, 0), // difficulty
        try enc.encodeU64(alloc, number),
        try enc.encodeU64(alloc, 30_000_000), // gas_limit
        try enc.encodeU64(alloc, 21_000), // gas_used
        try enc.encodeU64(alloc, 1_700_000_000 +% number), // timestamp
    });
}

/// A header cut off after `fields` of the fields testHeader writes.
fn truncatedHeader(alloc: std.mem.Allocator, fields: usize) ![]u8 {
    const full = [_][]const u8{
        try enc.encodeBytes(alloc, &ZERO),
        try enc.encodeBytes(alloc, &ZERO),
        try enc.encodeBytes(alloc, &([_]u8{0} ** 20)),
        try enc.encodeBytes(alloc, &ZERO),
        try enc.encodeBytes(alloc, &ZERO),
        try enc.encodeBytes(alloc, &ZERO),
        try enc.encodeBytes(alloc, &([_]u8{0} ** 256)),
        try enc.encodeU64(alloc, 0),
        try enc.encodeU64(alloc, 10),
        try enc.encodeU64(alloc, 30_000_000),
    };
    return enc.encodeList(alloc, full[0..fields]);
}

test "a witness without headers is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidWitness, decodeWitnessHeaders(arena.allocator(), &.{}, ZERO, 1));
}

test "a single header that is the payload's parent is accepted" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parent = try testHeader(a, ZERO, @splat(0x22), 10);
    const headers = try decodeWitnessHeaders(a, &.{parent}, mpt.keccak256(parent), 11);
    try std.testing.expectEqual(@as(usize, 1), headers.block_hashes.len);
    try std.testing.expectEqual(@as(u64, 10), headers.block_hashes[0].number);
}

test "the pre-state root is the last witness header's state root" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const grandparent = try testHeader(a, ZERO, @splat(0x11), 9);
    const parent = try testHeader(a, mpt.keccak256(grandparent), @splat(0x22), 10);
    const headers = try decodeWitnessHeaders(a, &.{ grandparent, parent }, mpt.keccak256(parent), 11);
    try std.testing.expectEqual(@as([32]u8, @splat(0x22)), headers.pre_state_root);
}

test "block hashes list every header's number and hash, in witness order" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const grandparent = try testHeader(a, ZERO, @splat(0x11), 9);
    const parent = try testHeader(a, mpt.keccak256(grandparent), @splat(0x22), 10);
    const headers = try decodeWitnessHeaders(a, &.{ grandparent, parent }, mpt.keccak256(parent), 11);
    try std.testing.expectEqual(@as(usize, 2), headers.block_hashes.len);
    try std.testing.expectEqual(@as(u64, 9), headers.block_hashes[0].number);
    try std.testing.expectEqual(mpt.keccak256(grandparent), headers.block_hashes[0].hash);
    try std.testing.expectEqual(@as(u64, 10), headers.block_hashes[1].number);
    try std.testing.expectEqual(mpt.keccak256(parent), headers.block_hashes[1].hash);
}

test "the parent's gas and timestamp come from the last header, not an ancestor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const grandparent = try testHeader(a, ZERO, @splat(0x11), 9);
    const parent = try testHeader(a, mpt.keccak256(grandparent), @splat(0x22), 10);
    const headers = try decodeWitnessHeaders(a, &.{ grandparent, parent }, mpt.keccak256(parent), 11);
    try std.testing.expectEqual(@as(u64, 30_000_000), headers.parent.gas_limit);
    try std.testing.expectEqual(@as(u64, 21_000), headers.parent.gas_used);
    try std.testing.expectEqual(@as(u64, 1_700_000_010), headers.parent.timestamp);
    try std.testing.expectEqual(@as(?u64, null), headers.parent.base_fee_per_gas);
}

test "a header chain with a broken link is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const grandparent = try testHeader(a, ZERO, @splat(0x11), 9);
    const parent = try testHeader(a, @splat(0xff), @splat(0x22), 10); // not grandparent's child
    try std.testing.expectError(error.InvalidWitness, decodeWitnessHeaders(a, &.{ grandparent, parent }, mpt.keccak256(parent), 11));
}

test "headers out of ascending order are rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const grandparent = try testHeader(a, ZERO, @splat(0x11), 9);
    const parent = try testHeader(a, mpt.keccak256(grandparent), @splat(0x22), 10);
    try std.testing.expectError(error.InvalidWitness, decodeWitnessHeaders(a, &.{ parent, grandparent }, mpt.keccak256(grandparent), 11));
}

test "a witness whose chain ends before the payload's parent is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const grandparent = try testHeader(a, ZERO, @splat(0x11), 9);
    const parent = try testHeader(a, mpt.keccak256(grandparent), @splat(0x22), 10);
    // The payload's parent is `parent`, but the witness stops at its grandparent.
    try std.testing.expectError(error.InvalidWitness, decodeWitnessHeaders(a, &.{grandparent}, mpt.keccak256(parent), 11));
}

test "a last header that is not the payload's parent is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parent = try testHeader(a, ZERO, @splat(0x22), 10);
    try std.testing.expectError(error.InvalidWitness, decodeWitnessHeaders(a, &.{parent}, @splat(0xaa), 11));
}

test "a payload whose number is not the parent's plus one is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parent = try testHeader(a, ZERO, @splat(0x22), 10);
    const parent_hash = mpt.keccak256(parent);
    try std.testing.expectError(error.InvalidBlockNumber, decodeWitnessHeaders(a, &.{parent}, parent_hash, 12));
    try std.testing.expectError(error.InvalidBlockNumber, decodeWitnessHeaders(a, &.{parent}, parent_hash, 10));
    try std.testing.expectError(error.InvalidBlockNumber, decodeWitnessHeaders(a, &.{parent}, parent_hash, 0));
}

test "a payload number mismatch is classified as INVALID_BLOCK_NUMBER" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parent = try testHeader(a, ZERO, @splat(0x22), 10);
    const err = decodeWitnessHeaders(a, &.{parent}, mpt.keccak256(parent), 12);
    try std.testing.expectError(error.InvalidBlockNumber, err);
    const name = exceptions.mapBlockError(error.InvalidBlockNumber) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("BlockException.INVALID_BLOCK_NUMBER", name);
}

test "a parent numbered u64 max does not overflow the number check" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parent = try testHeader(a, ZERO, @splat(0x22), std.math.maxInt(u64));
    try std.testing.expectError(error.InvalidBlockNumber, decodeWitnessHeaders(a, &.{parent}, mpt.keccak256(parent), 0));
}

test "a malformed header is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const not_a_list: []const u8 = &.{0x01};
    const truncated_list: []const u8 = &.{ 0xc1, 0x01 };
    const no_number = try truncatedHeader(a, 8); // ends before the block number
    for ([_][]const u8{ not_a_list, truncated_list, no_number }) |bad| {
        try std.testing.expectError(error.InvalidWitness, decodeWitnessHeaders(a, &.{bad}, mpt.keccak256(bad), 1));
    }
}

test "a header whose hash fields are not 32 bytes is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const short_parent_hash = try enc.encodeList(a, &.{
        try enc.encodeBytes(a, &([_]u8{0} ** 31)),
        try enc.encodeBytes(a, &ZERO),
        try enc.encodeBytes(a, &([_]u8{0} ** 20)),
        try enc.encodeBytes(a, &ZERO),
        try enc.encodeBytes(a, &ZERO),
        try enc.encodeBytes(a, &ZERO),
        try enc.encodeBytes(a, &([_]u8{0} ** 256)),
        try enc.encodeU64(a, 0),
        try enc.encodeU64(a, 10),
    });
    try std.testing.expectError(error.InvalidWitness, decodeWitnessHeaders(a, &.{short_parent_hash}, mpt.keccak256(short_parent_hash), 11));
}

test "a parent header without its gas and timestamp fields is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Has number but stops before gas_limit/gas_used/timestamp.
    const no_gas = try truncatedHeader(a, 9);
    try std.testing.expectError(error.InvalidWitness, decodeWitnessHeaders(a, &.{no_gas}, mpt.keccak256(no_gas), 11));
}
