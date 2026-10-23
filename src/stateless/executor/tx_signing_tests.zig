//! Sender recovery: signature bounds (EIP-2 low-s from Homestead) and malleability.

const std = @import("std");
const input = @import("executor_types");

const tx_signing = @import("./tx_signing.zig");
const recoverSender = tx_signing.recoverSender;
const SECP256K1N = tx_signing.SECP256K1N;
const SECP256K1N_OVER_2 = tx_signing.SECP256K1N_OVER_2;

const SENDER: input.Address = .{ 0xf6, 0xc3, 0xa9, 0xed, 0xc1, 0xaf, 0xa0, 0xad, 0x5b, 0x72, 0x0e, 0x4d, 0x42, 0xe1, 0x43, 0x7c, 0x43, 0xd3, 0xb3, 0xff };

// A legacy transaction (unprotected) signed by SENDER, with s <= n/2.
fn testSignedTx() !input.TxInput {
    var to: input.Address = undefined;
    _ = try std.fmt.hexToBytes(&to, "f36afef4dcb45e52f80cb039335952f77cec8960");
    return .{
        .type = 0,
        .nonce = 0,
        .gas_price = 10,
        .gas = 100_000,
        .to = to,
        .value = 1,
        .protected = false,
        .v = 28,
        .r = 0xcb77a6f882ea66061adf985e7adf8ae26a8787c8ebb558c056e02426ad72d7d1,
        .s = 0x16d12b26a9158060358e97ba26c02c3de5036bb4e8cad6e7d462081f5f2b6105,
    };
}

// The same signature with s replaced by n - s and the other parity: it recovers the
// same sender, so only the s <= n/2 bound tells it apart.
fn testMalleatedTx() !input.TxInput {
    var tx = try testSignedTx();
    tx.v = 27;
    tx.s = SECP256K1N - tx.s.?;
    return tx;
}

test "recoverSender rejects a high-s signature from Homestead" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const signed = try testSignedTx();
    try std.testing.expectEqual(@as(?input.Address, SENDER), try recoverSender(arena.allocator(), &signed, 1, .amsterdam));

    const malleated = try testMalleatedTx();
    try std.testing.expectEqual(@as(?input.Address, null), try recoverSender(arena.allocator(), &malleated, 1, .amsterdam));
    try std.testing.expectEqual(@as(?input.Address, null), try recoverSender(arena.allocator(), &malleated, 1, .homestead));
    // Before EIP-2 a high s is valid.
    try std.testing.expectEqual(@as(?input.Address, SENDER), try recoverSender(arena.allocator(), &malleated, 1, .frontier));
}

test "recoverSender rejects r or s outside [1, n)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    for ([_][2]u256{ .{ 0, 1 }, .{ SECP256K1N, 1 }, .{ 1, 0 }, .{ 1, SECP256K1N } }) |rs| {
        var tx = try testSignedTx();
        tx.r = rs[0];
        tx.s = rs[1];
        try std.testing.expectEqual(@as(?input.Address, null), try recoverSender(arena.allocator(), &tx, 1, .frontier));
    }
}

test "signatureInBounds r boundaries" {
    for ([_]bool{ false, true }) |low_s| {
        try std.testing.expect(!tx_signing.signatureInBounds(0, 1, low_s));
        try std.testing.expect(tx_signing.signatureInBounds(1, 1, low_s));
        try std.testing.expect(tx_signing.signatureInBounds(SECP256K1N - 1, 1, low_s));
        try std.testing.expect(!tx_signing.signatureInBounds(SECP256K1N, 1, low_s));
    }
}

test "signatureInBounds s boundaries" {
    // EIP-2: s <= n/2.
    try std.testing.expect(!tx_signing.signatureInBounds(1, 0, true));
    try std.testing.expect(tx_signing.signatureInBounds(1, SECP256K1N_OVER_2, true));
    try std.testing.expect(!tx_signing.signatureInBounds(1, SECP256K1N_OVER_2 + 1, true));
    // Pre-EIP-2: s < n.
    try std.testing.expect(tx_signing.signatureInBounds(1, SECP256K1N_OVER_2 + 1, false));
    try std.testing.expect(tx_signing.signatureInBounds(1, SECP256K1N - 1, false));
    try std.testing.expect(!tx_signing.signatureInBounds(1, SECP256K1N, false));
}
