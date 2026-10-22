//! Strict transaction decoding: non-canonical RLP encodings are rejected.

const std = @import("std");
const input = @import("input");

const decodeSingleTx = @import("./rlp_decode.zig").decodeSingleTx;

// A legacy transaction (nonce 0, gas price 10, gas 400000, value 0, no data, v 37) in
// canonical RLP, and non-canonical encodings of it the reference refuses to decode.
const canonical_tx_hex = "f860800a83061a809492d2fc80312acd8c37857696d2224af18ce6f966808025a04ff8a4e4957d67afb417056cdc8cc22d2590d96b2d7fa1de345d27d621064913a040f0281c748387d842b625df32f11994909265433041a0ad75157634f4e63bdd";

fn decodeHexTx(alloc: std.mem.Allocator, hex: []const u8) !input.Transaction {
    const raw = try alloc.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(raw, hex);
    return decodeSingleTx(alloc, raw);
}

test "decodeSingleTx accepts the canonical encoding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const tx = try decodeHexTx(arena.allocator(), canonical_tx_hex);
    try std.testing.expectEqual(@as(u64, 400_000), tx.gas_limit);
}

test "decodeSingleTx rejects non-canonical transaction encodings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const body = canonical_tx_hex[4..]; // the list payload, after the f860 header
    const cases = [_][]const u8{
        // Nonce 0 written as 0x00 instead of the empty string 0x80.
        "f860" ++ "00" ++ body[2..],
        // Gas price 10 with a leading zero byte (0x82000a).
        "f862" ++ "80" ++ "82000a" ++ body[4..],
        // Gas price 10 (a single byte below 0x80) wrapped as a one-byte string.
        "f861" ++ "80" ++ "810a" ++ body[4..],
        // A byte after the transaction.
        canonical_tx_hex ++ "00",
        // An extra field after s.
        "f861" ++ body ++ "80",
    };
    for (cases) |hex| try std.testing.expectError(error.InvalidBlock, decodeHexTx(a, hex));
}
