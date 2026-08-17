//! EIP-7934: size of the RLP encoding of a block, derived from its execution payload.
//!
//! The stateless guest never sees the block's RLP — it decodes an SSZ payload — so the
//! `MAX_RLP_BLOCK_SIZE` limit has to be enforced against a size computed from the payload
//! fields. Only the *length* of the encoding is needed, so the header's roots and hashes
//! (transactions root, receipts root, BAL hash, …) never have to be known: every one of
//! them is a 32-byte string, 33 bytes encoded, whatever its value.
//!
//! Block RLP is `[header, transactions, ommers, withdrawals]` (execution-specs
//! `Block`), with ommers always empty post-merge.

const std = @import("std");
const primitives = @import("primitives");
const input = @import("input");

// ─── RLP length primitives ────────────────────────────────────────────────────

/// Encoded length of an RLP byte-string holding `len` arbitrary bytes.
/// Callers must use `singleByteSize` instead when the payload is one byte that
/// may be < 0x80 (that case is self-encoding).
fn stringSize(len: usize) usize {
    if (len <= 55) return 1 + len;
    return 1 + lengthOfLength(len) + len;
}

/// Encoded length of an RLP list whose concatenated items occupy `payload` bytes.
fn listSize(payload: usize) usize {
    if (payload <= 55) return 1 + payload;
    return 1 + lengthOfLength(payload) + payload;
}

/// Number of bytes in the minimal big-endian encoding of `n` (n > 0).
fn lengthOfLength(n: usize) usize {
    return (@as(usize, 64) - @clz(@as(u64, n)) + 7) / 8;
}

/// Encoded length of a u64 as a minimal-big-endian RLP byte-string.
fn uintSize(v: u64) usize {
    if (v == 0) return 1; // 0x80
    const bytes = lengthOfLength(v);
    if (bytes == 1 and v < 0x80) return 1; // self-encoding single byte
    return 1 + bytes;
}

/// Encoded length of an arbitrary byte slice, handling the self-encoding cases.
fn bytesSize(data: []const u8) usize {
    if (data.len == 1 and data[0] < 0x80) return 1;
    return stringSize(data.len);
}

// ─── Block components ─────────────────────────────────────────────────────────

const HASH_SIZE = 33; // 0xa0 ‖ 32 bytes
const ADDRESS_SIZE = 21; // 0x94 ‖ 20 bytes
const BLOOM_SIZE = 3 + 256; // 0xb9 0x01 0x00 ‖ 256 bytes
const NONCE_SIZE = 9; // 0x88 ‖ 8 bytes — always zero in PoS, but Bytes8, not a uint

/// Encoded size of the block header for `spec`, from the payload's fields.
fn headerSize(ep: *const input.ExecutionPayload, spec: primitives.SpecId) usize {
    // [0] parent_hash, [1] ommers_hash, [3] state_root, [4] transactions_root,
    // [5] receipts_root, [13] mix_hash — six 32-byte hashes.
    var payload: usize = 6 * HASH_SIZE;
    payload += ADDRESS_SIZE; // [2] beneficiary
    payload += BLOOM_SIZE; // [6] logs_bloom
    payload += uintSize(0); // [7] difficulty — 0 post-merge
    payload += uintSize(ep.block_number); // [8]
    payload += uintSize(ep.gas_limit); // [9]
    payload += uintSize(ep.gas_used); // [10]
    payload += uintSize(ep.timestamp); // [11]
    payload += bytesSize(ep.extra_data); // [12]
    payload += NONCE_SIZE; // [14]

    if (primitives.isEnabledIn(spec, .london)) payload += uintSize(ep.base_fee_per_gas); // [15]
    if (primitives.isEnabledIn(spec, .shanghai)) payload += HASH_SIZE; // [16] withdrawals_root
    if (primitives.isEnabledIn(spec, .cancun)) {
        payload += uintSize(ep.blob_gas_used); // [17]
        payload += uintSize(ep.excess_blob_gas); // [18]
        payload += HASH_SIZE; // [19] parent_beacon_block_root
    }
    if (primitives.isEnabledIn(spec, .prague)) payload += HASH_SIZE; // [20] requests_hash
    if (primitives.isEnabledIn(spec, .amsterdam)) {
        payload += HASH_SIZE; // [21] block_access_list_hash
        payload += uintSize(ep.slot_number orelse 0); // [22]
    }

    return listSize(payload);
}

/// Encoded size of the transactions list. Typed transactions are opaque byte-strings
/// in the block body; legacy transactions are their own RLP list, inlined as-is.
fn transactionsSize(raw_transactions: []const []const u8) usize {
    var payload: usize = 0;
    for (raw_transactions) |raw| {
        if (raw.len > 0 and raw[0] >= 0xc0) {
            payload += raw.len; // legacy: already an RLP list
        } else {
            payload += stringSize(raw.len); // typed: wrapped as a byte-string
        }
    }
    return listSize(payload);
}

/// Encoded size of the withdrawals list: each entry is
/// `[index, validator_index, address, amount]`.
fn withdrawalsSize(withdrawals: []const input.Withdrawal) usize {
    var payload: usize = 0;
    for (withdrawals) |wd| {
        payload += listSize(uintSize(wd.index) + uintSize(wd.validator_index) + ADDRESS_SIZE + uintSize(wd.amount));
    }
    return listSize(payload);
}

/// Size in bytes of the RLP encoding of the block described by `ep`.
///
/// Returns null when the payload carries no raw transaction bytes while holding
/// transactions — the JSON and RLP decode paths leave `raw_transactions` empty, and a
/// size computed without them would be wrong. Those callers set `Env.block_rlp_size`
/// from the real encoding instead.
pub fn compute(ep: *const input.ExecutionPayload, spec: primitives.SpecId) ?u64 {
    if (ep.raw_transactions.len != ep.transactions.len) return null;

    const payload = headerSize(ep, spec) +
        transactionsSize(ep.raw_transactions) +
        listSize(0) + // ommers: always empty post-merge
        withdrawalsSize(ep.withdrawals);
    return listSize(payload);
}

// ─── Tests ────────────────────────────────────────────────────────────────────

test "uintSize: self-encoding, single byte, and multi-byte" {
    try std.testing.expectEqual(@as(usize, 1), uintSize(0));
    try std.testing.expectEqual(@as(usize, 1), uintSize(0x7f));
    try std.testing.expectEqual(@as(usize, 2), uintSize(0x80));
    try std.testing.expectEqual(@as(usize, 5), uintSize(0x210f3d18));
    try std.testing.expectEqual(@as(usize, 9), uintSize(std.math.maxInt(u64)));
}

test "listSize: short and long forms" {
    try std.testing.expectEqual(@as(usize, 1), listSize(0));
    try std.testing.expectEqual(@as(usize, 56), listSize(55));
    try std.testing.expectEqual(@as(usize, 58), listSize(56));
    try std.testing.expectEqual(@as(usize, 259), listSize(256));
}

fn testPayload(extra_data: []const u8) input.ExecutionPayload {
    return .{
        .parent_hash = @splat(0),
        .fee_recipient = @splat(0),
        .state_root = @splat(0),
        .receipts_root = @splat(0),
        .logs_bloom = @splat(0),
        .prev_randao = @splat(0),
        .block_number = 1,
        .gas_limit = 0x210f3d18,
        .gas_used = 0x2109dcbc,
        .timestamp = 0x075bcd15,
        .extra_data = extra_data,
        .base_fee_per_gas = 7,
        .block_hash = @splat(0),
        .transactions = &.{},
        .raw_transactions = &.{},
        .withdrawals = &.{},
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .slot_number = 0,
    };
}

test "headerSize: Amsterdam header matches the fixture's 656-byte encoding" {
    // tests/osaka/eip7934_block_rlp_limit — block_at_rlp_size_limit_boundary,
    // whose header RLP is 656 bytes.
    const ep = testPayload(&([_]u8{0} ** 12));
    try std.testing.expectEqual(@as(usize, 656), headerSize(&ep, .amsterdam));
}

test "headerSize: pre-Amsterdam drops the BAL hash and slot number" {
    const ep = testPayload(&([_]u8{0} ** 12));
    try std.testing.expectEqual(@as(usize, 656 - HASH_SIZE - 1), headerSize(&ep, .osaka));
}

test "transactionsSize: typed transactions are wrapped, legacy inlined" {
    const typed: []const u8 = &([_]u8{0x04} ++ [_]u8{0xaa} ** 99); // 100 bytes → 2 + 100
    const legacy: []const u8 = &([_]u8{0xf8} ++ [_]u8{0xbb} ** 99); // 100 bytes, inlined
    try std.testing.expectEqual(@as(usize, listSize(102 + 100)), transactionsSize(&.{ typed, legacy }));
}

test "withdrawalsSize: empty list and one entry" {
    try std.testing.expectEqual(@as(usize, 1), withdrawalsSize(&.{}));
    const wd = [_]input.Withdrawal{.{ .index = 0, .validator_index = 1, .address = @splat(0), .amount = 0x100 }};
    // [0x80, 0x01, address(21), 0x82 0x01 0x00] = 26 payload bytes
    try std.testing.expectEqual(@as(usize, 1 + 27), withdrawalsSize(&wd));
}

test "compute: returns null when raw transaction bytes are unavailable" {
    var ep = testPayload(&([_]u8{0} ** 12));
    ep.transactions = &.{undefined};
    try std.testing.expectEqual(@as(?u64, null), compute(&ep, .amsterdam));
}
