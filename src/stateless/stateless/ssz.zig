//! Manual SSZ decoder for SszStatelessInput (Amsterdam stateless block execution).
//!
//! Implements the schema from stateless_ssz.py without any external SSZ library.
//! All container offsets are relative to the start of each container's byte slice.
//!
//! Container layouts (fixed region sizes):
//!   SszStatelessInput:    20 bytes  [4+4+8+4]  (v0.8.0: chain_config → inline chain_id)
//!   SszNewPayloadRequest: 44 bytes  [4+4+32+4]
//!   SszExecutionPayload: 540 bytes  (see EP_FIXED_SIZE)
//!   SszExecutionWitness:  12 bytes  [4+4+4]
//!   SszWithdrawal:        44 bytes  fixed (8+8+20+8)
//!
//! EIP-7495 `ProgressiveContainer` and EIP-7916 `ProgressiveList` (introduced by
//! zkevm@v0.8.0) serialize exactly like their stable counterparts, so only
//! `hash_tree_root` differs — see ssz_output.zig.

const std = @import("std");
const input_mod = @import("input");
const rlp_decode = @import("rlp_decode");

// ── Primitive reads (little-endian) ──────────────────────────────────────────

inline fn readU32(data: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, data[off..][0..4], .little);
}

inline fn readU64(data: []const u8, off: usize) u64 {
    return std.mem.readInt(u64, data[off..][0..8], .little);
}

// ── Input schema id ──────────────────────────────────────────────────────────

/// `STATELESS_INPUT_SCHEMA_ID` (stateless_ssz.py) = ProtocolFork.Amsterdam (0x15)
/// << 8 | schema revision (0x01), stored big-endian ahead of the SSZ payload.
/// The reference guest rejects any other value outright, so the schema pins both
/// the container layout and the fork the guest implements.
pub const SCHEMA_ID: u16 = 0x1501;
const SCHEMA_FORK_NAME = "Amsterdam";

// ── List[ByteList] decoder ────────────────────────────────────────────────────

/// Decode SSZ `List[ByteList[...], N]` from raw bytes.
/// The encoding is: N×4-byte LE offsets followed by concatenated element data.
/// Element i spans [off[i], off[i+1]) with off[N] = data.len.
/// Returns zero-copy slices pointing into `data`.
fn decodeByteListList(alloc: std.mem.Allocator, data: []const u8) ![]const []const u8 {
    if (data.len == 0) return &.{};
    if (data.len < 4) return error.InvalidSsz;

    const first_off = readU32(data, 0);
    // first_off == 4*N (size of the offset table itself)
    if (first_off == 0 or first_off % 4 != 0) return error.InvalidSsz;
    if (first_off > data.len) return error.InvalidSsz;
    const n = first_off / 4;

    const result = try alloc.alloc([]const u8, n);

    for (0..n) |i| {
        const off_i = readU32(data, i * 4);
        const end_i: u32 = if (i + 1 < n) readU32(data, (i + 1) * 4) else blk: {
            if (data.len > std.math.maxInt(u32)) return error.InvalidSsz;
            break :blk @intCast(data.len);
        };
        if (off_i > data.len or end_i > data.len or off_i > end_i) return error.InvalidSsz;
        result[i] = data[off_i..end_i];
    }

    return result;
}

// ── SszWithdrawal decoder ─────────────────────────────────────────────────────

/// SszWithdrawal fixed size: index(8) + validator_index(8) + address(20) + amount(uint64=8) = 44
const WITHDRAWAL_SIZE: usize = 44;

fn decodeWithdrawal(bytes: *const [WITHDRAWAL_SIZE]u8) input_mod.Withdrawal {
    const index = std.mem.readInt(u64, bytes[0..8], .little);
    const validator_index = std.mem.readInt(u64, bytes[8..16], .little);
    var address: [20]u8 = undefined;
    @memcpy(&address, bytes[16..36]);
    const amount = std.mem.readInt(u64, bytes[36..44], .little);
    return .{
        .index = index,
        .validator_index = validator_index,
        .address = address,
        .amount = amount,
    };
}

// ── Top-level decoder ─────────────────────────────────────────────────────────

/// SszExecutionPayload fixed region byte offsets:
///   [0..32]    parent_hash
///   [32..52]   fee_recipient
///   [52..84]   state_root
///   [84..116]  receipts_root
///   [116..372] logs_bloom
///   [372..404] prev_randao
///   [404..412] block_number
///   [412..420] gas_limit
///   [420..428] gas_used
///   [428..436] timestamp
///   [436..440] → extra_data (variable offset)
///   [440..472] base_fee_per_gas (uint256 LE)
///   [472..504] block_hash (ignored)
///   [504..508] → transactions (variable offset)
///   [508..512] → withdrawals (variable offset)
///   [512..520] blob_gas_used
///   [520..528] excess_blob_gas
///   [528..532] → block_access_list (variable offset, ignored)
///   [532..540] slot_number
const EP_FIXED_SIZE: usize = 540;

/// Decode an SSZ-serialized SszStatelessInput into a StatelessInput.
///
/// Supports two input layouts, detected in order:
///
/// 1. Ere-prefixed (4-byte u32 LE length prefix prepended by `Input::with_prefixed_stdin`):
///    stripped when declared length matches remaining bytes, then format re-detected.
///
/// 2. 2-byte big-endian schema_id + 20-byte SszStatelessInput fixed region:
///    [0..2]   schema_id (0x1501 BE)
///    [2..6]   offset → new_payload_request
///    [6..10]  offset → witness
///    [10..18] chain_id (uint64 LE, inline)
///    [18..22] offset → public_keys (packed ByteVector[65])
pub fn decode(alloc: std.mem.Allocator, data: []const u8) !input_mod.StatelessInput {
    // Strip Ere's 4-byte LE length prefix when present. The first 4 bytes of
    // raw SSZ are always a small offset value, so matching against data.len-4
    // is unambiguous for any real payload.
    const payload = if (data.len >= 4 and
        std.mem.readInt(u32, data[0..4], .little) == data.len - 4)
        data[4..]
    else
        data;

    if (payload.len < 2 or std.mem.readInt(u16, payload[0..2], .big) != SCHEMA_ID) return error.InvalidSsz;

    // ── SszStatelessInput fixed region (20 bytes) ────────────────────────────
    const body = payload[2..];
    if (body.len < 20) return error.InvalidSsz;
    const off_npr: usize = readU32(body, 0);
    const off_witness: usize = readU32(body, 4);
    const chain_id = readU64(body, 8);
    const off_pubkeys: usize = readU32(body, 16);

    if (off_npr != 20 or off_witness > body.len or off_pubkeys > body.len) return error.InvalidSsz;
    if (off_npr > off_witness or off_witness > off_pubkeys) return error.InvalidSsz;

    const npr_data = body[off_npr..off_witness];
    const witness_data = body[off_witness..off_pubkeys];
    const pubkeys_data = body[off_pubkeys..];

    // ── SszNewPayloadRequest fixed region (44 bytes) ──────────────────────────
    // [0..4]   offset → execution_payload (variable)
    // [4..8]   offset → versioned_hashes (variable)
    // [8..40]  parent_beacon_block_root: Bytes32 (fixed inline)
    // [40..44] offset → execution_requests (variable)
    if (npr_data.len < 44) return error.InvalidSsz;
    const off_ep: usize = readU32(npr_data, 0);
    const off_vh: usize = readU32(npr_data, 4);
    const off_er: usize = readU32(npr_data, 40);

    var parent_beacon_root: [32]u8 = undefined;
    @memcpy(&parent_beacon_root, npr_data[8..40]);

    if (off_ep < 44 or off_vh > npr_data.len or off_er > npr_data.len) return error.InvalidSsz;
    if (off_ep >= off_vh or off_vh > off_er) return error.InvalidSsz;

    const ep_data = npr_data[off_ep..off_vh];

    // versioned_hashes: List[Bytes32, 4096] — packed 32-byte elements (no offset table)
    const vh_bytes = npr_data[off_vh..off_er];
    if (vh_bytes.len % 32 != 0) return error.InvalidSsz;
    const vh_count = vh_bytes.len / 32;
    const versioned_hashes = try alloc.alloc([32]u8, vh_count);
    for (0..vh_count) |i| @memcpy(&versioned_hashes[i], vh_bytes[i * 32 ..][0..32]);

    // execution_requests: SszExecutionRequests — N variable-length request-type lists.
    // The first offset gives the fixed-region size (N*4), indicating how many types exist.
    // zkevm@v0.5.0 had 3 types (deposits, withdrawals, consolidations; fixed=12).
    // zkevm@v0.6.2 (EIP-8282) added builder_deposits + builder_exits → 5 types (fixed=20).
    const er_data = npr_data[off_er..];
    if (er_data.len < 12) return error.InvalidSsz;
    const off_deposits: usize = readU32(er_data, 0);
    // off_deposits == fixed-region size; a multiple of 4 covering at least 3 types.
    if (off_deposits < 12 or off_deposits % 4 != 0 or off_deposits > er_data.len) return error.InvalidSsz;
    const n_types = off_deposits / 4;
    // Read each type's offset, then its end (next offset, or er_data.len for the last type).
    var er_offsets: [8]usize = undefined;
    for (0..@min(n_types, 8)) |i| er_offsets[i] = readU32(er_data, i * 4);
    const getSlice = struct {
        fn f(er_bytes: []const u8, offs: []const usize, n: usize, idx: usize) ![]const u8 {
            if (idx >= n) return &.{};
            const start = offs[idx];
            const end = if (idx + 1 < n) offs[idx + 1] else er_bytes.len;
            if (start > end or end > er_bytes.len) return error.InvalidSsz;
            return er_bytes[start..end];
        }
    }.f;
    const execution_requests: input_mod.ExecutionRequests = .{
        .deposits = try getSlice(er_data, &er_offsets, n_types, 0),
        .withdrawals = try getSlice(er_data, &er_offsets, n_types, 1),
        .consolidations = try getSlice(er_data, &er_offsets, n_types, 2),
        .builder_deposits = try getSlice(er_data, &er_offsets, n_types, 3),
        .builder_exits = try getSlice(er_data, &er_offsets, n_types, 4),
    };

    // ── SszExecutionPayload fixed region ─────────────────────────────────────────
    // The schema id pins the payload to the Amsterdam 19-field layout (540B fixed).
    if (ep_data.len < EP_FIXED_SIZE) return error.InvalidSsz;

    var parent_hash: [32]u8 = undefined;
    @memcpy(&parent_hash, ep_data[0..32]);

    var fee_recipient: [20]u8 = undefined;
    @memcpy(&fee_recipient, ep_data[32..52]);

    var state_root: [32]u8 = undefined;
    @memcpy(&state_root, ep_data[52..84]);

    var receipts_root: [32]u8 = undefined;
    @memcpy(&receipts_root, ep_data[84..116]);

    var logs_bloom: [256]u8 = undefined;
    @memcpy(&logs_bloom, ep_data[116..372]);

    var prev_randao: [32]u8 = undefined;
    @memcpy(&prev_randao, ep_data[372..404]);

    const block_number: u64 = readU64(ep_data, 404);
    const gas_limit: u64 = readU64(ep_data, 412);
    const gas_used: u64 = readU64(ep_data, 420);
    const timestamp: u64 = readU64(ep_data, 428);

    const off_extra_data: usize = readU32(ep_data, 436);
    // base_fee_per_gas: uint256 LE — low 8 bytes give the u64 value
    const base_fee_per_gas: u64 = readU64(ep_data, 440);
    var block_hash: [32]u8 = undefined;
    @memcpy(&block_hash, ep_data[472..504]);
    // block_hash at [472..504] — not used for execution but needed for SSZ hash_tree_root
    const off_transactions: usize = readU32(ep_data, 504);
    const off_withdrawals: usize = readU32(ep_data, 508);
    const blob_gas_used: u64 = readU64(ep_data, 512);
    const excess_blob_gas: u64 = readU64(ep_data, 520);

    // The first variable-field offset always equals the fixed-region size.
    if (off_extra_data != EP_FIXED_SIZE) return error.InvalidSsz;
    const off_block_access_list: usize = readU32(ep_data, 528);
    const slot_number: ?u64 = readU64(ep_data, 532);

    // Validate variable-field offsets (must be ascending and in range)
    if (off_extra_data > off_transactions or off_transactions > off_withdrawals or
        off_withdrawals > off_block_access_list) return error.InvalidSsz;
    if (off_block_access_list > ep_data.len) return error.InvalidSsz;

    // extra_data: ByteList[32] — raw bytes (not an offset-table list)
    const extra_data = try alloc.dupe(u8, ep_data[off_extra_data..off_transactions]);

    // transactions: List[ByteList, N] — offset-table format
    const txs_raw = try decodeByteListList(alloc, ep_data[off_transactions..off_withdrawals]);
    const transactions = try alloc.alloc(input_mod.Transaction, txs_raw.len);
    for (txs_raw, 0..) |raw_tx, i| {
        transactions[i] = try rlp_decode.decodeSingleTx(alloc, raw_tx);
    }

    // block_access_list: last variable field.
    const block_access_list = try alloc.dupe(u8, ep_data[off_block_access_list..]);

    // withdrawals: List[SszWithdrawal, N] — packed fixed-size items (no offset table).
    const wd_bytes = ep_data[off_withdrawals..off_block_access_list];
    if (wd_bytes.len % WITHDRAWAL_SIZE != 0) return error.InvalidSsz;
    const wcount = wd_bytes.len / WITHDRAWAL_SIZE;
    const withdrawals = try alloc.alloc(input_mod.Withdrawal, wcount);
    for (0..wcount) |i| {
        withdrawals[i] = decodeWithdrawal(wd_bytes[i * WITHDRAWAL_SIZE ..][0..WITHDRAWAL_SIZE]);
    }

    // ── SszExecutionWitness fixed region (12 bytes) ───────────────────────────
    // [0..4]  offset → state (variable)
    // [4..8]  offset → codes (variable)
    // [8..12] offset → headers (variable)
    if (witness_data.len < 12) return error.InvalidSsz;
    const off_state: usize = readU32(witness_data, 0);
    const off_codes: usize = readU32(witness_data, 4);
    const off_headers: usize = readU32(witness_data, 8);

    if (off_state < 12 or off_headers > witness_data.len) return error.InvalidSsz;
    if (off_state > off_codes or off_codes > off_headers) return error.InvalidSsz;

    const nodes = try decodeByteListList(alloc, witness_data[off_state..off_codes]);
    const codes = try decodeByteListList(alloc, witness_data[off_codes..off_headers]);
    const headers = try decodeByteListList(alloc, witness_data[off_headers..]);

    // ── Public keys: List[ByteVector[65], N] (glamsterdam-devnet-6 / zkevm@v0.5.0) ────
    // Pre-recovered secp256k1 public keys, one per transaction in order.
    // SSZ schema is now SszList[ByteVector[PUBLIC_KEY_BYTES=65], MAX_PUBLIC_KEYS],
    // i.e. fixed-size elements → encoded as packed 65-byte chunks (no offset table).
    // Each key is uncompressed (0x04 || X || Y, 65 bytes). transition.zig peels the
    // 0x04 prefix to derive the 64-byte form used for address recovery.
    const PUBKEY_SIZE: usize = 65;
    if (pubkeys_data.len % PUBKEY_SIZE != 0) return error.InvalidSsz;
    const pubkey_count = pubkeys_data.len / PUBKEY_SIZE;
    const public_keys = try alloc.alloc([]const u8, pubkey_count);
    for (0..pubkey_count) |i| {
        public_keys[i] = pubkeys_data[i * PUBKEY_SIZE ..][0..PUBKEY_SIZE];
    }

    // ── Assemble StatelessInput ───────────────────────────────────────────────
    return input_mod.StatelessInput{
        .new_payload_request = .{
            .execution_payload = .{
                .parent_hash = parent_hash,
                .fee_recipient = fee_recipient,
                .state_root = state_root, // POST-execution (for output verification)
                .receipts_root = receipts_root,
                .logs_bloom = logs_bloom,
                .prev_randao = prev_randao,
                .block_number = block_number,
                .gas_limit = gas_limit,
                .gas_used = gas_used,
                .timestamp = timestamp,
                .extra_data = extra_data,
                .base_fee_per_gas = base_fee_per_gas,
                .block_hash = block_hash,
                .transactions = transactions,
                .raw_transactions = txs_raw,
                .withdrawals = withdrawals,
                .blob_gas_used = blob_gas_used,
                .excess_blob_gas = excess_blob_gas,
                .slot_number = slot_number,
                .block_access_list = block_access_list,
            },
            .parent_beacon_block_root = parent_beacon_root,
            .versioned_hashes = versioned_hashes,
            .execution_requests = execution_requests,
        },
        .witness = .{
            .nodes = nodes,
            .codes = codes,
            .headers = headers,
        },
        .chain_config = .{
            .chain_id = if (chain_id != 0) chain_id else 1,
            .fork_name = SCHEMA_FORK_NAME,
            .schema_id = SCHEMA_ID,
        },
        .public_keys = public_keys,
    };
}
