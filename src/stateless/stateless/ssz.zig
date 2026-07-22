//! Manual SSZ decoder for SszStatelessInput (Amsterdam stateless block execution).
//!
//! Implements the schema from stateless_ssz.py without any external SSZ library.
//! All container offsets are relative to the start of each container's byte slice.
//!
//! Container layouts (fixed region sizes):
//!   SszStatelessInput:    16 bytes  [4+4+4+4] all-variable (v0.4.1)
//!   SszNewPayloadRequest: 44 bytes  [4+4+32+4]
//!   SszExecutionPayload: 540 bytes  (see EP_FIXED_SIZE)
//!   SszExecutionWitness:  12 bytes  [4+4+4]
//!   SszWithdrawal:        44 bytes  fixed (8+8+20+8)

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

// ── Fork enum (glamsterdam-devnet-6 / zkevm@v0.5.0) ──────────────────────────────────

/// ProtocolFork IntEnum values from execution-specs glamsterdam-devnet-7 / zkevm@v0.6.2.
/// PR#3138 replaced the zero-indexed PROTOCOL_FORKS tuple with a stable IntEnum where
/// Frontier=0x01, ..., Amsterdam=0x15. The first byte of the 2-byte schema_id prefix
/// carries this value; the fork is no longer encoded inside SszForkConfig.
/// The string returned here matches what zesu's spec resolver (fork.specForBlock) expects.
fn forkNameFromSchemaByte(b: u8) []const u8 {
    return switch (b) {
        0x01 => "Frontier",
        0x02 => "Homestead",
        0x03 => "DAOFork",
        0x04 => "TangerineWhistle",
        0x05 => "SpuriousDragon",
        0x06 => "Byzantium",
        0x07 => "StPetersburg",
        0x08 => "Istanbul",
        0x09 => "MuirGlacier",
        0x0a => "Berlin",
        0x0b => "London",
        0x0c => "ArrowGlacier",
        0x0d => "GrayGlacier",
        0x0e => "Paris",
        0x0f => "Shanghai",
        0x10 => "Cancun",
        0x11 => "Prague",
        0x12 => "Osaka",
        0x13 => "BPO1",
        0x14 => "BPO2",
        0x15 => "Amsterdam",
        else => "",
    };
}

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
/// 2. v0.4.1 layout (2-byte big-endian schema_id 0x0001 + 16-byte all-variable container):
///    [0..2]   schema_id (0x0001 BE)
///    [2..6]   offset → new_payload_request
///    [6..10]  offset → witness
///    [10..14] offset → chain_config (SszChainConfig: chain_id + SszForkConfig)
///    [14..18] offset → public_keys (packed ByteVector[65])
pub fn decode(alloc: std.mem.Allocator, data: []const u8) !input_mod.StatelessInput {
    // Strip Ere's 4-byte LE length prefix when present. The first 4 bytes of
    // raw SSZ are always a small offset value, so matching against data.len-4
    // is unambiguous for any real payload.
    const payload = if (data.len >= 4 and
        std.mem.readInt(u32, data[0..4], .little) == data.len - 4)
        data[4..]
    else
        data;

    // zkevm@v0.6.2 (PR#3138): schema_id = fork_byte || revision_byte, where fork_byte is the
    // ProtocolFork IntEnum value and revision_byte is 0x01 for the first schema revision.
    if (payload.len < 2 or payload[1] != 0x01) return error.InvalidSsz;
    const fork_name_bytes = forkNameFromSchemaByte(payload[0]);
    if (fork_name_bytes.len == 0) return error.InvalidSsz;

    // ── v0.4.1: schema_id prefix + 16-byte all-variable container ────────────
    const body = payload[2..];
    if (body.len < 16) return error.InvalidSsz;
    const off_npr: usize = readU32(body, 0);
    const off_witness: usize = readU32(body, 4);
    const off_chain_config: usize = readU32(body, 8);
    const off_pubkeys: usize = readU32(body, 12);

    if (off_npr != 16 or off_witness > body.len or off_chain_config > body.len or off_pubkeys > body.len) return error.InvalidSsz;
    if (off_npr > off_witness or off_witness > off_chain_config or off_chain_config > off_pubkeys) return error.InvalidSsz;

    const chain_config_data = body[off_chain_config..off_pubkeys];

    // SszChainConfig: chain_id (uint64 LE) + offset → active_fork + SszForkConfig.
    // zkevm@v0.6.2 (PR#3138): SszForkConfig no longer contains fork or blob_schedule;
    // it only carries activation_offset (4 bytes). Fork identity comes from the schema prefix.
    if (chain_config_data.len < 12) return error.InvalidSsz;
    const chain_id = readU64(chain_config_data, 0);
    const off_active_fork: usize = readU32(chain_config_data, 8);
    if (off_active_fork + 4 > chain_config_data.len) return error.InvalidSsz;

    // SszForkConfig: activation_offset [0..4] (only field).
    // SszForkActivation: block_number list offset [0..4], timestamp list offset [4..8]; each
    // list is 0 bytes (empty) or 8 bytes (a single uint64).
    var activation_block: ?u64 = null;
    var activation_timestamp: ?u64 = null;
    {
        const af = chain_config_data[off_active_fork..];
        const off_activation: usize = readU32(af, 0);
        if (off_activation + 8 <= af.len) {
            const act = af[off_activation..];
            const off_bn: usize = readU32(act, 0);
            const off_ts: usize = readU32(act, 4);
            if (off_bn <= off_ts and off_ts <= act.len) {
                if (off_ts - off_bn >= 8) activation_block = readU64(act, off_bn);
                if (act.len - off_ts >= 8) activation_timestamp = readU64(act, off_ts);
            }
        }
    }
    const npr_data = body[off_npr..off_witness];
    const witness_data = body[off_witness..off_chain_config];
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
    // V3 EP (Prague/Osaka): 528B fixed, off_extra_data == 528. No block_access_list or slot_number.
    // V4 EP (Amsterdam+):  540B fixed, off_extra_data == 540. Adds both fields.
    // Detect by the extra_data offset value, which always equals the fixed-region size.
    const EP_V3_FIXED_SIZE: usize = 528;
    if (ep_data.len < EP_V3_FIXED_SIZE) return error.InvalidSsz;

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

    // V4-specific fields (Amsterdam+); use sentinel/null for V3.
    const ep_is_amsterdam = (off_extra_data == EP_FIXED_SIZE);
    const ep_is_v3 = (off_extra_data == EP_V3_FIXED_SIZE);
    if (!ep_is_amsterdam and !ep_is_v3) return error.InvalidSsz;
    if (ep_is_amsterdam and ep_data.len < EP_FIXED_SIZE) return error.InvalidSsz;
    // For V3, sentinel points past all variable data so block_access_list comes out empty.
    const off_block_access_list: usize = if (ep_is_amsterdam) readU32(ep_data, 528) else ep_data.len;
    const slot_number: ?u64 = if (ep_is_amsterdam) readU64(ep_data, 532) else null;

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

    // block_access_list: last variable field (V4 only; empty for V3 via sentinel offset).
    const block_access_list = try alloc.dupe(u8, ep_data[off_block_access_list..]);

    // withdrawals: List[SszWithdrawal, N] — packed fixed-size items (no offset table).
    // off_block_access_list acts as the end sentinel for V3 (== ep_data.len).
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
            .fork_name = if (fork_name_bytes.len > 0) fork_name_bytes else null,
            .active_fork_idx = payload[0],
            .activation_block = activation_block,
            .activation_timestamp = activation_timestamp,
        },
        .public_keys = public_keys,
    };
}
