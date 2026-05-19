//! Raw RLP → input type decoders.
//!
//! Single source of truth for decoding Ethereum wire-format bytes into the
//! typed structs defined in input.zig.  Both io.zig (JSON path) and
//! executor/tx_decode.zig (raw-bytes path) call into these functions.

const std = @import("std");
const input = @import("input");
const primitives = @import("primitives");
const mpt = @import("mpt");

// ── Public types ──────────────────────────────────────────────────────────────

/// Number + state root extracted from a bare RLP block header.
/// Used by findPreStateRoot to scan witness.headers.
pub const MinimalHeader = struct {
    number: u64,
    state_root: [32]u8,
};

/// Subset of header fields needed to populate Env.parent_* before execution
/// (gas/basefee for EIP-1559 base-fee check, blob-gas pair for EIP-4844
/// excess-blob-gas check). All optionals are `null` for pre-fork parents.
pub const ParentHeader = struct {
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    base_fee_per_gas: ?u64,
    blob_gas_used: ?u64,
    excess_blob_gas: ?u64,
};

// ── Public API ────────────────────────────────────────────────────────────────

/// Decode all block header fields from a bare RLP list payload (no outer wrapper).
pub fn decodeBlockHeader(allocator: std.mem.Allocator, payload: []const u8) !input.BlockHeader {
    var rest = payload;
    var hdr: input.BlockHeader = std.mem.zeroes(input.BlockHeader);

    hdr.parent_hash = try nextHash(&rest); // [0]
    hdr.ommers_hash = try nextHash(&rest); // [1]
    hdr.beneficiary = try nextAddress(&rest); // [2]
    hdr.state_root = try nextHash(&rest); // [3]
    hdr.transactions_root = try nextHash(&rest); // [4]
    hdr.receipts_root = try nextHash(&rest); // [5]

    // [6] logsBloom — 256 bytes
    {
        const r = mpt.rlp.decodeItem(rest) catch return error.InvalidBlock;
        const b = switch (r.item) {
            .bytes => |bs| bs,
            .list => return error.InvalidBlock,
        };
        if (b.len != 256) return error.InvalidBlock;
        @memcpy(&hdr.logs_bloom, b);
        rest = rest[r.consumed..];
    }

    hdr.difficulty = try nextUint256(&rest); // [7]
    hdr.number = try nextUint64(&rest); // [8]
    hdr.gas_limit = try nextUint64(&rest); // [9]
    hdr.gas_used = try nextUint64(&rest); // [10]
    hdr.timestamp = try nextUint64(&rest); // [11]

    // [12] extraData — variable-length bytes
    {
        const r = mpt.rlp.decodeItem(rest) catch return error.InvalidBlock;
        const b = switch (r.item) {
            .bytes => |bs| bs,
            .list => return error.InvalidBlock,
        };
        const copy = allocator.alloc(u8, b.len) catch return error.InvalidBlock;
        @memcpy(copy, b);
        hdr.extra_data = copy;
        rest = rest[r.consumed..];
    }

    hdr.mix_hash = try nextHash(&rest); // [13]

    // [14] nonce — 8 bytes, always 0 in PoS
    {
        const r = mpt.rlp.decodeItem(rest) catch return error.InvalidBlock;
        const b = switch (r.item) {
            .bytes => |bs| bs,
            .list => return error.InvalidBlock,
        };
        if (b.len > 8) return error.InvalidBlock;
        var v: u64 = 0;
        for (b) |byte| v = (v << 8) | byte;
        hdr.nonce = v;
        rest = rest[r.consumed..];
    }

    // Optional post-London fields — absent in pre-London blocks.
    if (rest.len > 0) hdr.base_fee_per_gas = try nextUint64(&rest); // [15]
    if (rest.len > 0) hdr.withdrawals_root = try nextHash(&rest); // [16]
    if (rest.len > 0) hdr.blob_gas_used = try nextUint64(&rest); // [17]
    if (rest.len > 0) hdr.excess_blob_gas = try nextUint64(&rest); // [18]
    if (rest.len > 0) hdr.parent_beacon_block_root = try nextHash(&rest); // [19]
    if (rest.len > 0) hdr.requests_hash = try nextHash(&rest); // [20]
    if (rest.len > 0) hdr.block_access_list_hash = try nextHash(&rest); // [21]
    if (rest.len > 0) hdr.slot_number = try nextUint64(&rest); // [22]

    return hdr;
}

/// Decode the subset of header fields needed for Env.parent_* population
/// (gas_limit, gas_used, timestamp, base_fee_per_gas, blob_gas_used,
/// excess_blob_gas). Returns null for absent post-London/Cancun fields.
/// No heap allocation — extra_data, bloom etc. are skipped.
pub fn decodeParentHeader(raw: []const u8) error{InvalidBlock}!ParentHeader {
    const hdr_r = mpt.rlp.decodeItem(raw) catch return error.InvalidBlock;
    const hdr_payload = switch (hdr_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBlock,
    };
    var rest = hdr_payload;

    // Skip fields [0]..[8]: parent_hash, ommers, beneficiary, state_root,
    // tx_root, receipts_root, logs_bloom, difficulty, number.
    var i: usize = 0;
    while (i < 9) : (i += 1) {
        if (rest.len == 0) return error.InvalidBlock;
        const r = mpt.rlp.decodeItem(rest) catch return error.InvalidBlock;
        rest = rest[r.consumed..];
    }

    const gas_limit = try nextUint64(&rest); // [9]
    const gas_used = try nextUint64(&rest); // [10]
    const timestamp = try nextUint64(&rest); // [11]

    // Skip [12] extra_data, [13] mix_hash, [14] nonce.
    var j: usize = 0;
    while (j < 3) : (j += 1) {
        if (rest.len == 0) {
            return .{
                .gas_limit = gas_limit,
                .gas_used = gas_used,
                .timestamp = timestamp,
                .base_fee_per_gas = null,
                .blob_gas_used = null,
                .excess_blob_gas = null,
            };
        }
        const r = mpt.rlp.decodeItem(rest) catch return error.InvalidBlock;
        rest = rest[r.consumed..];
    }

    // [15] base_fee_per_gas (London+).
    const base_fee_per_gas: ?u64 = if (rest.len == 0) null else try nextUint64(&rest);

    // Skip [16] withdrawals_root (Shanghai+).
    if (rest.len > 0) {
        const r = mpt.rlp.decodeItem(rest) catch return error.InvalidBlock;
        rest = rest[r.consumed..];
    }

    // [17] blob_gas_used, [18] excess_blob_gas (Cancun+).
    const blob_gas_used: ?u64 = if (rest.len == 0) null else try nextUint64(&rest);
    const excess_blob_gas: ?u64 = if (rest.len == 0) null else try nextUint64(&rest);

    return .{
        .gas_limit = gas_limit,
        .gas_used = gas_used,
        .timestamp = timestamp,
        .base_fee_per_gas = base_fee_per_gas,
        .blob_gas_used = blob_gas_used,
        .excess_blob_gas = excess_blob_gas,
    };
}

/// Find the pre-execution state root for `block_number` by scanning `headers`
/// (bare RLP-encoded block headers from the witness) for block number-1.
/// Returns null if block_number is 0 or no matching header is found.
pub fn findPreStateRoot(headers: []const []const u8, block_number: u64) ?[32]u8 {
    if (block_number == 0) return null;
    const parent_number = block_number - 1;
    for (headers) |hdr_bytes| {
        const hdr = decodeMinimalHeader(hdr_bytes) catch continue;
        if (hdr.number == parent_number) return hdr.state_root;
    }
    return null;
}

/// Decode number and state root from a bare RLP block header.
/// Used to scan witness.headers for the pre-execution state root.
pub fn decodeMinimalHeader(raw: []const u8) error{InvalidBlock}!MinimalHeader {
    const hdr_r = mpt.rlp.decodeItem(raw) catch return error.InvalidBlock;
    const hdr_payload = switch (hdr_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBlock,
    };

    var rest = hdr_payload;
    var state_root: [32]u8 = @splat(0);
    var number: u64 = 0;
    var i: usize = 0;
    while (i <= 8) : (i += 1) {
        if (rest.len == 0) return error.InvalidBlock;
        const r = mpt.rlp.decodeItem(rest) catch return error.InvalidBlock;
        switch (i) {
            3 => {
                const b = switch (r.item) {
                    .bytes => |bts| bts,
                    .list => return error.InvalidBlock,
                };
                if (b.len != 32) return error.InvalidBlock;
                @memcpy(&state_root, b);
            },
            8 => {
                const b = switch (r.item) {
                    .bytes => |bts| bts,
                    .list => return error.InvalidBlock,
                };
                if (b.len > 8) return error.InvalidBlock;
                for (b) |byte| number = (number << 8) | byte;
            },
            else => {},
        }
        rest = rest[r.consumed..];
    }
    return MinimalHeader{ .number = number, .state_root = state_root };
}

/// Decode the withdrawals list RLP payload (EIP-4895, Shanghai+).
/// Each withdrawal is RLP([index, validatorIndex, address, amount]).
pub fn decodeWithdrawals(alloc: std.mem.Allocator, payload: []const u8) ![]const input.Withdrawal {
    var wds = std.ArrayListUnmanaged(input.Withdrawal).empty;
    var rest = payload;
    while (rest.len > 0) {
        const wr = mpt.rlp.decodeItem(rest) catch break;
        rest = rest[wr.consumed..];
        var wp = switch (wr.item) {
            .list => |p| p,
            .bytes => continue,
        };
        const index = try txU64(&wp);
        const validator_index = try txU64(&wp);
        const addr = (try txAddr(&wp)) orelse return error.InvalidBlock;
        const amount = try txU64(&wp);
        wds.append(alloc, .{
            .index = index,
            .validator_index = validator_index,
            .address = addr,
            .amount = amount,
        }) catch return error.InvalidBlock;
    }
    return wds.toOwnedSlice(alloc) catch return error.InvalidBlock;
}

/// Decode the block body's transaction list RLP payload into decoded Transactions.
/// Each entry is either a legacy RLP list or an EIP-2718 typed tx (byte string).
pub fn decodeTxList(allocator: std.mem.Allocator, payload: []const u8) ![]const input.Transaction {
    var txns = std.ArrayListUnmanaged(input.Transaction).empty;
    var rest = payload;
    while (rest.len > 0) {
        const r = mpt.rlp.decodeItem(rest) catch return error.InvalidBlock;
        const tx = try decodeTxItem(allocator, r.item);
        txns.append(allocator, tx) catch return error.InvalidBlock;
        rest = rest[r.consumed..];
    }
    return txns.toOwnedSlice(allocator) catch return error.InvalidBlock;
}

/// Decode a single transaction from standalone wire-format bytes.
///   Legacy tx:  raw[0] >= 0xc0 — full RLP list.
///   Typed tx:   raw[0] < 0x80  — type byte followed by RLP-encoded payload.
pub fn decodeSingleTx(allocator: std.mem.Allocator, raw: []const u8) !input.Transaction {
    if (raw.len == 0) return error.InvalidBlock;
    if (raw[0] >= 0xc0) {
        const r = mpt.rlp.decodeItem(raw) catch return error.InvalidBlock;
        return decodeTxItem(allocator, r.item);
    }
    if (raw[0] < 0x80) {
        const tx_type = raw[0];
        if (tx_type == 0 or tx_type > 4) return error.InvalidBlock;
        const r = mpt.rlp.decodeItem(raw[1..]) catch return error.InvalidBlock;
        const payload = switch (r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBlock,
        };
        return decodeTxFields(allocator, tx_type, payload);
    }
    return error.InvalidBlock;
}

// ── Private dispatch ──────────────────────────────────────────────────────────

/// Dispatch from an RLP item (as decoded from a block body tx list) to decodeTxFields.
fn decodeTxItem(allocator: std.mem.Allocator, item: anytype) !input.Transaction {
    switch (item) {
        .list => |p| return decodeTxFields(allocator, 0, p),
        .bytes => |data| {
            if (data.len < 2) return error.InvalidBlock;
            const tx_type = data[0];
            if (tx_type == 0 or tx_type > 4) return error.InvalidBlock;
            const r = mpt.rlp.decodeItem(data[1..]) catch return error.InvalidBlock;
            const payload = switch (r.item) {
                .list => |p| p,
                .bytes => return error.InvalidBlock,
            };
            return decodeTxFields(allocator, tx_type, payload);
        },
    }
}

/// Decode all transaction fields given a type byte and the decoded RLP list payload.
fn decodeTxFields(allocator: std.mem.Allocator, tx_type: u8, payload: []const u8) !input.Transaction {
    var tx = input.Transaction{
        .tx_type = tx_type,
        .chain_id = null,
        .nonce = 0,
        .gas_price = 0,
        .gas_priority_fee = null,
        .gas_limit = 0,
        .to = null,
        .value = 0,
        .data = &.{},
        .access_list = &.{},
        .blob_hashes = &.{},
        .max_fee_per_blob_gas = 0,
        .authorization_list = &.{},
        .v = 0,
        .r = 0,
        .s = 0,
    };
    var rest = payload;

    switch (tx_type) {
        0 => {
            // Legacy: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
            tx.nonce = try txU64(&rest);
            tx.gas_price = try txU128(&rest);
            tx.gas_limit = try txU64(&rest);
            tx.to = try txAddr(&rest);
            tx.value = try txU256(&rest);
            tx.data = try txBytesCopy(allocator, &rest);
            const v_raw = try txU256(&rest);
            tx.r = try txU256(&rest);
            tx.s = try txU256(&rest);
            // Decode y_parity and chain_id from the raw Ethereum v.
            // EIP-155: v = chain_id*2 + 35 + y_parity  →  y_parity = (v-35) % 2
            // Legacy:  v = 27 + y_parity               →  y_parity = v - 27
            if (v_raw >= 35) {
                tx.chain_id = @intCast((v_raw - 35) / 2);
                tx.v = @intCast((v_raw - 35) % 2);
            } else if (v_raw >= 27) {
                tx.v = @intCast(v_raw - 27);
            }
        },
        1 => {
            // EIP-2930: [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, v, r, s]
            tx.chain_id = try txU64(&rest);
            tx.nonce = try txU64(&rest);
            tx.gas_price = try txU128(&rest);
            tx.gas_limit = try txU64(&rest);
            tx.to = try txAddr(&rest);
            tx.value = try txU256(&rest);
            tx.data = try txBytesCopy(allocator, &rest);
            tx.access_list = try txAccessList(allocator, &rest);
            tx.v = try txU64(&rest);
            tx.r = try txU256(&rest);
            tx.s = try txU256(&rest);
        },
        2 => {
            // EIP-1559: [chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, accessList, v, r, s]
            tx.chain_id = try txU64(&rest);
            tx.nonce = try txU64(&rest);
            tx.gas_priority_fee = try txU128(&rest);
            tx.gas_price = try txU128(&rest);
            tx.gas_limit = try txU64(&rest);
            tx.to = try txAddr(&rest);
            tx.value = try txU256(&rest);
            tx.data = try txBytesCopy(allocator, &rest);
            tx.access_list = try txAccessList(allocator, &rest);
            tx.v = try txU64(&rest);
            tx.r = try txU256(&rest);
            tx.s = try txU256(&rest);
        },
        3 => {
            // EIP-4844: [..., accessList, maxFeePerBlobGas, blobVersionedHashes, v, r, s]
            tx.chain_id = try txU64(&rest);
            tx.nonce = try txU64(&rest);
            tx.gas_priority_fee = try txU128(&rest);
            tx.gas_price = try txU128(&rest);
            tx.gas_limit = try txU64(&rest);
            tx.to = try txAddr(&rest);
            tx.value = try txU256(&rest);
            tx.data = try txBytesCopy(allocator, &rest);
            tx.access_list = try txAccessList(allocator, &rest);
            tx.max_fee_per_blob_gas = try txU128(&rest);
            tx.blob_hashes = try txHashList(allocator, &rest);
            tx.v = try txU64(&rest);
            tx.r = try txU256(&rest);
            tx.s = try txU256(&rest);
        },
        4 => {
            // EIP-7702: [..., accessList, authorizationList, v, r, s]
            tx.chain_id = try txU64(&rest);
            tx.nonce = try txU64(&rest);
            tx.gas_priority_fee = try txU128(&rest);
            tx.gas_price = try txU128(&rest);
            tx.gas_limit = try txU64(&rest);
            tx.to = try txAddr(&rest);
            tx.value = try txU256(&rest);
            tx.data = try txBytesCopy(allocator, &rest);
            tx.access_list = try txAccessList(allocator, &rest);
            tx.authorization_list = try txAuthList(allocator, &rest);
            tx.v = try txU64(&rest);
            tx.r = try txU256(&rest);
            tx.s = try txU256(&rest);
        },
        else => return error.InvalidBlock,
    }
    return tx;
}

// ── Transaction field helpers ─────────────────────────────────────────────────

fn txBytesView(rest: *[]const u8) error{InvalidBlock}![]const u8 {
    const r = mpt.rlp.decodeItem(rest.*) catch return error.InvalidBlock;
    const b = switch (r.item) {
        .bytes => |bs| bs,
        .list => return error.InvalidBlock,
    };
    rest.* = rest.*[r.consumed..];
    return b;
}

fn txBytesCopy(alloc: std.mem.Allocator, rest: *[]const u8) ![]const u8 {
    const b = try txBytesView(rest);
    return alloc.dupe(u8, b) catch return error.InvalidBlock;
}

fn txU64(rest: *[]const u8) error{InvalidBlock}!u64 {
    const b = try txBytesView(rest);
    if (b.len > 8) return error.InvalidBlock;
    var v: u64 = 0;
    for (b) |byte| v = (v << 8) | byte;
    return v;
}

fn txU128(rest: *[]const u8) error{InvalidBlock}!u128 {
    const b = try txBytesView(rest);
    if (b.len > 16) return std.math.maxInt(u128);
    var v: u128 = 0;
    for (b) |byte| v = (v << 8) | byte;
    return v;
}

fn txU256(rest: *[]const u8) error{InvalidBlock}!u256 {
    const b = try txBytesView(rest);
    if (b.len > 32) return error.InvalidBlock;
    var v: u256 = 0;
    for (b) |byte| v = (v << 8) | byte;
    return v;
}

fn txAddr(rest: *[]const u8) error{InvalidBlock}!?primitives.Address {
    const r = mpt.rlp.decodeItem(rest.*) catch return error.InvalidBlock;
    rest.* = rest.*[r.consumed..];
    const b = switch (r.item) {
        .bytes => |bs| bs,
        .list => return error.InvalidBlock,
    };
    if (b.len == 0) return null;
    if (b.len != 20) return error.InvalidBlock;
    var addr: primitives.Address = undefined;
    @memcpy(&addr, b);
    return addr;
}

fn txAccessList(alloc: std.mem.Allocator, rest: *[]const u8) ![]const input.AccessListEntry {
    const r = mpt.rlp.decodeItem(rest.*) catch return error.InvalidBlock;
    const al_payload = switch (r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBlock,
    };
    rest.* = rest.*[r.consumed..];

    var entries = std.ArrayListUnmanaged(input.AccessListEntry).empty;
    var al = al_payload;
    while (al.len > 0) {
        const er = mpt.rlp.decodeItem(al) catch return error.InvalidBlock;
        var ep = switch (er.item) {
            .list => |p| p,
            .bytes => return error.InvalidBlock,
        };
        al = al[er.consumed..];

        const addr_r = mpt.rlp.decodeItem(ep) catch return error.InvalidBlock;
        const addr_b = switch (addr_r.item) {
            .bytes => |b| b,
            .list => return error.InvalidBlock,
        };
        if (addr_b.len != 20) return error.InvalidBlock;
        var addr: primitives.Address = undefined;
        @memcpy(&addr, addr_b);
        ep = ep[addr_r.consumed..];

        const keys_r = mpt.rlp.decodeItem(ep) catch return error.InvalidBlock;
        const kp_payload = switch (keys_r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBlock,
        };
        var keys = std.ArrayListUnmanaged(primitives.Hash).empty;
        var kp = kp_payload;
        while (kp.len > 0) {
            const k_r = mpt.rlp.decodeItem(kp) catch return error.InvalidBlock;
            const k_b = switch (k_r.item) {
                .bytes => |b| b,
                .list => return error.InvalidBlock,
            };
            if (k_b.len != 32) return error.InvalidBlock;
            var key: primitives.Hash = undefined;
            @memcpy(&key, k_b);
            keys.append(alloc, key) catch return error.InvalidBlock;
            kp = kp[k_r.consumed..];
        }
        entries.append(alloc, .{
            .address = addr,
            .storage_keys = keys.toOwnedSlice(alloc) catch return error.InvalidBlock,
        }) catch return error.InvalidBlock;
    }
    return entries.toOwnedSlice(alloc) catch return error.InvalidBlock;
}

fn txHashList(alloc: std.mem.Allocator, rest: *[]const u8) ![]const primitives.Hash {
    const r = mpt.rlp.decodeItem(rest.*) catch return error.InvalidBlock;
    const payload = switch (r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBlock,
    };
    rest.* = rest.*[r.consumed..];
    var hashes = std.ArrayListUnmanaged(primitives.Hash).empty;
    var p = payload;
    while (p.len > 0) {
        const hr = mpt.rlp.decodeItem(p) catch return error.InvalidBlock;
        const b = switch (hr.item) {
            .bytes => |bs| bs,
            .list => return error.InvalidBlock,
        };
        if (b.len != 32) return error.InvalidBlock;
        var h: primitives.Hash = undefined;
        @memcpy(&h, b);
        hashes.append(alloc, h) catch return error.InvalidBlock;
        p = p[hr.consumed..];
    }
    return hashes.toOwnedSlice(alloc) catch return error.InvalidBlock;
}

fn txAuthList(alloc: std.mem.Allocator, rest: *[]const u8) ![]const input.AuthorizationTuple {
    const r = mpt.rlp.decodeItem(rest.*) catch return error.InvalidBlock;
    const payload = switch (r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBlock,
    };
    rest.* = rest.*[r.consumed..];
    var items = std.ArrayListUnmanaged(input.AuthorizationTuple).empty;
    var p = payload;
    while (p.len > 0) {
        const ir = mpt.rlp.decodeItem(p) catch return error.InvalidBlock;
        var ep = switch (ir.item) {
            .list => |lp| lp,
            .bytes => return error.InvalidBlock,
        };
        p = p[ir.consumed..];
        const chain_id = try txU256(&ep);
        const addr_b = try txBytesView(&ep);
        if (addr_b.len != 20) return error.InvalidBlock;
        var addr: primitives.Address = undefined;
        @memcpy(&addr, addr_b);
        const nonce = try txU64(&ep);
        const v = try txU64(&ep);
        const rv = try txU256(&ep);
        const sv = try txU256(&ep);
        items.append(alloc, .{
            .chain_id = chain_id,
            .address = addr,
            .nonce = nonce,
            .v = v,
            .r = rv,
            .s = sv,
        }) catch return error.InvalidBlock;
    }
    return items.toOwnedSlice(alloc) catch return error.InvalidBlock;
}

// ── Header field helpers ──────────────────────────────────────────────────────

fn nextHash(rest: *[]const u8) error{InvalidBlock}![32]u8 {
    const r = mpt.rlp.decodeItem(rest.*) catch return error.InvalidBlock;
    const b = switch (r.item) {
        .bytes => |bs| bs,
        .list => return error.InvalidBlock,
    };
    if (b.len != 32) return error.InvalidBlock;
    var out: [32]u8 = undefined;
    @memcpy(&out, b);
    rest.* = rest.*[r.consumed..];
    return out;
}

fn nextAddress(rest: *[]const u8) error{InvalidBlock}![20]u8 {
    const r = mpt.rlp.decodeItem(rest.*) catch return error.InvalidBlock;
    const b = switch (r.item) {
        .bytes => |bs| bs,
        .list => return error.InvalidBlock,
    };
    if (b.len != 20) return error.InvalidBlock;
    var out: [20]u8 = undefined;
    @memcpy(&out, b);
    rest.* = rest.*[r.consumed..];
    return out;
}

fn nextUint64(rest: *[]const u8) error{InvalidBlock}!u64 {
    const r = mpt.rlp.decodeItem(rest.*) catch return error.InvalidBlock;
    const b = switch (r.item) {
        .bytes => |bs| bs,
        .list => return error.InvalidBlock,
    };
    if (b.len > 8) return error.InvalidBlock;
    var v: u64 = 0;
    for (b) |byte| v = (v << 8) | byte;
    rest.* = rest.*[r.consumed..];
    return v;
}

fn nextUint256(rest: *[]const u8) error{InvalidBlock}!u256 {
    const r = mpt.rlp.decodeItem(rest.*) catch return error.InvalidBlock;
    const b = switch (r.item) {
        .bytes => |bs| bs,
        .list => return error.InvalidBlock,
    };
    if (b.len > 32) return error.InvalidBlock;
    var v: u256 = 0;
    for (b) |byte| v = (v << 8) | byte;
    rest.* = rest.*[r.consumed..];
    return v;
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

/// Append an RLP-encoded byte string of length ≤ 55.
fn appendShortBytes(buf: *std.ArrayListUnmanaged(u8), alloc: std.mem.Allocator, b: []const u8) !void {
    try buf.append(alloc, 0x80 + @as(u8, @intCast(b.len)));
    try buf.appendSlice(alloc, b);
}

// Writes the RLP long-form length header: one byte of (base + number-of-length-bytes),
// followed by the big-endian length with leading zeros stripped.
fn appendLongHeader(buf: *std.ArrayListUnmanaged(u8), alloc: std.mem.Allocator, base: u8, len: usize) !void {
    var be: [8]u8 = undefined;
    std.mem.writeInt(u64, &be, len, .big);
    var i: usize = 0;
    while (i < 8 and be[i] == 0) : (i += 1) {}
    const compact = be[i..];
    try buf.append(alloc, base + @as(u8, @intCast(compact.len)));
    try buf.appendSlice(alloc, compact);
}

/// Append an RLP-encoded byte string of any length.
fn appendBytes(buf: *std.ArrayListUnmanaged(u8), alloc: std.mem.Allocator, b: []const u8) !void {
    if (b.len == 0) {
        try buf.append(alloc, 0x80);
    } else if (b.len == 1 and b[0] < 0x80) {
        try buf.append(alloc, b[0]);
    } else if (b.len <= 55) {
        try appendShortBytes(buf, alloc, b);
    } else {
        try appendLongHeader(buf, alloc, 0xb7, b.len);
        try buf.appendSlice(alloc, b);
    }
}

/// Append an RLP-encoded unsigned integer (compact, no leading zeros).
fn appendUint(buf: *std.ArrayListUnmanaged(u8), alloc: std.mem.Allocator, v: u64) !void {
    if (v == 0) {
        try buf.append(alloc, 0x80);
        return;
    }
    var be: [8]u8 = undefined;
    std.mem.writeInt(u64, &be, v, .big);
    var i: usize = 0;
    while (i < 8 and be[i] == 0) : (i += 1) {}
    try appendBytes(buf, alloc, be[i..]);
}

/// Wrap a raw payload in an RLP list prefix, producing a fully-encoded RLP list.
fn wrapRlpList(alloc: std.mem.Allocator, payload: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);
    if (payload.len <= 55) {
        try buf.append(alloc, 0xc0 + @as(u8, @intCast(payload.len)));
    } else {
        try appendLongHeader(&buf, alloc, 0xf7, payload.len);
    }
    try buf.appendSlice(alloc, payload);
    return buf.toOwnedSlice(alloc);
}

/// Build a header RLP payload with the given list of optional trailing fields appended
/// after the 15 mandatory fields (parent_hash..nonce). Returns owned bytes.
fn buildHeaderPayload(alloc: std.mem.Allocator, opt_trailers: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);

    const zero_hash: [32]u8 = @splat(0);
    const zero_addr: [20]u8 = @splat(0);
    const zero_bloom: [256]u8 = @splat(0);

    try appendBytes(&buf, alloc, &zero_hash); // [0] parent_hash
    try appendBytes(&buf, alloc, &zero_hash); // [1] ommers_hash
    try appendBytes(&buf, alloc, &zero_addr); // [2] beneficiary
    try appendBytes(&buf, alloc, &zero_hash); // [3] state_root
    try appendBytes(&buf, alloc, &zero_hash); // [4] transactions_root
    try appendBytes(&buf, alloc, &zero_hash); // [5] receipts_root
    try appendBytes(&buf, alloc, &zero_bloom); // [6] logs_bloom
    try appendUint(&buf, alloc, 0); // [7] difficulty
    try appendUint(&buf, alloc, 1234); // [8] number
    try appendUint(&buf, alloc, 30_000_000); // [9] gas_limit
    try appendUint(&buf, alloc, 21_000); // [10] gas_used
    try appendUint(&buf, alloc, 1_700_000_000); // [11] timestamp
    try appendBytes(&buf, alloc, &.{}); // [12] extra_data (empty)
    try appendBytes(&buf, alloc, &zero_hash); // [13] mix_hash
    try appendUint(&buf, alloc, 0); // [14] nonce
    try buf.appendSlice(alloc, opt_trailers);

    return buf.toOwnedSlice(alloc);
}

test "decodeBlockHeader: post-Prague header has Amsterdam fields null" {
    const alloc = std.testing.allocator;
    const zero_hash: [32]u8 = @splat(0);

    var trailers: std.ArrayListUnmanaged(u8) = .empty;
    defer trailers.deinit(alloc);
    try appendUint(&trailers, alloc, 7); // [15] base_fee_per_gas
    try appendBytes(&trailers, alloc, &zero_hash); // [16] withdrawals_root
    try appendUint(&trailers, alloc, 0); // [17] blob_gas_used
    try appendUint(&trailers, alloc, 0); // [18] excess_blob_gas
    try appendBytes(&trailers, alloc, &zero_hash); // [19] parent_beacon_block_root
    try appendBytes(&trailers, alloc, &zero_hash); // [20] requests_hash

    const payload = try buildHeaderPayload(alloc, trailers.items);
    defer alloc.free(payload);

    const hdr = try decodeBlockHeader(alloc, payload);
    defer alloc.free(hdr.extra_data);

    try std.testing.expectEqual(@as(u64, 1234), hdr.number);
    try std.testing.expectEqual(@as(?u64, 7), hdr.base_fee_per_gas);
    try std.testing.expect(hdr.requests_hash != null);
    try std.testing.expectEqual(@as(?primitives.Hash, null), hdr.block_access_list_hash);
    try std.testing.expectEqual(@as(?u64, null), hdr.slot_number);
}

test "decodeBlockHeader: Amsterdam header decodes block_access_list_hash and slot_number" {
    const alloc = std.testing.allocator;
    const zero_hash: [32]u8 = @splat(0);
    var bal_hash: [32]u8 = @splat(0);
    bal_hash[31] = 0xab;

    var trailers: std.ArrayListUnmanaged(u8) = .empty;
    defer trailers.deinit(alloc);
    try appendUint(&trailers, alloc, 7); // [15] base_fee_per_gas
    try appendBytes(&trailers, alloc, &zero_hash); // [16] withdrawals_root
    try appendUint(&trailers, alloc, 0); // [17] blob_gas_used
    try appendUint(&trailers, alloc, 0); // [18] excess_blob_gas
    try appendBytes(&trailers, alloc, &zero_hash); // [19] parent_beacon_block_root
    try appendBytes(&trailers, alloc, &zero_hash); // [20] requests_hash
    try appendBytes(&trailers, alloc, &bal_hash); // [21] block_access_list_hash
    try appendUint(&trailers, alloc, 4242); // [22] slot_number

    const payload = try buildHeaderPayload(alloc, trailers.items);
    defer alloc.free(payload);

    const hdr = try decodeBlockHeader(alloc, payload);
    defer alloc.free(hdr.extra_data);

    try std.testing.expectEqual(@as(u64, 1234), hdr.number);
    try std.testing.expect(hdr.block_access_list_hash != null);
    try std.testing.expectEqualSlices(u8, &bal_hash, &hdr.block_access_list_hash.?);
    try std.testing.expectEqual(@as(?u64, 4242), hdr.slot_number);
}

test "decodeParentHeader: cancun header populates blob-gas fields" {
    const alloc = std.testing.allocator;
    const zero_hash: [32]u8 = @splat(0);

    var trailers: std.ArrayListUnmanaged(u8) = .empty;
    defer trailers.deinit(alloc);
    try appendUint(&trailers, alloc, 7); // [15] base_fee_per_gas
    try appendBytes(&trailers, alloc, &zero_hash); // [16] withdrawals_root
    try appendUint(&trailers, alloc, 131_072); // [17] blob_gas_used (1 blob)
    try appendUint(&trailers, alloc, 524_288); // [18] excess_blob_gas (4 blobs)

    const inner = try buildHeaderPayload(alloc, trailers.items);
    defer alloc.free(inner);
    const payload = try wrapRlpList(alloc, inner);
    defer alloc.free(payload);

    const p = try decodeParentHeader(payload);
    try std.testing.expectEqual(@as(u64, 30_000_000), p.gas_limit);
    try std.testing.expectEqual(@as(u64, 21_000), p.gas_used);
    try std.testing.expectEqual(@as(u64, 1_700_000_000), p.timestamp);
    try std.testing.expectEqual(@as(?u64, 7), p.base_fee_per_gas);
    try std.testing.expectEqual(@as(?u64, 131_072), p.blob_gas_used);
    try std.testing.expectEqual(@as(?u64, 524_288), p.excess_blob_gas);
}

test "decodeParentHeader: pre-London header leaves trailing fields null" {
    const alloc = std.testing.allocator;

    // No optional trailing fields → pre-London.
    const inner = try buildHeaderPayload(alloc, &.{});
    defer alloc.free(inner);
    const payload = try wrapRlpList(alloc, inner);
    defer alloc.free(payload);

    const p = try decodeParentHeader(payload);
    try std.testing.expectEqual(@as(u64, 30_000_000), p.gas_limit);
    try std.testing.expectEqual(@as(u64, 21_000), p.gas_used);
    try std.testing.expectEqual(@as(u64, 1_700_000_000), p.timestamp);
    try std.testing.expectEqual(@as(?u64, null), p.base_fee_per_gas);
    try std.testing.expectEqual(@as(?u64, null), p.blob_gas_used);
    try std.testing.expectEqual(@as(?u64, null), p.excess_blob_gas);
}

test "decodeParentHeader: shanghai header has base_fee but no blob fields" {
    const alloc = std.testing.allocator;
    const zero_hash: [32]u8 = @splat(0);

    var trailers: std.ArrayListUnmanaged(u8) = .empty;
    defer trailers.deinit(alloc);
    try appendUint(&trailers, alloc, 13); // [15] base_fee_per_gas
    try appendBytes(&trailers, alloc, &zero_hash); // [16] withdrawals_root

    const inner = try buildHeaderPayload(alloc, trailers.items);
    defer alloc.free(inner);
    const payload = try wrapRlpList(alloc, inner);
    defer alloc.free(payload);

    const p = try decodeParentHeader(payload);
    try std.testing.expectEqual(@as(?u64, 13), p.base_fee_per_gas);
    try std.testing.expectEqual(@as(?u64, null), p.blob_gas_used);
    try std.testing.expectEqual(@as(?u64, null), p.excess_blob_gas);
}
