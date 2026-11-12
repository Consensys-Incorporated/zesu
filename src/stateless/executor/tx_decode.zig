//! Map transactions (raw wire bytes or decoded input.Transaction) to executor TxInput.
//! Sender recovery is not done here; transition() does it.
const std = @import("std");
const types = @import("executor_types");
const input = @import("input");
const rlp_decode = @import("rlp_decode");

pub const TxDecodeError = error{
    InvalidTx,
    OutOfMemory,
};

/// Decode a slice of raw wire-format transactions into TxInput structs.
pub fn decodeTxs(
    alloc: std.mem.Allocator,
    raw_txs: []const []const u8,
) ![]types.TxInput {
    const result = try alloc.alloc(types.TxInput, raw_txs.len);
    for (raw_txs, 0..) |raw, i| {
        const input_tx = rlp_decode.decodeSingleTx(alloc, raw) catch return error.InvalidTx;
        result[i] = try mapInputTx(alloc, input_tx);
    }
    return result;
}

/// Map decoded input.Transaction structs to TxInput (the block executor's path).
pub fn decodeTxsFromInput(
    alloc: std.mem.Allocator,
    txs: []const input.Transaction,
) ![]types.TxInput {
    const result = try alloc.alloc(types.TxInput, txs.len);
    for (txs, 0..) |tx, i| {
        result[i] = try mapInputTx(alloc, tx);
    }
    return result;
}

fn mapInputTx(alloc: std.mem.Allocator, tx: input.Transaction) !types.TxInput {
    var out = types.TxInput{
        .type = tx.tx_type,
        .nonce = tx.nonce,
        .gas = tx.gas_limit,
        .to = tx.to,
        .value = tx.value,
        .data = tx.data,
        .chain_id = tx.chain_id,
        .r = tx.r,
        .s = tx.s,
    };

    switch (tx.tx_type) {
        0 => {
            // Legacy: gas_price is the actual gas price.
            out.gas_price = tx.gas_price;
            // Reconstruct raw Ethereum v so transition()'s recoverSender works.
            // EIP-155: v = chain_id*2 + 35 + y_parity
            // Legacy:  v = 27 + y_parity
            if (tx.chain_id) |cid| {
                out.v = @as(u256, cid) * 2 + 35 + @as(u256, tx.v);
                out.protected = true;
            } else {
                out.v = 27 + @as(u256, tx.v);
                out.protected = false;
            }
        },
        1 => {
            // EIP-2930: gas_price is the actual gas price; v is y_parity (0 or 1).
            out.gas_price = tx.gas_price;
            out.v = @as(u256, tx.v);
            out.protected = true;
        },
        2, 3, 4 => {
            // EIP-1559/4844/7702: gas_price field holds maxFeePerGas; v is y_parity.
            out.max_fee_per_gas = tx.gas_price;
            out.max_priority_fee_per_gas = tx.gas_priority_fee;
            out.v = @as(u256, tx.v);
            out.protected = true;
        },
        else => return error.InvalidTx,
    }

    // Access list (types 1–4).
    if (tx.access_list.len > 0) {
        const al = try alloc.alloc(types.AccessListEntry, tx.access_list.len);
        for (tx.access_list, 0..) |entry, j| {
            al[j] = .{
                .address = entry.address,
                .storage_keys = entry.storage_keys,
            };
        }
        out.access_list = al;
    }

    // EIP-4844 blob versioned hashes.
    if (tx.blob_hashes.len > 0) {
        out.blob_versioned_hashes = try alloc.dupe(types.Hash, tx.blob_hashes);
        out.max_fee_per_blob_gas = tx.max_fee_per_blob_gas;
    }

    // EIP-7702 authorization list.
    if (tx.authorization_list.len > 0) {
        const auth = try alloc.alloc(types.AuthorizationItem, tx.authorization_list.len);
        for (tx.authorization_list, 0..) |item, j| {
            auth[j] = .{
                .chain_id = item.chain_id,
                .address = item.address,
                .nonce = item.nonce,
                .signer = null, // recovered later in transition()
                .y_parity = @as(u256, item.v),
                .r = item.r,
                .s = item.s,
            };
        }
        out.authorization_list = auth;
    }

    return out;
}
