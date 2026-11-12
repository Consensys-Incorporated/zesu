/// JSON output serialization for the t8n tool.
///
/// Produces geth-compatible result.json and alloc.json files.
/// All numbers are hex-encoded with 0x prefix; hashes are 0x-prefixed 32-byte hex.
///
/// The trie-root functions are re-exported from the executor's output module.
const std = @import("std");

/// Minimal anytype-writer wrapper backed by an ArrayListUnmanaged(u8).
pub const ListWriter = struct {
    list: *std.ArrayListUnmanaged(u8),
    alloc: std.mem.Allocator,
    pub const Error = std.mem.Allocator.Error;
    pub fn writeAll(self: @This(), bytes: []const u8) Error!void {
        return self.list.appendSlice(self.alloc, bytes);
    }
    pub fn print(self: @This(), comptime fmt: []const u8, args: anytype) Error!void {
        return self.list.print(self.alloc, fmt, args);
    }
    pub fn writeByte(self: @This(), byte: u8) Error!void {
        return self.list.append(self.alloc, byte);
    }
};

const executor = @import("executor");
const types = executor.executor_types;
const transition_mod = executor.executor_transition;
const executor_output = executor.executor_output;

// ─── Re-export canonical computation functions ────────────────────────────────

pub const computeLogsHash = executor_output.computeLogsHash;
pub const computeTxRoot = executor_output.computeTxRoot;
pub const computeReceiptsRoot = executor_output.computeReceiptsRoot;
pub const computeStateRoot = executor_output.computeStateRoot;

// ─── Formatting helpers ───────────────────────────────────────────────────────

fn writeHex(w: anytype, bytes: []const u8) !void {
    try w.writeAll("\"0x");
    for (bytes) |b| try w.print("{x:0>2}", .{b});
    try w.writeAll("\"");
}

fn writeHash(w: anytype, hash: [32]u8) !void {
    return writeHex(w, &hash);
}

fn writeAddr(w: anytype, addr: [20]u8) !void {
    return writeHex(w, &addr);
}

fn writeU64Hex(w: anytype, n: u64) !void {
    try w.print("\"0x{x}\"", .{n});
}

fn writeU128Hex(w: anytype, n: u128) !void {
    try w.print("\"0x{x}\"", .{n});
}

fn writeU256Hex(w: anytype, n: u256) !void {
    try w.print("\"0x{x}\"", .{n});
}

fn writeBloom(w: anytype, b: [256]u8) !void {
    try w.writeAll("\"0x");
    for (b) |byte| try w.print("{x:0>2}", .{byte});
    try w.writeAll("\"");
}

// ─── result.json writer ───────────────────────────────────────────────────────

pub fn writeResultJson(
    alloc: std.mem.Allocator,
    writer: anytype,
    result: transition_mod.TransitionResult,
    difficulty: u256,
) !void {
    const logs_hash = try executor_output.computeLogsHash(alloc, result.receipts);
    const state_root = try executor_output.computeStateRoot(alloc, result.alloc, &.{});
    const tx_root = try executor_output.computeTxRoot(alloc, result.accepted_txs, result.chain_id);
    const receipts_root = try executor_output.computeReceiptsRoot(alloc, result.receipts);

    var fields = std.ArrayListUnmanaged([]const u8).empty;
    defer fields.deinit(alloc);

    var buf = std.ArrayListUnmanaged(u8).empty;
    defer buf.deinit(alloc);

    var bw: ListWriter = .{ .list = &buf, .alloc = alloc };

    buf.clearRetainingCapacity();
    try bw.writeAll("\"stateRoot\": ");
    try writeHash(bw, state_root);
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    buf.clearRetainingCapacity();
    try bw.writeAll("\"txRoot\": ");
    try writeHash(bw, tx_root);
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    buf.clearRetainingCapacity();
    try bw.writeAll("\"receiptsRoot\": ");
    try writeHash(bw, receipts_root);
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    buf.clearRetainingCapacity();
    try bw.writeAll("\"logsHash\": ");
    try writeHash(bw, logs_hash);
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    buf.clearRetainingCapacity();
    try bw.writeAll("\"logsBloom\": ");
    try writeBloom(bw, result.block_bloom);
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    buf.clearRetainingCapacity();
    try bw.writeAll("\"receipts\": [\n");
    for (result.receipts, 0..) |receipt, i| {
        try writeReceiptJson(bw, receipt);
        if (i < result.receipts.len - 1) try bw.writeAll(",");
        try bw.writeAll("\n");
    }
    try bw.writeAll("  ]");
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    // Always empty: transition() fails fast on any invalid tx instead of rejecting it.
    buf.clearRetainingCapacity();
    try bw.writeAll("\"rejected\": []");
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    buf.clearRetainingCapacity();
    try bw.writeAll("\"currentDifficulty\": ");
    try writeU256Hex(bw, difficulty);
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    buf.clearRetainingCapacity();
    try bw.writeAll("\"gasUsed\": ");
    try writeU64Hex(bw, result.cumulative_gas);
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    if (result.current_base_fee) |bf| {
        buf.clearRetainingCapacity();
        try bw.writeAll("\"currentBaseFee\": ");
        try writeU64Hex(bw, bf);
        try fields.append(alloc, try alloc.dupe(u8, buf.items));
    }

    if (result.excess_blob_gas) |ebg| {
        buf.clearRetainingCapacity();
        try bw.writeAll("\"currentExcessBlobGas\": ");
        try writeU64Hex(bw, ebg);
        try fields.append(alloc, try alloc.dupe(u8, buf.items));
    }

    // Omitted when zero.
    if (result.blob_gas_used > 0) {
        buf.clearRetainingCapacity();
        try bw.writeAll("\"blobGasUsed\": ");
        try writeU64Hex(bw, result.blob_gas_used);
        try fields.append(alloc, try alloc.dupe(u8, buf.items));
    }

    try writer.writeAll("{\n");
    for (fields.items, 0..) |field, i| {
        try writer.writeAll("  ");
        try writer.writeAll(field);
        if (i < fields.items.len - 1) try writer.writeAll(",");
        try writer.writeAll("\n");
    }
    try writer.writeAll("}\n");
}

fn writeReceiptJson(writer: anytype, receipt: transition_mod.Receipt) !void {
    try writer.writeAll("    {\n");
    try writer.print("      \"type\": \"0x{x}\",\n", .{receipt.type});
    try writer.writeAll("      \"transactionHash\": ");
    try writeHash(writer, receipt.tx_hash);
    try writer.writeAll(",\n");
    try writer.print("      \"transactionIndex\": \"0x{x}\",\n", .{receipt.tx_index});
    try writer.writeAll("      \"blockHash\": ");
    try writeHash(writer, receipt.block_hash);
    try writer.writeAll(",\n");
    try writer.print("      \"blockNumber\": \"0x{x}\",\n", .{receipt.block_number});
    try writer.writeAll("      \"from\": ");
    try writeAddr(writer, receipt.from);
    try writer.writeAll(",\n");

    if (receipt.to) |to| {
        try writer.writeAll("      \"to\": ");
        try writeAddr(writer, to);
        try writer.writeAll(",\n");
    } else {
        try writer.writeAll("      \"to\": null,\n");
    }

    try writer.print("      \"cumulativeGasUsed\": \"0x{x}\",\n", .{receipt.cumulative_gas_used});
    try writer.print("      \"gasUsed\": \"0x{x}\",\n", .{receipt.gas_used});

    if (receipt.contract_address) |ca| {
        try writer.writeAll("      \"contractAddress\": ");
        try writeAddr(writer, ca);
        try writer.writeAll(",\n");
    } else {
        try writer.writeAll("      \"contractAddress\": null,\n");
    }

    // Logs
    try writer.writeAll("      \"logs\": [\n");
    for (receipt.logs, 0..) |log, li| {
        try writeLogJson(writer, log);
        if (li < receipt.logs.len - 1) try writer.writeAll(",");
        try writer.writeAll("\n");
    }
    try writer.writeAll("      ],\n");

    try writer.writeAll("      \"logsBloom\": ");
    try writeBloom(writer, receipt.logs_bloom);
    try writer.writeAll(",\n");

    try writer.print("      \"status\": \"0x{x}\",\n", .{receipt.status});
    try writer.print("      \"effectiveGasPrice\": \"0x{x}\"", .{receipt.effective_gas_price});

    if (receipt.blob_gas_used) |bgu| {
        try writer.writeAll(",\n");
        try writer.print("      \"blobGasUsed\": \"0x{x}\"", .{bgu});
    }
    if (receipt.blob_gas_price) |bgp| {
        try writer.writeAll(",\n");
        try writer.print("      \"blobGasPrice\": \"0x{x}\"", .{bgp});
    }

    try writer.writeAll("\n    }");
}

fn writeLogJson(writer: anytype, log: transition_mod.Log) !void {
    try writer.writeAll("        {\n");
    try writer.writeAll("          \"address\": ");
    try writeAddr(writer, log.address);
    try writer.writeAll(",\n");

    try writer.writeAll("          \"topics\": [");
    for (log.topics, 0..) |t, ti| {
        try writeHash(writer, t);
        if (ti < log.topics.len - 1) try writer.writeAll(", ");
    }
    try writer.writeAll("],\n");

    try writer.writeAll("          \"data\": ");
    try writeHex(writer, log.data);
    try writer.writeAll(",\n");

    try writer.print("          \"blockNumber\": \"0x{x}\",\n", .{log.block_number});
    try writer.writeAll("          \"transactionHash\": ");
    try writeHash(writer, log.tx_hash);
    try writer.writeAll(",\n");
    try writer.print("          \"transactionIndex\": \"0x{x}\",\n", .{log.tx_index});
    try writer.writeAll("          \"blockHash\": ");
    try writeHash(writer, log.block_hash);
    try writer.writeAll(",\n");
    try writer.print("          \"logIndex\": \"0x{x}\",\n", .{log.log_index});
    try writer.writeAll("          \"removed\": false\n");
    try writer.writeAll("        }");
}

// ─── alloc.json writer ────────────────────────────────────────────────────────

pub fn writeAllocJson(
    writer: anytype,
    alloc_map: std.AutoHashMapUnmanaged(types.Address, types.AllocAccount),
) !void {
    try writer.writeAll("{\n");

    var it = alloc_map.iterator();
    var first = true;
    while (it.next()) |entry| {
        if (!first) try writer.writeAll(",\n");
        first = false;

        const addr = entry.key_ptr.*;
        const acct = entry.value_ptr.*;

        try writer.writeAll("  \"0x");
        for (addr) |b| try writer.print("{x:0>2}", .{b});
        try writer.writeAll("\": {\n");

        try writer.writeAll("    \"balance\": ");
        try writeU256Hex(writer, acct.balance);
        try writer.writeAll(",\n");

        try writer.print("    \"nonce\": \"0x{x}\",\n", .{acct.nonce});

        try writer.writeAll("    \"code\": ");
        try writeHex(writer, acct.code);
        try writer.writeAll(",\n");

        try writer.writeAll("    \"storage\": {");
        var sit = acct.storage.iterator();
        var sfirst = true;
        while (sit.next()) |slot| {
            if (!sfirst) try writer.writeAll(", ");
            sfirst = false;
            try writer.writeAll("\n      ");
            try writeU256HexQuoted(writer, slot.key_ptr.*);
            try writer.writeAll(": ");
            try writeU256HexQuoted(writer, slot.value_ptr.*);
        }
        if (!sfirst) try writer.writeAll("\n    ");
        try writer.writeAll("}\n");

        try writer.writeAll("  }");
    }

    if (!first) try writer.writeAll("\n");
    try writer.writeAll("}\n");
}

fn writeU256HexQuoted(writer: anytype, n: u256) !void {
    try writer.print("\"0x{x}\"", .{n});
}

// ─── Utility ──────────────────────────────────────────────────────────────────

fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeAll("\"");
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => try writer.writeByte(c),
        }
    }
    try writer.writeAll("\"");
}
