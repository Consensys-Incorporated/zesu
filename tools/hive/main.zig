/// zesu Hive consume-rlp client.
///
/// Hive injects:
///   /genesis.json        — geth-format genesis block
///   /blocks/0001.rlp,    — RLP-encoded blocks in order
///     0002.rlp, ...
///   HIVE_CHAIN_ID, HIVE_FORK_*, HIVE_*_TIMESTAMP env vars
///
/// On startup: parse genesis → import blocks → serve eth_getBlockByNumber on :8545.
const std = @import("std");

const fork_env = @import("fork_env.zig");
const genesis = @import("genesis.zig");
const chain_mod = @import("chain.zig");
const rpc = @import("rpc.zig");

pub fn main(init: std.process.Init) !void {
    const backing = init.gpa;

    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    const alloc = arena.allocator();

    // ── Fork schedule from environment ────────────────────────────────────────
    const fork = fork_env.loadFromEnv(init.environ_map);

    // ── Parse genesis ─────────────────────────────────────────────────────────
    const genesis_json = std.Io.Dir.cwd().readFileAlloc(init.io, "/genesis.json", alloc, .limited(64 * 1024 * 1024)) catch |err| {
        std.debug.print("hive-rlp: cannot read /genesis.json: {}\n", .{err});
        std.process.exit(1);
    };

    // The genesis header layout depends on the spec active at genesis, which needs the
    // timestamp before the full parse.
    const genesis_ts = quickParseTimestamp(genesis_json);
    const genesis_spec = fork.specAt(0, genesis_ts);

    const g = genesis.parse(alloc, genesis_json, genesis_spec) catch |err| {
        std.debug.print("hive-rlp: genesis parse error: {}\n", .{err});
        std.process.exit(1);
    };

    // ── Initialize chain ──────────────────────────────────────────────────────
    var chain = chain_mod.Chain.init(backing, g.alloc, chain_mod.StoredHeader{
        .number = 0,
        .hash = g.hash,
        .coinbase = g.coinbase,
        .state_root = g.state_root,
        .gas_limit = g.gas_limit,
        .timestamp = g.timestamp,
        .extra_data = g.extra_data,
        .base_fee = g.base_fee,
        .withdrawals_root = g.withdrawals_root,
        .blob_gas_used = g.blob_gas_used,
        .excess_blob_gas = g.excess_blob_gas,
        .parent_beacon_block_root = g.parent_beacon_block_root,
        .requests_hash = g.requests_hash,
        .block_access_list_hash = g.block_access_list_hash,
        .slot_number = g.slot_number,
    }, fork);
    defer chain.deinit();

    std.debug.print("hive-rlp: genesis hash 0x{x}\n", .{g.hash});

    // ── Import blocks ─────────────────────────────────────────────────────────
    importBlocks(init.io, alloc, &chain) catch |err| {
        std.debug.print("hive-rlp: block import warning: {}\n", .{err});
        // Non-fatal: serve with whatever blocks we have
    };

    std.debug.print("hive-rlp: chain height {}\n", .{if (chain.getLatest()) |h| h.number else 0});

    // ── Serve JSON-RPC ────────────────────────────────────────────────────────
    std.debug.print("hive-rlp: listening on :8545\n", .{});
    try rpc.serve(init.io, &chain);
}

/// Read and import all /blocks/NNNN.rlp files in sorted order.
fn importBlocks(io: std.Io, alloc: std.mem.Allocator, chain: *chain_mod.Chain) !void {
    var blocks_dir = std.Io.Dir.openDirAbsolute(io, "/blocks", .{ .iterate = true }) catch return;
    defer blocks_dir.close(io);

    var names = std.ArrayListUnmanaged([]u8).empty;
    defer {
        for (names.items) |n| alloc.free(n);
        names.deinit(alloc);
    }

    var iter = blocks_dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".rlp")) continue;
        try names.append(alloc, try alloc.dupe(u8, entry.name));
    }

    // Sort lexicographically (0001.rlp < 0002.rlp < ...)
    std.mem.sort([]u8, names.items, {}, struct {
        fn lt(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);

    for (names.items) |name| {
        const block_rlp = blocks_dir.readFileAlloc(io, name, alloc, .limited(32 * 1024 * 1024)) catch continue;
        chain.importBlock(block_rlp);
    }
}

/// Quick-scan genesis JSON for timestamp without a full parse.
fn quickParseTimestamp(json: []const u8) u64 {
    // Takes the first "timestamp" key in the document; accepts "0x..." or a bare integer.
    const key = "\"timestamp\"";
    const pos = std.mem.indexOf(u8, json, key) orelse return 0;
    var i = pos + key.len;
    while (i < json.len and (json[i] == ' ' or json[i] == ':' or json[i] == '\t')) i += 1;
    if (i >= json.len) return 0;
    if (json[i] == '"') {
        i += 1;
        const start = i;
        while (i < json.len and json[i] != '"') i += 1;
        const s = json[start..i];
        const hex = if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X"))
            s[2..]
        else
            s;
        return std.fmt.parseInt(u64, hex, 16) catch
            std.fmt.parseInt(u64, hex, 10) catch 0;
    } else {
        const start = i;
        while (i < json.len and json[i] >= '0' and json[i] <= '9') i += 1;
        return std.fmt.parseInt(u64, json[start..i], 10) catch 0;
    }
}
