/// Blockchain test runner for zesu.
///
/// Reads blockchain test fixtures (JSON) and executes each test's blocks in order,
/// threading post-state from one valid block to the next. Per block it validates
/// stateRoot, receiptTrie and (when present) blockAccessListHash, and checks
/// `expectException` blocks fail with a matching exception. Finally `lastblockhash`
/// must equal the hash of the last block committed (genesis if none).
const std = @import("std");
const hardfork = @import("hardfork");
const executor = @import("executor");
const executor_types = executor.executor_types;
const executor_exceptions = executor.executor_exceptions;
const executor_tx_decode = executor.executor_tx_decode;
const mpt = @import("mpt");

const json_helpers = @import("json.zig");
const output = @import("output.zig");

// ─── Exception matching ───────────────────────────────────────────────────────

/// Returns true if `actual` matches any alternative in `expected`.
/// The `expected` string may contain `|`-separated alternatives
/// (e.g. "TransactionException.A|TransactionException.B").
fn matchesException(expected: []const u8, actual: []const u8) bool {
    var it = std.mem.splitScalar(u8, expected, '|');
    while (it.next()) |candidate| {
        if (std.mem.eql(u8, std.mem.trim(u8, candidate, " "), actual)) return true;
    }
    return false;
}

const Address = executor_types.Address;
const Hash = executor_types.Hash;
const AllocAccount = executor_types.AllocAccount;
const AllocMap = std.AutoHashMapUnmanaged(Address, AllocAccount);
const Env = executor_types.Env;
const Withdrawal = executor_types.Withdrawal;

// ─── Public types ─────────────────────────────────────────────────────────────

pub const RunStats = struct {
    passed: u64 = 0,
    failed: u64 = 0,
    skipped: u64 = 0,

    pub fn total(self: RunStats) u64 {
        return self.passed + self.failed + self.skipped;
    }
};

// ─── Main entry point ─────────────────────────────────────────────────────────

pub fn runFixture(
    alloc: std.mem.Allocator,
    json_text: []const u8,
    fork_filter: ?[]const u8,
    stop_on_fail: bool,
    quiet: bool,
    json_output: bool,
    stats: *RunStats,
    rel_path: []const u8,
) !bool {
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        alloc,
        json_text,
        .{ .duplicate_field_behavior = .use_last },
    );
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return true,
    };

    var it = root.iterator();
    while (it.next()) |entry| {
        const test_name = entry.key_ptr.*;
        const test_obj = switch (entry.value_ptr.*) {
            .object => |o| o,
            else => continue,
        };

        // Extract description from _info for failure diagnostics.
        const test_description: []const u8 = blk: {
            const info = test_obj.get("_info") orelse break :blk "";
            const info_obj = switch (info) {
                .object => |o| o,
                else => break :blk "",
            };
            break :blk json_helpers.getString(info_obj, "description") orelse "";
        };

        // Get network (fork) name.
        const network = if (test_obj.get("network")) |v| switch (v) {
            .string => |s| s,
            else => continue,
        } else continue;

        // Fork filter.
        if (fork_filter) |f| {
            if (!std.mem.eql(u8, f, network)) {
                stats.skipped += 1;
                continue;
            }
        }

        // Parse the blocks array.
        const blocks_arr = blk: {
            const bv = test_obj.get("blocks") orelse {
                stats.skipped += 1;
                continue;
            };
            break :blk switch (bv) {
                .array => |a| a,
                else => {
                    stats.skipped += 1;
                    continue;
                },
            };
        };
        if (blocks_arr.items.len == 0) {
            stats.skipped += 1;
            continue;
        }

        const genesis_bh = switch (test_obj.get("genesisBlockHeader") orelse {
            stats.skipped += 1;
            continue;
        }) {
            .object => |o| o,
            else => {
                stats.skipped += 1;
                continue;
            },
        };
        const genesis_number = if (genesis_bh.get("number")) |v| json_helpers.jsonU64(v) catch 0 else 0;
        const genesis_hash = json_helpers.hexToHash(json_helpers.getString(genesis_bh, "hash") orelse "") catch [_]u8{0} ** 32;

        const expected_lastblockhash = blk: {
            const lv = test_obj.get("lastblockhash") orelse break :blk [_]u8{0} ** 32;
            break :blk json_helpers.hexToHash(switch (lv) {
                .string => |s| s,
                else => "",
            }) catch [_]u8{0} ** 32;
        };

        // Chain id and blobSchedule from config.
        const fixture_chain_id: u64 = blk: {
            const cv = test_obj.get("config") orelse break :blk 1;
            const co = switch (cv) {
                .object => |o| o,
                else => break :blk 1,
            };
            const v = co.get("chainid") orelse break :blk 1;
            break :blk json_helpers.jsonU64(v) catch 1;
        };
        const blob_schedule: ?std.json.ObjectMap = blk: {
            const cv = test_obj.get("config") orelse break :blk null;
            const co = switch (cv) {
                .object => |o| o,
                else => break :blk null,
            };
            const bsv = co.get("blobSchedule") orelse break :blk null;
            break :blk switch (bsv) {
                .object => |o| o,
                else => null,
            };
        };

        // Decode SpecId from network string.
        // For transition forks, use the post-transition spec as the fixture-level default.
        const spec = hardfork.specForBlock(network, std.math.maxInt(u64)) orelse {
            if (!quiet) std.debug.print("SKIP {s}/{s} (unknown network: {s})\n", .{ rel_path, test_name, network });
            stats.skipped += 1;
            continue;
        };

        // Parse pre alloc.
        const pre_val = test_obj.get("pre") orelse {
            stats.skipped += 1;
            continue;
        };
        const pre_alloc = parseAllocFromValue(alloc, pre_val) catch {
            stats.skipped += 1;
            continue;
        };

        // ── Chain state threaded across blocks ───────────────────────────────
        var chain_alloc = pre_alloc;
        var block_hashes_list = std.ArrayListUnmanaged(executor_types.BlockHashEntry).empty;
        try block_hashes_list.append(alloc, .{ .number = genesis_number, .hash = genesis_hash });
        var last_valid_hash = genesis_hash;
        var test_failed = false;
        var prev_excess_blob_gas: ?u64 = blk: {
            const v = genesis_bh.get("excessBlobGas") orelse break :blk null;
            break :blk json_helpers.jsonU64(v) catch null;
        };
        var prev_blob_gas_used: ?u64 = blk: {
            const v = genesis_bh.get("blobGasUsed") orelse break :blk null;
            break :blk json_helpers.jsonU64(v) catch null;
        };
        var prev_gas_limit: ?u64 = blk: {
            const v = genesis_bh.get("gasLimit") orelse break :blk null;
            break :blk json_helpers.jsonU64(v) catch null;
        };
        var prev_gas_used: ?u64 = blk: {
            const v = genesis_bh.get("gasUsed") orelse break :blk null;
            break :blk json_helpers.jsonU64(v) catch null;
        };
        var prev_timestamp: ?u64 = blk: {
            const v = genesis_bh.get("timestamp") orelse break :blk null;
            break :blk json_helpers.jsonU64(v) catch null;
        };
        var prev_base_fee: ?u64 = blk: {
            const v = genesis_bh.get("baseFeePerGas") orelse break :blk null;
            break :blk json_helpers.jsonU64(v) catch null;
        };

        for (blocks_arr.items) |block_val| {
            const block = switch (block_val) {
                .object => |o| o,
                else => continue,
            };

            // expectException: this block is expected to be invalid.
            // We attempt execution and verify the actual exception type matches what is expected.
            const expect_exception_str: ?[]const u8 = blk: {
                const ev = block.get("expectException") orelse break :blk null;
                break :blk switch (ev) {
                    .string => |s| if (s.len > 0) s else null,
                    else => null,
                };
            };

            // blockHeader must be present for a valid block.
            const bh = switch (block.get("blockHeader") orelse continue) {
                .object => |o| o,
                else => continue,
            };
            const expected_block_state_root = json_helpers.hexToHash(json_helpers.getString(bh, "stateRoot") orelse "") catch [_]u8{0} ** 32;
            const expected_block_receipts_root = json_helpers.hexToHash(json_helpers.getString(bh, "receiptTrie") orelse "") catch [_]u8{0} ** 32;
            const expected_block_hash = json_helpers.hexToHash(json_helpers.getString(bh, "hash") orelse "") catch [_]u8{0} ** 32;
            const expected_bal_hash: ?Hash = blk: {
                const s = json_helpers.getString(bh, "blockAccessListHash") orelse break :blk null;
                break :blk json_helpers.hexToHash(s) catch null;
            };

            // Decode block RLP → raw transaction bytes.
            const rlp_hex = switch (block.get("rlp") orelse continue) {
                .string => |s| s,
                else => continue,
            };
            const block_bytes = json_helpers.hexToSlice(alloc, rlp_hex) catch continue;
            const raw_txs = decodeTxsFromBlock(alloc, block_bytes) catch continue;

            // Build execution environment from blockHeader + accumulated block hashes.
            var env = buildEnv(alloc, bh, block, block_hashes_list.items) catch continue;
            env.blob_base_fee_update_fraction = blobFractionForBlock(blob_schedule, network, env.timestamp);
            env.parent_excess_blob_gas = prev_excess_blob_gas;
            env.parent_blob_gas_used = prev_blob_gas_used;
            env.parent_gas_limit = prev_gas_limit;
            env.parent_gas_used = prev_gas_used;
            env.parent_timestamp = prev_timestamp;
            env.parent_base_fee = prev_base_fee;

            // Decode transactions.
            const txs = executor_tx_decode.decodeTxs(alloc, raw_txs) catch |err| {
                if (!quiet and json_output) {
                    var out = std.ArrayListUnmanaged(u8).empty;
                    defer out.deinit(alloc);
                    const w: output.ListWriter = .{ .list = &out, .alloc = alloc };
                    try output.writeTxDecodeError(w, test_name, env.number, @errorName(err), test_description);
                    std.debug.print("{s}\n", .{out.items});
                }
                test_failed = true;
                break;
            };

            // Execute the block. An execution error means the block is invalid — freeze state.
            // For transition forks, select the spec appropriate for this block's timestamp.
            const block_spec = hardfork.specForBlock(network, env.timestamp) orelse spec;
            const reward = hardfork.blockReward(block_spec);
            const result = executor.executeBlockFromAlloc(
                alloc,
                chain_alloc,
                env,
                txs,
                block_spec,
                fixture_chain_id,
                reward,
            ) catch |exec_err| {
                if (expect_exception_str) |expected| {
                    const classified = executor_exceptions.mapBlockError(exec_err) orelse executor_exceptions.mapTransactionError(exec_err);
                    if (!matchesException(expected, classified)) {
                        if (!std.mem.startsWith(u8, expected, executor_exceptions.block_exception_prefix)) {
                            test_failed = true;
                            if (!quiet) {
                                std.debug.print("FAIL {s} wrong exception: expected '{s}', got '{s}' (block {})\n", .{ test_name, expected, classified, env.number });
                            }
                        }
                    }
                } else {
                    // No exception was expected but execution failed — log and fail.
                    test_failed = true;
                    if (!quiet) {
                        const classified = executor_exceptions.mapBlockError(exec_err) orelse executor_exceptions.mapTransactionError(exec_err);
                        std.debug.print("FAIL {s} unexpected exception '{s}' (block {})\n", .{ test_name, classified, env.number });
                    }
                }
                continue;
            };

            const post_state_root = result.post_state_root;
            const receipts_root = result.receipts_root;

            const state_ok = std.mem.eql(u8, &post_state_root, &expected_block_state_root);
            const receipts_ok = std.mem.eql(u8, &receipts_root, &expected_block_receipts_root);
            const bal_ok = if (expected_bal_hash) |exp|
                if (result.bal_hash) |got| std.mem.eql(u8, &got, &exp) else false
            else
                true;

            if (expect_exception_str) |expected| {
                // No txs were rejected. For BlockException, the roots should not match.
                if (std.mem.startsWith(u8, expected, executor_exceptions.block_exception_prefix)) {
                    if (state_ok and receipts_ok) {
                        test_failed = true;
                        if (!quiet) {
                            std.debug.print("FAIL {s} expected block exception '{s}' but block was valid\n", .{ test_name, expected });
                        }
                    }
                } else {
                    // TransactionException expected but no tx was rejected.
                    test_failed = true;
                    if (!quiet) {
                        std.debug.print("FAIL {s} expected exception '{s}' but no tx was rejected (block {})\n", .{ test_name, expected, env.number });
                    }
                }
                // Do not advance chain for expected-exception blocks.
            } else if (state_ok and receipts_ok and bal_ok) {
                // Commit: thread state to next block.
                chain_alloc = result.post_alloc;
                last_valid_hash = expected_block_hash;
                try block_hashes_list.append(alloc, .{ .number = env.number, .hash = expected_block_hash });
                prev_excess_blob_gas = if (bh.get("excessBlobGas")) |v| json_helpers.jsonU64(v) catch null else null;
                prev_blob_gas_used = if (bh.get("blobGasUsed")) |v| json_helpers.jsonU64(v) catch null else null;
                prev_gas_limit = if (bh.get("gasLimit")) |v| json_helpers.jsonU64(v) catch null else null;
                prev_gas_used = if (bh.get("gasUsed")) |v| json_helpers.jsonU64(v) catch null else null;
                prev_timestamp = if (bh.get("timestamp")) |v| json_helpers.jsonU64(v) catch null else null;
                prev_base_fee = if (bh.get("baseFeePerGas")) |v| json_helpers.jsonU64(v) catch null else null;
            } else {
                test_failed = true;

                if (!quiet) {
                    std.debug.print("FAIL {s} ReceiptsOK={} StateOK={} BalOK={}\n", .{ test_name, receipts_ok, state_ok, bal_ok });
                }
                if (!quiet and json_output) {
                    var out = std.ArrayListUnmanaged(u8).empty;
                    defer out.deinit(alloc);
                    const w: output.ListWriter = .{ .list = &out, .alloc = alloc };
                    try output.writeBlockMismatch(
                        alloc,
                        w,
                        test_name,
                        test_description,
                        state_ok,
                        receipts_ok,
                        expected_block_state_root,
                        post_state_root,
                        expected_block_receipts_root,
                        receipts_root,
                        block,
                        test_obj.get("postState"),
                        result.receipts,
                        result.post_alloc,
                    );
                    std.debug.print("{s}\n", .{out.items});
                }
            }
        }

        // Validate lastblockhash = hash of last successfully committed block.
        const lbh_ok = std.mem.eql(u8, &last_valid_hash, &expected_lastblockhash);
        if (!test_failed and lbh_ok) {
            stats.passed += 1;
        } else {
            stats.failed += 1;
            if (!quiet and json_output and !test_failed and !lbh_ok) {
                var out = std.ArrayListUnmanaged(u8).empty;
                defer out.deinit(alloc);
                const w: output.ListWriter = .{ .list = &out, .alloc = alloc };
                try output.writeLastBlockHashMismatch(w, test_name, expected_lastblockhash, last_valid_hash, test_description);
                std.debug.print("{s}\n", .{out.items});
            }
            if (stop_on_fail) return false;
        }
    }

    return stats.failed == 0 or !stop_on_fail;
}

// ─── Block RLP decoder ────────────────────────────────────────────────────────

/// Extract raw transaction bytes from a full block RLP.
/// Block structure: RLP([header_list, txns_list, ommers_list, withdrawals_list])
///
/// Each returned entry is in canonical wire format:
///   legacy tx (type 0): full RLP list bytes
///   typed tx:           type_byte || rlp_payload (content of the RLP byte string)
fn decodeTxsFromBlock(alloc: std.mem.Allocator, block_rlp: []const u8) ![]const []const u8 {
    const outer = try mpt.rlp.decodeItem(block_rlp);
    const block_payload = switch (outer.item) {
        .list => |p| p,
        .bytes => return error.InvalidBlock,
    };

    // Skip header.
    const hdr = try mpt.rlp.decodeItem(block_payload);
    const after_hdr = block_payload[hdr.consumed..];

    // Decode txns list.
    const txns_r = try mpt.rlp.decodeItem(after_hdr);
    const txns_payload = switch (txns_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBlock,
    };

    // Count items.
    var count: usize = 0;
    var tmp = txns_payload;
    while (tmp.len > 0) {
        const r = try mpt.rlp.decodeItem(tmp);
        count += 1;
        tmp = tmp[r.consumed..];
    }

    const txns = try alloc.alloc([]const u8, count);
    var offset: usize = 0;
    for (0..count) |i| {
        const r = try mpt.rlp.decodeItem(txns_payload[offset..]);
        txns[i] = switch (r.item) {
            .bytes => |b| b, // typed tx: byte string content
            .list => txns_payload[offset .. offset + r.consumed], // legacy
        };
        offset += r.consumed;
    }
    return txns;
}

// ─── Environment builder ──────────────────────────────────────────────────────

/// Build an Env from the blockHeader JSON object and block entry (for withdrawals).
fn buildEnv(
    alloc: std.mem.Allocator,
    bh: std.json.ObjectMap,
    b0: std.json.ObjectMap,
    block_hashes: []executor_types.BlockHashEntry,
) !Env {
    var env = Env{};
    env.block_hashes = block_hashes;

    if (bh.get("coinbase")) |v| env.coinbase = json_helpers.hexToAddr(json_helpers.getString2(v) orelse "") catch env.coinbase;
    if (bh.get("gasLimit")) |v| env.gas_limit = json_helpers.jsonU64(v) catch env.gas_limit;
    if (bh.get("number")) |v| env.number = json_helpers.jsonU64(v) catch env.number;
    if (bh.get("timestamp")) |v| env.timestamp = json_helpers.jsonU64(v) catch env.timestamp;
    if (bh.get("difficulty")) |v| env.difficulty = json_helpers.jsonU256(v) catch env.difficulty;

    if (bh.get("baseFeePerGas")) |v| env.base_fee = json_helpers.jsonU64(v) catch null;

    // prevRandao / mixHash (same field, different names across forks)
    const randao_val = bh.get("mixHash") orelse bh.get("prevRandao");
    if (randao_val) |v| env.random = json_helpers.hexToHash(json_helpers.getString2(v) orelse "") catch null;

    if (bh.get("excessBlobGas")) |v| env.excess_blob_gas = json_helpers.jsonU64(v) catch null;
    if (bh.get("gasUsed")) |v| env.gas_used_header = json_helpers.jsonU64(v) catch null;
    if (bh.get("blobGasUsed")) |v| env.blob_gas_used_header = json_helpers.jsonU64(v) catch null;
    if (bh.get("parentBeaconBlockRoot")) |v| env.parent_beacon_block_root =
        json_helpers.hexToHash(json_helpers.getString2(v) orelse "") catch null;
    if (bh.get("parentHash")) |v| env.parent_hash =
        json_helpers.hexToHash(json_helpers.getString2(v) orelse "") catch null;
    if (bh.get("slotNumber")) |v| env.slot_number = json_helpers.jsonU64(v) catch null;

    // Withdrawals from block entry.
    if (b0.get("withdrawals")) |wv| {
        if (wv == .array) {
            var wds = std.ArrayListUnmanaged(Withdrawal).empty;
            for (wv.array.items) |wd_v| {
                if (wd_v != .object) continue;
                const wo = wd_v.object;
                try wds.append(alloc, Withdrawal{
                    .index = if (wo.get("index")) |v| json_helpers.jsonU64(v) catch 0 else 0,
                    .validator_index = if (wo.get("validatorIndex")) |v| json_helpers.jsonU64(v) catch 0 else 0,
                    .address = if (wo.get("address")) |v|
                        json_helpers.hexToAddr(json_helpers.getString2(v) orelse "") catch [_]u8{0} ** 20
                    else
                        [_]u8{0} ** 20,
                    .amount = if (wo.get("amount")) |v| json_helpers.jsonU64(v) catch 0 else 0,
                });
            }
            env.withdrawals = try wds.toOwnedSlice(alloc);
        }
    }

    return env;
}

// ─── Pre-alloc parser ─────────────────────────────────────────────────────────

fn parseAllocFromValue(alloc: std.mem.Allocator, val: std.json.Value) !AllocMap {
    var map = AllocMap{};
    const obj = switch (val) {
        .object => |o| o,
        else => return map,
    };

    var it = obj.iterator();
    while (it.next()) |entry| {
        const addr = json_helpers.hexToAddr(entry.key_ptr.*) catch continue;
        const acct_obj = switch (entry.value_ptr.*) {
            .object => |o| o,
            else => continue,
        };

        var acct = AllocAccount{};
        if (acct_obj.get("balance")) |v| acct.balance = json_helpers.jsonU256(v) catch 0;
        if (acct_obj.get("nonce")) |v| acct.nonce = json_helpers.jsonU64(v) catch 0;
        if (acct_obj.get("code")) |v| {
            acct.code = json_helpers.hexToSlice(alloc, json_helpers.getString2(v) orelse "") catch &.{};
        }
        if (acct_obj.get("storage")) |sv| {
            if (sv == .object) {
                var sit = sv.object.iterator();
                while (sit.next()) |skv| {
                    const key = json_helpers.hexToU256(skv.key_ptr.*) catch continue;
                    const val2 = json_helpers.jsonU256(skv.value_ptr.*) catch continue;
                    if (val2 != 0) try acct.storage.put(alloc, key, val2);
                }
            }
        }
        try map.put(alloc, addr, acct);
    }
    return map;
}

// ─── Blob schedule helpers ────────────────────────────────────────────────────

/// Look up baseFeeUpdateFraction from a fixture's blobSchedule for this block.
fn blobFractionForBlock(blob_schedule: ?std.json.ObjectMap, network: []const u8, timestamp: u64) ?u64 {
    const bs = blob_schedule orelse return null;
    const fork_name = hardfork.activeForkName(network, timestamp);
    const fork_entry = bs.get(fork_name) orelse return null;
    const entry_obj = switch (fork_entry) {
        .object => |o| o,
        else => return null,
    };
    const fraction_val = entry_obj.get("baseFeeUpdateFraction") orelse return null;
    return json_helpers.jsonU64(fraction_val) catch null;
}
