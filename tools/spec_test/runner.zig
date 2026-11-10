/// Spec-test runner: execute execution-spec-tests state fixtures and compare
/// stateRoot / logsHash against expected values.
///
/// Fixture format (execution-spec-tests):
///   { "test_name": { "pre": {...}, "env": {...}, "transaction": {...}, "post": { "Fork": [{...}] } } }
///
/// For each post[fork][i]:
///   - indexes.{data, gas, value} select from transaction.{data[], gasLimit[], value[]}
///   - transaction.sender is used directly as the caller (no signature recovery)
///   - run transition() and compare stateRoot + logsHash to post.hash / post.logs;
///     an entry with expectException passes iff transition() errors
const std = @import("std");

const input_mod = @import("t8n_input");
const hardfork = @import("hardfork");
const executor = @import("executor");
const transition_mod = executor.executor_transition;
const output_mod = executor.executor_output;

// ─── Public stats ─────────────────────────────────────────────────────────────

pub const RunStats = struct {
    passed: u64 = 0,
    failed: u64 = 0,
    skipped: u64 = 0,

    pub fn total(self: RunStats) u64 {
        return self.passed + self.failed;
    }
};

// ─── Hex helpers (mirror the private ones in tools/t8n/input.zig) ────────────

fn stripHex(s: []const u8) []const u8 {
    if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) return s[2..];
    return s;
}

fn hexToAddr(hex: []const u8) !input_mod.Address {
    const src = stripHex(hex);
    var addr: input_mod.Address = [_]u8{0} ** 20;
    if (src.len == 0) return addr;
    if (src.len > 40) return error.InvalidAddress;
    var padded: [40]u8 = [_]u8{'0'} ** 40;
    @memcpy(padded[40 - src.len ..], src);
    _ = try std.fmt.hexToBytes(&addr, &padded);
    return addr;
}

fn hexToHash(hex: []const u8) !input_mod.Hash {
    const src = stripHex(hex);
    var h: input_mod.Hash = [_]u8{0} ** 32;
    if (src.len == 0) return h;
    if (src.len > 64) return error.InvalidHash;
    var padded: [64]u8 = [_]u8{'0'} ** 64;
    @memcpy(padded[64 - src.len ..], src);
    _ = try std.fmt.hexToBytes(&h, &padded);
    return h;
}

fn hexToU64(hex: []const u8) !u64 {
    const src = stripHex(hex);
    if (src.len == 0) return 0;
    return std.fmt.parseInt(u64, src, 16);
}

fn hexToU128(hex: []const u8) !u128 {
    const src = stripHex(hex);
    if (src.len == 0) return 0;
    return std.fmt.parseInt(u128, src, 16);
}

fn hexToU256(hex: []const u8) !u256 {
    const src = stripHex(hex);
    if (src.len == 0) return 0;
    return std.fmt.parseInt(u256, src, 16);
}

fn hexToBytes(alloc: std.mem.Allocator, hex: []const u8) ![]u8 {
    const src = stripHex(hex);
    if (src.len == 0) return alloc.dupe(u8, &.{});
    if (src.len % 2 != 0) {
        // odd-length: pad with leading zero
        const padded = try std.fmt.allocPrint(alloc, "0{s}", .{src});
        defer alloc.free(padded);
        const buf = try alloc.alloc(u8, padded.len / 2);
        _ = try std.fmt.hexToBytes(buf, padded);
        return buf;
    }
    const buf = try alloc.alloc(u8, src.len / 2);
    _ = try std.fmt.hexToBytes(buf, src);
    return buf;
}

fn printHexBytes(bytes: []const u8) void {
    for (bytes) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});
}

fn jsonU64(v: std.json.Value) !u64 {
    return switch (v) {
        .integer => |n| @intCast(n),
        .string => |s| hexToU64(s) catch std.fmt.parseInt(u64, s, 10),
        else => error.InvalidNumeric,
    };
}

fn jsonU128(v: std.json.Value) !u128 {
    return switch (v) {
        .integer => |n| @intCast(n),
        .string => |s| hexToU128(s) catch std.fmt.parseInt(u128, s, 10),
        else => error.InvalidNumeric,
    };
}

fn jsonU256(v: std.json.Value) !u256 {
    return switch (v) {
        .integer => |n| @intCast(n),
        .string => |s| hexToU256(s) catch std.fmt.parseInt(u256, s, 10),
        else => error.InvalidNumeric,
    };
}

fn jStr(v: std.json.Value) ?[]const u8 {
    return if (v == .string) v.string else null;
}

// ─── Transaction builder ──────────────────────────────────────────────────────

/// Build a TxInput for one post-entry combination.
/// Uses transaction.sender directly (no ECDSA); v/r/s left null so transition
/// falls through to the tx.from path.
fn buildTx(
    alloc: std.mem.Allocator,
    txn: std.json.ObjectMap,
    di: usize,
    gi: usize,
    vi: usize,
) !input_mod.TxInput {
    var tx = input_mod.TxInput{};

    // Type defaults to 0 and is inferred from the fields below if absent.
    if (txn.get("type")) |v| tx.type = @intCast(jsonU64(v) catch 0);

    if (txn.get("nonce")) |v| tx.nonce = jsonU64(v) catch 0;

    // Indexed: gasLimit[gi]
    if (txn.get("gasLimit")) |v| {
        if (v == .array and gi < v.array.items.len) {
            const gv = v.array.items[gi];
            if (jStr(gv)) |s| tx.gas = hexToU64(s) catch tx.gas;
        }
    }

    // Indexed: value[vi]
    if (txn.get("value")) |v| {
        if (v == .array and vi < v.array.items.len) {
            const vv = v.array.items[vi];
            if (jStr(vv)) |s| tx.value = hexToU256(s) catch 0;
        }
    }

    // Indexed: data[di]
    if (txn.get("data")) |v| {
        if (v == .array and di < v.array.items.len) {
            const dv = v.array.items[di];
            if (jStr(dv)) |s| tx.data = try hexToBytes(alloc, s);
        }
    }

    // Destination (empty string or "0x" → contract creation)
    if (txn.get("to")) |v| {
        if (v != .null) {
            if (jStr(v)) |s| {
                if (s.len > 0 and !std.mem.eql(u8, s, "0x")) {
                    tx.to = hexToAddr(s) catch null;
                }
            }
        }
    }

    // Sender — set tx.from directly; transition() will use it without ECDSA
    if (txn.get("sender")) |v| {
        if (jStr(v)) |s| tx.from = hexToAddr(s) catch null;
    }

    if (txn.get("gasPrice")) |v| tx.gas_price = jsonU128(v) catch null;
    if (txn.get("maxFeePerGas")) |v| tx.max_fee_per_gas = jsonU128(v) catch null;
    if (txn.get("maxPriorityFeePerGas")) |v| tx.max_priority_fee_per_gas = jsonU128(v) catch null;

    // Chain ID / EIP-155
    if (txn.get("chainId")) |v| tx.chain_id = jsonU64(v) catch null;
    if (txn.get("protected")) |v| tx.protected = if (v == .bool) v.bool else true;

    // Fixtures use "accessLists", indexed by `di` like data[]; fall back to the singular
    // "accessList". The field's mere presence marks type 1, even when empty.
    var has_access_list_field = false;
    const al_json_val: ?std.json.Value = blk: {
        if (txn.get("accessLists")) |v| {
            has_access_list_field = true;
            if (v == .array and di < v.array.items.len) break :blk v.array.items[di];
        }
        if (txn.get("accessList")) |v| {
            has_access_list_field = true;
            break :blk v;
        }
        break :blk null;
    };
    if (al_json_val) |alv| {
        if (alv == .array) {
            var al = std.ArrayListUnmanaged(input_mod.AccessListEntry).empty;
            for (alv.array.items) |al_item| {
                if (al_item != .object) continue;
                const alo = al_item.object;
                const entry_addr = if (alo.get("address")) |av|
                    hexToAddr(jStr(av) orelse "") catch [_]u8{0} ** 20
                else
                    [_]u8{0} ** 20;

                var keys = std.ArrayListUnmanaged(input_mod.Hash).empty;
                if (alo.get("storageKeys")) |skv| {
                    if (skv == .array) {
                        for (skv.array.items) |sk_item| {
                            if (jStr(sk_item)) |s| {
                                try keys.append(alloc, hexToHash(s) catch [_]u8{0} ** 32);
                            }
                        }
                    }
                }
                try al.append(alloc, .{
                    .address = entry_addr,
                    .storage_keys = try keys.toOwnedSlice(alloc),
                });
            }
            tx.access_list = try al.toOwnedSlice(alloc);
        }
    }

    // EIP-4844: blob versioned hashes and max fee per blob gas
    if (txn.get("blobVersionedHashes")) |bvhv| {
        if (bvhv == .array) {
            var hashes = std.ArrayListUnmanaged(input_mod.Hash).empty;
            for (bvhv.array.items) |h_item| {
                if (jStr(h_item)) |s| {
                    try hashes.append(alloc, hexToHash(s) catch [_]u8{0} ** 32);
                }
            }
            tx.blob_versioned_hashes = try hashes.toOwnedSlice(alloc);
        }
    }
    if (txn.get("maxFeePerBlobGas")) |v| tx.max_fee_per_blob_gas = jsonU128(v) catch null;

    // EIP-7702: authorization list
    var has_authorization_list_field = false;
    if (txn.get("authorizationList")) |alv| {
        if (alv == .array) {
            has_authorization_list_field = true;
            var auth_items = std.ArrayListUnmanaged(input_mod.AuthorizationItem).empty;
            for (alv.array.items) |item| {
                if (item != .object) continue;
                const obj = item.object;
                var ai = input_mod.AuthorizationItem{};
                if (obj.get("chainId")) |v| ai.chain_id = hexToU256(jStr(v) orelse "0") catch 0;
                if (obj.get("address")) |v| ai.address = hexToAddr(jStr(v) orelse "") catch [_]u8{0} ** 20;
                if (obj.get("nonce")) |v| ai.nonce = hexToU64(jStr(v) orelse "0") catch 0;
                if (obj.get("signer")) |v| ai.signer = hexToAddr(jStr(v) orelse "") catch null;
                // EIP-7702 requires low-S: if s > N/2, the authorization is invalid (signer=None).
                if (obj.get("s")) |sv| {
                    const s_val = hexToU256(jStr(sv) orelse "0") catch 0;
                    const secp256k1_n_over_2: u256 = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
                    if (s_val > secp256k1_n_over_2) ai.signer = null;
                }
                try auth_items.append(alloc, ai);
            }
            tx.authorization_list = try auth_items.toOwnedSlice(alloc);
        }
    }

    if (tx.type == 0) {
        if (has_authorization_list_field) {
            tx.type = 4;
        } else if (tx.blob_versioned_hashes.len > 0 or tx.max_fee_per_blob_gas != null) {
            tx.type = 3;
        } else if (tx.max_fee_per_gas != null) {
            tx.type = 2;
        } else if (has_access_list_field or tx.access_list.len > 0) {
            tx.type = 1;
        }
    }

    return tx;
}

// ─── JSON value → JSON string (for passing to existing parsers) ───────────────

fn valueToJson(alloc: std.mem.Allocator, v: std.json.Value) ![]u8 {
    return std.json.Stringify.valueAlloc(alloc, v, .{});
}

// ─── Main fixture runner ──────────────────────────────────────────────────────

/// Process a fixture JSON file. For each (test, fork, idx) combination, runs the
/// state transition and compares stateRoot + logsHash to expected values.
///
/// Parameters:
///   alloc        — allocator (arena recommended; reset between files)
///   json_text    — raw JSON content of the fixture file
///   fork_filter  — if non-null, only run tests for this fork
///   chain_id     — EVM chain ID (default 1)
///   stop_on_fail — stop processing after the first failure
///   quiet        — suppress per-test PASS output
///   stats        — in/out: updated with PASS/FAIL/SKIP counts
///   rel_path     — relative path for log messages
///
/// Returns true unless stop_on_fail is set and a failure occurs.
pub fn runFixture(
    alloc: std.mem.Allocator,
    json_text: []const u8,
    fork_filter: ?[]const u8,
    chain_id: u64,
    stop_on_fail: bool,
    quiet: bool,
    stats: *RunStats,
    rel_path: []const u8,
) !bool {
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json_text, .{
        .duplicate_field_behavior = .use_last,
    });
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return true,
    };

    var test_it = root.iterator();
    while (test_it.next()) |test_kv| {
        const test_name = test_kv.key_ptr.*;
        const test_obj = switch (test_kv.value_ptr.*) {
            .object => |o| o,
            else => continue,
        };

        const pre_json_val = test_obj.get("pre") orelse continue;
        const env_json_val = test_obj.get("env") orelse continue;
        const txn_val = switch (test_obj.get("transaction") orelse continue) {
            .object => |o| o,
            else => continue,
        };
        const post_val = switch (test_obj.get("post") orelse continue) {
            .object => |o| o,
            else => continue,
        };

        // Parse pre-state and env once per test (shared across all post entries)
        const pre_json = try valueToJson(alloc, pre_json_val);
        const env_json = try valueToJson(alloc, env_json_val);

        const pre_alloc_base = input_mod.parseAlloc(alloc, pre_json) catch continue;
        const env_base = input_mod.parseEnv(alloc, env_json) catch continue;

        // blobSchedule from config (optional; used to pass per-fork blob fraction to the executor)
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

        var fork_it = post_val.iterator();
        while (fork_it.next()) |fork_kv| {
            const fork = fork_kv.key_ptr.*;

            if (fork_filter) |ff| {
                if (!std.mem.eql(u8, fork, ff)) continue;
            }

            const spec = hardfork.specFromFork(fork) orelse {
                const post_entries = switch (fork_kv.value_ptr.*) {
                    .array => |a| a.items,
                    else => continue,
                };
                stats.skipped += @intCast(post_entries.len);
                if (!quiet) {
                    std.debug.print("SKIP  {s}  (fork {s} not supported)\n", .{ rel_path, fork });
                }
                continue;
            };

            const post_entries = switch (fork_kv.value_ptr.*) {
                .array => |a| a.items,
                else => continue,
            };

            // Apply per-fork blob base fee update fraction from blobSchedule.
            var env = env_base;
            if (blob_schedule) |bs| {
                if (bs.get(fork)) |fv| {
                    if (fv == .object) {
                        if (fv.object.get("baseFeeUpdateFraction")) |frac_v| {
                            env.blob_base_fee_update_fraction = switch (frac_v) {
                                .integer => |n| @intCast(n),
                                .string => |s| blk: {
                                    const stripped = if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) s[2..] else s;
                                    break :blk std.fmt.parseInt(u64, stripped, 16) catch
                                        std.fmt.parseInt(u64, s, 10) catch null;
                                },
                                else => null,
                            };
                        }
                    }
                }
            }

            for (post_entries, 0..) |post_entry_v, post_idx| {
                const post_entry = switch (post_entry_v) {
                    .object => |o| o,
                    else => continue,
                };

                // Whether this post entry expects the transaction to be invalid.
                const expect_exception = post_entry.get("expectException") != null;

                const exp_hash_str = jStr(post_entry.get("hash") orelse continue) orelse continue;
                const exp_logs_str = jStr(post_entry.get("logs") orelse continue) orelse continue;
                const exp_hash = hexToHash(exp_hash_str) catch {
                    stats.skipped += 1;
                    continue;
                };
                const exp_logs = hexToHash(exp_logs_str) catch {
                    stats.skipped += 1;
                    continue;
                };

                const indexes_obj: ?std.json.ObjectMap = if (post_entry.get("indexes")) |iv|
                    (if (iv == .object) iv.object else null)
                else
                    null;

                const di: usize = if (indexes_obj) |io|
                    @intCast(jsonU64(io.get("data") orelse .{ .integer = 0 }) catch 0)
                else
                    0;
                const gi: usize = if (indexes_obj) |io|
                    @intCast(jsonU64(io.get("gas") orelse .{ .integer = 0 }) catch 0)
                else
                    0;
                const vi: usize = if (indexes_obj) |io|
                    @intCast(jsonU64(io.get("value") orelse .{ .integer = 0 }) catch 0)
                else
                    0;

                const tx = buildTx(alloc, txn_val, di, gi, vi) catch |err| {
                    stats.skipped += 1;
                    if (!quiet) {
                        std.debug.print("SKIP  {s}  {s}  {s}[{}]  (tx build error: {})\n", .{
                            rel_path, test_name, fork, post_idx, err,
                        });
                    }
                    continue;
                };

                // tx.from must be set; otherwise transition rejects the tx
                if (tx.from == null) {
                    stats.skipped += 1;
                    if (!quiet) {
                        std.debug.print("SKIP  {s}  {s}  {s}[{}]  (no sender)\n", .{
                            rel_path, test_name, fork, post_idx,
                        });
                    }
                    continue;
                }

                // Child arena per post entry, on page_allocator so its pages stay separate
                // from the c_allocator heap zesu_allocator uses natively.
                var child_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
                defer child_arena.deinit();
                const ca = child_arena.allocator();

                const pre_clone = try cloneAllocMap(ca, pre_alloc_base);

                var txs = [1]input_mod.TxInput{tx};
                const result = transition_mod.transition(
                    ca,
                    pre_clone,
                    env,
                    txs[0..],
                    spec,
                    chain_id,
                    -1, // no mining reward in state tests (avoids spurious coinbase touch)
                ) catch |err| {
                    if (expect_exception) {
                        stats.passed += 1;
                    } else {
                        stats.failed += 1;
                        std.debug.print("FAIL  {s}  {s}  {s}[{}]  (transition: {})\n", .{
                            rel_path, test_name, fork, post_idx, err,
                        });
                        if (stop_on_fail) return false;
                    }
                    continue;
                };

                const got_state = output_mod.computeStateRoot(ca, result.alloc, &.{}) catch [_]u8{0} ** 32;
                const got_logs = output_mod.computeLogsHash(ca, result.receipts) catch [_]u8{0} ** 32;

                if (expect_exception) {
                    stats.failed += 1;
                    std.debug.print("FAIL  {s}  {s}  {s}[{}]  (expected exception, but transition succeeded)\n", .{
                        rel_path, test_name, fork, post_idx,
                    });
                    if (stop_on_fail) return false;
                    continue;
                }

                if (std.mem.eql(u8, &got_state, &exp_hash) and
                    std.mem.eql(u8, &got_logs, &exp_logs))
                {
                    stats.passed += 1;
                } else {
                    stats.failed += 1;
                    std.debug.print("FAIL  {s}  {s}  {s}[{}]\n", .{
                        rel_path, test_name, fork, post_idx,
                    });
                    if (!std.mem.eql(u8, &got_state, &exp_hash)) {
                        std.debug.print("      stateRoot  got=0x", .{});
                        printHexBytes(&got_state);
                        std.debug.print("                 exp=0x", .{});
                        printHexBytes(&exp_hash);
                    }
                    if (!std.mem.eql(u8, &got_logs, &exp_logs)) {
                        std.debug.print("      logsHash   got=0x", .{});
                        printHexBytes(&got_logs);
                        std.debug.print("                 exp=0x", .{});
                        printHexBytes(&exp_logs);
                    }
                    if (stop_on_fail) return false;
                }
            }
        }
    }

    return true;
}

// ─── Deep clone of alloc map ──────────────────────────────────────────────────

/// Clone the pre-state alloc map into the given allocator so that the transition
/// can be run in an isolated child arena without corrupting the base pre-state.
fn cloneAllocMap(
    alloc: std.mem.Allocator,
    src: std.AutoHashMapUnmanaged(input_mod.Address, input_mod.AllocAccount),
) !std.AutoHashMapUnmanaged(input_mod.Address, input_mod.AllocAccount) {
    var dst = std.AutoHashMapUnmanaged(input_mod.Address, input_mod.AllocAccount).empty;
    var it = src.iterator();
    while (it.next()) |entry| {
        var acct = input_mod.AllocAccount{
            .balance = entry.value_ptr.balance,
            .nonce = entry.value_ptr.nonce,
            .code = try alloc.dupe(u8, entry.value_ptr.code),
        };
        var sit = entry.value_ptr.storage.iterator();
        while (sit.next()) |slot| {
            try acct.storage.put(alloc, slot.key_ptr.*, slot.value_ptr.*);
        }
        try dst.put(alloc, entry.key_ptr.*, acct);
    }
    return dst;
}
