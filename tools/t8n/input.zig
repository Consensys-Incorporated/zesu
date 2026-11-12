/// JSON input parsing for the t8n tool: alloc, env, and txs.
///
/// Accepts geth-compatible formats:
///   alloc: { "0xaddr": { "balance": "0x...", "nonce": "0x...", "code": "0x...", "storage": {...} } }
///   env:   { "currentCoinbase": "0x...", "currentGasLimit": "0x...", ... }
///   txs:   [ { "type": "0x0", "nonce": "0x...", ... } ]
///
/// All numeric fields may be hex strings ("0x1a") or decimal integers.
///
/// The types are re-exported from executor_types.
const std = @import("std");

// ─── Re-export canonical types from executor ──────────────────────────────────

const types = @import("executor").executor_types;

pub const Address = types.Address;
pub const Hash = types.Hash;
pub const U256 = types.U256;
pub const AllocAccount = types.AllocAccount;
pub const AccessListEntry = types.AccessListEntry;
pub const Withdrawal = types.Withdrawal;
pub const BlockHashEntry = types.BlockHashEntry;
pub const Env = types.Env;
pub const AuthorizationItem = types.AuthorizationItem;
pub const TxInput = types.TxInput;

// ─── Hex/number helpers ───────────────────────────────────────────────────────

fn stripHexPrefix(s: []const u8) []const u8 {
    if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) return s[2..];
    return s;
}

fn hexToAddr(hex: []const u8) !Address {
    const src = stripHexPrefix(hex);
    var addr: Address = [_]u8{0} ** 20;
    if (src.len == 0) return addr;
    if (src.len > 40) return error.InvalidAddress;
    // Pad to 40 hex chars (left-pad with zeros for short addresses)
    var padded: [40]u8 = [_]u8{'0'} ** 40;
    @memcpy(padded[40 - src.len ..], src);
    _ = try std.fmt.hexToBytes(&addr, &padded);
    return addr;
}

fn hexToHash(hex: []const u8) !Hash {
    const src = stripHexPrefix(hex);
    var hash: Hash = [_]u8{0} ** 32;
    if (src.len == 0) return hash;
    if (src.len > 64) return error.InvalidHash;
    var padded: [64]u8 = [_]u8{'0'} ** 64;
    @memcpy(padded[64 - src.len ..], src);
    _ = try std.fmt.hexToBytes(&hash, &padded);
    return hash;
}

fn hexToU64(hex: []const u8) !u64 {
    const src = stripHexPrefix(hex);
    if (src.len == 0) return 0;
    return std.fmt.parseInt(u64, src, 16);
}

fn hexToU128(hex: []const u8) !u128 {
    const src = stripHexPrefix(hex);
    if (src.len == 0) return 0;
    return std.fmt.parseInt(u128, src, 16);
}

fn hexToU256(hex: []const u8) !U256 {
    const src = stripHexPrefix(hex);
    if (src.len == 0) return 0;
    return std.fmt.parseInt(u256, src, 16);
}

fn hexToBytes(alloc: std.mem.Allocator, hex: []const u8) ![]u8 {
    const src = stripHexPrefix(hex);
    if (src.len == 0) return &.{};
    // Odd-length hex: pad with leading zero
    if (src.len % 2 != 0) {
        const padded = try std.fmt.allocPrint(alloc, "0{s}", .{src});
        defer alloc.free(padded);
        const byte_len = padded.len / 2;
        const buf = try alloc.alloc(u8, byte_len);
        _ = try std.fmt.hexToBytes(buf, padded);
        return buf;
    }
    const byte_len = src.len / 2;
    const buf = try alloc.alloc(u8, byte_len);
    _ = try std.fmt.hexToBytes(buf, src);
    return buf;
}

/// Parse a JSON value as u64 (accepts integer or hex string).
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

fn jsonU256(v: std.json.Value) !U256 {
    return switch (v) {
        .integer => |n| @intCast(n),
        .string => |s| hexToU256(s) catch std.fmt.parseInt(u256, s, 10),
        else => error.InvalidNumeric,
    };
}

fn jsonStr(v: std.json.Value) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

// ─── Alloc parser ─────────────────────────────────────────────────────────────

pub fn parseAlloc(
    alloc: std.mem.Allocator,
    json_text: []const u8,
) !std.AutoHashMapUnmanaged(Address, AllocAccount) {
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json_text, .{
        .duplicate_field_behavior = .use_last,
    });
    defer parsed.deinit();

    var map = std.AutoHashMapUnmanaged(Address, AllocAccount).empty;
    const root = switch (parsed.value) {
        .object => |o| o,
        else => return map,
    };

    var it = root.iterator();
    while (it.next()) |entry| {
        const addr = hexToAddr(entry.key_ptr.*) catch continue;
        const acct_json = switch (entry.value_ptr.*) {
            .object => |o| o,
            else => continue,
        };

        var acct = AllocAccount{};

        if (acct_json.get("balance")) |bv| acct.balance = jsonU256(bv) catch 0;
        if (acct_json.get("nonce")) |nv| acct.nonce = jsonU64(nv) catch 0;
        if (acct_json.get("code")) |cv| {
            if (jsonStr(cv)) |s| {
                acct.code = hexToBytes(alloc, s) catch &.{};
            }
        }

        if (acct_json.get("storage")) |sv| {
            if (sv == .object) {
                var sit = sv.object.iterator();
                while (sit.next()) |skv| {
                    const key = hexToU256(skv.key_ptr.*) catch continue;
                    const val = jsonU256(skv.value_ptr.*) catch continue;
                    try acct.storage.put(alloc, key, val);
                }
            }
        }

        try map.put(alloc, addr, acct);
    }
    return map;
}

// ─── Env parser ───────────────────────────────────────────────────────────────

/// Parse geth-format env.json. Accepts both "currentXxx" and plain field names.
pub fn parseEnv(alloc: std.mem.Allocator, json_text: []const u8) !Env {
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json_text, .{
        .duplicate_field_behavior = .use_last,
    });
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return Env{},
    };

    // Helper: look up with legacy "current*" fallback
    const get = struct {
        fn field(o: std.json.ObjectMap, key: []const u8, legacy: []const u8) ?std.json.Value {
            if (o.get(key)) |v| return v;
            return o.get(legacy);
        }
    }.field;

    var env = Env{};

    if (get(obj, "coinbase", "currentCoinbase")) |v|
        env.coinbase = hexToAddr(jsonStr(v) orelse "") catch env.coinbase;
    if (get(obj, "gasLimit", "currentGasLimit")) |v|
        env.gas_limit = jsonU64(v) catch env.gas_limit;
    if (get(obj, "number", "currentNumber")) |v|
        env.number = jsonU64(v) catch env.number;
    if (get(obj, "timestamp", "currentTimestamp")) |v|
        env.timestamp = jsonU64(v) catch env.timestamp;
    if (get(obj, "difficulty", "currentDifficulty")) |v|
        env.difficulty = jsonU256(v) catch env.difficulty;

    // London+: base fee
    if (get(obj, "baseFeePerGas", "currentBaseFee")) |v|
        env.base_fee = jsonU64(v) catch null;

    // Post-merge: prevrandao
    if (get(obj, "random", "currentRandom") orelse obj.get("prevRandao") orelse obj.get("currentRandom")) |v| {
        if (jsonStr(v)) |s| env.random = hexToHash(s) catch null;
    }

    // Cancun+: excess blob gas
    if (obj.get("currentExcessBlobGas") orelse obj.get("excessBlobGas")) |v|
        env.excess_blob_gas = jsonU64(v) catch null;

    // Parent fields
    if (obj.get("parentDifficulty")) |v| env.parent_difficulty = jsonU256(v) catch null;
    if (obj.get("parentBaseFee")) |v| env.parent_base_fee = jsonU64(v) catch null;
    if (obj.get("parentGasUsed")) |v| env.parent_gas_used = jsonU64(v) catch null;
    if (obj.get("parentGasLimit")) |v| env.parent_gas_limit = jsonU64(v) catch null;
    if (obj.get("parentTimestamp")) |v| env.parent_timestamp = jsonU64(v) catch null;
    if (obj.get("parentUncleHash")) |v| {
        if (jsonStr(v)) |s| env.parent_uncle_hash = hexToHash(s) catch null;
    }
    if (obj.get("parentExcessBlobGas")) |v| env.parent_excess_blob_gas = jsonU64(v) catch null;
    if (obj.get("parentBlobGasUsed")) |v| env.parent_blob_gas_used = jsonU64(v) catch null;
    if (obj.get("parentBeaconBlockRoot")) |v| {
        if (jsonStr(v)) |s| env.parent_beacon_block_root = hexToHash(s) catch null;
    }
    if (obj.get("parentHash")) |v| {
        if (jsonStr(v)) |s| env.parent_hash = hexToHash(s) catch null;
    }

    // blockHashes: {"0x1": "0xhash", ...} or {"1": "0xhash", ...}
    if (obj.get("blockHashes")) |bhv| {
        if (bhv == .object) {
            var bh_list = std.ArrayListUnmanaged(BlockHashEntry).empty;
            var bit = bhv.object.iterator();
            while (bit.next()) |bhe| {
                const num = hexToU64(bhe.key_ptr.*) catch
                    (std.fmt.parseInt(u64, bhe.key_ptr.*, 10) catch continue);
                const hash = if (jsonStr(bhe.value_ptr.*)) |s|
                    hexToHash(s) catch continue
                else
                    continue;
                try bh_list.append(alloc, .{ .number = num, .hash = hash });
            }
            env.block_hashes = try bh_list.toOwnedSlice(alloc);
        }
    }

    // Amsterdam+: beacon chain slot number
    if (obj.get("slotNumber") orelse obj.get("currentSlotNumber")) |v|
        env.slot_number = jsonU64(v) catch null;

    // withdrawals (Shanghai+)
    if (obj.get("withdrawals")) |wv| {
        if (wv == .array) {
            var wds = std.ArrayListUnmanaged(Withdrawal).empty;
            for (wv.array.items) |wd_v| {
                if (wd_v != .object) continue;
                const wo = wd_v.object;
                const wd = Withdrawal{
                    .index = if (wo.get("index")) |v| jsonU64(v) catch 0 else 0,
                    .validator_index = if (wo.get("validatorIndex") orelse wo.get("validator")) |v|
                        jsonU64(v) catch 0
                    else
                        0,
                    .address = if (wo.get("address")) |v|
                        hexToAddr(jsonStr(v) orelse "") catch [_]u8{0} ** 20
                    else
                        [_]u8{0} ** 20,
                    .amount = if (wo.get("amount")) |v| jsonU64(v) catch 0 else 0,
                };
                try wds.append(alloc, wd);
            }
            env.withdrawals = try wds.toOwnedSlice(alloc);
        }
    }

    return env;
}

// ─── Txs parser ───────────────────────────────────────────────────────────────

/// Parse a JSON array of transaction objects. Returns a slice of TxInput.
pub fn parseTxs(alloc: std.mem.Allocator, json_text: []const u8) ![]TxInput {
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json_text, .{
        .duplicate_field_behavior = .use_last,
    });
    defer parsed.deinit();

    const arr = switch (parsed.value) {
        .array => |a| a,
        else => return &.{},
    };

    var txs = std.ArrayListUnmanaged(TxInput).empty;
    for (arr.items) |tx_v| {
        const tx_obj = switch (tx_v) {
            .object => |o| o,
            else => continue,
        };
        const tx = try parseTxObject(alloc, tx_obj);
        try txs.append(alloc, tx);
    }
    return txs.toOwnedSlice(alloc);
}

fn parseTxObject(alloc: std.mem.Allocator, obj: std.json.ObjectMap) !TxInput {
    var tx = TxInput{};

    // Transaction type
    if (obj.get("type")) |v| {
        tx.type = @intCast(jsonU64(v) catch 0);
    }

    if (obj.get("nonce")) |v| tx.nonce = jsonU64(v) catch null;
    if (obj.get("gas") orelse obj.get("gasLimit")) |v| tx.gas = jsonU64(v) catch tx.gas;
    if (obj.get("value")) |v| tx.value = jsonU256(v) catch 0;

    // Gas pricing (legacy vs EIP-1559)
    if (obj.get("gasPrice")) |v| tx.gas_price = jsonU128(v) catch null;
    if (obj.get("maxFeePerGas")) |v| tx.max_fee_per_gas = jsonU128(v) catch null;
    if (obj.get("maxPriorityFeePerGas")) |v| tx.max_priority_fee_per_gas = jsonU128(v) catch null;

    // Destination
    if (obj.get("to")) |v| {
        if (v != .null) {
            if (jsonStr(v)) |s| {
                if (s.len > 0 and !std.mem.eql(u8, s, "0x")) {
                    tx.to = hexToAddr(s) catch null;
                }
            }
        }
    }

    // Sender
    if (obj.get("from") orelse obj.get("sender")) |v| {
        if (jsonStr(v)) |s| tx.from = hexToAddr(s) catch null;
    }

    // Calldata
    if (obj.get("data") orelse obj.get("input")) |v| {
        if (jsonStr(v)) |s| tx.data = try hexToBytes(alloc, s);
    }

    // Signature
    if (obj.get("v")) |v| tx.v = jsonU256(v) catch null;
    if (obj.get("r")) |v| tx.r = jsonU256(v) catch null;
    if (obj.get("s")) |v| tx.s = jsonU256(v) catch null;

    // Secret key (for unsigned tx signing)
    if (obj.get("secretKey")) |v| {
        if (jsonStr(v)) |s| {
            const raw = hexToBytes(alloc, s) catch null;
            if (raw) |bytes| {
                if (bytes.len == 32) {
                    var sk: [32]u8 = undefined;
                    @memcpy(&sk, bytes);
                    tx.secret_key = sk;
                }
            }
        }
    }

    // EIP-155
    if (obj.get("protected")) |v| {
        tx.protected = switch (v) {
            .bool => |b| b,
            else => true,
        };
    }
    if (obj.get("chainId")) |v| tx.chain_id = jsonU64(v) catch null;

    // Access list (EIP-2930)
    if (obj.get("accessList")) |alv| {
        if (alv == .array) {
            var al = std.ArrayListUnmanaged(AccessListEntry).empty;
            for (alv.array.items) |al_item| {
                if (al_item != .object) continue;
                const alo = al_item.object;
                const entry_addr = if (alo.get("address")) |v|
                    hexToAddr(jsonStr(v) orelse "") catch [_]u8{0} ** 20
                else
                    [_]u8{0} ** 20;

                var keys = std.ArrayListUnmanaged(Hash).empty;
                if (alo.get("storageKeys")) |skv| {
                    if (skv == .array) {
                        for (skv.array.items) |sk_item| {
                            if (jsonStr(sk_item)) |s| {
                                const key = hexToHash(s) catch [_]u8{0} ** 32;
                                try keys.append(alloc, key);
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

    // EIP-4844
    if (obj.get("blobVersionedHashes")) |bvhv| {
        if (bvhv == .array) {
            var hashes = std.ArrayListUnmanaged(Hash).empty;
            for (bvhv.array.items) |h_item| {
                if (jsonStr(h_item)) |s| {
                    const hash = hexToHash(s) catch [_]u8{0} ** 32;
                    try hashes.append(alloc, hash);
                }
            }
            tx.blob_versioned_hashes = try hashes.toOwnedSlice(alloc);
        }
    }
    if (obj.get("maxFeePerBlobGas")) |v| tx.max_fee_per_blob_gas = jsonU128(v) catch null;

    return tx;
}
