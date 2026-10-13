/// transaction-test-runner — runner for execution-specs `transaction_tests` fixtures.
///
/// Fixture format:
///   { "test_name": { "txbytes": "0x...", "result": { "<Fork>": {
///       "intrinsicGas": "0x...", "hash": "0x...", "sender": "0x..." } } } }      valid
///   { ... "<Fork>": { "intrinsicGas": "0x...", "exception": "TransactionException...." } }  invalid
///
/// For each fork in `result`, a fixture naming an exception expects the transaction to be
/// rejected; otherwise it expects the transaction to be accepted, with the given hash,
/// sender and intrinsic gas.
///
/// A transaction is accepted when it decodes, its type exists at the fork, its chain id is
/// the fixture chain's, its signature recovers a sender, and it passes the stateless
/// transaction checks: EIP-7702 shape, the EIP-2681 nonce limit, and intrinsic and floor
/// gas within the gas limit.
///
/// Usage:
///   transaction-test-runner [--fixtures DIR] [--file FILE] [-x]
const std = @import("std");

const executor = @import("executor");
const handler = @import("handler");
const context = @import("context");
const hardfork = @import("hardfork");
const primitives = @import("primitives");

const tx_decode = executor.executor_tx_decode;
const tx_signing = executor.executor_tx_signing;
const types = executor.executor_types;
const keccak256 = executor.executor_rlp_encode.keccak256;
const Validation = handler.Validation;

/// Transaction tests are filled for chain id 1.
const CHAIN_ID: u64 = 1;
/// Block gas limit for the intrinsic gas calculation; the Amsterdam intrinsic reads it.
const BLOCK_GAS_LIMIT: u64 = 30_000_000;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var fixtures_dir: []const u8 = "spec-tests/fixtures/transaction_tests";
    var single_file: ?[]const u8 = null;
    var stop_on_fail = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--fixtures") and i + 1 < args.len) {
            i += 1;
            fixtures_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--file") and i + 1 < args.len) {
            i += 1;
            single_file = args[i];
        } else if (std.mem.eql(u8, arg, "-x")) {
            stop_on_fail = true;
        }
    }

    var stats: Stats = .{};

    if (single_file) |path| {
        processFile(init.io, allocator, path, &stats) catch {};
    } else {
        var dir = std.Io.Dir.cwd().openDir(init.io, fixtures_dir, .{ .iterate = true }) catch |err| {
            std.debug.print("error: cannot open fixtures dir '{s}': {}\n", .{ fixtures_dir, err });
            std.process.exit(1);
        };
        defer dir.close(init.io);

        var walker = try dir.walk(allocator);
        defer walker.deinit();

        var paths = std.ArrayList([]u8).empty;
        defer {
            for (paths.items) |p| allocator.free(p);
            paths.deinit(allocator);
        }
        while (try walker.next(init.io)) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.path, ".json")) continue;
            try paths.append(allocator, try allocator.dupe(u8, entry.path));
        }
        std.mem.sort([]u8, paths.items, {}, struct {
            fn lessThan(_: void, a: []u8, b: []u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lessThan);

        for (paths.items) |rel_path| {
            const full_path = try std.Io.Dir.path.join(allocator, &.{ fixtures_dir, rel_path });
            defer allocator.free(full_path);
            const failed_before = stats.failed;
            processFile(init.io, allocator, full_path, &stats) catch {};
            if (stop_on_fail and stats.failed > failed_before) break;
        }
    }

    const total = stats.passed + stats.failed;
    const pct: u64 = if (total > 0) 100 * stats.passed / total else 0;
    std.debug.print("\n============================================================\n", .{});
    std.debug.print("  Results:  {}/{} passed  ({}%)\n", .{ stats.passed, total, pct });
    if (stats.failed > 0) std.debug.print("  Failed:   {}\n", .{stats.failed});
    if (stats.skipped > 0) std.debug.print("  Skipped:  {} (fork unknown to zesu)\n", .{stats.skipped});
    std.debug.print("============================================================\n", .{});

    if (stats.failed > 0) std.process.exit(1);
}

const Stats = struct { passed: u64 = 0, failed: u64 = 0, skipped: u64 = 0 };

fn processFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8, stats: *Stats) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const json_text = std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(256 * 1024 * 1024)) catch |err| {
        std.debug.print("error: cannot read '{s}': {}\n", .{ path, err });
        return;
    };
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, json_text, .{}) catch |err| {
        std.debug.print("error: JSON parse failed in '{s}': {}\n", .{ path, err });
        return;
    };
    defer parsed.deinit();
    if (parsed.value != .object) return;

    var it = parsed.value.object.iterator();
    while (it.next()) |kv| {
        const test_name = kv.key_ptr.*;
        const case = kv.value_ptr.*;
        if (case != .object) continue;
        const txbytes = stringField(case, "txbytes") orelse continue;
        const result = case.object.get("result") orelse continue;
        if (result != .object) continue;

        const raw = hexBytes(alloc, txbytes) catch {
            std.debug.print("FAIL {s}  txbytes is not hex\n", .{test_name});
            stats.failed += 1;
            continue;
        };

        var rit = result.object.iterator();
        while (rit.next()) |fork_kv| {
            const fork = fork_kv.key_ptr.*;
            const expected = fork_kv.value_ptr.*;
            const spec = hardfork.specFromFork(fork) orelse {
                stats.skipped += 1;
                continue;
            };
            if (runCase(alloc, test_name, fork, raw, expected, spec)) stats.passed += 1 else stats.failed += 1;
        }
    }
}

/// Run one fork's expectation; print a FAIL line and return false on a mismatch.
fn runCase(alloc: std.mem.Allocator, test_name: []const u8, fork: []const u8, raw: []const u8, expected: std.json.Value, spec: primitives.SpecId) bool {
    const verdict = check(alloc, raw, spec);
    if (stringField(expected, "exception")) |exception| {
        switch (verdict) {
            .invalid => return true,
            .valid => {
                std.debug.print("FAIL {s} [{s}]  expected {s}, got valid\n", .{ test_name, fork, exception });
                return false;
            },
        }
    }
    switch (verdict) {
        .invalid => |err| {
            std.debug.print("FAIL {s} [{s}]  expected valid, got invalid: {s}\n", .{ test_name, fork, @errorName(err) });
            return false;
        },
        .valid => |v| {
            var ok = true;
            if (stringField(expected, "hash")) |h| {
                const want = hexBytes(alloc, h) catch &.{};
                const got = keccak256(raw);
                if (!std.mem.eql(u8, want, &got)) {
                    std.debug.print("FAIL {s} [{s}]  hash mismatch\n", .{ test_name, fork });
                    ok = false;
                }
            }
            if (stringField(expected, "sender")) |s| {
                const want = hexBytes(alloc, s) catch &.{};
                if (!std.mem.eql(u8, want, &v.sender)) {
                    std.debug.print("FAIL {s} [{s}]  sender mismatch: got 0x{x}\n", .{ test_name, fork, v.sender });
                    ok = false;
                }
            }
            if (stringField(expected, "intrinsicGas")) |g| {
                const want = std.fmt.parseInt(u64, stripHex(g), 16) catch 0;
                if (want != v.intrinsic_gas) {
                    std.debug.print("FAIL {s} [{s}]  intrinsic gas {} (expected {})\n", .{ test_name, fork, v.intrinsic_gas, want });
                    ok = false;
                }
            }
            return ok;
        },
    }
}

const Verdict = union(enum) {
    valid: struct { sender: primitives.Address, intrinsic_gas: u64 },
    invalid: anyerror,
};

/// Decide whether zesu accepts `raw` as a transaction at `spec`, using the same decoder,
/// signature recovery and transaction checks as block execution.
fn check(alloc: std.mem.Allocator, raw: []const u8, spec: primitives.SpecId) Verdict {
    const txs = tx_decode.decodeTxs(alloc, &.{raw}) catch |err| return .{ .invalid = err };
    const tx = &txs[0];

    if (!typeSupported(tx.type, spec)) return .{ .invalid = error.TypeNotSupported };
    // EIP-155 / typed transactions: the transaction's chain id must be the chain's.
    if (tx.chain_id) |cid| {
        if (cid != CHAIN_ID) return .{ .invalid = error.InvalidChainId };
    }
    // EIP-2681: the decoder clamps an oversized nonce to maxInt(u64), which is invalid.
    if ((tx.nonce orelse 0) == std.math.maxInt(u64)) return .{ .invalid = error.NonceIsMax };

    const sender = (tx_signing.recoverSender(alloc, tx, CHAIN_ID) catch |err| return .{ .invalid = err }) orelse
        return .{ .invalid = error.InvalidSignature };

    const env = txEnv(alloc, tx, sender) catch |err| return .{ .invalid = err };
    Validation.validateEip7702Tx(&env, spec) catch |err| return .{ .invalid = err };

    const intrinsic_gas = Validation.calculateInitialGas(&env, spec, BLOCK_GAS_LIMIT);
    if (tx.gas < intrinsic_gas) return .{ .invalid = error.InsufficientGas };
    if (primitives.isEnabledIn(spec, .prague)) {
        const floor = Validation.calculateFloorGas(&env, spec);
        if (floor > 0 and tx.gas < 21_000 + floor) return .{ .invalid = error.InsufficientGas };
    }
    return .{ .valid = .{ .sender = sender, .intrinsic_gas = intrinsic_gas } };
}

/// The fork that introduced each transaction type (as transition.zig checks it).
fn typeSupported(tx_type: u8, spec: primitives.SpecId) bool {
    return switch (tx_type) {
        0 => true,
        1 => primitives.isEnabledIn(spec, .berlin),
        2 => primitives.isEnabledIn(spec, .london),
        3 => primitives.isEnabledIn(spec, .cancun),
        4 => primitives.isEnabledIn(spec, .prague),
        else => false,
    };
}

/// The fields of the transaction environment that the transaction checks read.
fn txEnv(alloc: std.mem.Allocator, tx: *const types.TxInput, sender: primitives.Address) !context.TxEnv {
    var env = context.TxEnv.default();
    env.tx_type = tx.type;
    env.caller = sender;
    env.gas_limit = tx.gas;
    env.value = tx.value;
    env.nonce = tx.nonce orelse 0;
    env.kind = if (tx.to) |to| .{ .Call = to } else .Create;
    if (tx.data.len > 0) {
        var data = std.ArrayList(u8).empty;
        try data.appendSlice(alloc, tx.data);
        env.data = data;
    }
    if (tx.access_list.len > 0) {
        var items = std.ArrayList(context.AccessListItem).empty;
        for (tx.access_list) |entry| {
            var item = context.AccessListItem{ .address = entry.address, .storage_keys = std.ArrayList(primitives.StorageKey).empty };
            for (entry.storage_keys) |key| try item.storage_keys.append(alloc, std.mem.readInt(u256, &key, .big));
            try items.append(alloc, item);
        }
        env.access_list = .{ .items = items };
    }
    if (tx.type == 4) {
        // Only the length of the list matters to the checks below.
        var auths = std.ArrayList(context.Either).empty;
        for (tx.authorization_list) |a| {
            try auths.append(alloc, .{ .Right = context.RecoveredAuthorization.newUnchecked(
                .{ .chain_id = a.chain_id, .address = a.address, .nonce = a.nonce },
                .Invalid,
            ) });
        }
        env.authorization_list = auths;
    }
    return env;
}

fn stringField(v: std.json.Value, name: []const u8) ?[]const u8 {
    if (v != .object) return null;
    const f = v.object.get(name) orelse return null;
    return if (f == .string) f.string else null;
}

fn stripHex(s: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
}

fn hexBytes(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    const h = stripHex(s);
    const out = try alloc.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}
