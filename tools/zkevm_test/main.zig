/// zkevm-blockchain-test-runner — runner for zkevm execution-specs fixtures.
///
/// Fixture format (zkevm@v0.8.0 — under `blockchain_tests/`):
///   { "test_name": { "network": "Amsterdam", "blocks": [
///       { "statelessInputBytes": "0x...", "statelessOutputBytes": "0x...", ... }
///   ] } }
///
/// For each block, decodes the SSZ input, runs stateless execution, serializes
/// the 43-byte SSZ output and asserts it matches `statelessOutputBytes`.
/// (The `blockchain_tests_engine/` directory uses a different JSON engine-API
///  layout and is NOT consumed by this runner.)
///
/// Usage:
///   zkevm-blockchain-test-runner [--fixtures DIR] [--file FILE] [-q] [-x]
const std = @import("std");

const ssz_decode = @import("ssz_decode");
const ssz_output = @import("ssz_output");
const executor = @import("executor");
const executor_exceptions = @import("executor").executor_exceptions;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var fixtures_dir: []const u8 = "spec-tests/fixtures/zkevm/blockchain_tests";
    var single_file: ?[]const u8 = null;
    var stop_on_fail: bool = false;

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

    var passed: u64 = 0;
    var failed: u64 = 0;
    // Test cases whose blocks carry no stateless artifacts: nothing to execute,
    // so they are reported separately rather than counted as passes.
    var skipped: u64 = 0;

    if (single_file) |path| {
        processFile(init.io, allocator, path, &passed, &failed, &skipped) catch {};
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

            const failed_before = failed;
            processFile(init.io, allocator, full_path, &passed, &failed, &skipped) catch {};
            if (stop_on_fail and failed > failed_before) break;
        }
    }

    const total = passed + failed;
    const pct: u64 = if (total > 0) 100 * passed / total else 0;
    std.debug.print("\n============================================================\n", .{});
    std.debug.print("  Results:  {}/{} passed  ({}%)\n", .{ passed, total, pct });
    if (failed > 0) std.debug.print("  Failed:   {}\n", .{failed});
    if (skipped > 0) std.debug.print("  Skipped:  {} (no statelessInputBytes in any block)\n", .{skipped});
    std.debug.print("============================================================\n", .{});

    if (failed > 0) std.process.exit(1);
}

fn processFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8, passed: *u64, failed: *u64, skipped: *u64) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 2 GiB: zkevm@v0.8.0 ships a 276 MiB fixture (invalid_negative_excess_blob_gas,
    // 2744 test cases) that a 256 MiB cap silently dropped from the run.
    const json_text = std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(2 * 1024 * 1024 * 1024)) catch |err| {
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
        const test_case = kv.value_ptr.*;
        if (test_case != .object) continue;

        const fork_name: ?[]const u8 = if (test_case.object.get("network")) |nv|
            switch (nv) {
                .string => |s| s,
                else => null,
            }
        else
            null;

        const blocks_val = test_case.object.get("blocks") orelse continue;
        if (blocks_val != .array) continue;

        var test_ok = true;
        var ran_any = false;
        for (blocks_val.array.items, 0..) |block_val, block_idx| {
            if (block_val != .object) continue;
            const in_hex = switch (block_val.object.get("statelessInputBytes") orelse continue) {
                .string => |s| s,
                else => continue,
            };
            const out_hex = switch (block_val.object.get("statelessOutputBytes") orelse continue) {
                .string => |s| s,
                else => continue,
            };

            // Extract transactionsTrie from blockHeader or rlp_decoded.blockHeader.
            const expected_tx_root_hex: ?[]const u8 = blk: {
                if (block_val.object.get("blockHeader")) |bh| {
                    if (bh == .object) {
                        if (bh.object.get("transactionsTrie")) |t| {
                            if (t == .string) break :blk t.string;
                        }
                    }
                }
                if (block_val.object.get("rlp_decoded")) |rd| {
                    if (rd == .object) {
                        if (rd.object.get("blockHeader")) |bh| {
                            if (bh == .object) {
                                if (bh.object.get("transactionsTrie")) |t| {
                                    if (t == .string) break :blk t.string;
                                }
                            }
                        }
                    }
                }
                break :blk null;
            };

            const block_ok = runBlock(alloc, test_name, block_idx, in_hex, out_hex, expected_tx_root_hex, fork_name) catch |err| blk: {
                std.debug.print("FAIL {s}[{}]  error: {}\n", .{ test_name, block_idx, err });
                break :blk false;
            };
            ran_any = true;
            if (!block_ok) test_ok = false;
        }
        if (!ran_any) skipped.* += 1 else if (test_ok) passed.* += 1 else failed.* += 1;
    }
}

fn runBlock(
    alloc: std.mem.Allocator,
    test_name: []const u8,
    block_idx: usize,
    in_hex: []const u8,
    out_hex: []const u8,
    expected_tx_root_hex: ?[]const u8,
    fork_name: ?[]const u8,
) !bool {
    const in_stripped = if (std.mem.startsWith(u8, in_hex, "0x")) in_hex[2..] else in_hex;
    const out_stripped = if (std.mem.startsWith(u8, out_hex, "0x")) out_hex[2..] else out_hex;

    const input_bytes = try alloc.alloc(u8, in_stripped.len / 2);
    _ = try std.fmt.hexToBytes(input_bytes, in_stripped);

    // EIP-8025 (optional proofs): when the stateless input cannot be decoded, the guest
    // emits the "default failed" result (root=0, successful_validation=false,
    // chain_id=0, schema_id=0) — reference stateless_guest run_stateless_guest /
    // _default_failed_stateless_output. Assert the fixture's expected output equals the
    // exact bytes the guest commits (ssz_output.DEFAULT_FAILED_OUTPUT) byte-for-byte, so
    // a regression in the guest's failed-output encoding is caught here instead of
    // silently passing.
    const si = ssz_decode.decode(alloc, input_bytes) catch {
        const failed_hex = std.fmt.bytesToHex(ssz_output.DEFAULT_FAILED_OUTPUT, .lower);
        if (std.ascii.eqlIgnoreCase(out_stripped, &failed_hex)) return true;
        std.debug.print("FAIL {s}[{}]  input failed to decode; fixture expects 0x{s} but guest emits default-failed 0x{s}\n", .{ test_name, block_idx, out_stripped, &failed_hex });
        return false;
    };

    // zkevm@v0.8.0: SszStatelessValidationResult is a flat 43-byte container
    // (root + successful_validation + chain_id + schema_id) → 86 hex chars.
    if (out_stripped.len != 2 * ssz_output.OUTPUT_SIZE) return error.BadOutputLength;
    var expected: [ssz_output.OUTPUT_SIZE]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, out_stripped);

    const ep = &si.new_payload_request.execution_payload;

    // Pre-execution: check that the SSZ transactions match the block's transactionsTrie
    // from the fixture.  When they differ the SSZ is missing transactions (e.g. a block
    // with an invalid tx that cannot be SSZ-encoded).  The block is invalid in that case,
    // so we set successful_validation=false and verify the output without executing.
    var tx_root_mismatch = false;
    if (expected_tx_root_hex) |hex| {
        const stripped = if (std.mem.startsWith(u8, hex, "0x")) hex[2..] else hex;
        if (stripped.len == 64) {
            var want: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&want, stripped) catch {};
            const got = try executor.computeRawTxRoot(alloc, ep.raw_transactions);
            if (!std.mem.eql(u8, &got, &want)) tx_root_mismatch = true;
        }
    }

    // successful_validation mirrors spec: True iff execution succeeds AND
    // post_state_root and receipts_root match the payload. executeStatelessInput
    // validates the roots itself (StateRootMismatch / ReceiptsRootMismatch), so a
    // successful return is authoritative.
    var exec_err: anyerror = error.Success;
    const successful_validation = if (tx_root_mismatch) false else blk: {
        _ = executor.executeStatelessInput(alloc, si, fork_name) catch |err| {
            exec_err = err;
            break :blk false;
        };
        break :blk true;
    };

    const computed = try ssz_output.serialize(alloc, si.chain_config, si.new_payload_request, successful_validation);
    if (!std.mem.eql(u8, &computed, &expected)) {
        const got_valid = computed[32] == 0x01;
        const expected_valid = expected[32] == 0x01;
        if (expected_valid and !got_valid) {
            const exc_name = executor_exceptions.mapBlockError(exec_err) orelse executor_exceptions.mapTransactionError(exec_err);
            std.debug.print("FAIL {s}[{}]  expected valid, got invalid: {s}\n", .{ test_name, block_idx, exc_name });
        } else if (!expected_valid and got_valid) {
            std.debug.print("FAIL {s}[{}]  expected invalid, got valid\n", .{ test_name, block_idx });
        } else {
            const got_hex = std.fmt.bytesToHex(computed, .lower);
            const exp_hex = std.fmt.bytesToHex(expected, .lower);
            std.debug.print("FAIL {s}[{}]  output mismatch\n  got:      0x{s}\n  expected: 0x{s}\n", .{ test_name, block_idx, &got_hex, &exp_hex });
        }
        return false;
    }

    return true;
}
