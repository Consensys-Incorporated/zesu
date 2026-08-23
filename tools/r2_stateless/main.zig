//! r2-stateless — fetch the latest stateless-input batches from a public R2
//! devnet catalog and execute each block natively, in-process, through the
//! same path the zkVM guest uses (executor.executeStatelessInput — see
//! src/stateless/stateless/run.zig).
//!
//! No external tools required: HTTPS fetch (std.http), zstd decompression
//! (std.compress.zstd), tar parsing (std.tar), SHA-256 (std.crypto) and JSON
//! (std.json) all come from the Zig standard library.
//!
//! The R2 catalog layout (see <catalog>/index.html):
//!   batches.jsonl                    one JSON object per batch, oldest → newest
//!   exports/batches/<a>-<b>.tar.zst  zstd tarball of block artifacts + manifest
//! Each block artifact is blockchain_tests/NNNNNN/<block>-<hash>.json (plain
//! JSON; only the tarball itself is zstd-compressed), in the canonical EEST
//! blockchain-test fixture format:
//!   { "<test-name>": { "network", "config", "blocks": [
//!       { "statelessInputBytes": "0x..", "statelessOutputBytes": "0x..", "blockHeader" }
//!   ], "_info" } }
//! `statelessOutputBytes` is the authoritative expected SSZ output. A block
//! "passes" iff execution succeeds AND the computed SSZ output matches it
//! byte-for-byte (executeStatelessInput itself validates the post-state/
//! receipts roots against the payload as part of producing that output).
//!
//! Usage:
//!   r2-stateless [--catalog URL] [--batches N] [--strict]
//!                [--summary-md PATH] [--summary-json PATH]
//!
//! Runs the latest N batches (default 1). Following the devnet head — e.g.
//! "all blocks from the last 2 hours" — is the caller's job: the CI workflow
//! computes how many batches that window spans and passes it as --batches N.

const std = @import("std");
const ssz_decode = @import("ssz_decode");
const ssz_output = @import("ssz_output");
const executor = @import("executor");
const executor_exceptions = @import("executor").executor_exceptions;
const build_options = @import("build_options");
const zstd = std.compress.zstd;

/// Default catalog, baked in at build time (see `-Dr2-catalog` in build.zig).
/// Overridable at runtime with `--catalog`.
const default_catalog = build_options.catalog_url;

const BlockResult = struct {
    number: u64,
    ok: bool,
    reason: []const u8, // owned by the caller's allocator when !ok
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    // ── Args ──────────────────────────────────────────────────────────────────
    var catalog: []const u8 = default_catalog;
    var batch_count: usize = 1;
    var strict = false;
    var summary_md: ?[]const u8 = null;
    var summary_json: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--catalog") and i + 1 < args.len) {
            i += 1;
            catalog = args[i];
        } else if (std.mem.eql(u8, a, "--batches") and i + 1 < args.len) {
            i += 1;
            batch_count = std.fmt.parseInt(usize, args[i], 10) catch {
                std.debug.print("error: --batches expects an integer\n", .{});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, a, "--strict")) {
            strict = true;
        } else if (std.mem.eql(u8, a, "--summary-md") and i + 1 < args.len) {
            i += 1;
            summary_md = args[i];
        } else if (std.mem.eql(u8, a, "--summary-json") and i + 1 < args.len) {
            i += 1;
            summary_json = args[i];
        } else {
            std.debug.print("error: unexpected argument '{s}'\n", .{a});
            std.process.exit(2);
        }
    }
    if (batch_count == 0) batch_count = 1;
    catalog = normalizeCatalog(catalog);

    std.debug.print("Catalog:     {s}\n", .{catalog});
    std.debug.print("Batches:     latest {d}\n", .{batch_count});

    var client: std.http.Client = .{ .allocator = gpa, .io = init.io };
    defer client.deinit();

    // ── Fetch batch index ───────────────────────────────────────────────────────
    const batches_url = try std.fmt.allocPrint(gpa, "{s}/batches.jsonl", .{catalog});
    defer gpa.free(batches_url);
    const batches_jsonl = httpGet(gpa, &client, batches_url) catch |err| {
        std.debug.print("error: failed to fetch batches.jsonl: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer gpa.free(batches_jsonl);

    // Batch index is ordered oldest → newest, one JSON object per line.
    var lines = std.ArrayList([]const u8).empty;
    defer lines.deinit(gpa);
    var line_it = std.mem.tokenizeScalar(u8, batches_jsonl, '\n');
    while (line_it.next()) |ln| {
        const t = std.mem.trim(u8, ln, " \t\r");
        if (t.len > 0) try lines.append(gpa, t);
    }
    if (lines.items.len == 0) {
        std.debug.print("error: no batches found in catalog\n", .{});
        std.process.exit(1);
    }

    // Latest N batches = last N lines (catalog is ordered oldest → newest).
    const start_idx = if (lines.items.len > batch_count) lines.items.len - batch_count else 0;
    const selected = lines.items[start_idx..];

    // ── Run ───────────────────────────────────────────────────────────────────
    var results = std.ArrayList(BlockResult).empty;
    defer {
        for (results.items) |r| if (!r.ok) gpa.free(r.reason);
        results.deinit(gpa);
    }
    var batch_n: usize = 0;
    var first_block: u64 = 0;
    var last_block: u64 = 0;
    var network: []const u8 = "unknown";
    var network_buf: ?[]u8 = null;
    defer if (network_buf) |nb| gpa.free(nb);

    for (selected) |line| {
        var parsed = std.json.parseFromSlice(std.json.Value, gpa, line, .{}) catch |err| {
            std.debug.print("error: bad batch index line: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        defer parsed.deinit();
        const obj = parsed.value.object;

        const path = (obj.get("path") orelse continue).string;
        const start = jsonU64(obj.get("batchStartBlock"));
        const end = jsonU64(obj.get("batchEndBlock"));
        const sha_hex: ?[]const u8 = if (obj.get("sha256")) |v| (if (v == .string) v.string else null) else null;
        if (network_buf == null) {
            if (obj.get("network")) |v| if (v == .string) {
                network_buf = try gpa.dupe(u8, v.string);
                network = network_buf.?;
            };
        }

        if (batch_n == 0) first_block = start;
        last_block = end;
        batch_n += 1;
        std.debug.print("==> batch {d}-{d} ({s})\n", .{ start, end, path });

        const url = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ catalog, path });
        defer gpa.free(url);
        const tarball = httpGet(gpa, &client, url) catch |err| {
            std.debug.print("error: failed to fetch {s}: {s}\n", .{ path, @errorName(err) });
            std.process.exit(1);
        };
        defer gpa.free(tarball);

        if (sha_hex) |want_hex| {
            if (!sha256Matches(tarball, want_hex)) {
                std.debug.print("error: sha256 mismatch for {s}\n", .{path});
                std.process.exit(1);
            }
        }

        const tar_bytes = zstdDecompress(gpa, tarball) catch |err| {
            std.debug.print("error: zstd decompress failed for {s}: {s}\n", .{ path, @errorName(err) });
            std.process.exit(1);
        };
        defer gpa.free(tar_bytes);

        try runTar(gpa, tar_bytes, &results);
    }

    // ── Tally ───────────────────────────────────────────────────────────────────
    var passed: usize = 0;
    var failed: usize = 0;
    for (results.items) |r| {
        if (r.ok) passed += 1 else failed += 1;
    }
    const total = passed + failed;

    try writeSummaries(init.io, gpa, summary_md, summary_json, network, catalog, batch_n, first_block, last_block, results.items, passed, failed, total);

    std.debug.print("\nSummary: {d}/{d} passed\n", .{ passed, total });
    if (strict) {
        if (total == 0) {
            std.debug.print("error: --strict: no blocks were executed\n", .{});
            std.process.exit(1);
        }
        if (failed > 0) std.process.exit(1);
    }
}

/// Iterate a tar archive (in memory) and execute each `*.json` block
/// artifact. Appends one BlockResult per block.
fn runTar(gpa: std.mem.Allocator, tar_bytes: []const u8, results: *std.ArrayList(BlockResult)) !void {
    var tar_reader = std.Io.Reader.fixed(tar_bytes);
    var name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    var it = std.tar.Iterator.init(&tar_reader, .{
        .file_name_buffer = &name_buf,
        .link_name_buffer = &link_buf,
    });

    while (try it.next()) |file| {
        if (file.kind != .file) continue;
        if (!std.mem.endsWith(u8, file.name, ".json")) continue;

        var aw = std.Io.Writer.Allocating.init(gpa);
        defer aw.deinit();
        try it.streamRemaining(file, &aw.writer);

        try runArtifact(gpa, aw.writer.buffered(), results);
    }
}

/// Decode + execute every block in one canonical EEST blockchain-test
/// fixture (a per-artifact arena bounds peak memory):
///   { "<test-name>": { "blocks": [ { statelessInputBytes,
///     statelessOutputBytes, blockHeader: { number, .. } } ] } }
fn runArtifact(gpa: std.mem.Allocator, artifact_json: []const u8, results: *std.ArrayList(BlockResult)) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const alloc = arena.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, alloc, artifact_json, .{}) catch {
        return; // not a block artifact
    };
    if (parsed.value != .object) return;

    var test_it = parsed.value.object.iterator();
    while (test_it.next()) |test_kv| {
        const test_case = test_kv.value_ptr.*;
        if (test_case != .object) continue;

        const blocks_val = test_case.object.get("blocks") orelse continue;
        if (blocks_val != .array) continue;

        for (blocks_val.array.items) |block_val| {
            if (block_val != .object) continue;
            try runBlock(gpa, alloc, block_val.object, results);
        }
    }
}

/// Decode + execute one block, and check the computed SSZ output against
/// the fixture's authoritative `statelessOutputBytes` byte-for-byte.
fn runBlock(gpa: std.mem.Allocator, alloc: std.mem.Allocator, block: std.json.ObjectMap, results: *std.ArrayList(BlockResult)) !void {
    const number: u64 = blk: {
        const bh = block.get("blockHeader") orelse break :blk 0;
        if (bh != .object) break :blk 0;
        break :blk jsonU64(bh.object.get("number"));
    };

    const in_val = block.get("statelessInputBytes") orelse return;
    if (in_val != .string) return;
    const out_val = block.get("statelessOutputBytes") orelse return;
    if (out_val != .string) return;

    const in_hex = in_val.string;
    const in_stripped = if (std.mem.startsWith(u8, in_hex, "0x")) in_hex[2..] else in_hex;
    const input_bytes = try alloc.alloc(u8, in_stripped.len / 2);
    _ = std.fmt.hexToBytes(input_bytes, in_stripped) catch {
        try appendResult(gpa, results, number, false, "invalid statelessInputBytes hex");
        return;
    };

    const out_hex = out_val.string;
    const out_stripped = if (std.mem.startsWith(u8, out_hex, "0x")) out_hex[2..] else out_hex;

    // EIP-8025 (optional proofs): when the stateless input cannot be decoded, the guest
    // emits the "default failed" result (root=0, successful_validation=false, chain_id=0,
    // schema_id=0) — reference stateless_guest run_stateless_guest /
    // _default_failed_stateless_output. The decode attempt must come before any length
    // check on statelessOutputBytes.
    const si = ssz_decode.decode(alloc, input_bytes) catch {
        const failed_hex = std.fmt.bytesToHex(ssz_output.DEFAULT_FAILED_OUTPUT, .lower);
        const ok = std.ascii.eqlIgnoreCase(out_stripped, &failed_hex);
        try appendResult(gpa, results, number, ok, if (ok) "" else "input failed to decode; fixture does not expect default-failed output");
        if (ok) {
            std.debug.print("PASS block {d}  output=0x{s}\n", .{ number, &failed_hex });
        } else {
            std.debug.print("FAIL block {d}  input failed to decode; fixture expects 0x{s}\n", .{ number, out_stripped });
        }
        return;
    };

    if (out_stripped.len != 2 * ssz_output.OUTPUT_SIZE) {
        try appendResult(gpa, results, number, false, "unexpected statelessOutputBytes length");
        return;
    }
    var expected: [ssz_output.OUTPUT_SIZE]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected, out_stripped) catch {
        try appendResult(gpa, results, number, false, "invalid statelessOutputBytes hex");
        return;
    };

    // Execute via the same entry point the zkVM guest wraps (run.zig →
    // executeStatelessInput). The executor validates the block — including the
    // post-state/receipts roots against the payload (StateRootMismatch /
    // ReceiptsRootMismatch) alongside its gas/blob/BAL checks.
    var exec_err: anyerror = error.Success;
    const validated = if (executor.executeStatelessInput(alloc, si, si.chain_config.fork_name)) |_| true else |err| blk: {
        exec_err = err;
        break :blk false;
    };

    // Serialize the SSZ output (the guest's public commitment): 32-byte
    // new_payload_request root + 1-byte success + chain_id + schema_id.
    const computed = try ssz_output.serialize(alloc, si.chain_config, si.new_payload_request, validated);
    const computed_hex = std.fmt.bytesToHex(computed, .lower);

    const ok = std.mem.eql(u8, &computed, &expected);
    var reason: []const u8 = "";
    if (!ok) {
        const got_valid = computed[32] == 0x01;
        const expected_valid = expected[32] == 0x01;
        reason = if (expected_valid and !got_valid)
            executor_exceptions.mapBlockError(exec_err) orelse executor_exceptions.mapTransactionError(exec_err)
        else if (!expected_valid and got_valid)
            "expected invalid, got valid"
        else
            "output mismatch";
    }

    if (ok) {
        std.debug.print("PASS block {d}  output=0x{s}\n", .{ number, &computed_hex });
    } else {
        std.debug.print("FAIL block {d}  {s}  output=0x{s}\n", .{ number, reason, &computed_hex });
    }
    try appendResult(gpa, results, number, ok, reason);
}

fn appendResult(gpa: std.mem.Allocator, results: *std.ArrayList(BlockResult), number: u64, ok: bool, reason: []const u8) !void {
    try results.append(gpa, .{
        .number = number,
        .ok = ok,
        .reason = if (ok) "" else try gpa.dupe(u8, reason),
    });
}

// ── HTTP / compression / hashing helpers ──────────────────────────────────────

fn httpGet(gpa: std.mem.Allocator, client: *std.http.Client, url: []const u8) ![]u8 {
    const max_attempts = 3;
    var last_err: anyerror = error.HttpStatus;
    for (0..max_attempts) |attempt| {
        if (attempt > 0) {
            std.debug.print("  retry {d}/{d} after transport error ({s})\n", .{ attempt, max_attempts - 1, @errorName(last_err) });
            const ts = std.c.timespec{ .sec = 3, .nsec = 0 };
            _ = std.c.nanosleep(&ts, null);
        }
        var aw = std.Io.Writer.Allocating.init(gpa);
        defer aw.deinit();
        const res = client.fetch(.{
            .location = .{ .url = url },
            .response_writer = &aw.writer,
        }) catch |err| {
            last_err = err;
            continue;
        };
        if (res.status != .ok) {
            std.debug.print("error: HTTP {d} for {s}\n", .{ @intFromEnum(res.status), url });
            return error.HttpStatus;
        }
        return gpa.dupe(u8, aw.writer.buffered());
    }
    std.debug.print("error: {d} attempts failed for {s}: {s}\n", .{ max_attempts, url, @errorName(last_err) });
    return last_err;
}

fn zstdDecompress(gpa: std.mem.Allocator, comp: []const u8) ![]u8 {
    var in = std.Io.Reader.fixed(comp);
    const win = try gpa.alloc(u8, zstd.default_window_len + zstd.block_size_max);
    defer gpa.free(win);
    var d = zstd.Decompress.init(&in, win, .{});
    return d.reader.allocRemaining(gpa, .unlimited);
}

/// Caller only invokes this when a digest is present, so a malformed digest
/// (not 32 bytes of hex) is treated as a verification failure, not skipped.
fn sha256Matches(data: []const u8, want_hex: []const u8) bool {
    const h = if (std.mem.startsWith(u8, want_hex, "0x")) want_hex[2..] else want_hex;
    if (h.len != 64) return false;
    var want: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&want, h) catch return false;
    var got: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &got, .{});
    return std.mem.eql(u8, &got, &want);
}

fn normalizeCatalog(url: []const u8) []const u8 {
    var u = url;
    if (std.mem.endsWith(u8, u, "/index.html")) u = u[0 .. u.len - "/index.html".len];
    if (std.mem.endsWith(u8, u, "/manifest.json")) u = u[0 .. u.len - "/manifest.json".len];
    if (std.mem.endsWith(u8, u, "/")) u = u[0 .. u.len - 1];
    return u;
}

fn jsonU64(v: ?std.json.Value) u64 {
    const val = v orelse return 0;
    return switch (val) {
        .integer => |n| if (n < 0) 0 else @intCast(n),
        .string => |s| if (std.mem.startsWith(u8, s, "0x"))
            std.fmt.parseInt(u64, s[2..], 16) catch 0
        else
            std.fmt.parseInt(u64, s, 10) catch 0,
        else => 0,
    };
}

// ── Summaries ──────────────────────────────────────────────────────────────────

fn writeSummaries(
    io: std.Io,
    gpa: std.mem.Allocator,
    summary_md: ?[]const u8,
    summary_json: ?[]const u8,
    network: []const u8,
    catalog: []const u8,
    batch_n: usize,
    first_block: u64,
    last_block: u64,
    results: []const BlockResult,
    passed: usize,
    failed: usize,
    total: usize,
) !void {
    if (summary_md) |path| {
        var aw = std.Io.Writer.Allocating.init(gpa);
        defer aw.deinit();
        const w = &aw.writer;
        try w.print("## R2 stateless inputs — native execution\n\n", .{});
        try w.print("- **Network:** `{s}`\n", .{network});
        try w.print("- **Catalog:** {s}\n", .{catalog});
        try w.print("- **Batches:** {d} (blocks {d}–{d})\n", .{ batch_n, first_block, last_block });
        try w.print("- **Blocks:** {d}/{d} passed\n\n", .{ passed, total });
        if (failed > 0) {
            try w.print("### Failures\n\n```\n", .{});
            for (results) |r| if (!r.ok) try w.print("block {d}  {s}\n", .{ r.number, r.reason });
            try w.print("```\n", .{});
        } else {
            try w.print("All blocks executed successfully (computed SSZ output matched the fixture's statelessOutputBytes).\n", .{});
        }
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = w.buffered() });
    }

    if (summary_json) |path| {
        var aw = std.Io.Writer.Allocating.init(gpa);
        defer aw.deinit();
        const w = &aw.writer;
        try w.print(
            "{{\"network\":\"{s}\",\"catalog\":\"{s}\",\"batches\":{d}," ++
                "\"firstBlock\":{d},\"lastBlock\":{d}," ++
                "\"passed\":{d},\"failed\":{d},\"total\":{d}}}\n",
            .{ network, catalog, batch_n, first_block, last_block, passed, failed, total },
        );
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = w.buffered() });
    }
}
