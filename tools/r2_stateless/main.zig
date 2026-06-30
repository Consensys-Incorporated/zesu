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
//! Each block artifact is blocks/NNNNNN/<block>-<hash>.json.zst, a flat JSON
//! object carrying `statelessInputBytes` (hex SSZ) and no expected output. A
//! block "passes" iff execution succeeds AND the computed post-state/receipts
//! roots match the roots claimed in the payload (executeStatelessInput errors
//! otherwise).
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
    if (strict and failed > 0) std.process.exit(1);
}

/// Iterate a tar archive (in memory), decompress each `*.json.zst` block
/// artifact, and execute it. Appends one BlockResult per artifact.
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
        if (!std.mem.endsWith(u8, file.name, ".json.zst")) continue;

        // Read the (zstd-compressed) artifact out of the tar stream.
        var aw = std.Io.Writer.Allocating.init(gpa);
        defer aw.deinit();
        try it.streamRemaining(file, &aw.writer);
        const artifact_json = try zstdDecompress(gpa, aw.writer.buffered());
        defer gpa.free(artifact_json);

        try runArtifact(gpa, artifact_json, results);
    }
}

/// Decode + execute one block artifact (a per-block arena bounds peak memory).
fn runArtifact(gpa: std.mem.Allocator, artifact_json: []const u8, results: *std.ArrayList(BlockResult)) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const alloc = arena.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, alloc, artifact_json, .{}) catch {
        return; // not a block artifact
    };
    const obj = parsed.value.object;

    const in_val = obj.get("statelessInputBytes") orelse return;
    if (in_val != .string) return;
    const number = jsonU64(obj.get("blockNumber"));

    const in_hex = in_val.string;
    const stripped = if (std.mem.startsWith(u8, in_hex, "0x")) in_hex[2..] else in_hex;
    const input_bytes = try alloc.alloc(u8, stripped.len / 2);
    _ = std.fmt.hexToBytes(input_bytes, stripped) catch {
        try appendResult(gpa, results, number, false, "invalid statelessInputBytes hex");
        return;
    };

    const si = ssz_decode.decode(alloc, input_bytes) catch |err| {
        try appendResult(gpa, results, number, false, @errorName(err));
        return;
    };

    // Same entry point the zkVM guest wraps (run.zig → executeStatelessInput).
    const exec_result = executor.executeStatelessInput(alloc, si, si.chain_config.fork_name);
    const success = if (exec_result) |_| true else |_| false;

    // Serialize the SSZ output (the guest's public commitment): 32-byte
    // new_payload_request root + 1-byte success + 72-byte SszChainConfig.
    const out = try ssz_output.serialize(alloc, si.new_payload_request, si.chain_config.chain_id, success);
    const out_hex = std.fmt.bytesToHex(out, .lower);

    if (exec_result) |_| {
        std.debug.print("PASS block {d}  output=0x{s}\n", .{ number, &out_hex });
        try appendResult(gpa, results, number, true, "");
    } else |err| {
        std.debug.print("FAIL block {d}  {s}  output=0x{s}\n", .{ number, @errorName(err), &out_hex });
        try appendResult(gpa, results, number, false, @errorName(err));
    }
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
    var aw = std.Io.Writer.Allocating.init(gpa);
    defer aw.deinit();
    const res = try client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &aw.writer,
    });
    if (res.status != .ok) {
        std.debug.print("error: HTTP {d} for {s}\n", .{ @intFromEnum(res.status), url });
        return error.HttpStatus;
    }
    return gpa.dupe(u8, aw.writer.buffered());
}

fn zstdDecompress(gpa: std.mem.Allocator, comp: []const u8) ![]u8 {
    var in = std.Io.Reader.fixed(comp);
    const win = try gpa.alloc(u8, zstd.default_window_len + zstd.block_size_max);
    defer gpa.free(win);
    var d = zstd.Decompress.init(&in, win, .{});
    return d.reader.allocRemaining(gpa, .unlimited);
}

fn sha256Matches(data: []const u8, want_hex: []const u8) bool {
    const h = if (std.mem.startsWith(u8, want_hex, "0x")) want_hex[2..] else want_hex;
    if (h.len != 64) return true; // no/!32-byte digest → skip check
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
        .string => |s| std.fmt.parseInt(u64, s, 10) catch 0,
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
            try w.print("All blocks executed successfully (computed roots matched the payload).\n", .{});
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
