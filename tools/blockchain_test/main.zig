/// blockchain-test-runner — Ethereum blockchain test fixture runner.
///
/// Usage:
///   blockchain-test-runner [OPTIONS]
///
/// Options:
///   --fixtures DIR    Root directory of blockchain_tests fixtures
///                     (default: spec-tests/fixtures/blockchain_tests)
///   --fork FORK       Only run tests for a specific fork (e.g. Cancun, Prague)
///   --file FILE       Run a single fixture file instead of the whole suite
///   -x                Stop after the first failure
///   -q                Quiet — only print FAIL lines and the summary
///   --json            Print JSON diagnostics on failure
///
/// Each fixture file runs in a child process (re-invoking this binary with --file) so a
/// crash or heap corruption is isolated to that file; children report counts on a
/// `STATS:` stderr line that the parent aggregates.
const std = @import("std");

const runner = @import("runner");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    // ── Parse CLI flags ───────────────────────────────────────────────────────

    var fixtures_dir: []const u8 = "spec-tests/fixtures/blockchain_tests";
    var fork_filter: ?[]const u8 = null;
    var single_file: ?[]const u8 = null;
    var stop_on_fail: bool = false;
    var quiet: bool = false;
    var json_output: bool = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--fixtures") and i + 1 < args.len) {
            i += 1;
            fixtures_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--fork") and i + 1 < args.len) {
            i += 1;
            fork_filter = args[i];
        } else if (std.mem.eql(u8, arg, "--file") and i + 1 < args.len) {
            i += 1;
            single_file = args[i];
        } else if (std.mem.eql(u8, arg, "-x")) {
            stop_on_fail = true;
        } else if (std.mem.eql(u8, arg, "-q")) {
            quiet = true;
        } else if (std.mem.eql(u8, arg, "--json")) {
            json_output = true;
        } else if (std.mem.startsWith(u8, arg, "--fixtures=")) {
            fixtures_dir = arg["--fixtures=".len..];
        } else if (std.mem.startsWith(u8, arg, "--fork=")) {
            fork_filter = arg["--fork=".len..];
        } else if (std.mem.startsWith(u8, arg, "--file=")) {
            single_file = arg["--file=".len..];
        }
    }

    // ── Run fixtures ──────────────────────────────────────────────────────────

    var stats = runner.RunStats{};

    if (single_file) |path| {
        _ = try processFile(init.io, allocator, path, path, fork_filter, stop_on_fail, quiet, json_output, &stats);
    } else {
        var dir = std.Io.Dir.cwd().openDir(init.io, fixtures_dir, .{ .iterate = true }) catch |err| {
            std.debug.print("error: cannot open fixtures dir '{s}': {}\n", .{ fixtures_dir, err });
            std.process.exit(1);
        };
        defer dir.close(init.io);

        var walker = try dir.walk(allocator);
        defer walker.deinit();

        // Collect and sort .json paths for deterministic ordering.
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

        var exe_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const exe_len = std.process.executablePath(init.io, &exe_buf) catch 0;
        const exe_path: []const u8 = if (exe_len > 0) exe_buf[0..exe_len] else args[0];

        for (paths.items) |rel_path| {
            const full_path = try std.Io.Dir.path.join(allocator, &.{ fixtures_dir, rel_path });
            defer allocator.free(full_path);

            var argv = std.ArrayList([]const u8).empty;
            defer argv.deinit(allocator);
            try argv.appendSlice(allocator, &.{ exe_path, "--file", full_path });
            if (fork_filter) |f| try argv.appendSlice(allocator, &.{ "--fork", f });
            if (quiet) try argv.append(allocator, "-q");
            if (stop_on_fail) try argv.append(allocator, "-x");
            if (json_output) try argv.append(allocator, "--json");

            const result = std.process.run(allocator, init.io, .{
                .argv = argv.items,
            }) catch |err| {
                if (!quiet) std.debug.print("SPAWN_ERROR  {s}: {}\n", .{ rel_path, err });
                stats.skipped += 1;
                if (stop_on_fail and stats.failed > 0) break;
                continue;
            };
            defer {
                allocator.free(result.stdout);
                allocator.free(result.stderr);
            }

            var lines = std.mem.splitScalar(u8, result.stderr, '\n');
            while (lines.next()) |line| {
                if (std.mem.startsWith(u8, line, "STATS:")) {
                    var tok = std.mem.tokenizeScalar(u8, line["STATS:".len..], ' ');
                    while (tok.next()) |kv| {
                        if (std.mem.startsWith(u8, kv, "passed="))
                            stats.passed += std.fmt.parseInt(u64, kv["passed=".len..], 10) catch 0
                        else if (std.mem.startsWith(u8, kv, "failed="))
                            stats.failed += std.fmt.parseInt(u64, kv["failed=".len..], 10) catch 0
                        else if (std.mem.startsWith(u8, kv, "skipped="))
                            stats.skipped += std.fmt.parseInt(u64, kv["skipped=".len..], 10) catch 0;
                    }
                } else if (!std.mem.startsWith(u8, line, "===") and
                    !std.mem.startsWith(u8, line, "  Results:") and
                    !std.mem.startsWith(u8, line, "  Failed:") and
                    !std.mem.startsWith(u8, line, "  Skipped:") and
                    line.len > 0)
                {
                    std.debug.print("{s}\n", .{line});
                }
            }

            switch (result.term) {
                .exited => |code| {
                    if (code > 1) {
                        if (!quiet) std.debug.print("CRASH(exit:{})  {s}\n", .{ code, rel_path });
                        stats.skipped += 1;
                    }
                },
                .signal => |sig| {
                    if (!quiet) std.debug.print("CRASH(sig:{})  {s}\n", .{ @intFromEnum(sig), rel_path });
                    stats.skipped += 1;
                },
                else => {
                    if (!quiet) std.debug.print("CRASH  {s}\n", .{rel_path});
                    stats.skipped += 1;
                },
            }

            if (stop_on_fail and stats.failed > 0) break;
        }
    }

    // ── Summary ───────────────────────────────────────────────────────────────

    printSummary(stats);
    if (stats.failed > 0) std.process.exit(1);
}

fn processFile(
    io: std.Io,
    allocator: std.mem.Allocator,
    full_path: []const u8,
    rel_path: []const u8,
    fork_filter: ?[]const u8,
    stop_on_fail: bool,
    quiet: bool,
    json_output: bool,
    stats: *runner.RunStats,
) !bool {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const json_text = std.Io.Dir.cwd().readFileAlloc(io, full_path, alloc, .limited(256 * 1024 * 1024)) catch |err| {
        std.debug.print("error: cannot read '{s}': {}\n", .{ full_path, err });
        return true;
    };

    return runner.runFixture(alloc, json_text, fork_filter, stop_on_fail, quiet, json_output, stats, rel_path);
}

fn printSummary(stats: runner.RunStats) void {
    const total = stats.total();
    const pct: u64 = if (total > 0) 100 * stats.passed / total else 0;
    std.debug.print("\n", .{});
    std.debug.print("============================================================\n", .{});
    std.debug.print("  Results:  {}/{} passed  ({}%)\n", .{ stats.passed, total, pct });
    if (stats.failed > 0) std.debug.print("  Failed:   {}\n", .{stats.failed});
    if (stats.skipped > 0) std.debug.print("  Skipped:  {}\n", .{stats.skipped});
    std.debug.print("============================================================\n", .{});
    std.debug.print("STATS: passed={} failed={} skipped={}\n", .{ stats.passed, stats.failed, stats.skipped });
}
