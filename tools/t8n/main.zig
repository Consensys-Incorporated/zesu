/// t8n — Ethereum State Transition Tool
///
/// Compatible with execution-spec-tests and geth's evm t8n interface.
///
/// Usage:
///   t8n [flags]
///
/// Input flags:
///   --input.alloc FILE    Pre-state allocation (default: alloc.json)
///   --input.env FILE      Block environment (default: env.json)
///   --input.txs FILE      Transactions (default: txs.json)
///
/// Output flags:
///   --output.basedir DIR  Base directory for output files
///   --output.alloc FILE   Post-state allocation (default: alloc.json)
///   --output.result FILE  Execution result (default: result.json)
///   --output.body FILE    RLP-encoded transactions (stub: always writes "0xc0")
///
/// Execution flags:
///   --state.fork FORK     Fork name (default: Cancun)
///   --state.chainid N     Chain ID (default: 1)
///   --state.reward N      Mining reward in wei, -1 to disable (default: -1)
///
/// Output path "stdout" writes to stdout; "" suppresses the output. When both alloc and
/// result go to stdout they are combined as {"alloc":..., "result":...}. Input path
/// "stdin" reads from stdin.
const std = @import("std");

const input_mod = @import("input.zig");
const transition_mod = @import("executor").executor_transition;
const hardfork = @import("hardfork");
const output_mod = @import("output.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.minimal.args.toSlice(init.arena.allocator());

    // ── Parse CLI flags ───────────────────────────────────────────────────────

    var input_alloc_path: []const u8 = "alloc.json";
    var input_env_path: []const u8 = "env.json";
    var input_txs_path: []const u8 = "txs.json";
    var output_basedir: ?[]const u8 = null;
    var output_alloc_path: []const u8 = "alloc.json";
    var output_result_path: []const u8 = "result.json";
    var output_body_path: ?[]const u8 = null;
    var state_fork: []const u8 = "Cancun";
    var state_chainid: u64 = 1;
    var state_reward: i64 = -1;
    var trace_enabled: bool = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        const val = getFlag(arg, args, &i);

        if (matchFlag(arg, "--input.alloc")) {
            if (val) |v| input_alloc_path = v;
        } else if (matchFlag(arg, "--input.env")) {
            if (val) |v| input_env_path = v;
        } else if (matchFlag(arg, "--input.txs")) {
            if (val) |v| input_txs_path = v;
        } else if (matchFlag(arg, "--output.basedir")) {
            if (val) |v| output_basedir = v;
        } else if (matchFlag(arg, "--output.alloc")) {
            if (val) |v| output_alloc_path = v;
        } else if (matchFlag(arg, "--output.result")) {
            if (val) |v| output_result_path = v;
        } else if (matchFlag(arg, "--output.body")) {
            if (val) |v| output_body_path = v;
        } else if (matchFlag(arg, "--state.fork")) {
            if (val) |v| state_fork = v;
        } else if (matchFlag(arg, "--state.chainid")) {
            if (val) |v| state_chainid = std.fmt.parseInt(u64, v, 10) catch 1;
        } else if (matchFlag(arg, "--state.reward")) {
            if (val) |v| state_reward = std.fmt.parseInt(i64, v, 10) catch 0;
        } else if (std.mem.eql(u8, arg, "--trace")) {
            trace_enabled = true;
        }
    }
    if (trace_enabled) {
        std.debug.print("t8n: --trace flag noted; EIP-3155 tracing not yet implemented\n", .{});
    }

    // ── Resolve fork ──────────────────────────────────────────────────────────

    const spec = hardfork.specFromFork(state_fork) orelse {
        std.debug.print("t8n: unknown fork: {s}\n", .{state_fork});
        std.process.exit(3);
    };

    // ── Read and parse inputs ─────────────────────────────────────────────────

    const alloc_json = readFile(init.io, arena, input_alloc_path) catch |err| {
        std.debug.print("t8n: cannot read alloc '{s}': {}\n", .{ input_alloc_path, err });
        std.process.exit(11);
    };
    const env_json = readFile(init.io, arena, input_env_path) catch |err| {
        std.debug.print("t8n: cannot read env '{s}': {}\n", .{ input_env_path, err });
        std.process.exit(11);
    };
    const txs_json = readFile(init.io, arena, input_txs_path) catch |err| {
        std.debug.print("t8n: cannot read txs '{s}': {}\n", .{ input_txs_path, err });
        std.process.exit(11);
    };

    const pre_alloc = input_mod.parseAlloc(arena, alloc_json) catch |err| {
        std.debug.print("t8n: cannot parse alloc: {}\n", .{err});
        std.process.exit(10);
    };
    const env = input_mod.parseEnv(arena, env_json) catch |err| {
        std.debug.print("t8n: cannot parse env: {}\n", .{err});
        std.process.exit(10);
    };
    const txs = input_mod.parseTxs(arena, txs_json) catch |err| {
        std.debug.print("t8n: cannot parse txs: {}\n", .{err});
        std.process.exit(10);
    };

    // ── Run state transition ──────────────────────────────────────────────────

    const result = transition_mod.transition(
        arena,
        pre_alloc,
        env,
        txs,
        spec,
        state_chainid,
        state_reward,
    ) catch |err| {
        std.debug.print("t8n: transition failed: {}\n", .{err});
        std.process.exit(2);
    };

    // ── Write outputs ─────────────────────────────────────────────────────────

    const alloc_out = resolveOutputPath(arena, output_basedir, output_alloc_path) catch output_alloc_path;
    const result_out = resolveOutputPath(arena, output_basedir, output_result_path) catch output_result_path;

    const alloc_stdout = std.mem.eql(u8, alloc_out, "stdout");
    const result_stdout = std.mem.eql(u8, result_out, "stdout");

    if (alloc_stdout and result_stdout) {
        var out = std.ArrayListUnmanaged(u8).empty;
        const w: output_mod.ListWriter = .{ .list = &out, .alloc = arena };
        try w.writeAll("{\"alloc\": ");
        try output_mod.writeAllocJson(w, result.alloc);
        try w.writeAll(", \"result\": ");
        try output_mod.writeResultJson(arena, w, result, env.difficulty);
        try w.writeAll("}\n");
        try std.Io.File.stdout().writeStreamingAll(init.io, out.items);
    } else {
        if (alloc_stdout) {
            var out = std.ArrayListUnmanaged(u8).empty;
            const w: output_mod.ListWriter = .{ .list = &out, .alloc = arena };
            try output_mod.writeAllocJson(w, result.alloc);
            try std.Io.File.stdout().writeStreamingAll(init.io, out.items);
        } else if (!std.mem.eql(u8, alloc_out, "")) {
            writeOutputFile(init.io, arena, alloc_out, result.alloc, result, env.difficulty, .alloc) catch |err| {
                std.debug.print("t8n: cannot write alloc '{s}': {}\n", .{ alloc_out, err });
                std.process.exit(11);
            };
        }

        if (result_stdout) {
            var out = std.ArrayListUnmanaged(u8).empty;
            const w: output_mod.ListWriter = .{ .list = &out, .alloc = arena };
            try output_mod.writeResultJson(arena, w, result, env.difficulty);
            try std.Io.File.stdout().writeStreamingAll(init.io, out.items);
        } else if (!std.mem.eql(u8, result_out, "")) {
            writeOutputFile(init.io, arena, result_out, result.alloc, result, env.difficulty, .result) catch |err| {
                std.debug.print("t8n: cannot write result '{s}': {}\n", .{ result_out, err });
                std.process.exit(11);
            };
        }
    }

    // output.body stub: always the empty RLP list.
    if (output_body_path) |body_path| {
        const body_out = resolveOutputPath(arena, output_basedir, body_path) catch body_path;
        if (!std.mem.eql(u8, body_out, "stdout") and !std.mem.eql(u8, body_out, "")) {
            if (ensureParentDir(init.io, body_out)) {
                const f = std.Io.Dir.cwd().createFile(init.io, body_out, .{}) catch null;
                if (f) |file| {
                    defer file.close(init.io);
                    file.writeStreamingAll(init.io, "\"0xc0\"\n") catch {};
                }
            }
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const OutputKind = enum { alloc, result };

fn writeOutputFile(
    io: std.Io,
    arena: std.mem.Allocator,
    path: []const u8,
    alloc_map: std.AutoHashMapUnmanaged(input_mod.Address, input_mod.AllocAccount),
    result: transition_mod.TransitionResult,
    difficulty: u256,
    kind: OutputKind,
) !void {
    _ = ensureParentDir(io, path);
    var out = std.ArrayListUnmanaged(u8).empty;
    const w: output_mod.ListWriter = .{ .list = &out, .alloc = arena };
    switch (kind) {
        .alloc => try output_mod.writeAllocJson(w, alloc_map),
        .result => try output_mod.writeResultJson(arena, w, result, difficulty),
    }
    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, out.items);
}

fn ensureParentDir(io: std.Io, path: []const u8) bool {
    const dir = std.Io.Dir.path.dirname(path) orelse return true;
    std.Io.Dir.cwd().createDirPath(io, dir) catch {};
    return true;
}

fn resolveOutputPath(
    arena: std.mem.Allocator,
    basedir: ?[]const u8,
    path: []const u8,
) ![]const u8 {
    if (std.mem.eql(u8, path, "stdout") or
        std.mem.eql(u8, path, "stderr") or
        std.mem.eql(u8, path, "")) return path;

    const bd = basedir orelse return path;

    // Absolute paths ignore basedir
    if (std.Io.Dir.path.isAbsolute(path)) return path;

    return std.Io.Dir.path.join(arena, &.{ bd, path });
}

fn readFile(io: std.Io, arena: std.mem.Allocator, path: []const u8) ![]u8 {
    if (std.mem.eql(u8, path, "stdin")) {
        var buf: [4096]u8 = undefined;
        var reader = std.Io.File.stdin().reader(io, &buf);
        return reader.interface.allocRemaining(arena, .limited(64 << 20));
    }
    return std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(64 << 20));
}

fn matchFlag(arg: []const u8, flag: []const u8) bool {
    if (std.mem.eql(u8, arg, flag)) return true;
    if (std.mem.startsWith(u8, arg, flag) and arg.len > flag.len and arg[flag.len] == '=') return true;
    return false;
}

fn getFlag(arg: []const u8, args: []const [:0]const u8, i: *usize) ?[]const u8 {
    if (std.mem.indexOf(u8, arg, "=")) |eq| {
        if (eq < arg.len - 1) return arg[eq + 1 ..];
    }
    if (i.* + 1 < args.len) {
        const next = args[i.* + 1];
        if (next.len == 0 or next[0] != '-') {
            i.* += 1;
            return next;
        }
        // A leading '-' is still a value if it looks like a negative number
        // (e.g. --state.reward -1).
        if (next.len > 2 and next[1] == '-' and std.ascii.isDigit(next[2])) {
            i.* += 1;
            return next;
        }
        if (next.len > 1 and std.ascii.isDigit(next[1])) {
            i.* += 1;
            return next;
        }
    }
    return null;
}
