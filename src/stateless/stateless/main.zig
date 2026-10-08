const std = @import("std");

const io = @import("io.zig");
const ssz_output = @import("ssz_output.zig");
const input = @import("input");
const executor = @import("executor");
const alloc_mod = @import("zesu_allocator");
const zkvm_io = @import("zkvm_io");

const InputSource = union(enum) {
    ssz_stream, // default: zkvm_io.read_input()
    ssz_file: []const u8, // --ssz <file>
};

pub fn main(init: std.process.Init) !void {
    const allocator = alloc_mod.get();
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    // ── Arg parsing ───────────────────────────────────────────────────────────
    var source: InputSource = .ssz_stream;

    var arg_i: usize = 1;
    while (arg_i < args.len) : (arg_i += 1) {
        const arg = args[arg_i];

        if (std.mem.eql(u8, arg, "--ssz")) {
            // --ssz may optionally be followed by a file path
            if (arg_i + 1 < args.len and !std.mem.startsWith(u8, args[arg_i + 1], "--")) {
                arg_i += 1;
                source = .{ .ssz_file = args[arg_i] };
            } else {
                source = .ssz_stream;
            }
        } else {
            std.debug.print("error: unexpected argument '{s}'\n", .{arg});
            std.debug.print("hint:  use --ssz [file]\n", .{});
            printUsage();
            std.process.exit(1);
        }
    }

    // ── Load input ────────────────────────────────────────────────────────────
    const si: input.StatelessInput = switch (source) {
        .ssz_stream => io.fromSszStream(allocator) catch |err| {
            std.debug.print("error: failed to parse SSZ from zkvm_io.read_input(): {}\n", .{err});
            std.process.exit(1);
        },
        .ssz_file => |path| io.fromSszFile(init.io, allocator, path) catch |err| {
            std.debug.print("error: failed to parse SSZ from '{s}': {}\n", .{ path, err });
            std.process.exit(1);
        },
    };

    const ep = &si.new_payload_request.execution_payload;

    std.debug.print("=== zesu: block #{d} ===\n\n", .{ep.block_number});
    std.debug.print("  {d} node(s), {d} code(s), {d} header(s)\n\n", .{ si.witness.nodes.len, si.witness.codes.len, si.witness.headers.len });

    // ── Block execution ───────────────────────────────────────────────────────
    std.debug.print("Block execution\n", .{});
    std.debug.print("  block env\n", .{});
    std.debug.print("    number      = {d}\n", .{ep.block_number});
    std.debug.print("    coinbase    = 0x{x}\n", .{ep.fee_recipient});
    std.debug.print("    timestamp   = {d}\n", .{ep.timestamp});
    std.debug.print("    gas_limit   = {d}\n", .{ep.gas_limit});
    std.debug.print("    basefee     = {d}\n", .{ep.base_fee_per_gas});
    std.debug.print("    prevrandao  = 0x{x}\n", .{ep.prev_randao});
    if (ep.excess_blob_gas != 0) {
        std.debug.print("    excess_blob_gas = {d}\n", .{ep.excess_blob_gas});
    }

    std.debug.print("  transactions  = {d}\n", .{ep.raw_transactions.len});

    // The same entry point the zkVM guest uses (run.zig).
    const proof_out = executor.executeStatelessInput(allocator, si, si.chain_config.fork_name) catch |err| {
        std.debug.print("  FAIL → {}\n", .{err});
        std.process.exit(1);
    };

    std.debug.print("  fork            = {s}\n", .{proof_out.fork_name});
    std.debug.print("  receipts        = {d}\n", .{proof_out.receipts.len});
    std.debug.print("  pre_state_root  = 0x{x}\n", .{proof_out.pre_state_root});

    // executeStatelessInput validates the computed roots against the payload
    // (returning StateRootMismatch / ReceiptsRootMismatch, handled above), so
    // reaching here means both matched.
    std.debug.print("  post_state_root = 0x{x}  ✓\n", .{proof_out.post_state_root});
    std.debug.print("  receipts_root   = 0x{x}  ✓\n", .{proof_out.receipts_root});

    const ssz_bytes = try ssz_output.serialize(allocator, si.chain_config, si.new_payload_request, true);
    std.debug.print("  new_payload_request_root = 0x{x}\n", .{ssz_bytes[0..32].*});
    zkvm_io.write_output(&ssz_bytes);

    std.debug.print("\nOK\n", .{});
}

fn printUsage() void {
    std.debug.print(
        \\usage:
        \\  zesu                # SSZ from zkvm_io (default / zkVM)
        \\  zesu --ssz <file>   # SSZ binary file
        \\
    , .{});
}
