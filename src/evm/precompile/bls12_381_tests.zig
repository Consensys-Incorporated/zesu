// BLS12-381 precompile tests ported from Besu's gnark EIP-2537 test suite.
// CSV sources: testdata/eip2537_*.csv.
// Format: input,result,gas,notes  — empty notes = success, non-empty = expect error.
//
// Note: Gas values in the Besu CSVs use an older EIP-2537 schedule. We verify gas
// only for fixed-cost operations using our implementation's constants.

const std = @import("std");
const testing = std.testing;
const impls = @import("default_impls.zig");

const g1_add_csv = @embedFile("testdata/eip2537_g1_add.csv");
const g2_add_csv = @embedFile("testdata/eip2537_g2_add.csv");
const g1_msm_csv = @embedFile("testdata/eip2537_g1_msm.csv");
const g2_msm_csv = @embedFile("testdata/eip2537_g2_msm.csv");
const pairing_csv = @embedFile("testdata/eip2537_pairing.csv");
const pairing_invalid_csv = @embedFile("testdata/eip2537_pairing_invalid_subgroup.csv");
const fp_to_g1_csv = @embedFile("testdata/eip2537_fp_to_g1.csv");
const fp2_to_g2_csv = @embedFile("testdata/eip2537_fp2_to_g2.csv");

// Gas constants from our EIP-2537 implementation
const G1_ADD_GAS: u64 = 375;
const G2_ADD_GAS: u64 = 600;
const MAP_FP_TO_G1_GAS: u64 = 5500;
const MAP_FP2_TO_G2_GAS: u64 = 23800;

const GAS_LIMIT: u64 = 100_000_000;

/// Decode a hex string (optional 0x/0X prefix; odd-length is left-padded) to bytes.
fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    var h = hex;
    if (h.len >= 2 and h[0] == '0' and (h[1] == 'x' or h[1] == 'X')) {
        h = h[2..];
    }
    if (h.len == 0) return allocator.alloc(u8, 0);

    const byte_len = (h.len + 1) / 2;
    const out = try allocator.alloc(u8, byte_len);
    errdefer allocator.free(out);

    if (h.len % 2 != 0) {
        const padded = try allocator.alloc(u8, h.len + 1);
        defer allocator.free(padded);
        padded[0] = '0';
        @memcpy(padded[1..], h);
        _ = std.fmt.hexToBytes(out, padded) catch return error.InvalidHex;
    } else {
        _ = std.fmt.hexToBytes(out, h) catch return error.InvalidHex;
    }
    return out;
}

/// Split a line into exactly 4 CSV fields (at most 3 comma splits, remainder in field[3]).
fn splitCsv4(line: []const u8) [4][]const u8 {
    var fields: [4][]const u8 = .{ "", "", "", "" };
    var idx: usize = 0;
    var start: usize = 0;
    for (line, 0..) |ch, i| {
        if (ch == ',' and idx < 3) {
            fields[idx] = line[start..i];
            idx += 1;
            start = i + 1;
        }
    }
    fields[idx] = line[start..];
    return fields;
}

test "BLS12-381 G1 Add - Besu EIP-2537 vectors" {
    const alloc = testing.allocator;
    var line_iter = std.mem.splitScalar(u8, g1_add_csv, '\n');
    var row: usize = 0;
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        row += 1;
        if (row == 1 or line.len == 0) continue;

        const fields = splitCsv4(line);
        const input_hex = fields[0];
        const expected_hex = fields[1];
        const notes = fields[3];

        const input_bytes = try hexDecode(alloc, input_hex);
        defer alloc.free(input_bytes);

        const result = impls.bls12_g1_add(input_bytes, GAS_LIMIT);

        if (notes.len > 0) {
            testing.expect(result == .err) catch |e| {
                std.debug.print("G1Add row {d}: expected error ('{s}') but got success\n", .{ row, notes });
                return e;
            };
        } else {
            testing.expect(result == .success) catch |e| {
                std.debug.print("G1Add row {d}: expected success but got error\n", .{row});
                return e;
            };
            const output = result.success;
            testing.expectEqual(G1_ADD_GAS, output.gas_used) catch |e| {
                std.debug.print("G1Add row {d}: wrong gas (got {d})\n", .{ row, output.gas_used });
                return e;
            };
            const expected = try hexDecode(alloc, expected_hex);
            defer alloc.free(expected);
            testing.expect(std.mem.eql(u8, output.bytes, expected)) catch |e| {
                std.debug.print("G1Add row {d}: output mismatch\n", .{row});
                return e;
            };
        }
    }
}

test "BLS12-381 G2 Add - Besu EIP-2537 vectors" {
    const alloc = testing.allocator;
    var line_iter = std.mem.splitScalar(u8, g2_add_csv, '\n');
    var row: usize = 0;
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        row += 1;
        if (row == 1 or line.len == 0) continue;

        const fields = splitCsv4(line);
        const input_hex = fields[0];
        const expected_hex = fields[1];
        const notes = fields[3];

        const input_bytes = try hexDecode(alloc, input_hex);
        defer alloc.free(input_bytes);

        const result = impls.bls12_g2_add(input_bytes, GAS_LIMIT);

        if (notes.len > 0) {
            testing.expect(result == .err) catch |e| {
                std.debug.print("G2Add row {d}: expected error ('{s}') but got success\n", .{ row, notes });
                return e;
            };
        } else {
            testing.expect(result == .success) catch |e| {
                std.debug.print("G2Add row {d}: expected success but got error\n", .{row});
                return e;
            };
            const output = result.success;
            testing.expectEqual(G2_ADD_GAS, output.gas_used) catch |e| {
                std.debug.print("G2Add row {d}: wrong gas (got {d})\n", .{ row, output.gas_used });
                return e;
            };
            const expected = try hexDecode(alloc, expected_hex);
            defer alloc.free(expected);
            testing.expect(std.mem.eql(u8, output.bytes, expected)) catch |e| {
                std.debug.print("G2Add row {d}: output mismatch\n", .{row});
                return e;
            };
        }
    }
}

test "BLS12-381 G1 MSM - Besu EIP-2537 vectors" {
    const alloc = testing.allocator;
    var line_iter = std.mem.splitScalar(u8, g1_msm_csv, '\n');
    var row: usize = 0;
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        row += 1;
        if (row == 1 or line.len == 0) continue;

        const fields = splitCsv4(line);
        const input_hex = fields[0];
        const expected_hex = fields[1];
        const notes = fields[3];

        const input_bytes = try hexDecode(alloc, input_hex);
        defer alloc.free(input_bytes);

        const result = impls.bls12_g1_msm(input_bytes, GAS_LIMIT);

        if (notes.len > 0) {
            testing.expect(result == .err) catch |e| {
                std.debug.print("G1MSM row {d}: expected error ('{s}') but got success\n", .{ row, notes });
                return e;
            };
        } else {
            testing.expect(result == .success) catch |e| {
                std.debug.print("G1MSM row {d}: expected success but got error\n", .{row});
                return e;
            };
            const output = result.success;
            const expected = try hexDecode(alloc, expected_hex);
            defer alloc.free(expected);
            testing.expect(std.mem.eql(u8, output.bytes, expected)) catch |e| {
                std.debug.print("G1MSM row {d}: output mismatch\n", .{row});
                return e;
            };
        }
    }
}

test "BLS12-381 G2 MSM - Besu EIP-2537 vectors" {
    const alloc = testing.allocator;
    var line_iter = std.mem.splitScalar(u8, g2_msm_csv, '\n');
    var row: usize = 0;
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        row += 1;
        if (row == 1 or line.len == 0) continue;

        const fields = splitCsv4(line);
        const input_hex = fields[0];
        const expected_hex = fields[1];
        const notes = fields[3];

        const input_bytes = try hexDecode(alloc, input_hex);
        defer alloc.free(input_bytes);

        const result = impls.bls12_g2_msm(input_bytes, GAS_LIMIT);

        if (notes.len > 0) {
            testing.expect(result == .err) catch |e| {
                std.debug.print("G2MSM row {d}: expected error ('{s}') but got success\n", .{ row, notes });
                return e;
            };
        } else {
            testing.expect(result == .success) catch |e| {
                std.debug.print("G2MSM row {d}: expected success but got error\n", .{row});
                return e;
            };
            const output = result.success;
            const expected = try hexDecode(alloc, expected_hex);
            defer alloc.free(expected);
            testing.expect(std.mem.eql(u8, output.bytes, expected)) catch |e| {
                std.debug.print("G2MSM row {d}: output mismatch\n", .{row});
                return e;
            };
        }
    }
}

test "BLS12-381 Pairing - Besu EIP-2537 vectors" {
    const alloc = testing.allocator;
    inline for (.{ pairing_csv, pairing_invalid_csv }, .{ "Pairing", "PairingInvalid" }) |csv, label| {
        var line_iter = std.mem.splitScalar(u8, csv, '\n');
        var row: usize = 0;
        while (line_iter.next()) |raw_line| {
            const line = std.mem.trimEnd(u8, raw_line, "\r");
            row += 1;
            if (row == 1 or line.len == 0) continue;

            const fields = splitCsv4(line);
            const input_hex = fields[0];
            const expected_hex = fields[1];
            const notes = fields[3];

            // Empty input (an error per EIP-2537) is covered by the unit tests in tests.zig.
            if (input_hex.len == 0) continue;

            const input_bytes = try hexDecode(alloc, input_hex);
            defer alloc.free(input_bytes);

            const result = impls.bls12_pairing(input_bytes, GAS_LIMIT);

            if (notes.len > 0) {
                testing.expect(result == .err) catch |e| {
                    std.debug.print("{s} row {d}: expected error ('{s}') but got success\n", .{ label, row, notes });
                    return e;
                };
            } else {
                testing.expect(result == .success) catch |e| {
                    std.debug.print("{s} row {d}: expected success but got error\n", .{ label, row });
                    return e;
                };
                const output = result.success;
                const expected = try hexDecode(alloc, expected_hex);
                defer alloc.free(expected);
                testing.expect(std.mem.eql(u8, output.bytes, expected)) catch |e| {
                    std.debug.print("{s} row {d}: output mismatch\n", .{ label, row });
                    return e;
                };
            }
        }
    }
}

test "BLS12-381 MapFpToG1 - Besu EIP-2537 vectors" {
    const alloc = testing.allocator;
    var line_iter = std.mem.splitScalar(u8, fp_to_g1_csv, '\n');
    var row: usize = 0;
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        row += 1;
        if (row == 1 or line.len == 0) continue;

        const fields = splitCsv4(line);
        const input_hex = fields[0];
        const expected_hex = fields[1];
        const notes = fields[3];

        const input_bytes = try hexDecode(alloc, input_hex);
        defer alloc.free(input_bytes);

        const result = impls.bls12_map_fp_to_g1(input_bytes, GAS_LIMIT);

        if (notes.len > 0) {
            testing.expect(result == .err) catch |e| {
                std.debug.print("MapFpToG1 row {d}: expected error ('{s}') but got success\n", .{ row, notes });
                return e;
            };
        } else {
            testing.expect(result == .success) catch |e| {
                std.debug.print("MapFpToG1 row {d}: expected success but got error\n", .{row});
                return e;
            };
            const output = result.success;
            testing.expectEqual(MAP_FP_TO_G1_GAS, output.gas_used) catch |e| {
                std.debug.print("MapFpToG1 row {d}: wrong gas (got {d})\n", .{ row, output.gas_used });
                return e;
            };
            const expected = try hexDecode(alloc, expected_hex);
            defer alloc.free(expected);
            testing.expect(std.mem.eql(u8, output.bytes, expected)) catch |e| {
                std.debug.print("MapFpToG1 row {d}: output mismatch\n", .{row});
                return e;
            };
        }
    }
}

test "BLS12-381 MapFp2ToG2 - Besu EIP-2537 vectors" {
    const alloc = testing.allocator;
    var line_iter = std.mem.splitScalar(u8, fp2_to_g2_csv, '\n');
    var row: usize = 0;
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        row += 1;
        if (row == 1 or line.len == 0) continue;

        const fields = splitCsv4(line);
        const input_hex = fields[0];
        const expected_hex = fields[1];
        const notes = fields[3];

        const input_bytes = try hexDecode(alloc, input_hex);
        defer alloc.free(input_bytes);

        const result = impls.bls12_map_fp2_to_g2(input_bytes, GAS_LIMIT);

        if (notes.len > 0) {
            testing.expect(result == .err) catch |e| {
                std.debug.print("MapFp2ToG2 row {d}: expected error ('{s}') but got success\n", .{ row, notes });
                return e;
            };
        } else {
            testing.expect(result == .success) catch |e| {
                std.debug.print("MapFp2ToG2 row {d}: expected success but got error\n", .{row});
                return e;
            };
            const output = result.success;
            testing.expectEqual(MAP_FP2_TO_G2_GAS, output.gas_used) catch |e| {
                std.debug.print("MapFp2ToG2 row {d}: wrong gas (got {d})\n", .{ row, output.gas_used });
                return e;
            };
            const expected = try hexDecode(alloc, expected_hex);
            defer alloc.free(expected);
            testing.expect(std.mem.eql(u8, output.bytes, expected)) catch |e| {
                std.debug.print("MapFp2ToG2 row {d}: output mismatch\n", .{row});
                return e;
            };
        }
    }
}
