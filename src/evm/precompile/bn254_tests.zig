// BN254 precompile tests ported from Besu's Gnark AltBN128 test suite.
// CSV sources: testdata/eip196_*.csv.
// Format: input,result,gas,notes  — empty notes = success, non-empty = expect error.

const std = @import("std");
const testing = std.testing;
const impls = @import("default_impls.zig");

const g1_add_csv = @embedFile("testdata/eip196_g1_add.csv");
const g1_mul_csv = @embedFile("testdata/eip196_g1_mul.csv");
const pairing_csv = @embedFile("testdata/eip196_pairing.csv");

// Istanbul gas constants (EIP-1108)
const ISTANBUL_ADD_GAS: u64 = 150;
const ISTANBUL_MUL_GAS: u64 = 6_000;
const ISTANBUL_PAIRING_BASE: u64 = 45_000;
const ISTANBUL_PAIRING_PER_POINT: u64 = 34_000;

const GAS_LIMIT: u64 = 10_000_000;

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
        // Odd-length: left-pad with '0' into a temporary buffer.
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

test "BN254 G1Add Istanbul - Besu EIP-196 vectors" {
    const alloc = testing.allocator;
    var line_iter = std.mem.splitScalar(u8, g1_add_csv, '\n');
    var row: usize = 0;
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        row += 1;
        if (row == 1 or line.len == 0) continue; // header / blank

        const fields = splitCsv4(line);
        const input_hex = fields[0];
        const expected_hex = fields[1];
        const notes = fields[3];

        const input_bytes = try hexDecode(alloc, input_hex);
        defer alloc.free(input_bytes);

        const result = impls.bn254_add_istanbul(input_bytes, GAS_LIMIT);

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
            testing.expectEqual(ISTANBUL_ADD_GAS, output.gas_used) catch |e| {
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

test "BN254 G1Mul Istanbul - Besu EIP-196 vectors" {
    const alloc = testing.allocator;
    var line_iter = std.mem.splitScalar(u8, g1_mul_csv, '\n');
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

        const result = impls.bn254_mul_istanbul(input_bytes, GAS_LIMIT);

        if (notes.len > 0) {
            testing.expect(result == .err) catch |e| {
                std.debug.print("G1Mul row {d}: expected error ('{s}') but got success\n", .{ row, notes });
                return e;
            };
        } else {
            testing.expect(result == .success) catch |e| {
                std.debug.print("G1Mul row {d}: expected success but got error\n", .{row});
                return e;
            };
            const output = result.success;
            testing.expectEqual(ISTANBUL_MUL_GAS, output.gas_used) catch |e| {
                std.debug.print("G1Mul row {d}: wrong gas (got {d})\n", .{ row, output.gas_used });
                return e;
            };
            const expected = try hexDecode(alloc, expected_hex);
            defer alloc.free(expected);
            testing.expect(std.mem.eql(u8, output.bytes, expected)) catch |e| {
                std.debug.print("G1Mul row {d}: output mismatch\n", .{row});
                return e;
            };
        }
    }
}

test "BN254 Pairing Istanbul - Besu EIP-196 vectors" {
    const alloc = testing.allocator;
    var line_iter = std.mem.splitScalar(u8, pairing_csv, '\n');
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

        const result = impls.bn254_pairing_istanbul(input_bytes, GAS_LIMIT);

        if (notes.len > 0) {
            testing.expect(result == .err) catch |e| {
                std.debug.print("Pairing row {d}: expected error ('{s}') but got success\n", .{ row, notes });
                return e;
            };
        } else {
            testing.expect(result == .success) catch |e| {
                std.debug.print("Pairing row {d}: expected success but got error\n", .{row});
                return e;
            };
            const output = result.success;
            const num_pairs = input_bytes.len / 192;
            const expected_gas = ISTANBUL_PAIRING_BASE + @as(u64, num_pairs) * ISTANBUL_PAIRING_PER_POINT;
            testing.expectEqual(expected_gas, output.gas_used) catch |e| {
                std.debug.print("Pairing row {d}: wrong gas (expected {d}, got {d})\n", .{ row, expected_gas, output.gas_used });
                return e;
            };
            const expected = try hexDecode(alloc, expected_hex);
            defer alloc.free(expected);
            testing.expect(std.mem.eql(u8, output.bytes, expected)) catch |e| {
                std.debug.print("Pairing row {d}: output mismatch\n", .{row});
                return e;
            };
        }
    }
}
