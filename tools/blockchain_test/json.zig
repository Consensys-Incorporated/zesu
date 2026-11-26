/// Hex and JSON value parsing helpers for blockchain test fixtures.
const std = @import("std");

pub fn stripHex(s: []const u8) []const u8 {
    if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) return s[2..];
    return s;
}

pub fn hexToSlice(alloc: std.mem.Allocator, hex: []const u8) ![]u8 {
    const s = stripHex(hex);
    if (s.len % 2 != 0) return error.OddHexLength;
    const out = try alloc.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

pub fn hexToAddr(hex: []const u8) ![20]u8 {
    const s = stripHex(hex);
    var padded: [40]u8 = @splat('0');
    if (s.len > 40) return error.InvalidAddress;
    @memcpy(padded[40 - s.len ..], s);
    var out: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, &padded);
    return out;
}

pub fn hexToHash(hex: []const u8) ![32]u8 {
    const s = stripHex(hex);
    var padded: [64]u8 = @splat('0');
    if (s.len > 64) return error.InvalidHash;
    @memcpy(padded[64 - s.len ..], s);
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, &padded);
    return out;
}

pub fn hexToU256(hex: []const u8) !u256 {
    const s = stripHex(hex);
    if (s.len == 0) return 0;
    return std.fmt.parseInt(u256, s, 16);
}

pub fn jsonU64(v: std.json.Value) !u64 {
    return switch (v) {
        .integer => |n| @intCast(n),
        .string => |s| std.fmt.parseInt(u64, stripHex(s), 16) catch
            std.fmt.parseInt(u64, s, 10),
        else => error.InvalidNumeric,
    };
}

pub fn jsonU256(v: std.json.Value) !u256 {
    return switch (v) {
        .integer => |n| @intCast(n),
        .string => |s| std.fmt.parseInt(u256, stripHex(s), 16) catch
            std.fmt.parseInt(u256, s, 10),
        else => error.InvalidNumeric,
    };
}

pub fn getString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

pub fn getString2(v: std.json.Value) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}
