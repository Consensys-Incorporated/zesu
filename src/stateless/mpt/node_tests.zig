//! Sidecar tests for node.zig.

const std = @import("std");

const decodeNode = @import("./node.zig").decodeNode;

test "decodeNode invalid: a child that is neither empty, a hash nor embedded" {
    // Extension whose child is a 4-byte string.
    const bytes = &[_]u8{ 0xc7, 0x81, 0x11, 0x84, 0x01, 0x02, 0x03, 0x04 };
    try std.testing.expectError(error.InvalidNode, decodeNode(bytes));
}

const node = @import("./node.zig");
const rlp = @import("./rlp.zig");

// decodeNode's contract written plainly: every item through rlp.decodeItem, then the item count.
fn referenceDecode(bytes: []const u8) error{ InvalidRlp, InvalidNode }!node.DecodedNode {
    const outer = try rlp.decodeItem(bytes);
    if (outer.consumed != bytes.len) return error.InvalidNode;
    if (outer.item != .list) return error.InvalidNode;
    var items: [17]rlp.RlpItem = undefined;
    var raws: [17][]const u8 = undefined;
    var count: usize = 0;
    var rest = outer.item.list;
    while (rest.len > 0) : (count += 1) {
        if (count >= 17) return error.InvalidNode;
        const r = try rlp.decodeItem(rest);
        items[count] = r.item;
        raws[count] = rest[0..r.consumed];
        if (count == 16 and r.item == .list) return error.InvalidNode;
        rest = rest[r.consumed..];
    }
    if (count == 2) {
        if (items[0] != .bytes or items[0].bytes.len == 0) return error.InvalidNode;
        const key = items[0].bytes;
        if (key[0] & 0x20 != 0) {
            if (items[1] != .bytes) return error.InvalidNode;
            return .{ .leaf = .{ .key_end = key, .value = items[1].bytes } };
        }
        if (key.len == 1 and key[0] & 0x10 == 0) return error.InvalidNode;
        const child = try referenceRef(items[1], raws[1]);
        if (child == .empty) return error.InvalidNode;
        return .{ .extension = .{ .prefix = key, .child = child } };
    }
    if (count != 17) return error.InvalidNode;
    var children: [16]node.NodeRef = undefined;
    var occupied: usize = 0;
    var bad = false;
    for (0..16) |i| {
        children[i] = referenceRef(items[i], raws[i]) catch blk: {
            bad = true;
            break :blk .{ .empty = {} };
        };
        occupied += @intFromBool(children[i] != .empty);
    }
    if (bad) return error.InvalidNode;
    if (occupied + @intFromBool(items[16].bytes.len != 0) < 2) return error.InvalidNode;
    return .{ .branch = .{ .children = children, .value = items[16].bytes } };
}

fn referenceRef(item: rlp.RlpItem, raw: []const u8) error{InvalidNode}!node.NodeRef {
    switch (item) {
        .bytes => |b| {
            if (b.len == 0) return .{ .empty = {} };
            if (b.len == 32) return .{ .hash = b[0..32] };
            return error.InvalidNode;
        },
        .list => {
            if (raw.len >= 32 or !rlp.isWellFormed(raw)) return error.InvalidNode;
            return .{ .inline_node = raw };
        },
    }
}

fn expectSameRef(a: node.NodeRef, b: node.NodeRef) !void {
    try std.testing.expectEqual(std.meta.activeTag(a), std.meta.activeTag(b));
    switch (a) {
        .empty => {},
        .hash => |h| try std.testing.expectEqual(h, b.hash),
        .inline_node => |n| {
            try std.testing.expectEqual(n.ptr, b.inline_node.ptr);
            try std.testing.expectEqual(n.len, b.inline_node.len);
        },
    }
}

fn expectSameSlice(a: []const u8, b: []const u8) !void {
    try std.testing.expectEqual(a.len, b.len);
    if (a.len != 0) try std.testing.expectEqual(a.ptr, b.ptr);
}

fn expectSameDecode(bytes: []const u8) !void {
    const want = referenceDecode(bytes);
    const got = decodeNode(bytes);
    const w = want catch |err| return std.testing.expectError(err, got);
    const g = try got;
    try std.testing.expectEqual(std.meta.activeTag(w), std.meta.activeTag(g));
    switch (w) {
        .leaf => |l| {
            try expectSameSlice(l.key_end, g.leaf.key_end);
            try expectSameSlice(l.value, g.leaf.value);
        },
        .extension => |e| {
            try expectSameSlice(e.prefix, g.extension.prefix);
            try expectSameRef(e.child, g.extension.child);
        },
        .branch => |b| {
            for (b.children, g.branch.children) |x, y| try expectSameRef(x, y);
            try expectSameSlice(b.value, g.branch.value);
        },
    }
}

fn appendItem(buf: []u8, len: *usize, random: std.Random) void {
    const out = buf[len.*..];
    const n: usize = switch (random.uintLessThan(u8, 12)) {
        0 => blk: { // single byte
            out[0] = random.int(u8) & 0x7f;
            break :blk 1;
        },
        1, 2 => blk: { // empty string
            out[0] = 0x80;
            break :blk 1;
        },
        3, 4, 5 => blk: { // 32-byte string
            out[0] = 0xa0;
            random.bytes(out[1..33]);
            break :blk 33;
        },
        6, 7, 8 => blk: { // short string, any length
            const l = random.uintLessThan(usize, 56);
            out[0] = 0x80 + @as(u8, @intCast(l));
            random.bytes(out[1 .. 1 + l]);
            break :blk 1 + l;
        },
        9 => blk: { // long string
            const l = 56 + random.uintLessThan(usize, 60);
            out[0] = 0xb8;
            out[1] = @intCast(l);
            random.bytes(out[2 .. 2 + l]);
            break :blk 2 + l;
        },
        10 => blk: { // embedded leaf
            out[0..4].* = .{ 0xc3, 0x81, 0x20, 0x01 };
            break :blk 4;
        },
        else => blk: { // list of single bytes, sometimes too long to embed
            const l = random.uintLessThan(usize, 40);
            out[0] = 0xc0 + @as(u8, @intCast(l));
            for (out[1 .. 1 + l]) |*x| x.* = random.int(u8) & 0x7f;
            break :blk 1 + l;
        },
    };
    len.* += n;
}

test "decodeNode agrees with an item-by-item reference decode" {
    var prng = std.Random.DefaultPrng.init(0x6e6f6465);
    const random = prng.random();
    var payload: [18 * 120]u8 = undefined;
    var buf: [payload.len + 3]u8 = undefined;
    for (0..4000) |round| {
        const count: usize = switch (round % 8) {
            0, 1, 2, 3 => 2,
            4, 5 => 17,
            else => random.uintLessThan(usize, 19),
        };
        var plen: usize = 0;
        for (0..count) |i| {
            if (count == 2 and i == 0 and random.boolean()) {
                // A hex-prefix path: flag nibble 0 to 3, then whole bytes.
                const l = 1 + random.uintLessThan(usize, 32);
                payload[plen] = 0x80 + @as(u8, @intCast(l));
                random.bytes(payload[plen + 1 .. plen + 1 + l]);
                payload[plen + 1] = (@as(u8, random.uintLessThan(u8, 4)) << 4) | (payload[plen + 1] & 0x0f);
                plen += 1 + l;
            } else appendItem(&payload, &plen, random);
        }
        var hdr: usize = undefined;
        if (plen < 56) {
            buf[0] = 0xc0 + @as(u8, @intCast(plen));
            hdr = 1;
        } else if (plen < 256) {
            buf[0..2].* = .{ 0xf8, @intCast(plen) };
            hdr = 2;
        } else {
            buf[0..3].* = .{ 0xf9, @intCast(plen >> 8), @truncate(plen) };
            hdr = 3;
        }
        @memcpy(buf[hdr .. hdr + plen], payload[0..plen]);
        const whole = buf[0 .. hdr + plen];
        try expectSameDecode(whole);
        // Cut short, then with one byte changed.
        try expectSameDecode(whole[0..random.uintLessThan(usize, whole.len)]);
        whole[random.uintLessThan(usize, whole.len)] = random.int(u8);
        try expectSameDecode(whole);
    }
}
