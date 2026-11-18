//! keccak256 through the accelerator interface. CI also runs these with
//! -Dkeccak-memo=false, so they must hold with and without the memo.

const std = @import("std");
const accel = @import("accelerators.zig");
const primitives = @import("primitives");
const Keccak256 = std.crypto.hash.sha3.Keccak256;

fn hash32(comptime hex: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn expectMatchesStd(data: []const u8) !void {
    var got: [32]u8 = undefined;
    var want: [32]u8 = undefined;
    accel.keccak256(data, &got);
    Keccak256.hash(data, &want, .{});
    try std.testing.expectEqual(want, got);
}

test "keccak256: empty input" {
    var out: [32]u8 = undefined;
    accel.keccak256(&.{}, &out);
    try std.testing.expectEqual(primitives.KECCAK_EMPTY, out);
    try std.testing.expectEqual(hash32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), out);
}

test "keccak256: 20- and 32-byte known answers" {
    var out: [32]u8 = undefined;
    accel.keccak256(&([_]u8{0} ** 20), &out);
    try std.testing.expectEqual(hash32("5380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312a"), out);
    accel.keccak256(&([_]u8{0} ** 32), &out);
    try std.testing.expectEqual(hash32("290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), out);
}

test "keccak256: matches std.crypto across lengths and random 20/32-byte inputs" {
    var buf: [300]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    for (0..buf.len + 1) |len| try expectMatchesStd(buf[0..len]);

    var prng = std.Random.DefaultPrng.init(0x6b656363616b);
    const r = prng.random();
    for (0..256) |_| {
        var k: [32]u8 = undefined;
        r.bytes(&k);
        try expectMatchesStd(k[0..20]);
        try expectMatchesStd(&k);
    }
}
