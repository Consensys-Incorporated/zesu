//! Sidecar tests for node.zig.

const std = @import("std");

const decodeNode = @import("./node.zig").decodeNode;

test "decodeNode invalid: a child that is neither empty, a hash nor embedded" {
    // Extension whose child is a 4-byte string.
    const bytes = &[_]u8{ 0xc7, 0x81, 0x11, 0x84, 0x01, 0x02, 0x03, 0x04 };
    try std.testing.expectError(error.InvalidNode, decodeNode(bytes));
}
