//! Regression tests for Journal.hasNonZeroStorageForAddress: a database failure
//! feeding the CREATE collision check must propagate rather than read as
//! "no storage here".

const std = @import("std");
const primitives = @import("primitives");
const Journal = @import("journal.zig").Journal;

// A stub DB whose hasNonZeroStorageForAddress always fails, standing in for a
// stateless witness that cannot prove the account. Only the members Journal
// touches on this path are provided.
const FailingStorageDb = struct {
    pub fn hasNonZeroStorageForAddress(_: *const @This(), _: primitives.Address) !bool {
        return error.InvalidWitness;
    }
};

// The CREATE collision check must not read a DB failure as "no storage here":
// that would let a CREATE succeed at an address the reference rejects. The journal
// propagates instead, leaving the caller (which owns ctx_error) to mark the block
// invalid.
test "a failing hasNonZeroStorageForAddress propagates instead of answering false" {
    var j = Journal(FailingStorageDb).new(.{});
    defer j.deinit();

    try std.testing.expectError(error.InvalidWitness, j.hasNonZeroStorageForAddress(@splat(0x11)));
}

// An infallible DB (InMemoryDB returns a plain bool) must keep working unchanged —
// the @hasDecl/duck-typed path must not require an error union.
test "an infallible DB still answers hasNonZeroStorageForAddress directly" {
    const PlainDb = struct {
        pub fn hasNonZeroStorageForAddress(_: *const @This(), _: primitives.Address) bool {
            return true;
        }
    };
    var j = Journal(PlainDb).new(.{});
    defer j.deinit();

    try std.testing.expect(try j.hasNonZeroStorageForAddress(@splat(0x22)));
}

// A DB without the method at all falls back to false, as before.
test "a DB without hasNonZeroStorageForAddress reports false" {
    const NoDeclDb = struct {};
    var j = Journal(NoDeclDb).new(.{});
    defer j.deinit();

    try std.testing.expect(!(try j.hasNonZeroStorageForAddress(@splat(0x33))));
}
