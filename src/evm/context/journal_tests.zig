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

// Sepolia 11856546/11856547: a tx CREATEs a proxy, then EXTCODESIZEs an older proxy
// with the same code, which the witness rightly omits.

const bytecode = @import("bytecode");
const state = @import("state");

const proxy_code = [_]u8{ 0x60, 0x00, 0x56, 0x5b, 0x00 }; // PUSH1 0 JUMP JUMPDEST STOP

// Knows Y and Z by code hash but cannot serve that code, like a witness without it.
const NoCodeDb = struct {
    code_hash: primitives.Hash,

    pub const Y: primitives.Address = @splat(0xA1);
    pub const Z: primitives.Address = @splat(0xA2);

    pub fn basic(self: *@This(), address: primitives.Address) !?state.AccountInfo {
        if (std.mem.eql(u8, &address, &Y) or std.mem.eql(u8, &address, &Z)) {
            var info = state.AccountInfo.default();
            info.nonce = 1;
            info.code_hash = self.code_hash;
            info.code = null;
            return info;
        }
        return null;
    }

    pub fn codeByHash(_: *@This(), _: primitives.Hash) !bytecode.Bytecode {
        return error.InvalidWitness;
    }

    pub fn storage(_: *@This(), _: primitives.Address, _: primitives.StorageKey) !primitives.StorageValue {
        return 0;
    }
};

test "code a CREATE deployed earlier in the tx is readable by hash until that CREATE reverts" {
    var hash: primitives.Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&proxy_code, &hash, .{});
    var j = Journal(NoCodeDb).new(.{ .code_hash = hash });
    defer j.deinit();

    const caller: primitives.Address = @splat(0xC0);
    const created: primitives.Address = @splat(0xC1);
    _ = try j.loadAccount(caller);
    _ = try j.loadAccount(created);
    const checkpoint = try j.createAccountCheckpoint(caller, created, 0, .amsterdam);
    j.setCodeWithHash(created, bytecode.Bytecode.newRaw(&proxy_code), hash);

    const y = try j.loadAccountWithCode(NoCodeDb.Y);
    const y_code = y.data.info.code.?;
    try std.testing.expectEqualSlices(u8, &proxy_code, y_code.originalBytes());
    const creator_code = j.inner.evm_state.get(created).?.info.code.?;
    try std.testing.expect(y_code.legacy_analyzed.jump_table.data.ptr != creator_code.legacy_analyzed.jump_table.data.ptr);

    // Once the CREATE reverts, its code is no longer readable by hash.
    j.checkpointRevert(checkpoint);
    try std.testing.expectError(error.InvalidWitness, j.loadAccountWithCode(NoCodeDb.Z));
}

// A witness that knows Y and Z by the hash of a delegation designator but lacks it. Like
// WitnessDatabase, it serves the designator once the journal has registered it.
const MarkerDb = struct {
    code_hash: primitives.Hash,
    registered: usize = 0,

    pub const Y: primitives.Address = @splat(0xB1);
    pub const Z: primitives.Address = @splat(0xB2);

    pub fn basic(self: *@This(), address: primitives.Address) !?state.AccountInfo {
        if (std.mem.eql(u8, &address, &Y) or std.mem.eql(u8, &address, &Z)) {
            var info = state.AccountInfo.default();
            info.code_hash = self.code_hash;
            info.code = null;
            return info;
        }
        return null;
    }

    pub fn codeByHash(self: *@This(), code_hash: primitives.Hash) !bytecode.Bytecode {
        if (self.registered > 0 and std.mem.eql(u8, &code_hash, &self.code_hash))
            return .{ .eip7702 = bytecode.Eip7702Bytecode.new(marker_target) };
        return error.InvalidWitness;
    }

    pub fn storage(_: *@This(), _: primitives.Address, _: primitives.StorageKey) !primitives.StorageValue {
        return 0;
    }

    pub fn notifyCodeDeployed(self: *@This(), code_hash: primitives.Hash, _: bytecode.Bytecode) void {
        if (std.mem.eql(u8, &code_hash, &self.code_hash)) self.registered += 1;
    }
};

const marker_target: primitives.Address = @splat(0xD0);

fn markerJournal() Journal(MarkerDb) {
    const marker = bytecode.Eip7702Bytecode.new(marker_target);
    var hash: primitives.Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(marker.raw(), &hash, .{});
    return Journal(MarkerDb).new(.{ .code_hash = hash });
}

test "a delegation designator set in the tx is readable by hash until it is rolled back" {
    var j = markerJournal();
    defer j.deinit();

    const alice: primitives.Address = @splat(0xA0);
    _ = try j.loadAccount(alice);
    const checkpoint = j.getCheckpoint();
    j.setDelegation(alice, .{ .eip7702 = bytecode.Eip7702Bytecode.new(marker_target) });

    const y = try j.loadAccountWithCode(MarkerDb.Y);
    try std.testing.expect(y.data.info.code.?.isEip7702());

    // Rolled back (for example, the top-frame preparation runs out of gas): the designator
    // is no longer readable by hash, and the transaction does not register it.
    j.checkpointRevert(checkpoint);
    try std.testing.expectError(error.InvalidWitness, j.loadAccountWithCode(MarkerDb.Z));
    j.commitTx();
    try std.testing.expectEqual(@as(usize, 0), j.database.registered);
}

test "a designator the tx sets and then clears stays readable and is registered at commitTx" {
    var j = markerJournal();
    defer j.deinit();

    const alice: primitives.Address = @splat(0xA0);
    _ = try j.loadAccount(alice);
    j.setDelegation(alice, .{ .eip7702 = bytecode.Eip7702Bytecode.new(marker_target) });
    j.setDelegation(alice, bytecode.Bytecode.new()); // cleared again in the same tx

    const y = try j.loadAccountWithCode(MarkerDb.Y);
    try std.testing.expect(y.data.info.code.?.isEip7702());
    j.commitTx();
    try std.testing.expect(j.database.registered > 0);
}
