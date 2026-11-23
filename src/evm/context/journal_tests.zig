//! Journal regression tests: hasNonZeroStorageForAddress error propagation, and reading
//! code a CREATE deployed earlier in the same transaction by hash.

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

// A DB failure in the CREATE collision check must propagate, not read as "no storage".
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

// A DB without the method falls back to false.
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

// Storage reads come back as (first address byte << 8 | key), so a slot served from the wrong
// account is visible.
const SlotDb = struct {
    pub fn basic(_: *@This(), _: primitives.Address) !?state.AccountInfo {
        var info = state.AccountInfo.default();
        info.nonce = 1;
        return info;
    }

    pub fn codeByHash(_: *@This(), _: primitives.Hash) !bytecode.Bytecode {
        return error.InvalidWitness;
    }

    pub fn storage(_: *@This(), address: primitives.Address, key: primitives.StorageKey) !primitives.StorageValue {
        return (@as(primitives.StorageValue, address[0]) << 8) | key;
    }
};

fn numberedAddress(n: u16) primitives.Address {
    var address: primitives.Address = @splat(0);
    std.mem.writeInt(u16, address[18..20], n, .big);
    return address;
}

test "storage accesses alternate between accounts and survive the state map growing" {
    var j = Journal(SlotDb).new(.{});
    defer j.deinit();

    const a: primitives.Address = @splat(0xA1);
    const b: primitives.Address = @splat(0xB2);
    _ = try j.loadAccount(a);
    _ = try j.loadAccount(b);

    try std.testing.expectEqual(@as(?primitives.StorageValue, null), j.sloadProbe(a, 1).value);
    try std.testing.expectEqual(@as(primitives.StorageValue, 0xA101), (try j.sload(a, 1)).data);
    const first = try j.sstore(a, 1, 11);
    try std.testing.expectEqual(@as(primitives.StorageValue, 0xA101), first.data.original_value);
    try std.testing.expectEqual(@as(primitives.StorageValue, 0xB201), (try j.sload(b, 1)).data);
    try std.testing.expectEqual(@as(?primitives.StorageValue, 11), j.sloadProbe(a, 1).value);
    try std.testing.expectEqual(@as(?primitives.StorageValue, 0xB201), j.sloadProbe(b, 1).value);
    try std.testing.expect(!j.isStorageCold(b, 1));
    try std.testing.expect(j.isStorageCold(b, 2));

    // Each load inserts an account; several of them reallocate the map under `a`.
    const capacity_before = j.inner.evm_state.capacity();
    var n: u16 = 0;
    while (n < 300) : (n += 1) {
        _ = try j.loadAccount(numberedAddress(n));
        try std.testing.expectEqual(@as(?primitives.StorageValue, 11), j.sloadProbe(a, 1).value);
    }
    try std.testing.expect(j.inner.evm_state.capacity() > capacity_before);

    const second = try j.sstore(a, 2, 22);
    try std.testing.expectEqual(@as(primitives.StorageValue, 0xA102), second.data.present_value);
    try std.testing.expectEqual(@as(primitives.StorageValue, 22), j.inner.evm_state.get(a).?.storage.get(2).?.present_value);
    try std.testing.expectEqual(@as(primitives.StorageValue, 0xB201), j.inner.evm_state.get(b).?.storage.get(1).?.present_value);
    try std.testing.expect(j.inner.evm_state.get(b).?.storage.get(2) == null);
}

test "a removed account's storage is not served after it is loaded again" {
    var j = Journal(SlotDb).new(.{});
    defer j.deinit();

    const a: primitives.Address = @splat(0xA1);
    _ = try j.loadAccount(a);
    _ = try j.sstore(a, 1, 11);
    try std.testing.expectEqual(@as(?primitives.StorageValue, 11), j.sloadProbe(a, 1).value);

    j.inner.removeAccount(a);
    try std.testing.expect(!j.inner.evm_state.contains(a));
    try std.testing.expectEqual(@as(?primitives.StorageValue, null), j.sloadProbe(a, 1).value);
    try std.testing.expect(j.isStorageCold(a, 1));

    _ = try j.loadAccount(a);
    try std.testing.expectEqual(@as(?primitives.StorageValue, null), j.sloadProbe(a, 1).value);
    try std.testing.expectEqual(@as(primitives.StorageValue, 0xA101), (try j.sload(a, 1)).data);
}

test "finalize hands the state over and later storage accesses use the new map" {
    var j = Journal(SlotDb).new(.{});
    defer j.deinit();

    const a: primitives.Address = @splat(0xA1);
    _ = try j.loadAccount(a);
    _ = try j.sstore(a, 1, 11);

    var taken = j.finalize();
    defer {
        var it = taken.valueIterator();
        while (it.next()) |account| account.storage.deinit();
        taken.deinit();
    }
    try std.testing.expectEqual(@as(?primitives.StorageValue, null), j.sloadProbe(a, 1).value);

    try j.inner.reserveAccounts(64);
    _ = try j.loadAccount(a);
    try std.testing.expectEqual(@as(primitives.StorageValue, 0xA101), (try j.sload(a, 1)).data);
    try std.testing.expectEqual(@as(primitives.StorageValue, 11), taken.get(a).?.storage.get(1).?.present_value);
}
