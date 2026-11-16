const std = @import("std");
const primitives = @import("primitives");
const state = @import("state");
const bytecode = @import("bytecode");

// Fixed addresses and balances for tests and benchmarks.
pub const FFADDRESS: primitives.Address = [_]u8{0xff} ** 20;
pub const BENCH_TARGET: primitives.Address = FFADDRESS;
pub const TEST_BALANCE: primitives.U256 = primitives.U256{10_000_000_000_000_000};
pub const BENCH_TARGET_BALANCE: primitives.U256 = TEST_BALANCE;
pub const EEADDRESS: primitives.Address = [_]u8{0xee} ** 20;
pub const BENCH_CALLER: primitives.Address = EEADDRESS;
pub const BENCH_CALLER_BALANCE: primitives.U256 = TEST_BALANCE;

pub fn DBErrorMarker(comptime T: type) type {
    return struct {
        const Self = @This();
        pub fn isDBError(_: T) bool {
            return true;
        }
    };
}

/// Adapts an immutable-receiver DB (basicRef, codeByHashRef, storageRef, blockHashRef)
/// to the mutable Database interface (basic, codeByHash, storage, blockHash) that
/// `Context(DB)` expects. Used by `Context.withRefDb`.
pub fn WrapDatabaseRef(comptime T: type) type {
    return struct {
        inner: T,

        const Self = @This();

        pub fn init(inner: T) Self {
            return Self{ .inner = inner };
        }

        pub fn basic(self: *Self, address: primitives.Address) !?state.AccountInfo {
            return self.inner.basicRef(address);
        }

        pub fn codeByHash(self: *Self, code_hash: primitives.Hash) !bytecode.Bytecode {
            return self.inner.codeByHashRef(code_hash);
        }

        pub fn storage(self: *Self, address: primitives.Address, index: primitives.StorageKey) !primitives.StorageValue {
            return self.inner.storageRef(address, index);
        }

        pub fn blockHash(self: *Self, number: u64) !primitives.Hash {
            return self.inner.blockHashRef(number);
        }

        pub fn basicRef(self: Self, address: primitives.Address) !?state.AccountInfo {
            return self.inner.basicRef(address);
        }

        pub fn codeByHashRef(self: Self, code_hash: primitives.Hash) !bytecode.Bytecode {
            return self.inner.codeByHashRef(code_hash);
        }

        pub fn storageRef(self: Self, address: primitives.Address, index: primitives.StorageKey) !primitives.StorageValue {
            return self.inner.storageRef(address, index);
        }

        pub fn blockHashRef(self: Self, number: u64) !primitives.Hash {
            return self.inner.blockHashRef(number);
        }
    };
}

/// Empty database implementation for testing and development.
pub const EmptyDB = struct {
    const Self = @This();

    pub fn basic(self: *Self, address: primitives.Address) !?state.AccountInfo {
        _ = self;
        _ = address;
        return null;
    }

    pub fn codeByHash(self: *Self, code_hash: primitives.Hash) !bytecode.Bytecode {
        _ = self;
        _ = code_hash;
        return bytecode.Bytecode.new();
    }

    pub fn storage(self: *Self, address: primitives.Address, index: primitives.StorageKey) !primitives.StorageValue {
        _ = self;
        _ = address;
        _ = index;
        return @as(primitives.StorageValue, 0);
    }

    pub fn blockHash(self: *Self, number: u64) !primitives.Hash {
        _ = self;
        _ = number;
        return [_]u8{0} ** 32;
    }

    pub fn basicRef(self: Self, address: primitives.Address) !?state.AccountInfo {
        _ = self;
        _ = address;
        return null;
    }

    pub fn codeByHashRef(self: Self, code_hash: primitives.Hash) !bytecode.Bytecode {
        _ = self;
        _ = code_hash;
        return bytecode.Bytecode.new();
    }

    pub fn storageRef(self: Self, address: primitives.Address, index: primitives.StorageKey) !primitives.StorageValue {
        _ = self;
        _ = address;
        _ = index;
        return @as(primitives.StorageValue, 0);
    }

    pub fn blockHashRef(self: Self, number: u64) !primitives.Hash {
        _ = self;
        _ = number;
        return [_]u8{0} ** 32;
    }
};

const StorageKeyContext = struct {
    pub fn hash(ctx: @This(), key: struct { primitives.Address, primitives.StorageKey }) u64 {
        _ = ctx;
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHash(&hasher, key[0]);
        std.hash.autoHash(&hasher, key[1]);
        return hasher.final();
    }
    pub fn eql(ctx: @This(), a: struct { primitives.Address, primitives.StorageKey }, b: struct { primitives.Address, primitives.StorageKey }) bool {
        _ = ctx;
        return std.mem.eql(u8, &a[0], &b[0]) and a[1] == b[1];
    }
};

/// In-memory database implementation.
///
/// Pre-populate with `insertAccount`, `insertCode`, `insertStorage`, `insertBlockHash`
/// before execution. Any DB type with the 4-method interface (basic, codeByHash,
/// storage, blockHash) can replace this via `Context(DB)`. Optional hooks
/// (`notifyCodeDeployed`, `hasNonZeroStorageForAddress`) are detected by the Journal
/// via @hasDecl.
pub const InMemoryDB = struct {
    accounts: std.HashMap(primitives.Address, state.AccountInfo, primitives.AddressContext, 80),
    code: std.HashMap(primitives.Hash, bytecode.Bytecode, primitives.HashContext, 80),
    storage_map: std.HashMap(struct { primitives.Address, primitives.StorageKey }, primitives.StorageValue, StorageKeyContext, std.hash_map.default_max_load_percentage),
    block_hashes: std.AutoHashMap(u64, primitives.Hash),
    /// Non-zero storage entries per address, maintained by putStorage so
    /// hasNonZeroStorageForAddress is O(1).
    nonzero_storage_count: std.HashMap(primitives.Address, u32, primitives.AddressContext, 80),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .accounts = std.HashMap(primitives.Address, state.AccountInfo, primitives.AddressContext, 80).init(allocator),
            .code = std.HashMap(primitives.Hash, bytecode.Bytecode, primitives.HashContext, 80).init(allocator),
            .storage_map = std.HashMap(struct { primitives.Address, primitives.StorageKey }, primitives.StorageValue, StorageKeyContext, std.hash_map.default_max_load_percentage).init(allocator),
            .block_hashes = std.AutoHashMap(u64, primitives.Hash).init(allocator),
            .nonzero_storage_count = std.HashMap(primitives.Address, u32, primitives.AddressContext, 80).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.accounts.deinit();
        self.code.deinit();
        self.storage_map.deinit();
        self.block_hashes.deinit();
        self.nonzero_storage_count.deinit();
    }

    /// Insert or update a storage slot, maintaining the nonzero_storage_count index.
    fn putStorage(self: *Self, address: primitives.Address, key: primitives.StorageKey, value: primitives.StorageValue) !void {
        const old_value = self.storage_map.get(.{ address, key }) orelse 0;
        try self.storage_map.put(.{ address, key }, value);
        if (old_value == 0 and value != 0) {
            const entry = try self.nonzero_storage_count.getOrPut(address);
            if (!entry.found_existing) entry.value_ptr.* = 0;
            entry.value_ptr.* += 1;
        } else if (old_value != 0 and value == 0) {
            if (self.nonzero_storage_count.getPtr(address)) |count| {
                count.* -= 1;
                if (count.* == 0) _ = self.nonzero_storage_count.remove(address);
            }
        }
    }

    pub fn basic(self: *Self, address: primitives.Address) !?state.AccountInfo {
        return self.accounts.get(address);
    }

    pub fn codeByHash(self: *Self, code_hash: primitives.Hash) !bytecode.Bytecode {
        return self.code.get(code_hash) orelse bytecode.Bytecode.new();
    }

    pub fn storage(self: *Self, address: primitives.Address, index: primitives.StorageKey) !primitives.StorageValue {
        return self.getStorage(address, index);
    }

    pub fn getStorage(self: *Self, address: primitives.Address, index: primitives.StorageKey) !primitives.StorageValue {
        return self.storage_map.get(.{ address, index }) orelse @as(primitives.StorageValue, 0);
    }

    pub fn blockHash(self: *Self, number: u64) !primitives.Hash {
        return self.block_hashes.get(number) orelse [_]u8{0} ** 32;
    }

    /// Returns true if the address has any non-zero storage entry (O(1)).
    pub fn hasNonZeroStorageForAddress(self: *const Self, address: primitives.Address) bool {
        const count = self.nonzero_storage_count.get(address) orelse return false;
        return count > 0;
    }

    pub fn basicRef(self: Self, address: primitives.Address) !?state.AccountInfo {
        return self.accounts.get(address);
    }

    pub fn codeByHashRef(self: Self, code_hash: primitives.Hash) !bytecode.Bytecode {
        return self.code.get(code_hash) orelse bytecode.Bytecode.new();
    }

    pub fn storageRef(self: Self, address: primitives.Address, index: primitives.StorageKey) !primitives.StorageValue {
        return self.storage_map.get(.{ address, index }) orelse @as(primitives.StorageValue, 0);
    }

    pub fn blockHashRef(self: Self, number: u64) !primitives.Hash {
        return self.block_hashes.get(number) orelse [_]u8{0} ** 32;
    }

    pub fn commit(self: *Self, changes: std.HashMap(primitives.Address, state.Account, std.hash_map.default_hash_fn(primitives.Address), std.hash_map.default_eql_fn(primitives.Address))) void {
        var iterator = changes.iterator();
        while (iterator.next()) |entry| {
            const address = entry.key_ptr.*;
            const account = entry.value_ptr.*;

            self.accounts.put(address, account.info) catch return;

            var storage_iterator = account.storage.iterator();
            while (storage_iterator.next()) |storage_entry| {
                const key = storage_entry.key_ptr.*;
                const slot = storage_entry.value_ptr.*;
                self.putStorage(address, key, slot.presentValue()) catch return;
            }
        }
    }

    pub fn insertAccount(self: *Self, address: primitives.Address, account_info: state.AccountInfo) !void {
        try self.accounts.put(address, account_info);
    }

    pub fn insertCode(self: *Self, code_hash: primitives.Hash, code: bytecode.Bytecode) !void {
        try self.code.put(code_hash, code);
    }

    pub fn insertStorage(self: *Self, address: primitives.Address, key: primitives.StorageKey, value: primitives.StorageValue) !void {
        try self.putStorage(address, key, value);
    }

    pub fn insertBlockHash(self: *Self, number: u64, hash: primitives.Hash) !void {
        try self.block_hashes.put(number, hash);
    }
};

/// Address -> Account map (accounts own their storage maps; freed in deinit).
pub const State = struct {
    accounts: std.HashMap(primitives.Address, state.Account, primitives.AddressContext, 80),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .accounts = std.HashMap(primitives.Address, state.Account, primitives.AddressContext, 80).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var iterator = self.accounts.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.storage.deinit();
        }
        self.accounts.deinit();
    }

    pub fn getAccount(self: *Self, address: primitives.Address) ?*state.Account {
        return self.accounts.getPtr(address);
    }

    pub fn insertAccount(self: *Self, address: primitives.Address, account: state.Account) !void {
        try self.accounts.put(address, account);
    }

    pub fn removeAccount(self: *Self, address: primitives.Address) ?state.Account {
        if (self.accounts.fetchRemove(address)) |kv| {
            return kv.value;
        }
        return null;
    }

    pub fn getAccounts(self: Self) std.HashMap(primitives.Address, state.Account, primitives.AddressContext, 80) {
        return self.accounts;
    }
};
