const std = @import("std");
const primitives = @import("primitives");
const bytecode = @import("bytecode");
const alloc_mod = @import("zesu_allocator");

/// Account balance, nonce, code hash and (optionally loaded) code.
pub const AccountInfo = struct {
    balance: primitives.U256,
    nonce: u64,
    /// Hash of the raw bytes in code, or KECCAK_EMPTY.
    code_hash: primitives.Hash,
    /// Loaded bytecode; null means "fetch by code_hash from the DB when needed".
    /// `default()` sets empty bytecode.
    code: ?bytecode.Bytecode,

    const Self = @This();

    pub fn default() Self {
        return Self{
            .balance = @as(primitives.U256, 0),
            .nonce = 0,
            .code_hash = primitives.KECCAK_EMPTY,
            .code = bytecode.Bytecode.new(),
        };
    }

    pub fn new(balance: primitives.U256, nonce: u64, code_hash: primitives.Hash, code: bytecode.Bytecode) Self {
        return Self{
            .balance = balance,
            .nonce = nonce,
            .code_hash = code_hash,
            .code = code,
        };
    }

    /// Creates a new AccountInfo with the given code.
    /// Recomputes code_hash via `hashSlow` (keccak over the code).
    pub fn withCode(self: Self, code: bytecode.Bytecode) Self {
        return Self{
            .balance = self.balance,
            .nonce = self.nonce,
            .code_hash = code.hashSlow(),
            .code = code,
        };
    }

    /// Creates a new AccountInfo with the given code hash.
    /// Resets code to null so it is re-fetched by the new hash.
    pub fn withCodeHash(self: Self, code_hash: primitives.Hash) Self {
        return Self{
            .balance = self.balance,
            .nonce = self.nonce,
            .code_hash = code_hash,
            .code = null,
        };
    }

    /// Creates a new AccountInfo with the given code and code hash.
    pub fn withCodeAndHash(self: Self, code: bytecode.Bytecode, code_hash: primitives.Hash) Self {
        std.debug.assert(std.mem.eql(u8, &code.hashSlow(), &code_hash));
        return Self{
            .balance = self.balance,
            .nonce = self.nonce,
            .code_hash = code_hash,
            .code = code,
        };
    }

    pub fn withBalance(self: Self, balance: primitives.U256) Self {
        var result = self;
        result.balance = balance;
        return result;
    }

    pub fn withNonce(self: Self, nonce: u64) Self {
        var result = self;
        result.nonce = nonce;
        return result;
    }

    pub fn setBalance(self: *Self, balance: primitives.U256) void {
        self.balance = balance;
    }

    pub fn setNonce(self: *Self, nonce: u64) void {
        self.nonce = nonce;
    }

    /// Sets the AccountInfo code_hash and clears any cached bytecode.
    pub fn setCodeHash(self: *Self, code_hash: primitives.Hash) void {
        self.code = null;
        self.code_hash = code_hash;
    }

    /// Replaces the AccountInfo bytecode and recalculates code_hash.
    pub fn setCode(self: *Self, code: bytecode.Bytecode) void {
        self.code_hash = code.hashSlow();
        self.code = code;
    }

    /// Sets the bytecode and its hash.
    pub fn setCodeAndHash(self: *Self, code: bytecode.Bytecode, code_hash: primitives.Hash) void {
        self.code_hash = code_hash;
        self.code = code;
    }

    /// Returns a copy of this account with the Bytecode removed.
    pub fn copyWithoutCode(self: Self) Self {
        return Self{
            .balance = self.balance,
            .nonce = self.nonce,
            .code_hash = self.code_hash,
            .code = null,
        };
    }

    /// Returns a copy with code set to null (the Bytecode is not freed).
    pub fn withoutCode(self: Self) Self {
        var result = self;
        result.code = null;
        return result;
    }

    /// EIP-161 empty: zero balance, zero nonce, and code_hash KECCAK_EMPTY or all-zero
    /// (uninitialized). The all-zero test must compare the full hash, not just byte 0.
    pub fn isEmpty(self: Self) bool {
        const zero_hash = [_]u8{0} ** 32;
        const code_empty = self.isEmptyCodeHash() or std.mem.eql(u8, &self.code_hash, &zero_hash);
        return code_empty and self.balance == 0 and self.nonce == 0;
    }

    pub fn exists(self: Self) bool {
        return !self.isEmpty();
    }

    /// True if the account has no code and a zero nonce.
    pub fn hasNoCodeAndNonce(self: Self) bool {
        return self.isEmptyCodeHash() and self.nonce == 0;
    }

    pub fn codeHash(self: Self) primitives.Hash {
        return self.code_hash;
    }

    /// Returns true if the code hash is the Keccak256 hash of the empty string "".
    pub fn isEmptyCodeHash(self: Self) bool {
        return std.mem.eql(u8, &self.code_hash, &primitives.KECCAK_EMPTY);
    }

    /// Moves the code out, leaving null.
    pub fn takeBytecode(self: *Self) ?bytecode.Bytecode {
        const result = self.code;
        self.code = null;
        return result;
    }

    /// Initializes an AccountInfo with the given balance, setting all other fields to their default values.
    pub fn fromBalance(balance: primitives.U256) Self {
        return Self{
            .balance = balance,
            .nonce = 0,
            .code_hash = primitives.KECCAK_EMPTY,
            .code = bytecode.Bytecode.new(),
        };
    }

    /// Initializes an AccountInfo with the given bytecode, setting its balance to zero, its
    /// nonce to 1, and calculating the code hash from the given bytecode.
    pub fn fromBytecode(bytecode_val: bytecode.Bytecode) Self {
        const hash = bytecode_val.hashSlow();
        return Self{
            .balance = @as(primitives.U256, 0),
            .nonce = 1,
            .code = bytecode_val,
            .code_hash = hash,
        };
    }
};

/// Account status flags
pub const AccountStatus = packed struct {
    /// Newly created: storage is not fetched from the database.
    created: bool = false,
    /// Locally created (see Account.markCreatedLocally); implies `created`.
    created_local: bool = false,
    self_destructed: bool = false,
    /// Locally self-destructed; implies `self_destructed`.
    self_destructed_local: bool = false,
    /// Only touched accounts are written back. Post-EIP-161, touching an empty
    /// account marks it for removal after the transaction.
    touched: bool = false,
    /// Pre-Spurious-Dragon only, where "non-existent" and "empty" were distinct (merged by EIP-161).
    loaded_as_not_existing: bool = false,
    /// EIP-2929 cold; reset when the account is loaded.
    cold: bool = false,
    /// Storage was wiped (e.g. SELFDESTRUCT in an earlier tx of the block): pre-state
    /// storage must not be inherited when computing post-state.
    storage_wiped: bool = false,

    pub fn empty() AccountStatus {
        return AccountStatus{};
    }

    pub fn isTouched(self: AccountStatus) bool {
        return self.touched;
    }

    /// Returns true if the account status contains the given flag.
    pub fn contains(self: AccountStatus, other: AccountStatus) bool {
        return (self.touched and other.touched) or
            (self.created and other.created) or
            (self.created_local and other.created_local) or
            (self.self_destructed and other.self_destructed) or
            (self.self_destructed_local and other.self_destructed_local) or
            (self.loaded_as_not_existing and other.loaded_as_not_existing) or
            (self.cold and other.cold);
    }

    pub fn setTouched(self: *AccountStatus) void {
        self.touched = true;
    }

    pub fn clearTouched(self: *AccountStatus) void {
        self.touched = false;
    }

    pub fn setCreated(self: *AccountStatus) void {
        self.created = true;
    }

    pub fn clearCreated(self: *AccountStatus) void {
        self.created = false;
    }

    pub fn setCreatedLocal(self: *AccountStatus) void {
        self.created_local = true;
    }

    pub fn clearCreatedLocal(self: *AccountStatus) void {
        self.created_local = false;
    }

    pub fn setSelfDestructed(self: *AccountStatus) void {
        self.self_destructed = true;
    }

    pub fn clearSelfDestructed(self: *AccountStatus) void {
        self.self_destructed = false;
    }

    pub fn setSelfDestructedLocal(self: *AccountStatus) void {
        self.self_destructed_local = true;
    }

    pub fn clearSelfDestructedLocal(self: *AccountStatus) void {
        self.self_destructed_local = false;
    }

    pub fn setStorageWiped(self: *AccountStatus) void {
        self.storage_wiped = true;
    }

    pub fn setLoadedAsNotExisting(self: *AccountStatus) void {
        self.loaded_as_not_existing = true;
    }

    pub fn clearLoadedAsNotExisting(self: *AccountStatus) void {
        self.loaded_as_not_existing = false;
    }

    pub fn setCold(self: *AccountStatus) void {
        self.cold = true;
    }

    pub fn clearCold(self: *AccountStatus) void {
        self.cold = false;
    }
};

/// A cached storage slot: original (tx-start), present, and block-start values.
pub const EvmStorageSlot = struct {
    /// Value at the start of the current transaction (EIP-2200 "original").
    original_value: primitives.StorageValue,
    present_value: primitives.StorageValue,
    /// Value at first DB load this block; never reset by commitTx. Used by
    /// extractPostState (stateless/executor/transition.zig) to emit only changed slots.
    pre_block_value: primitives.StorageValue,
    /// Transaction id, used to track when storage slot was made warm.
    transaction_id: usize,
    is_cold: bool,
    /// SSTORE hit this slot during the current block. Survives commitTx; cleared only
    /// by a journal revert past the write.
    was_written: bool,

    const Self = @This();

    /// Creates a new _unchanged_ EvmStorageSlot for the given value.
    pub fn new(original: primitives.StorageValue, transaction_id: usize) Self {
        return Self{
            .original_value = original,
            .present_value = original,
            .pre_block_value = original,
            .transaction_id = transaction_id,
            .is_cold = false,
            .was_written = false,
        };
    }

    /// Creates a new _changed_ EvmStorageSlot.
    pub fn newChanged(original_value: primitives.StorageValue, present_value: primitives.StorageValue, transaction_id: usize) Self {
        return Self{
            .original_value = original_value,
            .present_value = present_value,
            .pre_block_value = original_value,
            .transaction_id = transaction_id,
            .is_cold = false,
            .was_written = false,
        };
    }

    /// Returns true if the present value differs from the original value.
    pub fn isChanged(self: Self) bool {
        return self.original_value != self.present_value;
    }

    pub fn originalValue(self: Self) primitives.StorageValue {
        return self.original_value;
    }

    pub fn presentValue(self: Self) primitives.StorageValue {
        return self.present_value;
    }

    /// Marks the storage slot as cold. Does not change transaction_id.
    pub fn markCold(self: *Self) void {
        self.is_cold = true;
    }

    /// Cold if last warmed in a different transaction or explicitly marked cold.
    pub fn isColdTransactionId(self: Self, transaction_id: usize) bool {
        return self.transaction_id != transaction_id or self.is_cold;
    }

    /// Marks the slot warm for `transaction_id`; returns whether it was cold.
    pub fn markWarmWithTransactionId(self: *Self, transaction_id: usize) bool {
        const was_cold = self.isColdTransactionId(transaction_id);
        self.transaction_id = transaction_id;
        self.is_cold = false;
        return was_cold;
    }
};

/// Account type used inside Journal to track changes to state.
pub const Account = struct {
    info: AccountInfo,
    /// Transaction id, used to track when account was touched/loaded into journal.
    transaction_id: usize,
    storage: primitives.SlotMap(EvmStorageSlot),
    status: AccountStatus,

    const Self = @This();

    pub fn default() Self {
        return Self{
            .info = AccountInfo.default(),
            .transaction_id = 0,
            .storage = primitives.SlotMap(EvmStorageSlot).init(alloc_mod.get()),
            .status = AccountStatus.empty(),
        };
    }

    /// Creates new account and mark it as non existing.
    pub fn newNotExisting(transaction_id: usize) Self {
        return Self{
            .info = AccountInfo.default(),
            .storage = primitives.SlotMap(EvmStorageSlot).init(alloc_mod.get()),
            .transaction_id = transaction_id,
            .status = AccountStatus{ .loaded_as_not_existing = true },
        };
    }

    /// Touches the caller, sets its balance, and bumps the nonce if `is_call`.
    /// Returns the old balance.
    pub fn callerInitialModification(self: *Self, new_balance: primitives.U256, is_call: bool) primitives.U256 {
        self.markTouch();

        if (is_call) {
            // Nonce is already checked
            self.info.nonce = self.info.nonce + 1;
        }

        const old_balance = self.info.balance;
        self.info.balance = new_balance;
        return old_balance;
    }

    /// EIP-161 emptiness from Spurious Dragon on; before it, "loaded as non-existent and untouched".
    pub fn stateClearAwareIsEmpty(self: Self, spec: primitives.SpecId) bool {
        if (primitives.isEnabledIn(spec, .spurious_dragon)) {
            return self.isEmpty();
        } else {
            return self.isLoadedAsNotExistingNotTouched();
        }
    }

    pub fn markSelfdestruct(self: *Self) void {
        self.status.setSelfDestructed();
    }

    pub fn unmarkSelfdestruct(self: *Self) void {
        self.status.clearSelfDestructed();
    }

    pub fn isSelfdestructed(self: Self) bool {
        return self.status.self_destructed;
    }

    /// Adds `amount` and touches the account. On overflow the balance is left unchanged.
    pub fn incrBalance(self: *Self, amount: primitives.U256) void {
        self.markTouch();
        self.info.balance = std.math.add(primitives.U256, self.info.balance, amount) catch self.info.balance;
    }

    pub fn markTouch(self: *Self) void {
        self.status.setTouched();
    }

    pub fn unmarkTouch(self: *Self) void {
        self.status.clearTouched();
    }

    pub fn isTouched(self: Self) bool {
        return self.status.isTouched();
    }

    pub fn markCreated(self: *Self) void {
        self.status.setCreated();
    }

    pub fn unmarkCreated(self: *Self) void {
        self.status.clearCreated();
    }

    pub fn markCold(self: *Self) void {
        self.status.setCold();
    }

    /// Cold if last loaded in a different transaction or explicitly marked cold.
    pub fn isColdTransactionId(self: Self, transaction_id: usize) bool {
        return self.transaction_id != transaction_id or self.status.cold;
    }

    /// Marks the account as warm and return true if it was previously cold.
    pub fn markWarmWithTransactionId(self: *Self, transaction_id: usize) bool {
        const was_cold = self.isColdTransactionId(transaction_id);
        self.status.clearCold();
        self.transaction_id = transaction_id;
        return was_cold;
    }

    pub fn isCreatedLocally(self: Self) bool {
        return self.status.created_local;
    }

    pub fn isSelfdestructedLocally(self: Self) bool {
        return self.status.self_destructed_local;
    }

    /// Clears storage, frees the code, and resets the account info.
    pub fn selfdestruct(self: *Self) void {
        self.storage.clearAndFree();
        // Safe: each loaded Bytecode owns its own analysis buffers (analyzeLegacy
        // allocates per load), never shared across accounts.
        if (self.info.code) |*code| code.deinit();
        self.info = AccountInfo.default();
    }

    /// Mark account as locally created and mark global created flag.
    /// Returns true if it is created globally for first time.
    pub fn markCreatedLocally(self: *Self) bool {
        self.status.setCreatedLocal();
        const is_created_globally = !self.status.created;
        self.status.setCreated();
        return is_created_globally;
    }

    pub fn unmarkCreatedLocally(self: *Self) void {
        self.status.clearCreatedLocal();
    }

    /// Marks local and global self-destruct; returns true if newly self-destructed globally.
    pub fn markSelfdestructedLocally(self: *Self) bool {
        self.status.setSelfDestructedLocal();
        const is_global_selfdestructed = !self.status.self_destructed;
        self.status.setSelfDestructed();
        return is_global_selfdestructed;
    }

    pub fn unmarkSelfdestructedLocally(self: *Self) void {
        self.status.clearSelfDestructedLocal();
    }

    /// See `AccountStatus.loaded_as_not_existing`.
    pub fn isLoadedAsNotExisting(self: Self) bool {
        return self.status.loaded_as_not_existing;
    }

    /// Is account loaded as not existing from database and not touched.
    pub fn isLoadedAsNotExistingNotTouched(self: Self) bool {
        return self.isLoadedAsNotExisting() and !self.isTouched();
    }

    /// Is account newly created in this transaction.
    pub fn isCreated(self: Self) bool {
        return self.status.created;
    }

    pub fn isEmpty(self: Self) bool {
        return self.info.isEmpty();
    }

    pub fn withInfo(self: Self, info: AccountInfo) Self {
        var result = self;
        result.info = info;
        return result;
    }

    pub fn withSelfdestructMark(self: Self) Self {
        var result = self;
        result.markSelfdestruct();
        return result;
    }

    pub fn withTouchedMark(self: Self) Self {
        var result = self;
        result.markTouch();
        return result;
    }

    pub fn withCreatedMark(self: Self) Self {
        var result = self;
        result.markCreated();
        return result;
    }

    pub fn withColdMark(self: Self) Self {
        var result = self;
        result.markCold();
        return result;
    }

    /// Returns a warmed copy and whether the account was cold.
    pub fn withWarmMark(self: Self, transaction_id: usize) struct { Self, bool } {
        var result = self;
        const was_cold = result.markWarmWithTransactionId(transaction_id);
        return .{ result, was_cold };
    }

    /// Variant of withWarmMark that doesn't return the previous state.
    pub fn withWarm(self: Self, transaction_id: usize) Self {
        var result = self;
        _ = result.markWarmWithTransactionId(transaction_id);
        return result;
    }
};

/// EVM State is a mapping from addresses to accounts.
pub const EvmState = std.HashMap(primitives.Address, Account, primitives.AddressContext, 80);

/// EIP-1153 transient storage key.
pub const TransientKey = struct { primitives.Address, primitives.StorageKey };
/// Folds the address and slot hashes instead of Wyhashing the 52-byte padded struct.
pub const TransientContext = struct {
    pub fn hash(_: @This(), k: TransientKey) u64 {
        return primitives.AddressContext.hash(.{}, k[0]) ^ std.math.rotl(u64, primitives.SlotContext.hash(.{}, k[1]), 17);
    }
    pub fn eql(_: @This(), a: TransientKey, b: TransientKey) bool {
        return a[1] == b[1] and std.mem.eql(u8, &a[0], &b[0]);
    }
};
pub const TransientStorage = std.HashMap(TransientKey, primitives.StorageValue, TransientContext, 80);

/// An account's Storage is a mapping from 256-bit integer keys to EvmStorageSlots.
pub const EvmStorage = primitives.SlotMap(EvmStorageSlot);

pub const testing = struct {
    pub fn testAccountInfo() !void {
        const account = AccountInfo.default();
        try std.testing.expect(account.isEmpty());
        try std.testing.expect(!account.exists());
        try std.testing.expect(account.hasNoCodeAndNonce());
    }

    pub fn testAccountStatus() !void {
        var status = AccountStatus.empty();
        try std.testing.expect(!status.isTouched());

        status.setTouched();
        try std.testing.expect(status.isTouched());

        status.clearTouched();
        try std.testing.expect(!status.isTouched());
    }

    pub fn testEvmStorageSlot() !void {
        const slot = EvmStorageSlot.new(@as(primitives.U256, 100), 0);
        try std.testing.expectEqual(@as(primitives.U256, 100), slot.originalValue());
        try std.testing.expectEqual(@as(primitives.U256, 100), slot.presentValue());
        try std.testing.expect(!slot.isChanged());

        var slot_mut = slot;
        slot_mut.present_value = @as(primitives.U256, 200);
        try std.testing.expect(slot_mut.isChanged());
    }

    pub fn testAccount() !void {
        var account = Account.default();
        try std.testing.expect(account.isEmpty());
        try std.testing.expect(!account.isTouched());
        try std.testing.expect(!account.isSelfdestructed());

        account.markTouch();
        try std.testing.expect(account.isTouched());

        account.markSelfdestruct();
        try std.testing.expect(account.isSelfdestructed());

        account.unmarkSelfdestruct();
        try std.testing.expect(!account.isSelfdestructed());
    }
};
