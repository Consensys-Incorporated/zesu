const std = @import("std");
const primitives = @import("primitives");
const state = @import("state");
const bytecode = @import("bytecode");
const database = @import("database");
const alloc_mod = @import("zesu_allocator");

/// Journal entry factory functions
pub const JournalEntryFactory = struct {
    pub fn accountTouched(address: primitives.Address) JournalEntry {
        return JournalEntry{ .AccountTouched = address };
    }

    pub fn accountCreated(address: primitives.Address, is_created_globally: bool) JournalEntry {
        return JournalEntry{ .AccountCreated = .{ .address = address, .is_created_globally = is_created_globally } };
    }

    pub fn accountDestroyed(address: primitives.Address, target: primitives.Address, destroyed_status: SelfdestructionRevertStatus, balance: primitives.U256) JournalEntry {
        return JournalEntry{ .AccountDestroyed = .{ .address = address, .target = target, .destroyed_status = destroyed_status, .balance = balance } };
    }

    pub fn balanceChanged(address: primitives.Address, old_balance: primitives.U256) JournalEntry {
        return JournalEntry{ .BalanceChanged = .{ .address = address, .old_balance = old_balance } };
    }

    pub fn balanceTransfer(from: primitives.Address, to: primitives.Address, balance: primitives.U256) JournalEntry {
        return JournalEntry{ .BalanceTransfer = .{ .from = from, .to = to, .balance = balance } };
    }

    pub fn nonceChanged(address: primitives.Address) JournalEntry {
        return JournalEntry{ .NonceChanged = address };
    }

    pub fn codeChanged(address: primitives.Address, old_code: ?bytecode.Bytecode, old_code_hash: primitives.Hash) JournalEntry {
        return JournalEntry{ .CodeChanged = .{ .address = address, .old_code = old_code, .old_code_hash = old_code_hash } };
    }

    pub fn storageChanged(address: primitives.Address, key: primitives.StorageKey, old_value: primitives.StorageValue, old_was_written: bool) JournalEntry {
        return JournalEntry{ .StorageChanged = .{ .address = address, .key = key, .old_value = old_value, .old_was_written = old_was_written } };
    }

    pub fn storageWarmed(address: primitives.Address, key: primitives.StorageKey) JournalEntry {
        return JournalEntry{ .StorageWarmed = .{ .address = address, .key = key } };
    }

    pub fn accountWarmed(address: primitives.Address) JournalEntry {
        return JournalEntry{ .AccountWarmed = address };
    }

    pub fn transientStorageChanged(address: primitives.Address, key: primitives.StorageKey, old_value: primitives.StorageValue) JournalEntry {
        return JournalEntry{ .TransientStorageChanged = .{ .address = address, .key = key, .old_value = old_value } };
    }
};

/// Selfdestruction revert status
pub const SelfdestructionRevertStatus = enum {
    GloballySelfdestroyed,
    LocallySelfdestroyed,
    RepeatedSelfdestruction,
};

/// Journal entry
pub const JournalEntry = union(enum) {
    AccountTouched: primitives.Address,
    AccountCreated: struct { address: primitives.Address, is_created_globally: bool },
    AccountDestroyed: struct { address: primitives.Address, target: primitives.Address, destroyed_status: SelfdestructionRevertStatus, balance: primitives.U256 },
    BalanceChanged: struct { address: primitives.Address, old_balance: primitives.U256 },
    BalanceTransfer: struct { from: primitives.Address, to: primitives.Address, balance: primitives.U256 },
    NonceChanged: primitives.Address,
    CodeChanged: struct { address: primitives.Address, old_code: ?bytecode.Bytecode, old_code_hash: primitives.Hash },
    StorageChanged: struct { address: primitives.Address, key: primitives.StorageKey, old_value: primitives.StorageValue, old_was_written: bool },
    StorageWarmed: struct { address: primitives.Address, key: primitives.StorageKey },
    AccountWarmed: primitives.Address,
    TransientStorageChanged: struct { address: primitives.Address, key: primitives.StorageKey, old_value: primitives.StorageValue },

    pub fn revert(self: JournalEntry, evm_state: *state.EvmState, transient_storage: ?*state.TransientStorage, is_spurious_dragon_enabled: bool) void {
        switch (self) {
            .AccountTouched => |address| {
                if (evm_state.getPtr(address)) |account| {
                    account.unmarkTouch();
                }
            },
            .AccountCreated => |data| {
                if (evm_state.getPtr(data.address)) |account| {
                    account.unmarkCreatedLocally();
                    if (data.is_created_globally) {
                        account.unmarkCreated();
                    }
                    if (is_spurious_dragon_enabled) {
                        account.info.nonce = 0;
                    }
                }
            },
            .AccountDestroyed => |data| {
                if (evm_state.getPtr(data.address)) |account| {
                    switch (data.destroyed_status) {
                        .GloballySelfdestroyed => {
                            account.unmarkSelfdestructedLocally();
                            account.unmarkSelfdestruct();
                        },
                        .LocallySelfdestroyed => {
                            account.unmarkSelfdestructedLocally();
                        },
                        .RepeatedSelfdestruction => {
                            // Do nothing
                        },
                    }
                    account.info.balance = data.balance;
                }
                // Restore the target account's balance: the selfdestruct transferred
                // data.balance wei from source to target; undo that transfer on revert.
                if (!std.mem.eql(u8, &data.address, &data.target)) {
                    if (evm_state.getPtr(data.target)) |target_account| {
                        target_account.info.balance -= data.balance;
                    }
                }
            },
            .BalanceChanged => |data| {
                if (evm_state.getPtr(data.address)) |account| {
                    account.info.balance = data.old_balance;
                }
            },
            .BalanceTransfer => |data| {
                if (evm_state.getPtr(data.from)) |from_account| {
                    from_account.info.balance += data.balance;
                }
                if (evm_state.getPtr(data.to)) |to_account| {
                    to_account.info.balance -= data.balance;
                }
            },
            .NonceChanged => |address| {
                if (evm_state.getPtr(address)) |account| {
                    account.info.nonce -= 1;
                }
            },
            .CodeChanged => |data| {
                if (evm_state.getPtr(data.address)) |account| {
                    // Safe to free: the code being reverted away is uniquely owned (each
                    // load analyzes a fresh jump table) and code only changes at frame
                    // boundaries, so no live frame references it.
                    if (account.info.code) |*code| code.deinit();
                    // Restore the old code (a delegation clear/re-set reverts to the original
                    // delegation; a fresh contract reverts to empty).
                    account.info.code = data.old_code;
                    account.info.code_hash = data.old_code_hash;
                }
            },
            .StorageChanged => |data| {
                if (evm_state.getPtr(data.address)) |account| {
                    if (account.storage.getPtr(data.key)) |slot| {
                        slot.present_value = data.old_value;
                        slot.was_written = data.old_was_written;
                    }
                }
            },
            .StorageWarmed => |data| {
                if (evm_state.getPtr(data.address)) |account| {
                    if (account.storage.getPtr(data.key)) |slot| {
                        slot.markCold();
                    }
                }
            },
            .AccountWarmed => |address| {
                if (evm_state.getPtr(address)) |account| {
                    account.markCold();
                }
            },
            .TransientStorageChanged => |data| {
                if (transient_storage) |ts| {
                    if (data.old_value == 0) {
                        _ = ts.remove(.{ data.address, data.key });
                    } else {
                        ts.put(.{ data.address, data.key }, data.old_value) catch {};
                    }
                }
            },
        }
    }
};

/// Warm addresses
pub const WarmAddresses = struct {
    coinbase: ?primitives.Address,
    /// Bit n set ⇔ a precompile lives at short address n. 320 bits cover
    /// SHORT_ADDRESS_CAP (300), including P256VERIFY at 0x100 without warming 0x12..0xff.
    precompile_bitset: [5]u64,
    access_list: std.HashMap(primitives.Address, std.ArrayList(primitives.StorageKey), primitives.AddressContext, 80),

    pub fn new() WarmAddresses {
        return .{
            .coinbase = null,
            .precompile_bitset = .{0} ** 5,
            .access_list = std.HashMap(primitives.Address, std.ArrayList(primitives.StorageKey), primitives.AddressContext, 80).init(alloc_mod.get()),
        };
    }

    pub fn deinit(self: *WarmAddresses) void {
        var iterator = self.access_list.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit(alloc_mod.get());
        }
        self.access_list.deinit();
    }

    pub fn setCoinbase(self: *WarmAddresses, address: primitives.Address) void {
        self.coinbase = address;
    }

    pub fn setPrecompileBitset(self: *WarmAddresses, bitset: [5]u64) void {
        self.precompile_bitset = bitset;
    }

    pub fn setAccessList(self: *WarmAddresses, access_list: std.HashMap(primitives.Address, std.ArrayList(primitives.StorageKey), primitives.AddressContext, 80)) !void {
        // Clear existing access list
        var iterator = self.access_list.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit(alloc_mod.get());
        }
        self.access_list.clearRetainingCapacity();

        // Copy new access list
        var new_iterator = access_list.iterator();
        while (new_iterator.next()) |entry| {
            var storage_keys = std.ArrayList(primitives.StorageKey).empty;
            try storage_keys.appendSlice(alloc_mod.get(), entry.value_ptr.items);
            try self.access_list.put(entry.key_ptr.*, storage_keys);
        }
    }

    pub fn clearCoinbaseAndAccessList(self: *WarmAddresses) void {
        self.coinbase = null;
        var iterator = self.access_list.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit(alloc_mod.get());
        }
        self.access_list.clearRetainingCapacity();
    }

    pub fn isCold(self: WarmAddresses, address: primitives.Address) bool {
        // Check if address is coinbase
        if (self.coinbase) |coinbase| {
            if (std.mem.eql(u8, &address, &coinbase)) {
                return false;
            }
        }

        // Check if address is a precompile via bitset (O(1), no contiguity assumption)
        if (primitives.shortAddress(address)) |n| {
            const word = n / 64;
            const bit = @as(u64, 1) << @intCast(n % 64);
            if (word < 5 and (self.precompile_bitset[word] & bit) != 0) return false;
        }

        // Check if address is in access list
        if (self.access_list.contains(address)) {
            return false;
        }

        return true;
    }

    pub fn isStorageWarm(self: WarmAddresses, address: primitives.Address, key: primitives.StorageKey) bool {
        if (self.access_list.get(address)) |storage_keys| {
            for (storage_keys.items) |storage_key| {
                if (key == storage_key) {
                    return true;
                }
            }
        }
        return false;
    }
};

/// Journal checkpoint
pub const JournalCheckpoint = struct {
    log_i: usize,
    journal_i: usize,
    /// Index into JournalInner.pending_burns at checkpoint time (for EIP-7708 revert).
    burn_i: usize,
};

/// EIP-7708 deferred burn entry: an account whose balance at finalization is logged as burned
/// (see emitBurnLogs). `amount` is unused; the live balance is read instead. Never populated
/// since EIP-8246 removed the SELFDESTRUCT burn.
pub const PendingBurn = struct {
    address: primitives.Address,
    amount: primitives.U256,
};

/// State load result
pub fn StateLoad(comptime T: type) type {
    return struct {
        data: T,
        is_cold: bool,

        pub fn new(data: T, is_cold: bool) @This() {
            return .{ .data = data, .is_cold = is_cold };
        }

        pub fn map(self: @This(), comptime U: type, f: fn (T) U) StateLoad(U) {
            return StateLoad(U).new(f(self.data), self.is_cold);
        }
    };
}

/// SStore result
pub const SStoreResult = struct {
    original_value: primitives.StorageValue,
    present_value: primitives.StorageValue,
    new_value: primitives.StorageValue,
};

/// SelfDestruct result
pub const SelfDestructResult = struct {
    had_value: bool,
    target_exists: bool,
    previously_destroyed: bool,
};

/// Transfer error
pub const TransferError = error{
    OutOfFunds,
    OverflowPayment,
    CreateCollision,
};

/// Journal load error
pub const JournalLoadError = error{
    ColdLoadSkipped,
    DatabaseError,
};

/// Account load result
pub const AccountLoad = struct {
    is_delegate_account_cold: ?bool,
    is_empty: bool,
};

/// Account info load result
pub const AccountInfoLoad = struct {
    info: *state.AccountInfo,
    is_cold: bool,
    is_empty: bool,

    pub fn new(info: *state.AccountInfo, is_cold: bool, is_empty: bool) AccountInfoLoad {
        return .{ .info = info, .is_cold = is_cold, .is_empty = is_empty };
    }
};

/// Journaled account
pub const JournaledAccount = struct {
    address: primitives.Address,
    account: *state.Account,
    journal: *std.ArrayList(JournalEntry),

    pub fn new(address: primitives.Address, account: *state.Account, journal: *std.ArrayList(JournalEntry)) JournaledAccount {
        return .{ .address = address, .account = account, .journal = journal };
    }

    pub fn intoAccountRef(self: JournaledAccount) *state.Account {
        return self.account;
    }
};

/// Result of `JournalInner.sloadProbe`.
pub const SloadProbe = struct { value: ?primitives.StorageValue, is_cold: bool };

/// Inner journal evm_state that contains journal and evm_state changes.
///
/// Spec Id is a essential information for the Journal.
pub const JournalInner = struct {
    /// The current evm_state
    evm_state: state.EvmState,
    /// Transient storage that is discarded after every transaction.
    ///
    /// See EIP-1153.
    transient_storage: state.TransientStorage,
    /// Emitted logs
    logs: std.ArrayList(primitives.Log),
    /// State changes of the current transaction; cleared at commitTx/discardTx.
    journal: std.ArrayList(JournalEntry),
    /// Addresses whose `transaction_id` was set to the current transaction since this list
    /// was last consumed, in first-touch order — so EIP-7928 BAL detection need not scan
    /// all of `evm_state` per transaction.
    ///
    /// Appended at exactly the two sites that set an account's `transaction_id`, so it is a
    /// superset of `{a : a.transaction_id >= from_tx_id}`; consumers still apply that
    /// predicate. May contain duplicates across transactions. Amsterdam+ only: nothing
    /// drains it on earlier forks.
    tx_touched: std.ArrayList(primitives.Address),
    /// Number of transactions committed or discarded so far. Accounts and slots record the
    /// id of their last access, which is how warm/cold is decided per transaction.
    transaction_id: usize,
    /// Active hardfork; gates fork-dependent journal behaviour (EIP-161 empty accounts,
    /// EIP-6780 SELFDESTRUCT, Amsterdam BAL tracking, ...).
    spec: primitives.SpecId,
    /// Coinbase, precompiles and access list: addresses warm at transaction start.
    warm_addresses: WarmAddresses,
    /// EIP-7708 pending burns (see PendingBurn); checkpointed via burn_i.
    pending_burns: std.ArrayList(PendingBurn),

    // EIP-7928: addresses whose account was loaded via loadAccountMutOptionalCode
    // (the reference's get_account_optional). This is the reference's `account_reads`
    // set, which — unioned with account_writes and storage — determines BAL membership.
    // Crucially it EXCLUDES accounts merely created (never read), so a same-tx
    // create+selfdestruct ephemeral does not appear in the BAL. Block-scoped.
    bal_account_reads: std.HashMap(primitives.Address, void, primitives.AddressContext, 80),

    pub fn new() JournalInner {
        return .{
            .evm_state = state.EvmState.init(alloc_mod.get()),
            .transient_storage = state.TransientStorage.init(alloc_mod.get()),
            .logs = std.ArrayList(primitives.Log).empty,
            .journal = std.ArrayList(JournalEntry).empty,
            .tx_touched = std.ArrayList(primitives.Address).empty,
            .transaction_id = 0,
            .spec = primitives.SpecId.prague,
            .warm_addresses = WarmAddresses.new(),
            .pending_burns = std.ArrayList(PendingBurn).empty,
            .bal_account_reads = std.HashMap(primitives.Address, void, primitives.AddressContext, 80).init(alloc_mod.get()),
        };
    }

    pub fn deinit(self: *JournalInner) void {
        self.evm_state.deinit();
        self.transient_storage.deinit();
        for (self.logs.items) |log| log.deinit(alloc_mod.get());
        self.logs.deinit(alloc_mod.get());
        self.journal.deinit(alloc_mod.get());
        self.warm_addresses.deinit();
        self.pending_burns.deinit(alloc_mod.get());
        self.tx_touched.deinit(alloc_mod.get());
        self.bal_account_reads.deinit();
    }

    /// EIP-7928: returns true if the account was loaded (read) during the block —
    /// the reference's `account_reads` membership used for BAL inclusion.
    pub fn isAccountRead(self: *const JournalInner, address: primitives.Address) bool {
        return self.bal_account_reads.contains(address);
    }

    /// Returns the logs
    pub fn takeLogs(self: *JournalInner) std.ArrayList(primitives.Log) {
        const logs = self.logs;
        self.logs = std.ArrayList(primitives.Log).empty;
        return logs;
    }

    /// Keeps the current transaction's changes: promotes storage present values to original
    /// (EIP-2200), frees superseded code, clears the journal/transient storage/unclaimed logs
    /// and increments transaction_id.
    pub fn commitTx(self: *JournalInner) void {
        // EIP-2200: find written slots via the journal rather than a full evm_state scan.
        // Every slot whose present value changed this tx has a StorageChanged entry (reverted
        // ones are already gone); repeat entries for a slot are idempotent. Accounts created
        // AND selfdestructed in the same tx are skipped.
        for (self.journal.items) |entry| {
            const data = switch (entry) {
                .StorageChanged => |d| d,
                else => continue,
            };
            const acct = self.evm_state.getPtr(data.address) orelse continue;
            if (acct.status.created and acct.status.self_destructed) continue;
            const slot = acct.storage.getPtr(data.key) orelse continue;
            if (slot.present_value == slot.original_value) continue;
            // EIP-2200 (all forks): original_value becomes present_value at tx commit.
            slot.original_value = slot.present_value;
        }

        // Free superseded code from CodeChanged entries: it can no longer be restored and is
        // uniquely owned (see the CodeChanged revert case).
        for (self.journal.items) |entry| {
            if (entry == .CodeChanged) {
                if (entry.CodeChanged.old_code) |old| {
                    var old_code = old;
                    old_code.deinit();
                }
            }
        }

        self.transient_storage.clearRetainingCapacity();
        self.journal.clearRetainingCapacity();
        self.warm_addresses.clearCoinbaseAndAccessList();
        self.transaction_id += 1;
        // Free heap-allocated data/topics (in case takeLogs() was not called — e.g. failed tx)
        for (self.logs.items) |log| log.deinit(alloc_mod.get());
        self.logs.clearRetainingCapacity();
        self.pending_burns.clearRetainingCapacity();
    }

    /// Discard the current transaction, by reverting the journal entries and incrementing the transaction id.
    pub fn discardTx(self: *JournalInner) void {
        const is_spurious_dragon_enabled = primitives.isEnabledIn(self.spec, .spurious_dragon);

        // iterate over all journals entries and revert our global evm_state
        var i = self.journal.items.len;
        while (i > 0) {
            i -= 1;
            const entry = self.journal.swapRemove(i);
            entry.revert(&self.evm_state, &self.transient_storage, is_spurious_dragon_enabled);
        }

        self.transient_storage.clearRetainingCapacity();
        // Free heap-allocated data/topics before clearing the log list
        for (self.logs.items) |log| log.deinit(alloc_mod.get());
        self.logs.clearRetainingCapacity();
        self.pending_burns.clearRetainingCapacity();
        self.transaction_id += 1;
        self.warm_addresses.clearCoinbaseAndAccessList();
    }

    /// Takes the EvmState and resets the journal. Spec and the precompile bitset are kept.
    pub fn finalize(self: *JournalInner) state.EvmState {
        self.warm_addresses.clearCoinbaseAndAccessList();

        const evm_state = self.evm_state;
        self.evm_state = state.EvmState.init(alloc_mod.get());
        for (self.logs.items) |log| log.deinit(alloc_mod.get());
        self.logs.clearRetainingCapacity();
        self.pending_burns.clearRetainingCapacity();
        self.transient_storage.clearRetainingCapacity();
        self.journal.clearRetainingCapacity();
        self.tx_touched.clearRetainingCapacity();
        self.transaction_id = 0;

        return evm_state;
    }

    /// Return reference to state.
    pub fn getState(self: *JournalInner) *state.EvmState {
        return &self.evm_state;
    }

    /// Sets SpecId.
    pub fn setSpecId(self: *JournalInner, spec: primitives.SpecId) void {
        self.spec = spec;
    }

    /// Mark account as touched as only touched accounts will be added to state.
    /// This is especially important for evm_state clear where touched empty accounts needs to
    /// be removed from state.
    pub fn touch(self: *JournalInner, address: primitives.Address) void {
        if (self.evm_state.getPtr(address)) |account| {
            JournalInner.touchAccount(&self.journal, address, account);
        }
    }

    /// Mark account as touched.
    fn touchAccount(journal: *std.ArrayList(JournalEntry), address: primitives.Address, account: *state.Account) void {
        if (!account.isTouched()) {
            journal.append(alloc_mod.get(), JournalEntryFactory.accountTouched(address)) catch {};
            account.markTouch();
        }
    }

    /// Returns the already-loaded account; unreachable if it is not loaded.
    pub fn getAccount(self: JournalInner, address: primitives.Address) *const state.Account {
        return self.evm_state.get(address) orelse unreachable;
    }

    /// Sets code and its precomputed hash on a loaded account.
    pub fn setCodeWithHash(self: *JournalInner, address: primitives.Address, code: bytecode.Bytecode, hash: primitives.Hash) void {
        const account = self.evm_state.getPtr(address).?;
        JournalInner.touchAccount(&self.journal, address, account);

        // Capture the pre-change code so a revert restores it (EIP-7702 clear/re-delegation
        // reverts must put back the original delegation, not empty the account).
        self.journal.append(alloc_mod.get(), JournalEntryFactory.codeChanged(address, account.info.code, account.info.code_hash)) catch {};

        account.info.code_hash = hash;
        account.info.code = code;
    }

    /// Sets code on a loaded account. An EIP-7702 delegation to the zero address clears
    /// the code instead.
    pub fn setCode(self: *JournalInner, address: primitives.Address, code: bytecode.Bytecode) void {
        if (code == .eip7702) {
            if (std.mem.eql(u8, &code.eip7702.address, &[_]u8{0} ** 20)) {
                self.setCodeWithHash(address, bytecode.Bytecode.new(), primitives.KECCAK_EMPTY);
                return;
            }
        }

        const hash = code.hashSlow();
        self.setCodeWithHash(address, code, hash);
    }

    /// Journals the caller's upfront fee deduction (and nonce bump); the caller mutates
    /// the account itself.
    pub fn callerAccountingJournalEntry(self: *JournalInner, address: primitives.Address, old_balance: primitives.U256, bump_nonce: bool) void {
        self.journal.append(alloc_mod.get(), JournalEntryFactory.balanceChanged(address, old_balance)) catch {};
        self.journal.append(alloc_mod.get(), JournalEntryFactory.accountTouched(address)) catch {};

        if (bump_nonce) {
            self.journal.append(alloc_mod.get(), JournalEntryFactory.nonceChanged(address)) catch {};
        }
    }

    /// Loads the account, marks it touched and increments its balance; not journaled.
    pub fn balanceIncr(self: *JournalInner, db: anytype, address: primitives.Address, balance: primitives.U256) !void {
        const account = try self.loadAccountMut(db, address);
        account.data.account.incrBalance(balance);
    }

    /// Journals a nonce increment; the caller performs the increment itself.
    pub fn nonceBumpJournalEntry(self: *JournalInner, address: primitives.Address) void {
        self.journal.append(alloc_mod.get(), JournalEntryFactory.nonceChanged(address)) catch {};
    }

    /// Moves `balance` between two loaded accounts; returns OutOfFunds if the sender is short.
    pub fn transferLoaded(self: *JournalInner, from: primitives.Address, to: primitives.Address, balance: primitives.U256) ?TransferError {
        if (std.mem.eql(u8, &from, &to)) {
            const from_balance = self.evm_state.getPtr(to).?.info.balance;
            // Check if from balance is enough to transfer the balance.
            if (balance > from_balance) {
                return TransferError.OutOfFunds;
            }
            return null;
        }

        if (balance == 0) {
            JournalInner.touchAccount(&self.journal, to, self.evm_state.getPtr(to).?);
            return null;
        }

        // sub balance from
        const from_account = self.evm_state.getPtr(from).?;
        JournalInner.touchAccount(&self.journal, from, from_account);
        const from_balance = &from_account.info.balance;
        const from_balance_decr = std.math.sub(u256, from_balance.*, balance) catch return TransferError.OutOfFunds;
        from_balance.* = from_balance_decr;

        // add balance to
        const to_account = self.evm_state.getPtr(to).?;
        JournalInner.touchAccount(&self.journal, to, to_account);
        const to_balance = &to_account.info.balance;
        const to_balance_incr = std.math.add(u256, to_balance.*, balance) catch return TransferError.OverflowPayment;
        to_balance.* = to_balance_incr;

        // add journal entry
        self.journal.append(alloc_mod.get(), JournalEntryFactory.balanceTransfer(from, to, balance)) catch {};

        return null;
    }

    /// Loads both accounts, then transferLoaded.
    pub fn transfer(self: *JournalInner, db: anytype, from: primitives.Address, to: primitives.Address, balance: primitives.U256) !?TransferError {
        _ = try self.loadAccount(db, from);
        _ = try self.loadAccount(db, to);
        return self.transferLoaded(from, to, balance);
    }

    /// Takes a checkpoint, then creates the account at `target_address`: checks for a
    /// collision, marks it created, sets nonce 1 (Spurious Dragon+), and moves `balance`
    /// from the caller. On error the checkpoint is already reverted.
    ///
    /// Caller and target must already be loaded.
    pub fn createAccountCheckpoint(self: *JournalInner, caller: primitives.Address, target_address: primitives.Address, balance: primitives.U256, spec_id: primitives.SpecId) !JournalCheckpoint {
        const checkpoint = self.getCheckpoint();

        // Newly created account is present, as we just loaded it.
        const target_acc = self.evm_state.getPtr(target_address).?;
        const last_journal = &self.journal;

        // EIP-7610: CREATE fails if the target address already has non-empty code or non-zero nonce.
        // Pre-existing balance does NOT cause a collision — it is inherited by the new contract.
        if (!std.mem.eql(u8, &target_acc.info.code_hash, &primitives.KECCAK_EMPTY) or
            target_acc.info.nonce != 0)
        {
            self.checkpointRevert(checkpoint);
            return TransferError.CreateCollision;
        }

        const is_created_globally = target_acc.markCreatedLocally();

        // Reverting this entry also resets the nonce.
        last_journal.append(alloc_mod.get(), JournalEntryFactory.accountCreated(target_address, is_created_globally)) catch {};
        target_acc.info.code = null;
        // EIP-161: new contracts start at nonce 1.
        if (primitives.isEnabledIn(spec_id, .spurious_dragon)) {
            target_acc.info.nonce = 1;
        }

        // Touch it: pre-Spurious Dragon even an empty account is persisted.
        JournalInner.touchAccount(last_journal, target_address, target_acc);

        const new_balance = std.math.add(u256, target_acc.info.balance, balance) catch {
            self.checkpointRevert(checkpoint);
            return TransferError.OverflowPayment;
        };
        target_acc.info.balance = new_balance;

        // Decrement caller balance — if it underflows the value exceeds the caller's balance.
        const new_caller_balance = std.math.sub(u256, self.evm_state.getPtr(caller).?.info.balance, balance) catch {
            self.checkpointRevert(checkpoint);
            return TransferError.OutOfFunds;
        };
        self.evm_state.getPtr(caller).?.info.balance = new_caller_balance;

        last_journal.append(alloc_mod.get(), JournalEntryFactory.balanceTransfer(caller, target_address, balance)) catch {};

        return checkpoint;
    }

    /// Makes a checkpoint that in case of Revert can bring back evm_state to this point.
    pub fn getCheckpoint(self: *JournalInner) JournalCheckpoint {
        return JournalCheckpoint{
            .log_i = self.logs.items.len,
            .journal_i = self.journal.items.len,
            .burn_i = self.pending_burns.items.len,
        };
    }

    /// Commits the checkpoint (no-op: state accumulates until commitTx).
    pub fn checkpointCommit(self: *JournalInner) void {
        _ = self;
    }

    /// Code a CREATE deployed earlier in this transaction, by hash: the reference reads the
    /// transaction's own code writes before the pre-state, and the database only learns of
    /// them at commitTx. Reverted CREATEs are already gone from the journal. Returns a fresh
    /// analysis, since reverting the creator frees its jump table.
    fn createdCodeByHash(self: *const JournalInner, code_hash: primitives.Hash) ?bytecode.Bytecode {
        for (self.journal.items) |entry| {
            if (entry != .AccountCreated) continue;
            const acct = self.evm_state.get(entry.AccountCreated.address) orelse continue;
            const code = acct.info.code orelse continue;
            if (std.mem.eql(u8, &acct.info.code_hash, &code_hash))
                return bytecode.Bytecode.newLegacy(code.originalBytes());
        }
        return null;
    }

    /// Reverts all changes to evm_state until given checkpoint.
    pub fn checkpointRevert(self: *JournalInner, checkpoint: JournalCheckpoint) void {
        const is_spurious_dragon_enabled = primitives.isEnabledIn(self.spec, .spurious_dragon);
        // Free heap-allocated data/topics of logs being discarded by this revert.
        for (self.logs.items[checkpoint.log_i..]) |log| log.deinit(alloc_mod.get());
        self.logs.shrinkRetainingCapacity(checkpoint.log_i);
        // Revert EIP-7708 pending burns added since this checkpoint.
        self.pending_burns.shrinkRetainingCapacity(checkpoint.burn_i);

        // iterate over last N journals sets and revert our global evm_state
        if (checkpoint.journal_i < self.journal.items.len) {
            var i = self.journal.items.len;
            while (i > checkpoint.journal_i) {
                i -= 1;
                const entry = self.journal.swapRemove(i);
                entry.revert(&self.evm_state, &self.transient_storage, is_spurious_dragon_enabled);
            }
        }
    }

    // ─── EIP-7708 helpers ─────────────────────────────────────────────────────────

    /// EIP-7708: append a Transfer(from, to, amount) log. Addresses are left-padded to
    /// 32-byte topics.
    fn addEip7708TransferLog(self: *JournalInner, from: primitives.Address, to: primitives.Address, amount: primitives.U256) void {
        const alloc = alloc_mod.get();
        const topics = alloc.alloc(primitives.Hash, 3) catch @panic("out of memory");
        topics[0] = primitives.EIP7708_TRANSFER_TOPIC;
        topics[1] = std.mem.zeroes([32]u8);
        @memcpy(topics[1][12..], &from);
        topics[2] = std.mem.zeroes([32]u8);
        @memcpy(topics[2][12..], &to);
        const data = alloc.alloc(u8, 32) catch @panic("out of memory");
        const amount_bytes: [32]u8 = @bitCast(@byteSwap(amount));
        @memcpy(data, &amount_bytes);
        self.addLog(.{
            .address = primitives.EIP7708_LOG_ADDRESS,
            .topics = topics,
            .data = data,
        });
    }

    /// EIP-7708: Build and append a Burn(address, amount) log to the journal log list.
    fn addEip7708BurnLog(self: *JournalInner, addr: primitives.Address, amount: primitives.U256) void {
        const alloc = alloc_mod.get();
        const topics = alloc.alloc(primitives.Hash, 2) catch @panic("out of memory");
        topics[0] = primitives.EIP7708_BURN_TOPIC;
        topics[1] = std.mem.zeroes([32]u8);
        @memcpy(topics[1][12..], &addr);
        const data = alloc.alloc(u8, 32) catch @panic("out of memory");
        const amount_bytes: [32]u8 = @bitCast(@byteSwap(amount));
        @memcpy(data, &amount_bytes);
        self.addLog(.{
            .address = primitives.EIP7708_LOG_ADDRESS,
            .topics = topics,
            .data = data,
        });
    }

    /// EIP-7708: register an account for the deferred burn check in `emitBurnLogs()`.
    /// Currently has no callers: EIP-8246 removed the SELFDESTRUCT burn.
    fn addPendingBurn(self: *JournalInner, addr: primitives.Address, amount: primitives.U256) void {
        self.pending_burns.append(alloc_mod.get(), .{ .address = addr, .amount = amount }) catch {};
    }

    /// EIP-7708 finalization: emit a Burn log, in ascending address order, for each pending
    /// burn whose account holds a balance. postExecution calls it after the coinbase payment
    /// and before takeLogs() (EELS process_transaction order). No-op while `pending_burns`
    /// is never populated (see addPendingBurn).
    pub fn emitBurnLogs(self: *JournalInner) void {
        if (self.pending_burns.items.len == 0) return;
        std.mem.sort(PendingBurn, self.pending_burns.items, {}, struct {
            fn lessThan(_: void, a: PendingBurn, b: PendingBurn) bool {
                return std.mem.order(u8, &a.address, &b.address) == .lt;
            }
        }.lessThan);
        for (self.pending_burns.items) |burn| {
            const finalization_balance = if (self.evm_state.get(burn.address)) |acct|
                acct.info.balance
            else
                0;
            if (finalization_balance > 0) self.addEip7708BurnLog(burn.address, finalization_balance);
        }
        self.pending_burns.clearRetainingCapacity();
    }

    // ─── Selfdestruct ──────────────────────────────────────────────────────────────

    /// SELFDESTRUCT: moves the balance to `target` and marks the account destroyed (from
    /// Cancun, EIP-6780, only if it was created in this tx). Before Amsterdam a
    /// self-beneficiary destroy burns the balance; EIP-8246 keeps it.
    ///
    /// # References:
    ///  * <https://github.com/ethereum/go-ethereum/blob/141cd425310b503c5678e674a8c3872cf46b7086/core/vm/instructions.go#L832-L833>
    ///  * <https://github.com/ethereum/go-ethereum/blob/141cd425310b503c5678e674a8c3872cf46b7086/core/evm_state/evm_statedb.go#L449>
    ///  * <https://eips.ethereum.org/EIPS/eip-6780>
    pub fn selfdestruct(self: *JournalInner, db: anytype, address: primitives.Address, target: primitives.Address) !StateLoad(SelfDestructResult) {
        const spec = self.spec;
        const account_load = try self.loadAccount(db, target);
        const is_cold = account_load.is_cold;
        const is_empty = account_load.data.stateClearAwareIsEmpty(spec);

        if (!std.mem.eql(u8, &address, &target)) {
            // Both accounts are loaded before this point, `address` as we execute its contract.
            // and `target` at the beginning of the function.
            const acc_balance = self.evm_state.get(address).?.info.balance;

            const target_account = self.evm_state.getPtr(target).?;
            JournalInner.touchAccount(&self.journal, target, target_account);
            target_account.info.balance = std.math.add(u256, target_account.info.balance, acc_balance) catch unreachable;
        }

        const acc = self.evm_state.getPtr(address).?;
        const balance = acc.info.balance;

        const destroyed_status = if (!acc.isSelfdestructed())
            SelfdestructionRevertStatus.GloballySelfdestroyed
        else if (!acc.isSelfdestructedLocally())
            SelfdestructionRevertStatus.LocallySelfdestroyed
        else
            SelfdestructionRevertStatus.RepeatedSelfdestruction;

        const is_cancun_enabled = primitives.isEnabledIn(spec, .cancun);

        // EIP-6780 (Cancun hard-fork): selfdestruct only if contract is created in the same tx
        const journal_entry: ?JournalEntry = entry_blk: {
            if (acc.isCreatedLocally() or !is_cancun_enabled) {
                _ = acc.markSelfdestructedLocally();
                // EIP-8246 (Amsterdam+): SELFDESTRUCT no longer burns ETH. When the
                // beneficiary is the account itself, move_ether(self, self) is a no-op,
                // so the balance is preserved. For a different beneficiary the balance
                // was already added to the target above, so zeroing reflects that move.
                const preserve_self_balance = primitives.isEnabledIn(spec, .amsterdam) and std.mem.eql(u8, &address, &target);
                if (!preserve_self_balance) acc.info.balance = @as(primitives.U256, 0);
                break :entry_blk JournalEntryFactory.accountDestroyed(address, target, destroyed_status, balance);
            } else if (!std.mem.eql(u8, &address, &target)) {
                acc.info.balance = @as(primitives.U256, 0);
                break :entry_blk JournalEntryFactory.balanceTransfer(address, target, balance);
            } else {
                // State is not changed:
                // * if we are after Cancun upgrade and
                // * Selfdestruct account that is created in the same transaction and
                // * Specify the target is same as selfdestructed account. The balance stays unchanged.
                break :entry_blk null;
            }
        };

        if (journal_entry) |entry| {
            self.journal.append(alloc_mod.get(), entry) catch {};
        }

        // EIP-7708 (Amsterdam+): log a Transfer for ETH moved to a different beneficiary.
        // EIP-8246 removed the burn, so a self-beneficiary emits nothing.
        // Reference: execution-specs amsterdam/vm/instructions/system.py (selfdestruct).
        if (primitives.isEnabledIn(self.spec, .amsterdam)) {
            if (!std.mem.eql(u8, &address, &target) and balance > 0) {
                self.addEip7708TransferLog(address, target, balance);
            }
        }

        return StateLoad(SelfDestructResult).new(SelfDestructResult{
            .had_value = balance != 0,
            .target_exists = !is_empty,
            .previously_destroyed = destroyed_status == SelfdestructionRevertStatus.RepeatedSelfdestruction,
        }, is_cold);
    }

    /// Loads the account and marks it warm; `is_cold` reports the prior state.
    pub fn loadAccount(self: *JournalInner, db: anytype, address: primitives.Address) !StateLoad(*const state.Account) {
        return self.loadAccountOptional(db, address, false, false);
    }

    /// Loads the account with its code and marks it warm. An EIP-7702 delegation is not
    /// followed.
    pub fn loadCode(self: *JournalInner, db: anytype, address: primitives.Address) !StateLoad(*const state.Account) {
        return self.loadAccountOptional(db, address, true, false);
    }

    /// Check whether an address is cold WITHOUT loading it from the database.
    /// Used by opcode handlers to pre-check gas costs before committing to a DB load.
    pub fn isAddressCold(self: *const JournalInner, address: primitives.Address) bool {
        if (self.evm_state.get(address)) |acct| {
            if (acct.isColdTransactionId(self.transaction_id)) {
                // Account was loaded in a prior tx — defer to warm_addresses which covers
                // EIP-3651 coinbase, precompiles, and EIP-2930 access-list entries.
                return self.warm_addresses.isCold(address);
            }
            return false;
        }
        return self.warm_addresses.isCold(address);
    }

    pub fn loadAccountOptional(self: *JournalInner, db: anytype, address: primitives.Address, load_code: bool, skip_cold_load: bool) !StateLoad(*const state.Account) {
        const load = try self.loadAccountMutOptionalCode(db, address, load_code, skip_cold_load);
        return StateLoad(*const state.Account).new(load.data.account, load.is_cold);
    }

    /// Loads account into memory. If account is already loaded it will be marked as warm.
    pub fn loadAccountMut(self: *JournalInner, db: anytype, address: primitives.Address) !StateLoad(JournaledAccount) {
        return self.loadAccountMutOptionalCode(db, address, false, false);
    }

    /// Loads account. If account is already loaded it will be marked as warm.
    pub fn loadAccountMutOptionalCode(self: *JournalInner, db: anytype, address: primitives.Address, load_code: bool, skip_cold_load: bool) !StateLoad(JournaledAccount) {
        var is_cold: bool = undefined;
        var account_ptr: *state.Account = undefined;

        if (self.evm_state.getPtr(address)) |existing| {
            // Account already loaded — check warm/cold
            var acct_is_cold = existing.isColdTransactionId(self.transaction_id);
            if (acct_is_cold) {
                const should_be_cold = self.warm_addresses.isCold(address);
                if (should_be_cold and skip_cold_load) {
                    return JournalLoadError.ColdLoadSkipped;
                }
                acct_is_cold = should_be_cold;
                // transaction_id transitions to the current tx here, so this is
                // the account's first touch in it.
                _ = existing.markWarmWithTransactionId(self.transaction_id);
                if (primitives.isEnabledIn(self.spec, .amsterdam)) {
                    self.tx_touched.append(alloc_mod.get(), address) catch @panic("out of memory");
                }
                if (existing.isSelfdestructedLocally()) {
                    // EIP-8246 (Amsterdam+): SELFDESTRUCT no longer burns. A selfdestructed
                    // account that retains a non-zero balance is NOT deleted, so re-accessing
                    // it must preserve that balance (only code/storage/nonce are wiped).
                    // Pre-8246: the account is reborn empty (balance burned).
                    const preserved_balance: primitives.U256 = if (primitives.isEnabledIn(self.spec, .amsterdam)) existing.info.balance else 0;
                    existing.selfdestruct();
                    existing.info.balance = preserved_balance;
                    existing.unmarkSelfdestructedLocally();
                    // Clear the global self_destructed flag: when a new tx accesses a
                    // previously-selfdestructed account, it is reborn as an empty account.
                    existing.unmarkSelfdestruct();
                    // Mark that storage was wiped so post-state won't inherit pre-alloc storage.
                    existing.status.setStorageWiped();
                }
                if (existing.isCreatedLocally()) {
                    existing.unmarkCreatedLocally();
                }
            }
            is_cold = acct_is_cold;
            account_ptr = existing;
        } else {
            // Account not yet loaded — fetch from DB and insert.
            // EIP-7928 (Amsterdam+): record the account read here (reference
            // get_account_optional). This else branch is the sole evm_state insertion
            // path, so recording it covers every account exactly on its first load in the
            // block; warm re-accesses hit the branch above and are already in the set.
            // (Same-tx create+selfdestruct ephemerals reach this via setupCreateCore's
            // loadAccount, matching the reference — they are dropped later at BAL assembly.)
            if (primitives.isEnabledIn(self.spec, .amsterdam)) self.bal_account_reads.put(address, {}) catch {};
            const acct_is_cold = self.warm_addresses.isCold(address);
            if (acct_is_cold and skip_cold_load) {
                return JournalLoadError.ColdLoadSkipped;
            }
            const new_account = if (try db.basic(address)) |account_info|
                state.Account{
                    .info = account_info,
                    .storage = primitives.SlotMap(state.EvmStorageSlot).init(alloc_mod.get()),
                    .transaction_id = self.transaction_id,
                    .status = state.AccountStatus.empty(),
                }
            else
                state.Account.newNotExisting(self.transaction_id);
            const gop = try self.evm_state.getOrPut(address);
            gop.value_ptr.* = new_account;
            // Inserted with transaction_id = current, so also a first touch.
            if (primitives.isEnabledIn(self.spec, .amsterdam)) {
                self.tx_touched.append(alloc_mod.get(), address) catch @panic("out of memory");
            }
            is_cold = acct_is_cold;
            account_ptr = gop.value_ptr;
        }

        // Journal cold account load
        if (is_cold) {
            self.journal.append(alloc_mod.get(), JournalEntryFactory.accountWarmed(address)) catch {};
        }

        // Load code if requested and not yet loaded
        if (load_code and account_ptr.info.code == null) {
            const info = &account_ptr.info;
            const code = if (std.mem.eql(u8, &info.code_hash, &primitives.KECCAK_EMPTY))
                bytecode.Bytecode.new()
            else
                db.codeByHash(info.code_hash) catch |err| (self.createdCodeByHash(info.code_hash) orelse return err);
            info.code = code;
        }

        return StateLoad(JournaledAccount).new(
            JournaledAccount.new(address, account_ptr, &self.journal),
            is_cold,
        );
    }

    /// Check whether a storage slot is cold WITHOUT loading it from the database.
    pub fn isStorageCold(self: *const JournalInner, address: primitives.Address, key: primitives.StorageKey) bool {
        if (self.evm_state.get(address)) |acct| {
            if (acct.storage.get(key)) |slot| {
                var is_cold = slot.isColdTransactionId(self.transaction_id);
                if (is_cold and self.warm_addresses.isStorageWarm(address, key)) {
                    is_cold = false;
                }
                return is_cold;
            }
        }
        return !self.warm_addresses.isStorageWarm(address, key);
    }

    /// SLOAD's pre-charge probe. A slot already loaded and warm in this transaction returns its
    /// value: reading it has no side effects, so the caller skips `sload`. Otherwise `value` is
    /// null and `is_cold` is what `isStorageCold` would return.
    pub fn sloadProbe(self: *const JournalInner, address: primitives.Address, key: primitives.StorageKey) SloadProbe {
        if (self.evm_state.getPtr(address)) |acct| {
            if (acct.storage.getPtr(key)) |slot| {
                if (!slot.isColdTransactionId(self.transaction_id)) return .{ .value = slot.present_value, .is_cold = false };
            }
        }
        return .{ .value = null, .is_cold = !self.warm_addresses.isStorageWarm(address, key) };
    }

    /// Loads a storage slot and marks it warm. The account must already be loaded.
    pub fn sload(self: *JournalInner, db: anytype, address: primitives.Address, key: primitives.StorageKey, skip_cold_load: bool) !StateLoad(primitives.StorageValue) {
        const account = self.evm_state.getPtr(address).?;
        const is_newly_created = account.isCreated();

        // One probe for both outcomes: a miss leaves the entry reserved for the loaded value.
        const gop = try account.storage.getOrPut(key);
        if (gop.found_existing) {
            const slot = gop.value_ptr;
            var is_cold = slot.isColdTransactionId(self.transaction_id);
            // EIP-2930: an access-list slot is warm even before its first touch this tx.
            if (is_cold and self.warm_addresses.isStorageWarm(address, key)) {
                is_cold = false;
            }
            if (skip_cold_load and is_cold) {
                return JournalLoadError.ColdLoadSkipped;
            }
            _ = slot.markWarmWithTransactionId(self.transaction_id);
            if (is_cold) {
                self.journal.append(alloc_mod.get(), JournalEntryFactory.storageWarmed(address, key)) catch {};
            }
            return StateLoad(primitives.StorageValue).new(slot.present_value, is_cold);
        } else {
            // Storage slot not yet loaded — fetch from DB
            if (skip_cold_load) {
                account.storage.removeByPtr(gop.key_ptr);
                return JournalLoadError.ColdLoadSkipped;
            }
            // For newly-created accounts all storage is implicitly zero (no DB lookup needed).
            const value = if (is_newly_created) @as(primitives.StorageValue, 0) else db.storage(address, key) catch |err| {
                account.storage.removeByPtr(gop.key_ptr);
                return err;
            };
            gop.value_ptr.* = state.EvmStorageSlot.new(value, self.transaction_id);
            const is_cold = !self.warm_addresses.isStorageWarm(address, key);
            if (is_cold) {
                self.journal.append(alloc_mod.get(), JournalEntryFactory.storageWarmed(address, key)) catch {};
            }
            return StateLoad(primitives.StorageValue).new(value, is_cold);
        }
    }

    /// Stores a storage slot and returns its (original, present, new) values.
    /// The account must already be loaded.
    pub fn sstore(self: *JournalInner, db: anytype, address: primitives.Address, key: primitives.StorageKey, new_value: primitives.StorageValue, skip_cold_load: bool) !StateLoad(SStoreResult) {
        const present = try self.sload(db, address, key, skip_cold_load);
        const acc = self.evm_state.getPtr(address).?;

        const slot = acc.storage.getPtr(key).?;

        // No change: no journal entry (commitTx relies on this).
        if (present.data == new_value) {
            return StateLoad(SStoreResult).new(SStoreResult{
                .original_value = slot.originalValue(),
                .present_value = present.data,
                .new_value = new_value,
            }, present.is_cold);
        }

        self.journal.append(alloc_mod.get(), JournalEntryFactory.storageChanged(address, key, present.data, slot.was_written)) catch {};
        slot.present_value = new_value;
        slot.was_written = true;
        return StateLoad(SStoreResult).new(SStoreResult{
            .original_value = slot.originalValue(),
            .present_value = present.data,
            .new_value = new_value,
        }, present.is_cold);
    }

    /// Read transient storage tied to the account.
    ///
    /// EIP-1153: Transient storage opcodes
    pub fn tload(self: *JournalInner, address: primitives.Address, key: primitives.StorageKey) primitives.StorageValue {
        return self.transient_storage.get(.{ address, key }) orelse @as(primitives.StorageValue, 0);
    }

    /// Store transient storage tied to the account, journaling any change (EIP-1153).
    pub fn tstore(self: *JournalInner, address: primitives.Address, key: primitives.StorageKey, new_value: primitives.StorageValue) void {
        const previous_value = self.transient_storage.get(.{ address, key }) orelse @as(primitives.StorageValue, 0);

        if (new_value == 0) {
            // Remove entry from transient storage; journal only if there was a previous value.
            _ = self.transient_storage.remove(.{ address, key });
            if (previous_value != 0) {
                self.journal.append(alloc_mod.get(), JournalEntryFactory.transientStorageChanged(address, key, previous_value)) catch {};
            }
        } else {
            self.transient_storage.put(.{ address, key }, new_value) catch {};
            if (previous_value != new_value) {
                self.journal.append(alloc_mod.get(), JournalEntryFactory.transientStorageChanged(address, key, previous_value)) catch {};
            }
        }
    }

    /// Pushes log into subroutine.
    pub fn addLog(self: *JournalInner, log_entry: primitives.Log) void {
        self.logs.append(alloc_mod.get(), log_entry) catch {};
    }
};

/// Journaled EVM state over a database. One flat journal per transaction; a call frame's
/// changes are reverted by unwinding to the JournalCheckpoint taken at its start.
pub fn Journal(comptime DB: type) type {
    return struct {
        /// Database
        database: DB,
        /// Inner journal state.
        inner: JournalInner,

        pub fn new(db: DB) @This() {
            return .{
                .database = db,
                .inner = JournalInner.new(),
            };
        }

        pub fn deinit(self: *@This()) void {
            self.inner.deinit();
        }

        /// Wraps an existing JournalInner (state, logs, ...) around a different database.
        pub fn newWithInner(db: DB, inner: JournalInner) @This() {
            return .{ .database = db, .inner = inner };
        }

        /// Returns the inner journal by value (no clone).
        pub fn intoInit(self: @This()) JournalInner {
            return self.inner;
        }

        /// Same as intoInit: returns the inner journal by value; nothing is cloned.
        pub fn toInner(self: @This()) JournalInner {
            return self.inner;
        }

        pub fn getDb(self: *const @This()) *const DB {
            return &self.database;
        }

        pub fn getDbMut(self: *@This()) *DB {
            return &self.database;
        }

        pub fn sloadProbe(self: *const @This(), address: primitives.Address, key: primitives.StorageKey) SloadProbe {
            return self.inner.sloadProbe(address, key);
        }

        pub fn sload(self: *@This(), address: primitives.Address, key: primitives.StorageKey) !StateLoad(primitives.StorageValue) {
            return self.inner.sload(self.getDbMut(), address, key, false);
        }

        pub fn sstore(self: *@This(), address: primitives.Address, key: primitives.StorageKey, value: primitives.StorageValue) !StateLoad(SStoreResult) {
            return self.inner.sstore(self.getDbMut(), address, key, value, false);
        }

        pub fn tload(self: *@This(), address: primitives.Address, key: primitives.StorageKey) primitives.StorageValue {
            return self.inner.tload(address, key);
        }

        pub fn tstore(self: *@This(), address: primitives.Address, key: primitives.StorageKey, value: primitives.StorageValue) void {
            self.inner.tstore(address, key, value);
        }

        pub fn log(self: *@This(), log_entry: primitives.Log) void {
            self.inner.addLog(log_entry);
        }

        pub fn selfdestruct(self: *@This(), address: primitives.Address, target: primitives.Address) !StateLoad(SelfDestructResult) {
            return self.inner.selfdestruct(self.getDbMut(), address, target);
        }

        pub fn warmAccessList(self: *@This(), access_list: std.HashMap(primitives.Address, std.ArrayList(primitives.StorageKey), primitives.AddressContext, 80)) !void {
            try self.inner.warm_addresses.setAccessList(access_list);
        }

        pub fn warmCoinbaseAccount(self: *@This(), address: primitives.Address) void {
            self.inner.warm_addresses.setCoinbase(address);
        }

        pub fn setSpecId(self: *@This(), spec_id: primitives.SpecId) void {
            self.inner.setSpecId(spec_id);
        }

        pub fn transfer(self: *@This(), from: primitives.Address, to: primitives.Address, balance: primitives.U256) !?TransferError {
            return self.inner.transfer(self.getDbMut(), from, to, balance);
        }

        pub fn transferLoaded(self: *@This(), from: primitives.Address, to: primitives.Address, balance: primitives.U256) ?TransferError {
            return self.inner.transferLoaded(from, to, balance);
        }

        pub fn touchAccount(self: *@This(), address: primitives.Address) void {
            self.inner.touch(address);
        }

        pub fn callerAccountingJournalEntry(self: *@This(), address: primitives.Address, old_balance: primitives.U256, bump_nonce: bool) void {
            self.inner.callerAccountingJournalEntry(address, old_balance, bump_nonce);
        }

        /// Increments the balance of the account.
        pub fn balanceIncr(self: *@This(), address: primitives.Address, balance: primitives.U256) !void {
            try self.inner.balanceIncr(self.getDbMut(), address, balance);
        }

        /// Journals a nonce increment; the caller performs the increment itself.
        pub fn nonceBumpJournalEntry(self: *@This(), address: primitives.Address) void {
            self.inner.nonceBumpJournalEntry(address);
        }

        pub fn loadAccount(self: *@This(), address: primitives.Address) !StateLoad(*const state.Account) {
            return self.inner.loadAccount(self.getDbMut(), address);
        }

        pub fn loadAccountMutOptionalCode(self: *@This(), address: primitives.Address, load_code: bool, skip_cold_load: bool) !StateLoad(JournaledAccount) {
            return self.inner.loadAccountMutOptionalCode(self.getDbMut(), address, load_code, skip_cold_load);
        }

        pub fn loadAccountWithCode(self: *@This(), address: primitives.Address) !StateLoad(*const state.Account) {
            return self.inner.loadCode(self.getDbMut(), address);
        }

        pub fn loadAccountDelegated(self: *@This(), address: primitives.Address) !StateLoad(AccountLoad) {
            return self.inner.loadAccountDelegated(self.getDbMut(), address);
        }

        pub fn getCheckpoint(self: *@This()) JournalCheckpoint {
            return self.inner.getCheckpoint();
        }

        pub fn checkpointCommit(self: *@This()) void {
            self.inner.checkpointCommit();
        }

        pub fn checkpointRevert(self: *@This(), checkpoint: JournalCheckpoint) void {
            self.inner.checkpointRevert(checkpoint);
        }

        pub fn setCodeWithHash(self: *@This(), address: primitives.Address, code: bytecode.Bytecode, hash: primitives.Hash) void {
            self.inner.setCodeWithHash(address, code, hash);
        }

        /// EIP-7702: install a delegation designator, as inner.setCode does. The reference
        /// keys code by hash, so the designator is then readable by hash for the rest of the
        /// block: an account delegated to the same target in pre-state reads this code
        /// without it being in the witness.
        pub fn setDelegation(self: *@This(), address: primitives.Address, code: bytecode.Bytecode) void {
            self.inner.setCode(address, code);
            if (comptime @hasDecl(DB, "notifyCodeDeployed")) {
                const info = self.inner.evm_state.get(address).?.info;
                if (!info.isEmptyCodeHash()) self.database.notifyCodeDeployed(info.code_hash, code);
            }
        }

        pub fn createAccountCheckpoint(self: *@This(), caller: primitives.Address, address: primitives.Address, balance: primitives.U256, spec_id: primitives.SpecId) !JournalCheckpoint {
            return self.inner.createAccountCheckpoint(caller, address, balance, spec_id);
        }

        pub fn takeLogs(self: *@This()) std.ArrayList(primitives.Log) {
            return self.inner.takeLogs();
        }

        /// EIP-7708: Emit a Transfer log (Amsterdam+). Caller must already have verified
        /// that `from != to` and `amount > 0` and that the spec is Amsterdam or later.
        pub fn emitTransferLog(self: *@This(), from: primitives.Address, to: primitives.Address, amount: primitives.U256) void {
            self.inner.addEip7708TransferLog(from, to, amount);
        }

        /// See JournalInner.emitBurnLogs.
        pub fn emitBurnLogs(self: *@This()) void {
            self.inner.emitBurnLogs();
        }

        pub fn commitTx(self: *@This()) void {
            // Notify the DB of code deployed by this tx's CREATEs, found via the journal
            // rather than a scan of evm_state. Reverted CREATEs are already out of the journal.
            if (comptime @hasDecl(DB, "notifyCodeDeployed")) {
                for (self.inner.journal.items) |entry| {
                    switch (entry) {
                        .AccountCreated => |data| {
                            if (self.inner.evm_state.get(data.address)) |acct| {
                                if (acct.info.code) |code| {
                                    if (!acct.info.isEmptyCodeHash()) {
                                        self.database.notifyCodeDeployed(acct.info.code_hash, code);
                                    }
                                }
                            }
                        },
                        else => {},
                    }
                }
            }
            self.inner.commitTx();
        }

        pub fn discardTx(self: *@This()) void {
            self.inner.discardTx();
        }

        /// Takes the EvmState and resets the journal.
        pub fn finalize(self: *@This()) state.EvmState {
            return self.inner.finalize();
        }

        pub fn sloadSkipColdLoad(self: *@This(), address: primitives.Address, key: primitives.StorageKey, skip_cold_load: bool) !StateLoad(primitives.StorageValue) {
            return self.inner.sload(self.getDbMut(), address, key, skip_cold_load);
        }

        pub fn sstoreSkipColdLoad(self: *@This(), address: primitives.Address, key: primitives.StorageKey, value: primitives.StorageValue, skip_cold_load: bool) !StateLoad(SStoreResult) {
            return self.inner.sstore(self.getDbMut(), address, key, value, skip_cold_load);
        }

        /// Check whether an address is cold WITHOUT loading it from the database.
        pub fn isAddressCold(self: *const @This(), address: primitives.Address) bool {
            return self.inner.isAddressCold(address);
        }

        /// Check whether a storage slot is cold WITHOUT loading it from the database.
        pub fn isStorageCold(self: *const @This(), address: primitives.Address, key: primitives.StorageKey) bool {
            return self.inner.isStorageCold(address, key);
        }

        /// Returns true if the address has any non-zero storage in the DB.
        /// Used by CREATE collision check; returns false for DB types without this method.
        ///
        /// Propagates on a database error rather than answering "no storage here":
        /// that would let a CREATE succeed at an address the reference rejects. The
        /// caller (which owns ctx_error) marks the block invalid. Infallible
        /// databases (InMemoryDB) are unaffected.
        pub fn hasNonZeroStorageForAddress(self: *const @This(), addr: primitives.Address) !bool {
            if (comptime @hasDecl(DB, "hasNonZeroStorageForAddress")) {
                return self.getDb().hasNonZeroStorageForAddress(addr);
            }
            return false;
        }

        /// Whether the address is already in the EVM state cache (loaded earlier in the block).
        pub fn isAddressLoaded(self: *const @This(), address: primitives.Address) bool {
            return self.inner.evm_state.contains(address);
        }

        pub fn loadAccountInfoSkipColdLoad(self: *@This(), address: primitives.Address, load_code: bool, skip_cold_load: bool) !AccountInfoLoad {
            const spec = self.inner.spec;
            const account = try self.inner.loadAccountOptional(self.getDbMut(), address, load_code, skip_cold_load);
            return AccountInfoLoad.new(@constCast(&account.data.info), account.is_cold, account.data.stateClearAwareIsEmpty(spec));
        }
    };
}
