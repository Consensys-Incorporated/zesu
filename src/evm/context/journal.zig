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

    pub fn codeChanged(address: primitives.Address) JournalEntry {
        return JournalEntry{ .CodeChanged = address };
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

/// Pre-block account state snapshot for EIP-7928 BAL tracking.
pub const AccountPreState = struct {
    nonce: u64 = 0,
    balance: primitives.U256 = @as(primitives.U256, 0),
    code_hash: primitives.Hash = primitives.KECCAK_EMPTY,
};

/// Block Access List log produced after all txs complete.
/// Ownership of the maps is transferred by `JournalInner.takeAccessLog()`.
pub const AccessLog = struct {
    /// Pre-block account states (nonce, balance, code_hash) for all accessed addresses.
    accounts: std.HashMap(primitives.Address, AccountPreState, primitives.AddressContext, 80),
    /// Pre-block storage values for all accessed slots.
    storage: std.HashMap(primitives.Address, std.AutoHashMap(primitives.StorageKey, primitives.StorageValue), primitives.AddressContext, 80),
    /// Slots that were committed to a value different from the pre-block value at any tx boundary.
    /// Used to distinguish storageChanges from storageReads for cross-tx net-zero writes.
    committed_changed: std.HashMap(primitives.Address, std.AutoHashMap(primitives.StorageKey, void), primitives.AddressContext, 80),

    pub fn deinit(self: *@This()) void {
        self.accounts.deinit();
        var sit = self.storage.valueIterator();
        while (sit.next()) |m| m.deinit();
        self.storage.deinit();
        var cit = self.committed_changed.valueIterator();
        while (cit.next()) |m| m.deinit();
        self.committed_changed.deinit();
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
    CodeChanged: primitives.Address,
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
            .CodeChanged => |address| {
                if (evm_state.getPtr(address)) |account| {
                    account.info.code = null;
                    account.info.code_hash = primitives.KECCAK_EMPTY;
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
    precompiles: std.ArrayList(primitives.Address),
    access_list: std.HashMap(primitives.Address, std.ArrayList(primitives.StorageKey), primitives.AddressContext, 80),

    pub fn new() WarmAddresses {
        return .{
            .coinbase = null,
            .precompiles = std.ArrayList(primitives.Address).empty,
            .access_list = std.HashMap(primitives.Address, std.ArrayList(primitives.StorageKey), primitives.AddressContext, 80).init(alloc_mod.get()),
        };
    }

    pub fn deinit(self: *WarmAddresses) void {
        self.precompiles.deinit(alloc_mod.get());
        var iterator = self.access_list.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit(alloc_mod.get());
        }
        self.access_list.deinit();
    }

    pub fn setCoinbase(self: *WarmAddresses, address: primitives.Address) void {
        self.coinbase = address;
    }

    pub fn setPrecompileAddresses(self: *WarmAddresses, addresses: []const primitives.Address) !void {
        self.precompiles.clearRetainingCapacity();
        try self.precompiles.appendSlice(alloc_mod.get(), addresses);
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

        // Check if address is precompile
        for (self.precompiles.items) |precompile| {
            if (std.mem.eql(u8, &address, &precompile)) {
                return false;
            }
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

    pub fn getPrecompiles(self: *const WarmAddresses) []const primitives.Address {
        return self.precompiles.items;
    }
};

/// Journal checkpoint
pub const JournalCheckpoint = struct {
    log_i: usize,
    journal_i: usize,
    /// Index into JournalInner.pending_burns at checkpoint time (for EIP-7708 revert).
    burn_i: usize,
};

/// EIP-7708 deferred burn entry.
///
/// Tracks an account in `accounts_to_delete` that may receive ETH after its SELFDESTRUCT opcode
/// executes and before the transaction finalizes (e.g. a payer contract calling into the already-
/// destructed address, or the coinbase receiving its priority fee).  These accounts are added to
/// `pending_burns` at SELFDESTRUCT time; `emitBurnLogs()` re-reads their balance after the
/// coinbase payment and emits a Burn log for any non-zero remainder.
///
/// `amount` is unused — it is kept for potential future use (e.g. assertions) but the finalization
/// path always reads the live balance from `evm_state`.
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
    /// Slot is not yet loaded from DB and is pre-warmed via EIP-2930 access list.
    /// Caller should charge WARM_SLOAD cost then call sload normally.
    WarmPreloadSkipped,
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
    /// The journal of evm_state changes, one for each transaction
    journal: std.ArrayList(JournalEntry),
    /// Global transaction id that represent number of transactions executed (Including reverted ones).
    /// It can be different from number of `journal_history` as some transaction could be
    /// reverted or had a error on execution.
    ///
    /// This ID is used in `Self::evm_state` to determine if account/storage is touched/warm/cold.
    transaction_id: usize,
    /// The spec ID for the EVM. Spec is required for some journal entries and needs to be set for
    /// JournalInner to be functional.
    ///
    /// If spec is set it assumed that precompile addresses are set as well for this particular spec.
    ///
    /// This spec is used for two things:
    ///
    /// - EIP-161: Prior to this EIP, Ethereum had separate definitions for empty and non-existing accounts.
    /// - EIP-6780: `SELFDESTRUCT` only in same transaction
    spec: primitives.SpecId,
    /// Warm addresses containing both coinbase and current precompiles.
    warm_addresses: WarmAddresses,
    /// EIP-7708: pending burn entries for same-tx-created accounts that selfdestructed to self.
    /// Emitted as Burn logs at postExecution, sorted by address. Checkpointed via burn_i.
    pending_burns: std.ArrayList(PendingBurn),

    // ── EIP-7928 BAL tracking ──────────────────────────────────────────────────
    // Permanently committed account pre-states (survive across txs in a block).
    bal_pre_accounts: std.HashMap(primitives.Address, AccountPreState, primitives.AddressContext, 80),
    // Permanently committed storage pre-states.
    bal_pre_storage: std.HashMap(primitives.Address, std.AutoHashMap(primitives.StorageKey, primitives.StorageValue), primitives.AddressContext, 80),
    // Per-tx staging: flushed on commitTx, cleared on discardTx.
    bal_pending_accounts: std.HashMap(primitives.Address, AccountPreState, primitives.AddressContext, 80),
    bal_pending_storage: std.HashMap(primitives.Address, std.AutoHashMap(primitives.StorageKey, primitives.StorageValue), primitives.AddressContext, 80),
    // Slots committed to a non-pre-block value at any tx boundary.
    bal_committed_changed: std.HashMap(primitives.Address, std.AutoHashMap(primitives.StorageKey, void), primitives.AddressContext, 80),

    pub fn new() JournalInner {
        return .{
            .evm_state = state.EvmState.init(alloc_mod.get()),
            .transient_storage = state.TransientStorage.init(alloc_mod.get()),
            .logs = std.ArrayList(primitives.Log).empty,
            .journal = std.ArrayList(JournalEntry).empty,
            .transaction_id = 0,
            .spec = primitives.SpecId.prague,
            .warm_addresses = WarmAddresses.new(),
            .pending_burns = std.ArrayList(PendingBurn).empty,
            .bal_pre_accounts = std.HashMap(primitives.Address, AccountPreState, primitives.AddressContext, 80).init(alloc_mod.get()),
            .bal_pre_storage = std.HashMap(primitives.Address, std.AutoHashMap(primitives.StorageKey, primitives.StorageValue), primitives.AddressContext, 80).init(alloc_mod.get()),
            .bal_pending_accounts = std.HashMap(primitives.Address, AccountPreState, primitives.AddressContext, 80).init(alloc_mod.get()),
            .bal_pending_storage = std.HashMap(primitives.Address, std.AutoHashMap(primitives.StorageKey, primitives.StorageValue), primitives.AddressContext, 80).init(alloc_mod.get()),
            .bal_committed_changed = std.HashMap(primitives.Address, std.AutoHashMap(primitives.StorageKey, void), primitives.AddressContext, 80).init(alloc_mod.get()),
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
        self.bal_pre_accounts.deinit();
        var pre_sit = self.bal_pre_storage.valueIterator();
        while (pre_sit.next()) |m| m.deinit();
        self.bal_pre_storage.deinit();
        self.bal_pending_accounts.deinit();
        var pend_sit = self.bal_pending_storage.valueIterator();
        while (pend_sit.next()) |m| m.deinit();
        self.bal_pending_storage.deinit();
        var cc_it = self.bal_committed_changed.valueIterator();
        while (cc_it.next()) |m| m.deinit();
        self.bal_committed_changed.deinit();
    }

    // ── EIP-7928 BAL tracking helpers ─────────────────────────────────────────

    /// Record an account at its pre-block state (null = non-existent account).
    /// Uses first-access-wins: if the address is already in pre or pending, skip.
    fn recordAccountAccess(self: *JournalInner, address: primitives.Address, info: ?state.AccountInfo) void {
        if (self.bal_pre_accounts.contains(address) or self.bal_pending_accounts.contains(address)) return;
        const pre: AccountPreState = if (info) |i| .{
            .nonce = i.nonce,
            .balance = i.balance,
            .code_hash = i.code_hash,
        } else .{};
        self.bal_pending_accounts.put(address, pre) catch {};
    }

    /// Record a storage slot at its pre-block value.
    /// Uses first-access-wins per slot.
    fn recordStorageAccess(self: *JournalInner, address: primitives.Address, key: primitives.StorageKey, value: primitives.StorageValue) void {
        // Check permanent pre_storage first
        if (self.bal_pre_storage.get(address)) |slots| {
            if (slots.contains(key)) return;
        }
        // Check pending
        if (self.bal_pending_storage.get(address)) |slots| {
            if (slots.contains(key)) return;
        }
        const gop = self.bal_pending_storage.getOrPut(address) catch return;
        if (!gop.found_existing) gop.value_ptr.* = std.AutoHashMap(primitives.StorageKey, primitives.StorageValue).init(alloc_mod.get());
        gop.value_ptr.put(key, value) catch {};
    }

    /// Returns true if the address has been accessed (appears in the BAL).
    /// Phantom accesses are prevented at the opcode level, so all tracked addresses are legitimate.
    pub fn isTrackedAddress(self: *const JournalInner, address: primitives.Address) bool {
        return self.bal_pre_accounts.contains(address) or self.bal_pending_accounts.contains(address);
    }

    /// Drain the accumulated Block Access Log. Flushes any remaining pending state
    /// into the permanent maps and transfers ownership to the caller.
    pub fn takeAccessLog(self: *JournalInner) AccessLog {
        // Flush remaining pending (e.g. if called after last tx without commitTx)
        var pa_it = self.bal_pending_accounts.iterator();
        while (pa_it.next()) |e| {
            if (!self.bal_pre_accounts.contains(e.key_ptr.*)) {
                self.bal_pre_accounts.put(e.key_ptr.*, e.value_ptr.*) catch {};
            }
        }
        self.bal_pending_accounts.clearRetainingCapacity();

        var ps_it = self.bal_pending_storage.iterator();
        while (ps_it.next()) |e| {
            const addr = e.key_ptr.*;
            var slot_it = e.value_ptr.iterator();
            while (slot_it.next()) |s| {
                const pre_gop = self.bal_pre_storage.getOrPut(addr) catch continue;
                if (!pre_gop.found_existing) pre_gop.value_ptr.* = std.AutoHashMap(primitives.StorageKey, primitives.StorageValue).init(alloc_mod.get());
                if (!pre_gop.value_ptr.contains(s.key_ptr.*)) {
                    pre_gop.value_ptr.put(s.key_ptr.*, s.value_ptr.*) catch {};
                }
            }
            e.value_ptr.deinit();
        }
        self.bal_pending_storage.clearRetainingCapacity();

        const log = AccessLog{
            .accounts = self.bal_pre_accounts,
            .storage = self.bal_pre_storage,
            .committed_changed = self.bal_committed_changed,
        };
        self.bal_pre_accounts = std.HashMap(primitives.Address, AccountPreState, primitives.AddressContext, 80).init(alloc_mod.get());
        self.bal_pre_storage = std.HashMap(primitives.Address, std.AutoHashMap(primitives.StorageKey, primitives.StorageValue), primitives.AddressContext, 80).init(alloc_mod.get());
        self.bal_committed_changed = std.HashMap(primitives.Address, std.AutoHashMap(primitives.StorageKey, void), primitives.AddressContext, 80).init(alloc_mod.get());
        return log;
    }

    /// Returns the logs
    pub fn takeLogs(self: *JournalInner) std.ArrayList(primitives.Log) {
        const logs = self.logs;
        self.logs = std.ArrayList(primitives.Log).empty;
        return logs;
    }

    /// Prepare for next transaction, by committing the current journal to history, incrementing the transaction id
    /// and returning the logs.
    ///
    /// This function is used to prepare for next transaction. It will save the current journal
    /// and clear the journal for the next transaction.
    ///
    /// `commit_tx` is used even for discarding transactions so transaction_id will be incremented.
    pub fn commitTx(self: *JournalInner) void {
        // EIP-7928 + EIP-2200: single journal pass instead of two full evm_state scans.
        //
        // Correctness: StorageChanged is appended only when present_value actually changes
        // (sstore bails early if present == new). Reverted entries are swapRemoved before
        // this runs. A slot written N times has N entries; the first entry that sees
        // present != original records + resets; subsequent entries see original == present
        // and skip — idempotent.
        //
        // EIP-7928: slots where present != original at commit boundary are flagged in
        // bal_committed_changed so cross-tx net-zero writes are storageChanges, not reads.
        // Skip accounts created AND selfdestructed in the same tx (net zero effect).
        for (self.journal.items) |entry| {
            const data = switch (entry) {
                .StorageChanged => |d| d,
                else => continue,
            };
            const acct = self.evm_state.getPtr(data.address) orelse continue;
            if (acct.status.created and acct.status.self_destructed) continue;
            const slot = acct.storage.getPtr(data.key) orelse continue;
            if (slot.present_value == slot.original_value) continue;
            // EIP-7928: record cross-tx dirty slot.
            const gop = self.bal_committed_changed.getOrPut(data.address) catch continue;
            if (!gop.found_existing) gop.value_ptr.* = std.AutoHashMap(primitives.StorageKey, void).init(alloc_mod.get());
            gop.value_ptr.put(data.key, {}) catch {};
            // EIP-2200: original_value becomes present_value at tx commit.
            slot.original_value = slot.present_value;
        }

        // EIP-7928: flush per-tx pending into permanent pre-state maps (first-access-wins).
        {
            var pa_it = self.bal_pending_accounts.iterator();
            while (pa_it.next()) |e| {
                if (!self.bal_pre_accounts.contains(e.key_ptr.*)) {
                    self.bal_pre_accounts.put(e.key_ptr.*, e.value_ptr.*) catch {};
                }
            }
            self.bal_pending_accounts.clearRetainingCapacity();

            var ps_it = self.bal_pending_storage.iterator();
            while (ps_it.next()) |e| {
                const addr = e.key_ptr.*;
                var slot_it = e.value_ptr.iterator();
                while (slot_it.next()) |s| {
                    const pre_gop = self.bal_pre_storage.getOrPut(addr) catch continue;
                    if (!pre_gop.found_existing) pre_gop.value_ptr.* = std.AutoHashMap(primitives.StorageKey, primitives.StorageValue).init(alloc_mod.get());
                    if (!pre_gop.value_ptr.contains(s.key_ptr.*)) {
                        pre_gop.value_ptr.put(s.key_ptr.*, s.value_ptr.*) catch {};
                    }
                }
                e.value_ptr.deinit();
            }
            self.bal_pending_storage.clearRetainingCapacity();
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
        // EIP-7928: discard per-tx pending tracking; pre_* survives (from prior txs).
        self.bal_pending_accounts.clearRetainingCapacity();
        var ps_it = self.bal_pending_storage.valueIterator();
        while (ps_it.next()) |m| m.deinit();
        self.bal_pending_storage.clearRetainingCapacity();
    }

    /// Take the [`EvmState`] and clears the journal by resetting it to initial state.
    ///
    /// Note: Precompile addresses and spec are preserved and initial evm_state of
    /// warm_preloaded_addresses will contain precompiles addresses.
    pub fn finalize(self: *JournalInner) state.EvmState {
        self.warm_addresses.clearCoinbaseAndAccessList();

        const evm_state = self.evm_state;
        self.evm_state = state.EvmState.init(alloc_mod.get());
        for (self.logs.items) |log| log.deinit(alloc_mod.get());
        self.logs.clearRetainingCapacity();
        self.pending_burns.clearRetainingCapacity();
        self.transient_storage.clearRetainingCapacity();
        self.journal.clearRetainingCapacity();
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

    /// Returns the _loaded_ [Account] for the given address.
    ///
    /// This assumes that the account has already been loaded.
    ///
    /// # Panics
    ///
    /// Panics if the account has not been loaded and is missing from the evm_state set.
    pub fn getAccount(self: JournalInner, address: primitives.Address) *const state.Account {
        return self.evm_state.get(address) orelse unreachable;
    }

    /// Set code and its hash to the account.
    ///
    /// Note: Assume account is warm and that hash is calculated from code.
    pub fn setCodeWithHash(self: *JournalInner, address: primitives.Address, code: bytecode.Bytecode, hash: primitives.Hash) void {
        const account = self.evm_state.getPtr(address).?;
        JournalInner.touchAccount(&self.journal, address, account);

        self.journal.append(alloc_mod.get(), JournalEntryFactory.codeChanged(address)) catch {};

        account.info.code_hash = hash;
        account.info.code = code;
    }

    /// Use it only if you know that acc is warm.
    ///
    /// Assume account is warm.
    ///
    /// In case of EIP-7702 code with zero address, the bytecode will be erased.
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

    /// Add journal entry for caller accounting.
    pub fn callerAccountingJournalEntry(self: *JournalInner, address: primitives.Address, old_balance: primitives.U256, bump_nonce: bool) void {
        // account balance changed.
        self.journal.append(alloc_mod.get(), JournalEntryFactory.balanceChanged(address, old_balance)) catch {};
        // account is touched.
        self.journal.append(alloc_mod.get(), JournalEntryFactory.accountTouched(address)) catch {};

        if (bump_nonce) {
            // nonce changed.
            self.journal.append(alloc_mod.get(), JournalEntryFactory.nonceChanged(address)) catch {};
        }
    }

    /// Increments the balance of the account.
    ///
    /// Mark account as touched.
    pub fn balanceIncr(self: *JournalInner, db: anytype, address: primitives.Address, balance: primitives.U256) !void {
        const account = try self.loadAccountMut(db, address);
        account.data.account.incrBalance(balance);
    }

    /// Increments the nonce of the account.
    pub fn nonceBumpJournalEntry(self: *JournalInner, address: primitives.Address) void {
        self.journal.append(alloc_mod.get(), JournalEntryFactory.nonceChanged(address)) catch {};
    }

    /// Transfers balance from two accounts. Returns error if sender balance is not enough.
    ///
    /// # Panics
    ///
    /// Panics if from or to are not loaded.
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

    /// Transfers balance from two accounts. Returns error if sender balance is not enough.
    pub fn transfer(self: *JournalInner, db: anytype, from: primitives.Address, to: primitives.Address, balance: primitives.U256) !?TransferError {
        _ = try self.loadAccount(db, from);
        _ = try self.loadAccount(db, to);
        return self.transferLoaded(from, to, balance);
    }

    /// Creates account or returns false if collision is detected.
    ///
    /// There are few steps done:
    /// 1. Make created account warm loaded (AccessList) and this should
    ///    be done before subroutine checkpoint is created.
    /// 2. Check if there is collision of newly created account with existing one.
    /// 3. Mark created account as created.
    /// 4. Add fund to created account
    /// 5. Increment nonce of created account if SpuriousDragon is active
    /// 6. Decrease balance of caller account.
    ///
    /// # Panics
    ///
    /// Panics if the caller is not loaded inside the EVM state.
    /// This should have been done inside `create_inner`.
    pub fn createAccountCheckpoint(self: *JournalInner, caller: primitives.Address, target_address: primitives.Address, balance: primitives.U256, spec_id: primitives.SpecId) !JournalCheckpoint {
        // Enter subroutine
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

        // set account status to create.
        const is_created_globally = target_acc.markCreatedLocally();

        // this entry will revert set nonce.
        last_journal.append(alloc_mod.get(), JournalEntryFactory.accountCreated(target_address, is_created_globally)) catch {};
        target_acc.info.code = null;
        // EIP-161: State trie clearing (invariant-preserving alternative)
        if (primitives.isEnabledIn(spec_id, .spurious_dragon)) {
            // nonce is going to be reset to zero in AccountCreated journal entry.
            target_acc.info.nonce = 1;
        }

        // touch account. This is important as for pre SpuriousDragon account could be
        // saved even empty.
        JournalInner.touchAccount(last_journal, target_address, target_acc);

        // Add balance to created account, as we already have target here.
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

        // add journal entry of transferred balance
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

    /// Performs selfdestruct action.
    /// Transfers balance from address to target. Check if target exist/is_cold
    ///
    /// Note: Balance will be lost if address and target are the same BUT when
    /// current spec enables Cancun, this happens only when the account associated to address
    /// is created in the same tx
    ///
    // ─── EIP-7708 helpers ─────────────────────────────────────────────────────────

    /// EIP-7708: Build and append a Transfer(from, to, amount) log to the journal log list.
    /// Address is encoded into the upper 12 zero-padded bytes of a 32-byte topic.
    /// OOM silently skips the log (same policy as addLog).
    fn addEip7708TransferLog(self: *JournalInner, from: primitives.Address, to: primitives.Address, amount: primitives.U256) void {
        const alloc = alloc_mod.get();
        const topics = alloc.alloc(primitives.Hash, 3) catch return;
        topics[0] = primitives.EIP7708_TRANSFER_TOPIC;
        topics[1] = std.mem.zeroes([32]u8);
        @memcpy(topics[1][12..], &from);
        topics[2] = std.mem.zeroes([32]u8);
        @memcpy(topics[2][12..], &to);
        const data = alloc.alloc(u8, 32) catch {
            alloc.free(topics);
            return;
        };
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
        const topics = alloc.alloc(primitives.Hash, 2) catch return;
        topics[0] = primitives.EIP7708_BURN_TOPIC;
        topics[1] = std.mem.zeroes([32]u8);
        @memcpy(topics[1][12..], &addr);
        const data = alloc.alloc(u8, 32) catch {
            alloc.free(topics);
            return;
        };
        const amount_bytes: [32]u8 = @bitCast(@byteSwap(amount));
        @memcpy(data, &amount_bytes);
        self.addLog(.{
            .address = primitives.EIP7708_LOG_ADDRESS,
            .topics = topics,
            .data = data,
        });
    }

    /// EIP-7708: Register an account for a deferred finalization burn check.
    ///
    /// Called at SELFDESTRUCT time for every account entering `accounts_to_delete` (i.e. same-tx-
    /// created accounts under Cancun+, or any account pre-Cancun).  `amount` is stored but not
    /// used by `emitBurnLogs()`; pass 0.  The entry is checkpointed so it can be reverted if the
    /// enclosing call frame reverts.
    fn addPendingBurn(self: *JournalInner, addr: primitives.Address, amount: primitives.U256) void {
        self.pending_burns.append(alloc_mod.get(), .{ .address = addr, .amount = amount }) catch {};
    }

    /// EIP-7708 finalization: emit deferred Burn logs for accounts that received ETH after their
    /// SELFDESTRUCT opcode executed.
    ///
    /// # When this is called
    /// `postExecution` in `mainnet_builder.zig` calls this after the coinbase priority-fee payment
    /// and before `takeLogs()` collects the tx log list.  This matches the EELS ordering in
    /// `process_transaction` (amsterdam/fork.py): miner fee is transferred first, then for each
    /// address in `accounts_to_delete` the current balance is checked and a Burn log is emitted
    /// if non-zero.
    ///
    /// # Why two Burn logs can appear for the same address
    /// The SELFDESTRUCT opcode itself emits a Burn log for the balance held *at that moment*
    /// (see the `addEip7708BurnLog` call in `selfdestruct()`).  The account's `evm_state` balance
    /// is then zeroed.  Any ETH that arrives afterwards — a payer's CALL sending value, or the
    /// coinbase receiving its priority fee — accumulates back in `evm_state`.  This second pass
    /// emits a *separate* Burn log only for that post-SELFDESTRUCT ETH, producing two distinct
    /// log entries exactly as the EELS reference implementation does.
    ///
    /// # Sorting
    /// Logs are emitted in ascending address order (lexicographic bytes), matching EELS.
    pub fn emitBurnLogs(self: *JournalInner) void {
        if (self.pending_burns.items.len == 0) return;
        std.mem.sort(PendingBurn, self.pending_burns.items, {}, struct {
            fn lessThan(_: void, a: PendingBurn, b: PendingBurn) bool {
                return std.mem.order(u8, &a.address, &b.address) == .lt;
            }
        }.lessThan);
        for (self.pending_burns.items) |burn| {
            // The account's `evm_state` balance was zeroed when SELFDESTRUCT executed.
            // Any non-zero balance here is ETH that arrived *after* the opcode (e.g. a
            // subsequent CALL with value from a payer, or the coinbase priority fee).
            const finalization_balance = if (self.evm_state.get(burn.address)) |acct|
                acct.info.balance
            else
                0;
            if (finalization_balance > 0) self.addEip7708BurnLog(burn.address, finalization_balance);
        }
        self.pending_burns.clearRetainingCapacity();
    }

    // ─── Selfdestruct ──────────────────────────────────────────────────────────────

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
                acc.info.balance = @as(primitives.U256, 0);
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

        // ── EIP-7708 (Amsterdam+): ETH transfer / burn log emission ─────────────────
        //
        // EIP-7708 requires a LOG2 event for every wei movement that would otherwise be
        // invisible on-chain.  There are two distinct moments where logs must be emitted:
        //
        //  1. **Opcode time** — when SELFDESTRUCT executes:
        //       • SELFDESTRUCT to a *different* beneficiary: the ETH is moved now, so a
        //         Transfer log is emitted immediately (LOG3 with from/to/amount).
        //       • SELFDESTRUCT to *self* (same-tx-created or pre-Cancun): the ETH is
        //         destroyed now, so a Burn log is emitted immediately (LOG2 with addr/amount).
        //         The account's `evm_state` balance is then zeroed by `entry_blk` above.
        //
        //  2. **Finalization time** — after the coinbase priority-fee payment:
        //       Any account in `accounts_to_delete` (same-tx-created SELFDESTRUCTs) may
        //       receive ETH *after* the opcode executes but *before* the tx commits — for
        //       example a payer contract calling into the already-destructed address, or
        //       the coinbase receiving its miner tip.  A second Burn log is emitted for
        //       this post-opcode ETH via `emitBurnLogs()` in `postExecution`.
        //
        // Only accounts in `accounts_to_delete` (isCreatedLocally || pre-Cancun) are
        // eligible for the finalization burn; pre-existing Cancun+ self-destructed accounts
        // are a no-op (no state change, no log).
        //
        // Reference: ethereum/execution-specs — amsterdam/vm/instructions/system.py
        //            (selfdestruct) and amsterdam/fork.py (process_transaction finalization).
        if (primitives.isEnabledIn(self.spec, .amsterdam)) {
            if (!std.mem.eql(u8, &address, &target)) {
                // Case 1a: SELFDESTRUCT to a different beneficiary.
                // Emit Transfer log immediately for the ETH moved by `entry_blk` above.
                if (balance > 0) self.addEip7708TransferLog(address, target, balance);
                // If this account is also in `accounts_to_delete`, register it for the
                // finalization burn check: a payer may still send ETH to this address
                // within the same transaction after the opcode returns.
                if (acc.isCreatedLocally() or !is_cancun_enabled) {
                    self.addPendingBurn(address, 0);
                }
            } else if (acc.isCreatedLocally() or !is_cancun_enabled) {
                // Case 1b: SELFDESTRUCT to self (same-tx-created or pre-Cancun).
                // Emit Burn log immediately for the ETH destroyed right now, then register
                // for the finalization burn check so that any ETH arriving *after* this
                // opcode (payer call, coinbase priority fee) also gets a Burn log.
                // The two logs are intentionally separate, matching the EELS reference.
                if (balance > 0) self.addEip7708BurnLog(address, balance);
                self.addPendingBurn(address, 0);
            }
            // Case 2: SELFDESTRUCT to self on a pre-existing account (Cancun+).
            // EIP-6780 makes this a no-op — state is unchanged, no log is emitted.
        }

        return StateLoad(SelfDestructResult).new(SelfDestructResult{
            .had_value = balance != 0,
            .target_exists = !is_empty,
            .previously_destroyed = destroyed_status == SelfdestructionRevertStatus.RepeatedSelfdestruction,
        }, is_cold);
    }

    /// Loads account into memory. return if it is cold or warm accessed
    pub fn loadAccount(self: *JournalInner, db: anytype, address: primitives.Address) !StateLoad(*const state.Account) {
        return self.loadAccountOptional(db, address, false, false);
    }

    /// Loads account and its code. If account is already loaded it will load its code.
    ///
    /// It will mark account as warm loaded. If not existing Database will be queried for data.
    ///
    /// In case of EIP-7702 delegated account will not be loaded,
    /// [`Self::load_account_delegated`] should be used instead.
    pub fn loadCode(self: *JournalInner, db: anytype, address: primitives.Address) !StateLoad(*const state.Account) {
        return self.loadAccountOptional(db, address, true, false);
    }

    /// Loads account into memory. If account is already loaded it will be marked as warm.
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
                _ = existing.markWarmWithTransactionId(self.transaction_id);
                if (existing.isSelfdestructedLocally()) {
                    existing.selfdestruct();
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
            // Account not yet loaded — fetch from DB and insert
            const acct_is_cold = self.warm_addresses.isCold(address);
            if (acct_is_cold and skip_cold_load) {
                return JournalLoadError.ColdLoadSkipped;
            }
            const new_account = if (try db.basic(address)) |account_info|
                state.Account{
                    .info = account_info,
                    .storage = std.AutoHashMap(primitives.StorageKey, state.EvmStorageSlot).init(alloc_mod.get()),
                    .transaction_id = self.transaction_id,
                    .status = state.AccountStatus.empty(),
                }
            else
                state.Account.newNotExisting(self.transaction_id);
            const gop = try self.evm_state.getOrPut(address);
            gop.value_ptr.* = new_account;
            is_cold = acct_is_cold;
            account_ptr = gop.value_ptr;
            // EIP-7928: record pre-block account state at first load (using already-fetched info).
            self.recordAccountAccess(
                address,
                if (gop.value_ptr.isLoadedAsNotExisting()) null else gop.value_ptr.info,
            );
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
                try db.codeByHash(info.code_hash);
            info.code = code;
        }

        return StateLoad(JournaledAccount).new(
            JournaledAccount.new(address, account_ptr, &self.journal),
            is_cold,
        );
    }

    /// Loads storage slot.
    ///
    /// # Panics
    ///
    /// Panics if the account is not present in the state.
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

    pub fn sload(self: *JournalInner, db: anytype, address: primitives.Address, key: primitives.StorageKey, skip_cold_load: bool) !StateLoad(primitives.StorageValue) {
        // assume acc is warm
        const account = self.evm_state.getPtr(address).?;
        const is_newly_created = account.isCreated();

        if (account.storage.getPtr(key)) |slot| {
            // Storage slot already loaded
            var is_cold = slot.isColdTransactionId(self.transaction_id);
            // If the slot is cold by transaction ID but the EIP-2930 access list marks it warm,
            // treat it as warm (same effect as eager pre-warming via sload in preExecution).
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
                // Distinguish pre-warmed (EIP-2930) from truly cold for gas charging.
                return if (self.warm_addresses.isStorageWarm(address, key))
                    JournalLoadError.WarmPreloadSkipped
                else
                    JournalLoadError.ColdLoadSkipped;
            }
            // For newly-created accounts all storage is implicitly zero (no DB lookup needed).
            const value = if (is_newly_created) @as(primitives.StorageValue, 0) else try db.storage(address, key);
            // EIP-7928: record pre-block storage value at first access.
            self.recordStorageAccess(address, key, value);
            try account.storage.put(key, state.EvmStorageSlot.new(value, self.transaction_id));
            const is_cold = !self.warm_addresses.isStorageWarm(address, key);
            if (is_cold) {
                self.journal.append(alloc_mod.get(), JournalEntryFactory.storageWarmed(address, key)) catch {};
            }
            return StateLoad(primitives.StorageValue).new(value, is_cold);
        }
    }

    /// Stores storage slot.
    ///
    /// And returns (original,present,new) slot value.
    ///
    /// **Note**: Account should already be present in our state.
    pub fn sstore(self: *JournalInner, db: anytype, address: primitives.Address, key: primitives.StorageKey, new_value: primitives.StorageValue, skip_cold_load: bool) !StateLoad(SStoreResult) {
        // assume that acc exists and load the slot.
        const present = try self.sload(db, address, key, skip_cold_load);
        const acc = self.evm_state.getPtr(address).?;

        // if there is no original value in dirty return present value, that is our original.
        const slot = acc.storage.getPtr(key).?;

        // new value is same as present, we don't need to do anything
        if (present.data == new_value) {
            return StateLoad(SStoreResult).new(SStoreResult{
                .original_value = slot.originalValue(),
                .present_value = present.data,
                .new_value = new_value,
            }, present.is_cold);
        }

        self.journal.append(alloc_mod.get(), JournalEntryFactory.storageChanged(address, key, present.data, slot.was_written)) catch {};
        // insert value into present state.
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

    /// Store transient storage tied to the account.
    ///
    /// If values is different add entry to the journal
    /// so that old evm_state can be reverted if that action is needed.
    ///
    /// EIP-1153: Transient storage opcodes
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

/// A journal of evm_state changes internal to the EVM
///
/// On each additional call, the depth of the journaled evm_state is increased (`depth`) and a new journal is added.
///
/// The journal contains every evm_state change that happens within that call, making it possible to revert changes made in a specific call.
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

        /// Creates a new JournaledState by copying evm_state data from a JournalInit and provided database.
        /// This allows reusing the evm_state, logs, and other data from a previous execution context while
        /// connecting it to a different database backend.
        pub fn newWithInner(db: DB, inner: JournalInner) @This() {
            return .{ .database = db, .inner = inner };
        }

        /// Consumes the [`Journal`] and returns [`JournalInner`].
        ///
        /// If you need to preserve the original journal, use [`Self::to_inner`] instead which clones the state.
        pub fn intoInit(self: @This()) JournalInner {
            return self.inner;
        }

        /// Creates a new [`JournalInner`] by cloning all internal evm_state data (evm_state, storage, logs, etc)
        /// This allows creating a new journaled evm_state with the same evm_state data but without
        /// carrying over the original database.
        ///
        /// This is useful when you want to reuse the current evm_state for a new transaction or
        /// execution context, but want to start with a fresh database.
        pub fn toInner(self: @This()) JournalInner {
            return self.inner;
        }

        pub fn getDb(self: *const @This()) *const DB {
            return &self.database;
        }

        pub fn getDbMut(self: *@This()) *DB {
            return &self.database;
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

        pub fn warmPrecompiles(self: *@This(), precompiles: []const primitives.Address) !void {
            try self.inner.warm_addresses.setPrecompileAddresses(precompiles);
        }

        pub fn precompileAddresses(self: @This()) []const primitives.Address {
            return self.inner.warm_addresses.precompiles();
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

        /// Increments the nonce of the account.
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

        pub fn createAccountCheckpoint(self: *@This(), caller: primitives.Address, address: primitives.Address, balance: primitives.U256, spec_id: primitives.SpecId) !JournalCheckpoint {
            // Ignore error.
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

        /// EIP-7708: Sort and emit pending burn logs into the log list.
        /// Call after coinbase payment and before takeLogs() in postExecution.
        pub fn emitBurnLogs(self: *@This()) void {
            self.inner.emitBurnLogs();
        }

        pub fn commitTx(self: *@This()) void {
            // Notify DB of bytecodes deployed by CREATE in this transaction. We scan
            // the journal (O(tx ops)) rather than all of evm_state (O(loaded accounts)).
            // Reverted AccountCreated entries are already removed from the journal by
            // checkpointRevert, so only committed CREATEs appear here.
            if (comptime @hasDecl(DB, "notifyCodeDeployed")) {
                for (self.inner.journal.items) |entry| {
                    switch (entry) {
                        .AccountCreated => |data| {
                            if (self.inner.evm_state.get(data.address)) |acct| {
                                if (acct.info.code) |code| {
                                    if (!acct.info.isEmptyCodeHash()) {
                                        self.database.notifyCodeDeployed(acct.info.code_hash, code) catch {};
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

        /// Clear current journal resetting it to initial evm_state and return changes state.
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

        /// Returns true if the address has been accessed (appears in the BAL).
        pub fn isTrackedAddress(self: *const @This(), address: primitives.Address) bool {
            return self.inner.isTrackedAddress(address);
        }

        /// Drain the accumulated Block Access Log for EIP-7928 validation.
        pub fn takeAccessLog(self: *@This()) AccessLog {
            return self.inner.takeAccessLog();
        }

        /// Returns true if the address has any non-zero storage in the DB.
        /// Used by CREATE collision check; returns false for DB types without this method.
        pub fn hasNonZeroStorageForAddress(self: *const @This(), addr: primitives.Address) bool {
            if (comptime @hasDecl(DB, "hasNonZeroStorageForAddress")) return self.getDb().hasNonZeroStorageForAddress(addr);
            return false;
        }

        /// Check whether an address is already in the EVM state cache (was loaded before
        /// this call). Used to avoid un-tracking addresses that were legitimately accessed
        /// earlier in the same transaction.
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
