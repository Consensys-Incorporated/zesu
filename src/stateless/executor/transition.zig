/// Core state transition for the EVM executor.
///
/// Implements the Ethereum state transition function:
///   post_state, receipts = transition(pre_state, env, txs, fork, chain_id, reward)
///
/// Uses zevm's execution pipeline for actual EVM computation.
const std = @import("std");
const primitives = @import("primitives");
const state_mod = @import("state");
const bytecode_mod = @import("bytecode");
const database_mod = @import("database");
const context_mod = @import("context");
const handler_mod = @import("handler");

const input = @import("executor_types");
const bloom = @import("bloom.zig");
const rlp = @import("./rlp_encode.zig");
const precompile_mod = @import("precompile");
const accel = @import("accelerators");
const output_mod = @import("./output.zig");
const alloc_mod = @import("zesu_allocator");

const bal_mod = @import("./bal.zig");

const tx_signing = @import("tx_signing.zig");
const system_calls = @import("system_calls.zig");

// ─── Output types (re-exported from executor_types) ───────────────────────────

/// Re-export so callers can use transition.Log / transition.Receipt as before.
pub const Log = input.Log;
pub const Receipt = input.Receipt;

pub const TransitionResult = struct {
    alloc: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
    deleted_accounts: []input.Address,
    receipts: []Receipt,
    cumulative_gas: u64,
    block_bloom: input.Bloom,
    // Derived after execution
    current_base_fee: ?u64,
    excess_blob_gas: ?u64,
    blob_gas_used: u64,
    accepted_txs: []input.TxInput,
    chain_id: u64,
    bal_hash: ?[32]u8 = null,
    requests_hash: [32]u8 = [_]u8{0} ** 32,
    /// EIP-7928 (bal-devnet-7): true iff a user tx touched SYSTEM_ADDRESS
    /// (BALANCE / CALL / EXTCODE* etc.). buildAccessedEntries uses this to
    /// decide whether SYSTEM_ADDRESS belongs in the BAL — pre/post-block
    /// system-call touches alone must NOT pull it in.
    system_address_user_touched: bool = false,
};

// ─── Dummy block hash ─────────────────────────────────────────────────────────

const DUMMY_BLOCK_HASH: input.Hash = blk: {
    var h: input.Hash = undefined;
    @memset(&h, 0);
    break :blk h;
};

// ─── EIP-7928 Block Access List tracker ──────────────────────────────────────

const SYSTEM_ADDRESS = primitives.SYSTEM_ADDRESS;

const KnownAcct = struct {
    balance: u256 = 0,
    nonce: u64 = 0,
    code_hash: primitives.Hash = primitives.KECCAK_EMPTY,
};

const BaTracker = struct {
    alloc: std.mem.Allocator,
    // Last committed account state (updated after each phase)
    committed: std.AutoHashMapUnmanaged(input.Address, KnownAcct),
    committed_storage: std.AutoHashMapUnmanaged(input.Address, std.AutoHashMapUnmanaged(u256, u256)),
    // Accumulated per-BAI changes
    bal_chg: std.AutoHashMapUnmanaged(input.Address, std.ArrayListUnmanaged(bal_mod.BaiU256)),
    nonce_chg: std.AutoHashMapUnmanaged(input.Address, std.ArrayListUnmanaged(bal_mod.BaiU64)),
    code_chg: std.AutoHashMapUnmanaged(input.Address, std.ArrayListUnmanaged(bal_mod.BaiCode)),
    slot_chg: std.AutoHashMapUnmanaged(input.Address, std.AutoHashMapUnmanaged(u256, std.ArrayListUnmanaged(bal_mod.SlotBaiValue))),
    // Storage slots written then wiped by same-tx SELFDESTRUCT → appear as storage_reads, no changes.
    selfdestruct_reads: std.AutoHashMapUnmanaged(input.Address, std.AutoHashMapUnmanaged(u256, void)),
    // bal-devnet-7: SYSTEM_ADDRESS is included in BAL iff it was touched by USER tx code
    // (BALANCE/EXTCODE*/CALL etc.). Touches solely from pre/post-block system calls must
    // not pull it into the BAL. Set in detectAndRecord(bai) when bai is in user-tx range.
    system_address_user_touched: bool = false,

    fn initFromPreAlloc(a: std.mem.Allocator, pre: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount)) BaTracker {
        var self = BaTracker{
            .alloc = a,
            .committed = .empty,
            .committed_storage = .empty,
            .bal_chg = .empty,
            .nonce_chg = .empty,
            .code_chg = .empty,
            .slot_chg = .empty,
            .selfdestruct_reads = .empty,
            .system_address_user_touched = false,
        };
        var it = pre.iterator();
        while (it.next()) |e| {
            const addr = e.key_ptr.*;
            const acct = e.value_ptr.*;
            const code_hash = if (acct.code_hash) |ch| ch else if (acct.code.len > 0) rlp.keccak256(acct.code) else primitives.KECCAK_EMPTY;
            self.committed.put(a, addr, KnownAcct{
                .balance = acct.balance,
                .nonce = acct.nonce,
                .code_hash = code_hash,
            }) catch {};
            if (acct.storage.count() > 0) {
                var sm = std.AutoHashMapUnmanaged(u256, u256).empty;
                var sit = acct.storage.iterator();
                while (sit.next()) |se| {
                    if (se.value_ptr.* != 0) sm.put(a, se.key_ptr.*, se.value_ptr.*) catch {};
                }
                self.committed_storage.put(a, addr, sm) catch {};
            }
        }
        return self;
    }

    /// bal-devnet-7: detect whether the just-finished user tx warmed SYSTEM_ADDRESS.
    /// Called after each user tx (post-commitTx). transaction_id was incremented during
    /// commitTx; an account warmed in the just-finished tx has acct.transaction_id ==
    /// current transaction_id - 1.
    fn checkUserTxTouchedSystemAddress(self: *BaTracker, ctx: anytype) void {
        if (self.system_address_user_touched) return;
        const acct = ctx.journaled_state.inner.evm_state.getPtr(SYSTEM_ADDRESS) orelse return;
        const current_tx_id = ctx.journaled_state.inner.transaction_id;
        if (current_tx_id == 0) return;
        if (acct.transaction_id == current_tx_id - 1) {
            self.system_address_user_touched = true;
        }
    }

    fn detectAndRecord(self: *BaTracker, bai: u64, ctx: anytype, from_tx_id: usize) void {
        const a = self.alloc;
        // For bai > 0, skip accounts not touched since from_tx_id: their state hasn't
        // changed since the last detectAndRecord call, so nothing new to record.
        // Per-tx calls pass (tx_id - 1) to capture exactly the just-committed tx.
        // The post-block call passes txs.len to capture mining reward + withdrawals +
        // all post-block system calls, which each do their own commitTx().
        const filter_by_tx = bai > 0;
        var it = ctx.journaled_state.inner.evm_state.iterator();
        while (it.next()) |e| {
            const addr = e.key_ptr.*;
            const acct = e.value_ptr.*;
            if (filter_by_tx and acct.transaction_id < from_tx_id) continue;
            if (acct.status.loaded_as_not_existing and !acct.status.touched) continue;

            // Same-tx-created-and-selfdestructed (ephemeral) account: per EIP-7928 spec's
            // destroy_storage(), storage writes become reads. Nonce/code changes are suppressed,
            // but balance must still be recorded if the pre-existing balance changed (ETH transferred out).
            if (acct.status.self_destructed) {
                var stor_it = acct.storage.iterator();
                while (stor_it.next()) |se| {
                    if (!se.value_ptr.*.was_written) continue;
                    const sm = self.selfdestruct_reads.getOrPut(a, addr) catch continue;
                    if (!sm.found_existing) sm.value_ptr.* = .{};
                    sm.value_ptr.*.put(a, se.key_ptr.*, {}) catch {};
                }
                // Record balance change if pre-existing balance was nonzero (ETH transferred out).
                const known = blk: {
                    if (self.committed.get(addr)) |k| break :blk k;
                    const pre = ctx.journaled_state.database.basic(addr) catch null;
                    const k: KnownAcct = if (pre) |p| .{
                        .balance = p.balance,
                        .nonce = p.nonce,
                        .code_hash = p.code_hash,
                    } else KnownAcct{};
                    self.committed.put(self.alloc, addr, k) catch {};
                    break :blk k;
                };
                // Record any balance change on a self-destructed account. EIP-8246 (Amsterdam+)
                // no longer burns ETH, so a self-destructed account that keeps a non-zero balance
                // survives as a cleared account and its balance change must be recorded (including
                // 0→N for a same-tx self-beneficiary victim). Truly-destroyed accounts are absent
                // from account_reads and dropped at entry assembly, so recording here is safe and
                // mirrors the reference's diff of post-tx account state against pre.
                if (acct.info.balance != known.balance) {
                    const entry = self.bal_chg.getOrPutValue(a, addr, .empty) catch {
                        continue;
                    };
                    entry.value_ptr.*.append(a, bal_mod.BaiU256{ .bai = bai, .value = acct.info.balance }) catch {};
                }
                continue;
            }

            const known = blk: {
                if (self.committed.get(addr)) |k| break :blk k;
                // Lazy init: query DB for pre-block state (handles stateless path where
                // pre_alloc_in is empty and committed was not seeded for this account).
                const pre = ctx.journaled_state.database.basic(addr) catch null;
                const k: KnownAcct = if (pre) |p| .{
                    .balance = p.balance,
                    .nonce = p.nonce,
                    .code_hash = p.code_hash,
                } else KnownAcct{};
                self.committed.put(self.alloc, addr, k) catch {};
                break :blk k;
            };

            // Balance
            if (acct.info.balance != known.balance) {
                const entry = self.bal_chg.getOrPutValue(a, addr, .empty) catch continue;
                entry.value_ptr.*.append(a, bal_mod.BaiU256{ .bai = bai, .value = acct.info.balance }) catch {};
            }

            // Nonce
            if (acct.info.nonce != known.nonce) {
                const entry = self.nonce_chg.getOrPutValue(a, addr, .empty) catch continue;
                entry.value_ptr.*.append(a, bal_mod.BaiU64{ .bai = bai, .value = acct.info.nonce }) catch {};
            }

            // Code
            if (!std.mem.eql(u8, &acct.info.code_hash, &known.code_hash)) {
                const code_bytes: []const u8 = blk: {
                    if (std.mem.eql(u8, &acct.info.code_hash, &primitives.KECCAK_EMPTY)) break :blk &.{};
                    if (acct.info.code) |bc| {
                        if (bc == .eip7702) {
                            const buf = a.alloc(u8, 23) catch break :blk &.{};
                            buf[0] = 0xEF;
                            buf[1] = 0x01;
                            buf[2] = 0x00;
                            @memcpy(buf[3..], &bc.eip7702.address);
                            break :blk buf;
                        }
                        break :blk bc.originalBytes();
                    }
                    if (ctx.journaled_state.database.codeByHash(acct.info.code_hash)) |db_bc| {
                        if (db_bc == .eip7702) {
                            const buf = a.alloc(u8, 23) catch break :blk &.{};
                            buf[0] = 0xEF;
                            buf[1] = 0x01;
                            buf[2] = 0x00;
                            @memcpy(buf[3..], &db_bc.eip7702.address);
                            break :blk buf;
                        }
                        break :blk db_bc.originalBytes();
                    } else |_| break :blk &.{};
                };
                const entry = self.code_chg.getOrPutValue(a, addr, .empty) catch continue;
                entry.value_ptr.*.append(a, bal_mod.BaiCode{ .bai = bai, .code = code_bytes }) catch {};
            }

            // Storage changes: slots written in this phase
            var stor_it = acct.storage.iterator();
            while (stor_it.next()) |se| {
                if (!se.value_ptr.*.was_written) continue;
                const slot = se.key_ptr.*;
                const present = se.value_ptr.*.present_value;
                const committed_val: u256 = blk_slot: {
                    if (self.committed_storage.get(addr)) |sm| {
                        if (sm.get(slot)) |v| break :blk_slot v;
                    }
                    // Lazy init: query DB for the pre-block value (handles stateless path).
                    const db_val = ctx.journaled_state.database.storage(addr, slot) catch 0;
                    if (db_val != 0) {
                        const sm2 = self.committed_storage.getOrPut(self.alloc, addr) catch break :blk_slot db_val;
                        if (!sm2.found_existing) sm2.value_ptr.* = .{};
                        sm2.value_ptr.*.put(self.alloc, slot, db_val) catch {};
                    }
                    break :blk_slot db_val;
                };
                if (present == committed_val) continue;
                const addr_map = self.slot_chg.getOrPut(a, addr) catch continue;
                if (!addr_map.found_existing) addr_map.value_ptr.* = .{};
                const slot_list = addr_map.value_ptr.*.getOrPutValue(a, slot, .empty) catch continue;
                slot_list.value_ptr.*.append(a, bal_mod.SlotBaiValue{ .bai = bai, .value = present }) catch {};
            }
        }

        // Update committed state to current evm_state (only accounts touched this tx).
        var it2 = ctx.journaled_state.inner.evm_state.iterator();
        while (it2.next()) |e| {
            const addr = e.key_ptr.*;
            const acct = e.value_ptr.*;
            if (filter_by_tx and acct.transaction_id < from_tx_id) continue;
            if (acct.status.loaded_as_not_existing and !acct.status.touched) continue;
            // Selfdestructed accounts: nonce/code/storage are gone. Commit the live balance
            // (which may be non-zero if ETH arrived after the SELFDESTRUCT opcode) so that
            // subsequent BAIs don't spuriously re-record the same balance. Storage is cleared
            // so a re-creation in the next tx is detected via nonce/code changes.
            if (acct.status.self_destructed) {
                self.committed.put(a, addr, KnownAcct{ .balance = acct.info.balance }) catch {};
                if (self.committed_storage.getPtr(addr)) |sm| sm.clearRetainingCapacity();
                continue;
            }
            self.committed.put(a, addr, KnownAcct{
                .balance = acct.info.balance,
                .nonce = acct.info.nonce,
                .code_hash = acct.info.code_hash,
            }) catch {};
            var stor_it = acct.storage.iterator();
            while (stor_it.next()) |se| {
                if (!se.value_ptr.*.was_written) continue;
                const sm = self.committed_storage.getOrPut(a, addr) catch continue;
                if (!sm.found_existing) sm.value_ptr.* = .{};
                sm.value_ptr.*.put(a, se.key_ptr.*, se.value_ptr.*.present_value) catch {};
            }
        }
    }

    fn computeHash(self: *BaTracker, a: std.mem.Allocator, ctx: anytype, gas_limit: u64) ![32]u8 {
        // Collect storage reads: all accessed slots NOT in slot_chg.
        // Includes pure reads (was_written=false) AND net-zero writes (was_written=true
        // but value returned to original, so absent from slot_chg).
        var storage_reads = std.AutoHashMapUnmanaged(input.Address, std.AutoHashMapUnmanaged(u256, void)){};
        {
            var it = ctx.journaled_state.inner.evm_state.iterator();
            while (it.next()) |e| {
                const addr = e.key_ptr.*;
                var stor_it = e.value_ptr.*.storage.iterator();
                while (stor_it.next()) |se| {
                    const slot = se.key_ptr.*;
                    const in_slot_chg = if (self.slot_chg.get(addr)) |sm| sm.contains(slot) else false;
                    if (in_slot_chg) continue;
                    const sm = storage_reads.getOrPut(a, addr) catch continue;
                    if (!sm.found_existing) sm.value_ptr.* = .{};
                    sm.value_ptr.*.put(a, slot, {}) catch {};
                }
            }
        }
        // Also include selfdestruct-converted reads (slots written before same-tx SELFDESTRUCT).
        {
            var it = self.selfdestruct_reads.iterator();
            while (it.next()) |e| {
                const addr = e.key_ptr.*;
                var sit = e.value_ptr.*.keyIterator();
                while (sit.next()) |slot_ptr| {
                    const slot = slot_ptr.*;
                    const in_slot_chg = if (self.slot_chg.get(addr)) |sm| sm.contains(slot) else false;
                    if (in_slot_chg) continue;
                    const sm = storage_reads.getOrPut(a, addr) catch continue;
                    if (!sm.found_existing) sm.value_ptr.* = .{};
                    sm.value_ptr.*.put(a, slot, {}) catch {};
                }
            }
        }

        // Collect all addresses in the BAL. Per EIP-7928 (reference build_block_access_list):
        // an address appears iff it is in account_reads (get_account_optional — our
        // journal bal_account_reads) OR has storage activity. Account-level changes
        // (balance/nonce/code) only ever occur on accounts that were also read, so we do
        // NOT seed from the change maps — doing so would resurrect created-only accounts
        // (same-tx create+selfdestruct ephemerals) that the reference never reads or writes.
        var all_addrs = std.AutoHashMapUnmanaged(input.Address, void).empty;
        {
            var it = ctx.journaled_state.inner.bal_account_reads.keyIterator();
            while (it.next()) |k| all_addrs.put(a, k.*, {}) catch {};
        }
        {
            var it = self.slot_chg.keyIterator();
            while (it.next()) |k| all_addrs.put(a, k.*, {}) catch {};
        }
        {
            var it = storage_reads.keyIterator();
            while (it.next()) |k| all_addrs.put(a, k.*, {}) catch {};
        }
        // Include selfdestruct_reads addresses (ephemeral accounts with storage reads).
        {
            var it = self.selfdestruct_reads.keyIterator();
            while (it.next()) |k| all_addrs.put(a, k.*, {}) catch {};
        }

        var entries = std.ArrayListUnmanaged(bal_mod.EncodeEntry).empty;

        var addr_it = all_addrs.keyIterator();
        while (addr_it.next()) |addr_ptr| {
            const addr = addr_ptr.*;

            // bal-devnet-7: SYSTEM_ADDRESS is included if a user tx touched it
            // (BALANCE/EXTCODE*/CALL etc.) OR if it has real state changes / storage
            // reads. Touches solely from pre/post-block system calls are excluded
            // (the system call nonce bump/patch-back must not pull it into the BAL).
            if (std.mem.eql(u8, &addr, &SYSTEM_ADDRESS)) {
                const has_changes = self.bal_chg.contains(addr) or
                    self.nonce_chg.contains(addr) or
                    self.code_chg.contains(addr) or
                    self.slot_chg.contains(addr);
                if (!has_changes and storage_reads.get(addr) == null and !self.system_address_user_touched) continue;
            }

            // Build storage_changes sorted by slot
            var sc_list = std.ArrayListUnmanaged(bal_mod.EncodeSlotChange).empty;
            if (self.slot_chg.get(addr)) |slot_map| {
                var sit = slot_map.iterator();
                while (sit.next()) |se| {
                    try sc_list.append(a, bal_mod.EncodeSlotChange{
                        .slot = se.key_ptr.*,
                        .changes = se.value_ptr.*.items,
                    });
                }
                std.mem.sort(bal_mod.EncodeSlotChange, sc_list.items, {}, struct {
                    pub fn lessThan(_: void, x: bal_mod.EncodeSlotChange, y: bal_mod.EncodeSlotChange) bool {
                        return x.slot < y.slot;
                    }
                }.lessThan);
            }

            // Build storage_reads (not-changed slots), sorted, excluding those in slot_chg
            var sr_list = std.ArrayListUnmanaged(u256).empty;
            if (storage_reads.get(addr)) |sr_map| {
                var sit = sr_map.keyIterator();
                while (sit.next()) |slot_ptr| {
                    const slot = slot_ptr.*;
                    const in_chg = if (self.slot_chg.get(addr)) |sm| sm.contains(slot) else false;
                    if (!in_chg) try sr_list.append(a, slot);
                }
                std.mem.sort(u256, sr_list.items, {}, struct {
                    pub fn lessThan(_: void, x: u256, y: u256) bool {
                        return x < y;
                    }
                }.lessThan);
            }

            // Ephemeral accounts (selfdestruct_reads only) have no balance/nonce/code changes.
            const is_ephemeral = self.selfdestruct_reads.contains(addr) and
                !self.bal_chg.contains(addr) and !self.nonce_chg.contains(addr) and
                !self.code_chg.contains(addr) and !self.slot_chg.contains(addr);

            const bc_items: []const bal_mod.BaiU256 = if (!is_ephemeral) (if (self.bal_chg.get(addr)) |l| l.items else &.{}) else &.{};
            const nc_items: []const bal_mod.BaiU64 = if (!is_ephemeral) (if (self.nonce_chg.get(addr)) |l| l.items else &.{}) else &.{};
            const cc_items: []const bal_mod.BaiCode = if (!is_ephemeral) (if (self.code_chg.get(addr)) |l| l.items else &.{}) else &.{};

            try entries.append(a, bal_mod.EncodeEntry{
                .address = addr,
                .storage_changes = sc_list.items,
                .storage_reads = sr_list.items,
                .balance_changes = bc_items,
                .nonce_changes = nc_items,
                .code_changes = cc_items,
            });
        }

        std.mem.sort(bal_mod.EncodeEntry, entries.items, {}, struct {
            pub fn lessThan(_: void, x: bal_mod.EncodeEntry, y: bal_mod.EncodeEntry) bool {
                return std.mem.lessThan(u8, &x.address, &y.address);
            }
        }.lessThan);

        // EIP-7928: validate BAL item count <= gas_limit // GAS_BLOCK_ACCESS_LIST_ITEM (2000).
        // Each address and each unique storage slot counts as one item.
        const GAS_BLOCK_ACCESS_LIST_ITEM: u64 = 2000;
        var bal_items: u64 = 0;
        for (entries.items) |entry| {
            bal_items += 1; // address
            var unique_slots = std.AutoHashMapUnmanaged(u256, void).empty;
            for (entry.storage_changes) |sc| unique_slots.put(a, sc.slot, {}) catch {};
            for (entry.storage_reads) |sr| unique_slots.put(a, sr, {}) catch {};
            bal_items += unique_slots.count();
        }
        if (bal_items > gas_limit / GAS_BLOCK_ACCESS_LIST_ITEM) {
            return error.BalGasLimitExceeded;
        }

        return bal_mod.encodeAndHash(a, entries.items);
    }
};

// ─── Pre-state loader ─────────────────────────────────────────────────────────

fn buildDb(
    pre_alloc: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
    block_hashes: []const input.BlockHashEntry,
) !database_mod.InMemoryDB {
    var db = database_mod.InMemoryDB.init(alloc_mod.get());

    var it = pre_alloc.iterator();
    while (it.next()) |entry| {
        const addr = entry.key_ptr.*;
        const acct = entry.value_ptr.*;

        const code_hash: primitives.Hash = if (acct.code.len > 0) blk: {
            // Detect EIP-7702 delegation designators (EF 01 00 <20-byte address>)
            // and load them as Eip7702Bytecode so zevm recognizes them as delegations.
            const bc: bytecode_mod.Bytecode = if (acct.code.len == 23 and
                acct.code[0] == 0xEF and acct.code[1] == 0x01 and acct.code[2] == 0x00)
            blk2: {
                var delegation_addr: primitives.Address = [_]u8{0} ** 20;
                @memcpy(&delegation_addr, acct.code[3..23]);
                break :blk2 bytecode_mod.Bytecode{ .eip7702 = bytecode_mod.Eip7702Bytecode.new(delegation_addr) };
            } else bytecode_mod.Bytecode.newLegacy(acct.code);
            const h = bc.hashSlow();
            try db.insertCode(h, bc);
            break :blk h;
        } else primitives.KECCAK_EMPTY;

        try db.insertAccount(addr, state_mod.AccountInfo{
            .balance = acct.balance,
            .nonce = acct.nonce,
            .code_hash = code_hash,
            .code = null,
        });

        var sit = acct.storage.iterator();
        while (sit.next()) |slot| {
            if (slot.value_ptr.* != 0) {
                try db.insertStorage(addr, slot.key_ptr.*, slot.value_ptr.*);
            }
        }
    }

    for (block_hashes) |bhe| {
        try db.insertBlockHash(bhe.number, bhe.hash);
    }

    return db;
}

// ─── Context setup ────────────────────────────────────────────────────────────

/// Returns the blob base fee update fraction for a given spec.
/// Used as fallback when env.blob_base_fee_update_fraction is not set.
fn blobFractionForSpec(spec: primitives.SpecId) u64 {
    if (primitives.isEnabledIn(spec, .bpo2)) return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_BPO2;
    if (primitives.isEnabledIn(spec, .bpo1)) return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_BPO1;
    if (primitives.isEnabledIn(spec, .prague)) return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE;
    return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN;
}

pub fn buildBlockEnv(env: input.Env, spec: primitives.SpecId) context_mod.BlockEnv {
    var block = context_mod.BlockEnv.default();
    block.number = @as(primitives.U256, env.number);
    block.timestamp = @as(primitives.U256, env.timestamp);
    block.gas_limit = env.gas_limit;
    block.beneficiary = env.coinbase;
    block.basefee = env.base_fee orelse 0;
    block.difficulty = env.difficulty;
    block.prevrandao = env.random;
    if (env.excess_blob_gas) |ebg| {
        const fraction = env.blob_base_fee_update_fraction orelse blobFractionForSpec(spec);
        block.setBlobExcessGasAndPrice(ebg, fraction);
    }
    block.slot_number = env.slot_number;
    return block;
}

fn effectiveGasPrice(tx: *const input.TxInput, base_fee: u64) u128 {
    return switch (tx.type) {
        2 => blk: {
            const max_fee = tx.max_fee_per_gas orelse 0;
            const priority = tx.max_priority_fee_per_gas orelse 0;
            const bf: u128 = base_fee;
            break :blk @min(max_fee, bf + priority);
        },
        else => tx.gas_price orelse tx.max_fee_per_gas orelse 0,
    };
}

// ─── Main transition function ─────────────────────────────────────────────────

/// Backward-compatible entry point: builds InMemoryDB from pre_alloc, then runs transition.
/// Used by blockchain-test runner, t8n, and the stateful executor path.
pub fn transition(
    arena: std.mem.Allocator,
    pre_alloc_in: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
    env: input.Env,
    txs: []input.TxInput,
    spec: primitives.SpecId,
    chain_id: u64,
    reward: i64,
) !TransitionResult {
    const db = try buildDb(pre_alloc_in, env.block_hashes);
    return transitionWithDb(arena, db, pre_alloc_in, env, txs, spec, chain_id, reward, &.{});
}

/// Entry point for stateless execution: accepts any DB type (InMemoryDB for the stateful
/// path, WitnessDatabase for the stateless path), plus optional pre-recovered public keys.
/// Builds the EVM context internally. Use transitionWithContext when you need access to the
/// context (and its DB) after execution — e.g., to call witness_db.takeAccessLog().
pub fn transitionWithDb(
    arena: std.mem.Allocator,
    db: anytype,
    pre_alloc_in: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
    env: input.Env,
    txs: []input.TxInput,
    spec: primitives.SpecId,
    chain_id: u64,
    reward: i64,
    /// Pre-recovered secp256k1 public keys, one per tx in order (Amsterdam spec).
    /// Each entry must be exactly 64 bytes (uncompressed, no 0x04 prefix).
    /// When provided for tx i, sender = keccak256(pubkey)[12:] — avoids ecrecover.
    /// Empty slice or entry shorter than 64 bytes falls back to ecrecover.
    public_keys: []const []const u8,
) !TransitionResult {
    const DB = @TypeOf(db);
    var ctx = context_mod.Context(DB).new(db, spec);
    ctx.block = buildBlockEnv(env, spec);
    ctx.cfg.chain_id = chain_id;
    ctx.cfg.disable_base_fee = (env.base_fee == null);
    return transitionWithContext(arena, &ctx, pre_alloc_in, env, txs, spec, chain_id, reward, public_keys);
}

/// Low-level entry point: executes block transition on a pre-built context.
/// The caller owns the context and can access its DB (e.g., for takeAccessLog) after return.
pub fn transitionWithContext(
    arena: std.mem.Allocator,
    ctx: anytype,
    pre_alloc_in: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
    env: input.Env,
    txs: []input.TxInput,
    spec: primitives.SpecId,
    chain_id: u64,
    reward: i64,
    public_keys: []const []const u8,
) !TransitionResult {
    var instructions = handler_mod.Instructions.new(spec);
    var precompiles = handler_mod.Precompiles.new(spec);

    // EIP-2929: precompiles are always warm — set once per block, persists across commitTx/discardTx.
    ctx.journaled_state.inner.warm_addresses.setPrecompileBitset(precompiles.precompiles.precompile_bitset);

    // Pre-size journal HashMaps and ArrayLists to avoid repeated grows under the bump allocator.
    // Upper bound: all pre-state accounts plus a few new accounts per tx.
    const account_hint: u32 = @intCast(pre_alloc_in.count() + txs.len * 4);
    try ctx.journaled_state.inner.evm_state.ensureTotalCapacity(account_hint);
    // EIP-7928 BAL maps are only populated/consumed on Amsterdam+; pre-Amsterdam they
    // stay empty (recorders gated), so skip pre-sizing them — it only touches RAM
    // (proving-cost footprint) for buckets never used.
    if (primitives.isEnabledIn(spec, .amsterdam)) {
        try ctx.journaled_state.inner.bal_pre_accounts.ensureTotalCapacity(account_hint);
        try ctx.journaled_state.inner.bal_pending_accounts.ensureTotalCapacity(account_hint);
    }
    // ~64 journal entries per tx on average (account touches, balance changes, warms, etc.)
    try ctx.journaled_state.inner.journal.ensureTotalCapacity(alloc_mod.get(), txs.len * 64);

    // ── EIP-7928 BAL tracker (Amsterdam+) ────────────────────────────────────
    var tracker: ?BaTracker = if (primitives.isEnabledIn(spec, .amsterdam))
        BaTracker.initFromPreAlloc(arena, pre_alloc_in)
    else
        null;

    // ── Pre-block system calls (EIP-4788, EIP-2935) ───────────────────────────
    system_calls.applyPreBlockCalls(ctx, &instructions, &precompiles, env, spec, chain_id);

    if (tracker) |*t| t.detectAndRecord(0, ctx, 0);

    var receipts = std.ArrayListUnmanaged(Receipt).empty;
    var accepted_txs = std.ArrayListUnmanaged(input.TxInput).empty;
    var cumulative_gas: u64 = 0; // block gas (max(regular, state) per tx, for block header gasUsed)
    var cumulative_receipt_gas: u64 = 0; // receipt gas (regular + state per tx, for cumulativeGasUsed)
    var block_bloom = bloom.ZERO;
    var total_blob_gas: u64 = 0;
    var log_index_global: u64 = 0;

    // Per-block blob gas limit (EIP-4844 / EIP-7691 / BPO forks).
    const max_blob_gas_per_block: u64 = if (!primitives.isEnabledIn(spec, .cancun))
        0
    else if (primitives.isEnabledIn(spec, .bpo2))
        primitives.MAX_BLOB_NUMBER_PER_BLOCK_BPO2 * primitives.GAS_PER_BLOB
    else if (primitives.isEnabledIn(spec, .bpo1))
        primitives.MAX_BLOB_NUMBER_PER_BLOCK_BPO1 * primitives.GAS_PER_BLOB
    else if (primitives.isEnabledIn(spec, .prague))
        primitives.MAX_BLOB_NUMBER_PER_BLOCK_PRAGUE * primitives.GAS_PER_BLOB
    else
        primitives.MAX_BLOB_NUMBER_PER_BLOCK * primitives.GAS_PER_BLOB;

    // ── Execute each transaction ──────────────────────────────────────────────
    for (txs, 0..) |*tx, tx_idx| {
        // 1. Determine sender
        var sender: input.Address = undefined;
        const maybe_sender: ?input.Address = blk: {
            // Use pre-recovered public key (Amsterdam spec optimization) when provided.
            // bal-devnet-7 SSZ schema: ByteVector[65] = full uncompressed secp256k1 key
            // (0x04 || X || Y). Older snapshots used 64 bytes (X || Y, no 0x04 prefix).
            // sender = keccak256(X || Y)[12:] — peel the 0x04 prefix if present.
            if (tx_idx < public_keys.len) {
                const pk = public_keys[tx_idx];
                const xy: ?[]const u8 = if (pk.len == 64) pk else if (pk.len == 65 and pk[0] == 0x04) pk[1..] else null;
                if (xy) |bytes| {
                    const h = rlp.keccak256(bytes);
                    var addr: input.Address = undefined;
                    @memcpy(&addr, h[12..32]);
                    break :blk addr;
                }
            }
            if (tx.r != null and tx.s != null and (tx.r.? != 0 or tx.s.? != 0)) {
                break :blk try tx_signing.recoverSender(arena, tx, chain_id);
            }
            break :blk tx.from;
        };
        if (maybe_sender) |s| {
            sender = s;
        } else {
            return error.MissingSenderSignature;
        }
        // 1b. Validate tx type is supported by the current fork
        {
            const type_supported = switch (tx.type) {
                0 => true,
                1 => primitives.isEnabledIn(spec, .berlin),
                2 => primitives.isEnabledIn(spec, .london),
                3 => primitives.isEnabledIn(spec, .cancun),
                4 => primitives.isEnabledIn(spec, .prague),
                else => false,
            };
            if (!type_supported) {
                return switch (tx.type) {
                    1 => error.Type1TxPreFork,
                    2 => error.Type2TxPreFork,
                    3 => error.Type3TxPreFork,
                    4 => error.Type4TxPreFork,
                    else => error.TypeUnknownTxPreFork,
                };
            }
        }

        // 1c. EIP-7825 (Osaka+): max gas limit per transaction = TX_GAS_LIMIT_CAP
        if (primitives.isEnabledIn(spec, .osaka) and !primitives.isEnabledIn(spec, .amsterdam) and tx.gas > primitives.TX_GAS_LIMIT_CAP) {
            return error.GasLimitExceedsCap;
        }

        // 1d. Transaction gas limit cannot exceed remaining block gas allowance.
        // Pre-Amsterdam: tx.gas == block_gas_used, so this check is exact.
        // Amsterdam+: tx.gas = regular + state, but block_gas_used = max(regular, state),
        // which can be much smaller than tx.gas for state-dominant txs. Skip the
        // pre-execution check here; the overflow is detected post-execution below (step 5).
        if (!primitives.isEnabledIn(spec, .amsterdam)) {
            if (tx.gas > env.gas_limit - cumulative_gas) {
                return error.TxGasLimitExceedsBlockLimit;
            }
        }

        // 1e. Type-3 blob pre-checks (EIP-4844 / EIP-7594).
        // Per-block gas limit check must come BEFORE per-tx count check:
        // blob_count > per_block_max → BlobGasLimitExceeded (TYPE_3_TX_MAX_BLOB_GAS_ALLOWANCE_EXCEEDED)
        // per_tx_max < blob_count <= per_block_max → TooManyBlobs (TYPE_3_TX_BLOB_COUNT_EXCEEDED)
        if (tx.type == 3) {
            const blobs: u64 = @intCast(tx.blob_versioned_hashes.len);
            const tx_blob_gas = blobs * primitives.GAS_PER_BLOB;
            if (max_blob_gas_per_block > 0 and total_blob_gas + tx_blob_gas > max_blob_gas_per_block) {
                return error.BlobGasLimitExceeded;
            }
            // EIP-7594 (Osaka+): per-tx blob count limit = 6, independent of per-block max
            if (primitives.isEnabledIn(spec, .osaka) and blobs > primitives.MAX_BLOB_NUMBER_PER_TX) {
                return error.Eip7594TooManyBlobsPerTx;
            }
        }

        // 2. Compute tx hash
        const tx_hash_val = tx_signing.txHash(arena, tx, chain_id) catch [_]u8{0} ** 32;

        // 3. Set up TxEnv
        ctx.tx.caller = sender;
        ctx.tx.nonce = tx.nonce orelse 0;
        ctx.tx.gas_limit = tx.gas;
        ctx.tx.value = tx.value;
        ctx.tx.tx_type = tx.type;

        switch (tx.type) {
            2, 3, 4 => {
                ctx.tx.gas_price = tx.max_fee_per_gas orelse 0;
                ctx.tx.gas_priority_fee = tx.max_priority_fee_per_gas;
            },
            else => {
                ctx.tx.gas_price = tx.gas_price orelse tx.max_fee_per_gas orelse 0;
                ctx.tx.gas_priority_fee = null;
            },
        }

        // EIP-4844: blob hashes and max fee per blob gas
        if (ctx.tx.blob_hashes) |*old_bh| old_bh.deinit(alloc_mod.get());
        if (tx.type == 3) {
            // Always create a blob_hashes list for type-3 txs (even if empty), so that
            // validateBlobTx sees an empty list and rejects it with EmptyBlobList.
            var blob_list = std.ArrayList(primitives.Hash).empty;
            blob_list.appendSlice(alloc_mod.get(), tx.blob_versioned_hashes) catch {};
            ctx.tx.blob_hashes = blob_list;
            ctx.tx.max_fee_per_blob_gas = tx.max_fee_per_blob_gas orelse 0;
        } else {
            ctx.tx.blob_hashes = null;
            ctx.tx.max_fee_per_blob_gas = 0;
        }

        // EIP-7702: authorization list for type 4 transactions
        if (ctx.tx.authorization_list) |*old_al| old_al.deinit(alloc_mod.get());
        if (tx.type == 4 and tx.authorization_list.len > 0) {
            var auth_list = std.ArrayList(context_mod.Either).empty;
            for (tx.authorization_list) |ai| {
                const authority: context_mod.RecoveredAuthority = blk: {
                    if (ai.signer) |s| break :blk context_mod.RecoveredAuthority{ .Valid = s };
                    if (ai.y_parity > 1) break :blk context_mod.RecoveredAuthority.Invalid;
                    const SECP256K1N_OVER_2: u256 = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
                    if (ai.s > SECP256K1N_OVER_2) break :blk context_mod.RecoveredAuthority.Invalid;
                    const auth_hash = tx_signing.authorizationSigningHash(arena, &ai) catch break :blk context_mod.RecoveredAuthority.Invalid;
                    const recid: u8 = if (ai.y_parity == 0) 0 else 1;
                    var auth_sig: [64]u8 = undefined;
                    std.mem.writeInt(u256, auth_sig[0..32], ai.r, .big);
                    std.mem.writeInt(u256, auth_sig[32..64], ai.s, .big);
                    var auth_pubkey: [64]u8 = undefined;
                    if (!accel.ecrecover(&auth_hash, &auth_sig, recid, &auth_pubkey)) break :blk context_mod.RecoveredAuthority.Invalid;
                    var auth_keccak: [32]u8 = undefined;
                    accel.keccak256(&auth_pubkey, &auth_keccak);
                    var signer: [20]u8 = undefined;
                    @memcpy(&signer, auth_keccak[12..32]);
                    break :blk context_mod.RecoveredAuthority{ .Valid = signer };
                };
                const recovered = context_mod.RecoveredAuthorization.newUnchecked(
                    context_mod.Authorization{
                        .chain_id = ai.chain_id,
                        .address = ai.address,
                        .nonce = ai.nonce,
                    },
                    authority,
                );
                auth_list.append(alloc_mod.get(), context_mod.Either{ .Right = recovered }) catch {};
            }
            ctx.tx.authorization_list = auth_list;
        } else {
            ctx.tx.authorization_list = null;
        }

        // Chain ID. A tx that carries a chain id must match the block's chain id
        // (EIP-155): keep cfg.chain_id as the block's and enable the check so a
        // mismatched tx (e.g. a legacy signature for a different chain) is rejected.
        // Overwriting cfg.chain_id with the tx's id would make the check tautological.
        if (tx.chain_id) |cid| {
            ctx.tx.chain_id = cid;
            ctx.cfg.chain_id = chain_id;
            ctx.cfg.tx_chain_id_check = true;
        } else if (tx.type == 0 and !tx.protected) {
            ctx.tx.chain_id = null;
            ctx.cfg.tx_chain_id_check = false;
        } else {
            ctx.tx.chain_id = chain_id;
            ctx.cfg.chain_id = chain_id;
            ctx.cfg.tx_chain_id_check = true;
        }

        // Destination
        ctx.tx.kind = if (tx.to) |to|
            context_mod.TxKind{ .Call = to }
        else
            context_mod.TxKind.Create;

        // Calldata
        ctx.tx.data = null;
        if (tx.data.len > 0) {
            var data_list = std.ArrayList(u8).empty;
            data_list.appendSlice(alloc_mod.get(), tx.data) catch {
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                ctx.tx.authorization_list = null;
                return error.OutOfMemory;
            };
            ctx.tx.data = data_list;
        }

        // Access list
        if (tx.access_list.len > 0) {
            var al_items = std.ArrayList(context_mod.AccessListItem).empty;
            for (tx.access_list) |al_entry| {
                var item = context_mod.AccessListItem{
                    .address = al_entry.address,
                    .storage_keys = std.ArrayList(primitives.StorageKey).empty,
                };
                for (al_entry.storage_keys) |key| {
                    const sk = std.mem.readInt(u256, &key, .big);
                    item.storage_keys.append(alloc_mod.get(), sk) catch {};
                }
                al_items.append(alloc_mod.get(), item) catch {};
            }
            ctx.tx.access_list = context_mod.AccessList{ .items = al_items };
        } else {
            ctx.tx.access_list = context_mod.AccessList{ .items = null };
        }

        // EIP-7702: type 4 with empty authorization list is invalid.
        if (tx.type == 4 and tx.authorization_list.len == 0) {
            ctx.journaled_state.discardTx();
            if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
            ctx.tx.data = null;
            ctx.tx.access_list.deinit();
            if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
            ctx.tx.blob_hashes = null;
            ctx.tx.authorization_list = null;
            return error.EmptyAuthorizationList;
        }

        // 3b. Pre-validate sender state — zevm's ExecuteEvm.execute() swallows
        // validation errors and returns Fail(0 gas). To correctly classify
        // invalid txs as "rejected" (vs failed-execution with a receipt), we
        // pre-check nonce, balance, EIP-3607, and base fee here.
        {
            // Load with code so we can check EIP-3607 delegation exception.
            const sender_load = ctx.journaled_state.loadAccountMutOptionalCode(sender, true, false) catch |err| {
                ctx.journaled_state.discardTx();
                if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
                ctx.tx.data = null;
                ctx.tx.access_list.deinit();
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                ctx.tx.authorization_list = null;
                return err;
            };
            const sender_info = sender_load.data.account.info;

            // EIP-3607: reject txs from senders with deployed code (unless EIP-7702 delegation).
            if (!ctx.cfg.disable_eip3607) {
                if (!std.mem.eql(u8, &sender_info.code_hash, &primitives.KECCAK_EMPTY)) {
                    const is_delegation = if (sender_info.code) |code| code.isEip7702() else false;
                    if (!is_delegation) {
                        ctx.journaled_state.discardTx();
                        if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
                        ctx.tx.data = null;
                        ctx.tx.access_list.deinit();
                        if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                        ctx.tx.blob_hashes = null;
                        if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                        ctx.tx.authorization_list = null;
                        return error.SenderHasCode;
                    }
                }
            }

            const tx_nonce = tx.nonce orelse 0;
            if (sender_info.nonce != tx_nonce) {
                ctx.journaled_state.discardTx();
                if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
                ctx.tx.data = null;
                ctx.tx.access_list.deinit();
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                ctx.tx.authorization_list = null;
                return if (sender_info.nonce > tx_nonce) error.NonceMismatch else error.NonceMismatchTooHigh;
            }

            // EIP-2681: CREATE is invalid when sender nonce == maxInt(u64) (would overflow on increment).
            if (tx.to == null and sender_info.nonce == std.math.maxInt(u64)) {
                ctx.journaled_state.discardTx();
                if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
                ctx.tx.data = null;
                ctx.tx.access_list.deinit();
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                ctx.tx.authorization_list = null;
                return error.NonceIsMax;
            }

            // Base fee check (EIP-1559): gas_price (= maxFeePerGas for type 2/3/4) must cover basefee.
            if (!ctx.cfg.disable_base_fee) {
                if (ctx.tx.gas_price < ctx.block.basefee) {
                    ctx.journaled_state.discardTx();
                    if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
                    ctx.tx.data = null;
                    ctx.tx.access_list.deinit();
                    if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                    ctx.tx.blob_hashes = null;
                    if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                    ctx.tx.authorization_list = null;
                    return error.GasPriceLessThanBaseFee;
                }
            }

            // Use worst-case max gas price (maxFeePerGas for EIP-1559, gasPrice for legacy).
            // ctx.tx.gas_price is already set to maxFeePerGas for type 2/3/4.
            const max_gas_fee: u256 = @as(u256, tx.gas) * @as(u256, ctx.tx.gas_price);
            const blob_cost: u256 = if (tx.type == 3) blk: {
                const n: u256 = tx.blob_versioned_hashes.len;
                const max_blob_fee: u256 = tx.max_fee_per_blob_gas orelse 0;
                break :blk n * 131_072 * max_blob_fee;
            } else 0;
            const max_cost = max_gas_fee + tx.value + blob_cost;
            if (sender_info.balance < max_cost) {
                ctx.journaled_state.discardTx();
                if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
                ctx.tx.data = null;
                ctx.tx.access_list.deinit();
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                ctx.tx.authorization_list = null;
                return error.InsufficientBalance;
            }
        }

        // 3c. Pre-check intrinsic gas and initcode size — validateInitialTxGas() runs
        // inside ExecuteEvm.execute() but errors are swallowed there (returned as Fail(0)).
        // We replicate the checks here so violations reject the block instead of producing a receipt.
        {
            // EIP-3860 / EIP-7954: reject CREATE txs with oversized initcode.
            if (tx.to == null and primitives.isEnabledIn(spec, .shanghai)) {
                const max_initcode: usize = if (primitives.isEnabledIn(spec, .amsterdam)) primitives.AMSTERDAM_MAX_INITCODE_SIZE else primitives.MAX_INITCODE_SIZE;
                if (tx.data.len > max_initcode) {
                    ctx.journaled_state.discardTx();
                    if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
                    ctx.tx.data = null;
                    ctx.tx.access_list.deinit();
                    if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                    ctx.tx.blob_hashes = null;
                    if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                    ctx.tx.authorization_list = null;
                    return error.CreateInitcodeOverLimit;
                }
            }

            // Intrinsic gas check: call validateInitialTxGas via a temporary EVM instance.
            // ctx.tx is fully populated at this point (kind, data, access_list, etc.).
            var frame_stack_pre = handler_mod.FrameStack.new();
            var evm_pre = handler_mod.EvmFor(@TypeOf(ctx.*).DatabaseType).init(ctx, null, &instructions, &precompiles, &frame_stack_pre);
            _ = handler_mod.Validation.validateInitialTxGas(&evm_pre) catch |err| {
                ctx.journaled_state.discardTx();
                if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
                ctx.tx.data = null;
                ctx.tx.access_list.deinit();
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                ctx.tx.authorization_list = null;
                return err;
            };

            // Stateless env checks: priority fee > max fee, chain ID, gas limit cap.
            handler_mod.Validation.validateEnv(&evm_pre) catch |err| {
                ctx.journaled_state.discardTx();
                if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
                ctx.tx.data = null;
                ctx.tx.access_list.deinit();
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                ctx.tx.authorization_list = null;
                return err;
            };

            // Blob tx validation: versioned hash, empty list, create restriction, gas price.
            handler_mod.Validation.validateBlobTx(&ctx.tx, &ctx.block, spec) catch |err| {
                ctx.journaled_state.discardTx();
                if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
                ctx.tx.data = null;
                ctx.tx.access_list.deinit();
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                ctx.tx.authorization_list = null;
                return err;
            };

            // EIP-7702 type-4 validation: no CREATE, non-empty auth list.
            handler_mod.Validation.validateEip7702Tx(&ctx.tx, spec) catch |err| {
                ctx.journaled_state.discardTx();
                if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
                ctx.tx.data = null;
                ctx.tx.access_list.deinit();
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                ctx.tx.authorization_list = null;
                return err;
            };
        }

        // 4. Execute
        var frame_stack = handler_mod.FrameStack.new();
        var evm = handler_mod.EvmFor(@TypeOf(ctx.*).DatabaseType).init(ctx, null, &instructions, &precompiles, &frame_stack);

        var exec_result = handler_mod.ExecuteEvm.execute(&evm) catch |err| {
            ctx.journaled_state.discardTx();
            if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
            ctx.tx.data = null;
            ctx.tx.access_list.deinit();
            if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
            ctx.tx.blob_hashes = null;
            if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
            ctx.tx.authorization_list = null;
            return err;
        };


        if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
        ctx.tx.data = null;
        ctx.tx.access_list.deinit();
        if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
        ctx.tx.blob_hashes = null;
        if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
        ctx.tx.authorization_list = null;

        // 5. Build receipt
        cumulative_gas += exec_result.block_gas_used;
        // Amsterdam+: block_gas_used = max(regular, state), which is only known
        // post-execution. Reject the block immediately if this tx overflows the limit.
        if (primitives.isEnabledIn(spec, .amsterdam)) {
            if (cumulative_gas > env.gas_limit) {
                return error.TxGasLimitExceedsBlockLimit;
            }
        }
        cumulative_receipt_gas += exec_result.gas_used;

        const status: u8 = if (exec_result.status == .Success) 1 else 0;
        const egp = effectiveGasPrice(tx, env.base_fee orelse 0);

        const contract_addr: ?input.Address = if (tx.to == null and status == 1)
            tx_signing.createAddress(arena, sender, tx.nonce orelse 0) catch null
        else
            null;

        const logs_start = log_index_global;
        var receipt_logs = std.ArrayListUnmanaged(Log).empty;
        var receipt_bloom = bloom.ZERO;

        for (exec_result.logs.items) |log| {
            var topics = try arena.alloc(input.Hash, log.topics.len);
            for (log.topics, 0..) |t, ti| topics[ti] = t;

            bloom.addLog(&receipt_bloom, log.address, log.topics);

            try receipt_logs.append(arena, Log{
                .address = log.address,
                .topics = topics,
                .data = try arena.dupe(u8, log.data),
                .block_number = env.number,
                .tx_hash = tx_hash_val,
                .tx_index = tx_idx,
                .block_hash = DUMMY_BLOCK_HASH,
                .log_index = log_index_global,
                .removed = false,
            });
            log_index_global += 1;
        }
        bloom.merge(&block_bloom, &receipt_bloom);
        _ = logs_start;

        // Blob gas accumulation (limit checks were done pre-execution in 1e).
        if (tx.type == 3) {
            total_blob_gas += @as(u64, @intCast(tx.blob_versioned_hashes.len)) * primitives.GAS_PER_BLOB;
        }

        try receipts.append(arena, Receipt{
            .type = tx.type,
            .tx_hash = tx_hash_val,
            .tx_index = tx_idx,
            .block_hash = DUMMY_BLOCK_HASH,
            .block_number = env.number,
            .from = sender,
            .to = tx.to,
            .cumulative_gas_used = cumulative_receipt_gas,
            .gas_used = exec_result.gas_used,
            .contract_address = contract_addr,
            .logs = try receipt_logs.toOwnedSlice(arena),
            .logs_bloom = receipt_bloom,
            .status = status,
            .effective_gas_price = egp,
            .blob_gas_used = if (tx.type == 3) tx.blob_versioned_hashes.len * 131_072 else null,
            .blob_gas_price = if (tx.type == 3)
                if (ctx.block.blob_excess_gas_and_price) |bep| bep.blob_gasprice else null
            else
                null,
        });

        exec_result.deinit();

        if (tracker) |*t| {
            t.checkUserTxTouchedSystemAddress(ctx);
            t.detectAndRecord(tx_idx + 1, ctx, ctx.journaled_state.inner.transaction_id - 1);
        }

        // Pre-Byzantium (EIP-658 not yet active): compute per-tx intermediate state root.
        if (!primitives.isEnabledIn(spec, .byzantium)) {
            const per_tx_alloc = extractPostState(arena, pre_alloc_in, ctx, spec) catch null;
            if (per_tx_alloc) |pa| {
                const sr = output_mod.computeStateRoot(arena, pa, &.{}) catch null;
                receipts.items[receipts.items.len - 1].state_root = sr;
            }
        }

        try accepted_txs.append(arena, tx.*);
    }

    // ── Apply mining reward ───────────────────────────────────────────────────
    if (reward >= 0) {
        const reward_wei: primitives.U256 = @intCast(reward);
        ctx.journaled_state.inner.balanceIncr(
            &ctx.journaled_state.database,
            env.coinbase,
            reward_wei,
        ) catch {};
        ctx.journaled_state.commitTx();
    }

    // ── Apply withdrawals (Shanghai+) ─────────────────────────────────────────
    for (env.withdrawals) |wd| {
        const amount_wei: primitives.U256 = @as(u256, wd.amount) * 1_000_000_000;
        ctx.journaled_state.inner.balanceIncr(
            &ctx.journaled_state.database,
            wd.address,
            amount_wei,
        ) catch {};
    }
    if (env.withdrawals.len > 0) {
        ctx.journaled_state.commitTx();
    }

    // ── Post-block system calls (EIP-7002, EIP-7251) ──────────────────────────
    // Capture return data for EIP-7685 requests_hash computation.
    const post_block_reqs = try system_calls.applyPostBlockCallsCapture(arena, ctx, &instructions, &precompiles, spec, chain_id);

    // Detect changes from mining reward + withdrawals + post-block calls (all at BAI=N+1)
    if (tracker) |*t| t.detectAndRecord(txs.len + 1, ctx, txs.len);

    // ── Extract post-state ────────────────────────────────────────────────────
    const post_alloc = try extractPostState(arena, pre_alloc_in, ctx, spec);

    // Collect selfdestructed accounts for delta-root deletion.
    // EIP-8246 (Amsterdam+): a self-destructed account with a preserved non-zero balance
    // is NOT deleted from the trie (it survives as a cleared account); only truly-empty
    // (zero-balance) self-destructs are removed.
    const amsterdam_no_burn = primitives.isEnabledIn(spec, .amsterdam);
    var deleted = std.ArrayListUnmanaged(input.Address).empty;
    {
        var del_it = ctx.journaled_state.inner.evm_state.iterator();
        while (del_it.next()) |e| {
            if (e.value_ptr.*.status.self_destructed) {
                if (amsterdam_no_burn and e.value_ptr.*.info.balance != 0) continue;
                try deleted.append(arena, e.key_ptr.*);
            }
        }
    }

    const bal_hash: ?[32]u8 = if (tracker) |*t| try t.computeHash(arena, ctx, env.gas_limit) else null;

    // ── EIP-7685 requests_hash ────────────────────────────────────────────────
    const deposits = if (primitives.isEnabledIn(spec, .prague)) try collectDeposits(arena, receipts.items) else &.{};
    const requests_hash = try computeRequestsHash(
        arena,
        deposits,
        post_block_reqs.withdrawal_requests,
        post_block_reqs.consolidation_requests,
        post_block_reqs.builder_deposit_requests,
        post_block_reqs.builder_exit_requests,
    );

    return TransitionResult{
        .alloc = post_alloc,
        .deleted_accounts = try deleted.toOwnedSlice(arena),
        .receipts = try receipts.toOwnedSlice(arena),
        .cumulative_gas = cumulative_gas,
        .block_bloom = block_bloom,
        .current_base_fee = env.base_fee,
        .excess_blob_gas = env.excess_blob_gas,
        .blob_gas_used = total_blob_gas,
        .accepted_txs = try accepted_txs.toOwnedSlice(arena),
        .chain_id = chain_id,
        .bal_hash = bal_hash,
        .requests_hash = requests_hash,
        .system_address_user_touched = if (tracker) |t| t.system_address_user_touched else false,
    };
}

// ─── EIP-7685 requests_hash computation ──────────────────────────────────────

/// EIP-6110 deposit contract address.
const DEPOSIT_CONTRACT_ADDRESS: input.Address = .{
    0x00, 0x00, 0x00, 0x00, 0x21, 0x9a, 0xb5, 0x40, 0x35, 0x6c,
    0xbb, 0x83, 0x9c, 0xbe, 0x05, 0x30, 0x3d, 0x77, 0x05, 0xfa,
};

/// keccak256("DepositEvent(bytes,bytes,bytes,bytes,bytes)")
const DEPOSIT_EVENT_TOPIC: input.Hash = .{
    0x64, 0x9b, 0xbc, 0x62, 0xd0, 0xe3, 0x13, 0x42, 0xaf, 0xea,
    0x4e, 0x5c, 0xd8, 0x2d, 0x40, 0x49, 0xe7, 0xe1, 0xee, 0x91,
    0x2f, 0xc0, 0x88, 0x9a, 0xa7, 0x90, 0x80, 0x3b, 0xe3, 0x90,
    0x38, 0xc5,
};

/// Extract the canonical 192-byte deposit request from one deposit contract log.
///
/// The deposit contract emits ABI-encoded (bytes,bytes,bytes,bytes,bytes) with:
///   pubkey(48) | withdrawal_credentials(32) | amount(8) | signature(96) | index(8)
/// Total ABI-encoded size: 576 bytes.
fn depositFromLog(log: *const input.Log, out: *[192]u8) error{InvalidDepositEventLayout}!void {
    if (log.data.len != 576) return error.InvalidDepositEventLayout;
    @memcpy(out[0..48], log.data[192..240]); // pubkey
    @memcpy(out[48..80], log.data[288..320]); // withdrawal_credentials
    @memcpy(out[80..88], log.data[352..360]); // amount (8 bytes LE)
    @memcpy(out[88..184], log.data[416..512]); // signature
    @memcpy(out[184..192], log.data[544..552]); // index (8 bytes LE)
}

/// Collect all EIP-6110 deposit requests from block receipts.
/// Returns concatenated 192-byte deposit records (caller owns slice via arena).
/// Only processes logs from the deposit contract that have the DepositEvent topic.
/// Returns error.InvalidDepositEventLayout if such a log has the wrong data length.
fn collectDeposits(arena: std.mem.Allocator, receipts: []const Receipt) error{InvalidDepositEventLayout}![]const u8 {
    var buf = std.ArrayListUnmanaged(u8).empty;
    for (receipts) |*receipt| {
        for (receipt.logs) |*log| {
            if (!std.mem.eql(u8, &log.address, &DEPOSIT_CONTRACT_ADDRESS)) continue;
            // Only process logs that carry the DepositEvent signature topic.
            // Other log types emitted by the deposit contract are ignored.
            if (log.topics.len == 0 or !std.mem.eql(u8, &log.topics[0], &DEPOSIT_EVENT_TOPIC)) continue;
            var deposit: [192]u8 = undefined;
            try depositFromLog(log, &deposit);
            buf.appendSlice(arena, &deposit) catch {};
        }
    }
    return buf.items;
}

/// Compute EIP-7685 requests_hash.
///
/// Hash = SHA256( SHA256(0x00||deposits) || SHA256(0x01||withdrawals)
///                || SHA256(0x02||consolidations) || SHA256(0x03||builder_deposits)
///                || SHA256(0x04||builder_exits) )
/// where each type is omitted if its data is empty. Types 0x03/0x04 are the
/// EIP-8282 (Amsterdam+) builder execution requests.
fn computeRequestsHash(
    arena: std.mem.Allocator,
    deposits: []const u8,
    withdrawals: []const u8,
    consolidations: []const u8,
    builder_deposits: []const u8,
    builder_exits: []const u8,
) ![32]u8 {
    const max_len = @max(
        deposits.len,
        @max(withdrawals.len, @max(consolidations.len, @max(builder_deposits.len, builder_exits.len))),
    );
    const scratch = try arena.alloc(u8, 1 + max_len);

    var outer_buf: [160]u8 = undefined;
    var outer_len: usize = 0;

    inline for (.{
        .{ @as(u8, 0x00), deposits },
        .{ @as(u8, 0x01), withdrawals },
        .{ @as(u8, 0x02), consolidations },
        .{ @as(u8, 0x03), builder_deposits },
        .{ @as(u8, 0x04), builder_exits },
    }) |pair| {
        const data: []const u8 = pair[1];
        if (data.len > 0) {
            scratch[0] = pair[0];
            @memcpy(scratch[1..][0..data.len], data);
            accel.sha256(scratch[0 .. 1 + data.len], outer_buf[outer_len..][0..32]);
            outer_len += 32;
        }
    }

    var result: [32]u8 = undefined;
    accel.sha256(outer_buf[0..outer_len], &result);
    return result;
}

// ─── Post-state extraction ────────────────────────────────────────────────────

fn extractPostState(
    arena: std.mem.Allocator,
    pre_alloc: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
    ctx: anytype,
    spec: primitives.SpecId,
) !std.AutoHashMapUnmanaged(input.Address, input.AllocAccount) {
    // Start with a mutable copy of pre_alloc (use arena allocation for storage maps)
    var post = std.AutoHashMapUnmanaged(input.Address, input.AllocAccount).empty;
    try post.ensureTotalCapacity(arena, pre_alloc.count() + ctx.journaled_state.inner.evm_state.count());

    // Clone all pre-state accounts
    var pre_it = pre_alloc.iterator();
    while (pre_it.next()) |pre_entry| {
        var acct = input.AllocAccount{
            .balance = pre_entry.value_ptr.*.balance,
            .nonce = pre_entry.value_ptr.*.nonce,
            .code = pre_entry.value_ptr.*.code,
            .pre_storage_root = pre_entry.value_ptr.*.pre_storage_root,
        };
        // Clone storage (included for both normal and delta modes:
        //   - Normal mode (pre_storage_root==null): full pre-state for scratch-build.
        //   - Delta mode (pre_storage_root set): witness-proven slots, applied as
        //     updates/insertions to pre_storage_root; unchanged ones are idempotent.
        //     Zero values written later signal deletions.)
        var sit = pre_entry.value_ptr.*.storage.iterator();
        while (sit.next()) |slot| {
            try acct.storage.put(arena, slot.key_ptr.*, slot.value_ptr.*);
        }
        try post.put(arena, pre_entry.key_ptr.*, acct);
    }

    // Override with evm_state (all accounts touched during execution)
    var state_it = ctx.journaled_state.inner.evm_state.iterator();
    while (state_it.next()) |state_entry| {
        const addr = state_entry.key_ptr.*;
        const account = state_entry.value_ptr.*;

        // Skip accounts that were loaded as non-existent and never touched
        if (account.status.loaded_as_not_existing and !account.status.touched) continue;

        // Self-destructed accounts.
        // Pre-Amsterdam: removed entirely (balance burned if beneficiary == self).
        // EIP-8246 (Amsterdam+): SELFDESTRUCT no longer burns. The account is cleared
        // (nonce=0, code empty, storage wiped) but its balance is preserved; it is only
        // removed when the final balance is zero (EIP-161 empty-account clearing).
        if (account.status.self_destructed) {
            if (primitives.isEnabledIn(spec, .amsterdam) and account.info.balance != 0) {
                var acct = input.AllocAccount{
                    .balance = account.info.balance,
                    .nonce = 0,
                    .code = &.{},
                    .pre_storage_root = if (post.getPtr(addr)) |p| p.pre_storage_root else null,
                };
                // Storage is wiped by SELFDESTRUCT — leave acct.storage empty.
                _ = &acct;
                try post.put(arena, addr, acct);
                continue;
            }
            _ = post.remove(addr);
            continue;
        }

        // Get or create post-alloc entry (base from pre-state if exists).
        // Newly created accounts (created=true) and accounts whose storage was wiped by a
        // prior SELFDESTRUCT (storage_wiped=true) must NOT inherit pre-state storage.
        const fresh_storage = account.status.created or account.status.storage_wiped;
        var acct = post.get(addr) orelse input.AllocAccount{};
        if (fresh_storage) {
            acct.storage = .{};
            acct.pre_storage_root = null;
        }

        acct.balance = account.info.balance;
        acct.nonce = account.info.nonce;
        // Always record the authoritative code hash from EVM state.
        // computeStateRootDelta() uses this directly so that accounts whose code
        // bytes are absent from the witness still produce the correct account RLP.
        acct.code_hash = account.info.code_hash;

        // Update code: use code_hash as the source of truth.
        // KECCAK_EMPTY means empty code; otherwise look up actual bytes.
        // IMPORTANT: Eip7702Bytecode.raw() returns &self.raw_bytes where self is a value
        // parameter, so it returns a dangling pointer when called on a copy. For EIP-7702
        // bytecode we construct the bytes directly from the address field instead.
        if (!std.mem.eql(u8, &account.info.code_hash, &primitives.KECCAK_EMPTY)) {
            if (account.info.code) |bc| {
                if (bc == .eip7702) {
                    const buf = try arena.alloc(u8, 23);
                    buf[0] = 0xEF;
                    buf[1] = 0x01;
                    buf[2] = 0x00;
                    @memcpy(buf[3..], &bc.eip7702.address);
                    acct.code = buf;
                } else {
                    const raw = bc.originalBytes();
                    acct.code = if (raw.len > 0) raw else &.{};
                }
            } else {
                if (ctx.journaled_state.database.codeByHash(account.info.code_hash)) |db_bc| {
                    if (db_bc == .eip7702) {
                        const buf = try arena.alloc(u8, 23);
                        buf[0] = 0xEF;
                        buf[1] = 0x01;
                        buf[2] = 0x00;
                        @memcpy(buf[3..], &db_bc.eip7702.address);
                        acct.code = buf;
                    } else {
                        const raw = db_bc.originalBytes();
                        acct.code = if (raw.len > 0) raw else &.{};
                    }
                } else |_| {}
            }
        } else {
            acct.code = &.{};
        }

        // Update storage: emit block-level changes only.
        // Only slots whose present_value differs from pre_block_value (the value at first
        // DB load this block) need to appear in the MPT delta. Read-only slots and
        // net-zero writes are skipped; this eliminates the bulk of batchUpdateIndexed work.
        // fresh_storage (newly created / storage_wiped): all storage is new, use as-is.
        var stor_it = account.storage.iterator();
        while (stor_it.next()) |slot| {
            const key = slot.key_ptr.*;
            const present = slot.value_ptr.*.present_value;
            if (!fresh_storage) {
                // Skip slots unchanged vs. block start — no MPT update needed.
                const pre_block = slot.value_ptr.*.pre_block_value;
                if (present == pre_block) continue;
                // Emit deletion marker if slot existed before and is now zero.
                // Emit updated value otherwise.
                try acct.storage.put(arena, key, present);
            } else {
                if (present == 0) {
                    _ = acct.storage.remove(key);
                } else {
                    try acct.storage.put(arena, key, present);
                }
            }
        }

        // EIP-161 (Spurious Dragon+): remove empty accounts from state.
        // Use code_hash (authoritative) rather than code.len to detect empty code —
        // code bytes may be absent from the witness even for non-empty contracts.
        if (primitives.isEnabledIn(ctx.cfg.spec, .spurious_dragon)) {
            const has_code = if (acct.code_hash) |ch|
                !std.mem.eql(u8, &ch, &primitives.KECCAK_EMPTY)
            else
                acct.code.len > 0;
            if (acct.nonce == 0 and acct.balance == 0 and !has_code and acct.storage.count() == 0) {
                _ = post.remove(addr);
                continue;
            }
        }

        try post.put(arena, addr, acct);
    }

    return post;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

const TEST_SENDER: input.Address = @splat(0x11);
const TEST_COINBASE: input.Address = @splat(0x22);
const TEST_RECIPIENT: input.Address = @splat(0x33);

// A database that resolves only the accounts a block legitimately needs and fails
// for anything else, standing in for a stateless witness that is missing the
// CREATE target account. Mirrors WitnessDatabase's duck-typed surface.
const PartialWitnessDb = struct {
    fn known(address: input.Address) bool {
        return std.mem.eql(u8, &address, &TEST_SENDER) or
            std.mem.eql(u8, &address, &TEST_COINBASE) or
            std.mem.eql(u8, &address, &TEST_RECIPIENT);
    }

    pub fn basic(_: *@This(), address: input.Address) !?state_mod.AccountInfo {
        if (!known(address)) return error.InvalidWitness;
        var info = state_mod.AccountInfo.default();
        info.balance = 1_000_000_000_000;
        return info;
    }

    pub fn codeByHash(_: *@This(), _: primitives.Hash) !bytecode_mod.Bytecode {
        return bytecode_mod.Bytecode.newLegacy(&.{});
    }

    pub fn storage(_: *@This(), _: primitives.Address, _: primitives.StorageKey) !primitives.StorageValue {
        return 0;
    }

    pub fn blockHash(_: *@This(), _: u64) !primitives.Hash {
        return @splat(0);
    }
};

fn testEnv() input.Env {
    return .{ .coinbase = TEST_COINBASE, .gas_limit = 30_000_000, .base_fee = 0 };
}

fn makeTestCtx() context_mod.Context(PartialWitnessDb) {
    return context_mod.Context(PartialWitnessDb).new(.{}, primitives.SpecId.shanghai);
}

fn runTestBlock(arena: std.mem.Allocator, ctx: anytype, txs: []input.TxInput) !TransitionResult {
    const pre_alloc: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount) = .{};
    return transitionWithContext(
        arena,
        ctx,
        pre_alloc,
        testEnv(),
        txs,
        primitives.SpecId.shanghai,
        1,
        0,
        &.{},
    );
}

// Integration counterpart to the unit tests in db/test.zig and host.zig: those
// prove the database error is raised and that setupCreateCore marks ctx_error,
// this proves it survives a whole block execution. transitionWithContext does not
// itself reject -- the block-level driver (executor/main.zig) turns a non-ok
// ctx_error into InvalidWitness -- so the contract asserted here is that the block
// is *marked* invalid rather than completing as if the CREATE legitimately failed.
test "a CREATE whose target is absent from the witness marks the block invalid" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    // to == null makes this a CREATE. The target address is derived from the
    // sender and nonce, so it is not one of the addresses the stub DB can resolve.
    var txs = [_]input.TxInput{.{
        .from = TEST_SENDER,
        .to = null,
        .nonce = 0,
        .gas = 200_000,
        .gas_price = 1,
        .data = &[_]u8{ 0x60, 0x00, 0x60, 0x00, 0xf3 }, // RETURN empty
    }};

    var ctx = makeTestCtx();
    // Whether this returns a value or an error is not the contract; the mark is.
    _ = runTestBlock(arena_state.allocator(), &ctx, &txs) catch {};

    try std.testing.expectEqual(
        context_mod.ContextError.database_error,
        ctx.ctx_error,
    );
}

// Control: the same stub DB and block shape, but a plain transfer to an address
// the witness *can* prove. Without this, the test above would also pass if every
// block were marked invalid for an unrelated reason.
test "a block whose accounts are all provable is not marked invalid" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var txs = [_]input.TxInput{.{
        .from = TEST_SENDER,
        .to = TEST_RECIPIENT,
        .nonce = 0,
        .gas = 100_000,
        .gas_price = 1,
        .value = 1,
    }};

    var ctx = makeTestCtx();
    _ = try runTestBlock(arena_state.allocator(), &ctx, &txs);

    try std.testing.expectEqual(context_mod.ContextError.ok, ctx.ctx_error);
}
