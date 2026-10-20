//! WitnessDatabase: stateless EVM database backed by a pre-built MPT NodeIndex.
//!
//! Serves account/storage reads via live MPT proof verification (O(log n) per read
//! via NodeIndex O(1) node lookups). Contract bytecodes live in one mutable hash → bytes
//! map: seeded from the witness codes at init, extended by the journal with code the block
//! itself writes (CREATE, EIP-7702 delegations).
//!
//! Used directly as the DB type in Context(WitnessDatabase):
//!   var ctx = context.Context(WitnessDatabase).new(witness_db, spec);
//!
//! Implements the zevm DB interface (basic, codeByHash, storage, blockHash).
//! EIP-7928 BAL tracking is handled by the Journal layer — no tracking state here.

const std = @import("std");
const primitives = @import("primitives");
const state = @import("state");
const bytecode = @import("bytecode");
const mpt = @import("mpt");
const types = @import("executor_types");

pub const DbError = error{
    /// Witness is incomplete or inconsistent: a required account proof, bytecode,
    /// or block hash was not provided. The block must be rejected.
    InvalidWitness,
};

/// EIP-4788/7002/7251 system calls run as this address; the reference never
/// reads it from pre-state (process_message_call with should_transfer_value=false),
/// so its proof is legitimately absent from the witness.
const SYSTEM_ADDRESS = primitives.SYSTEM_ADDRESS;

const EMPTY_TRIE_HASH: primitives.Hash = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};

/// Stateless database built from a pre-built NodeIndex + pre-state root.
///
/// Implements duck-typed Database interface (same methods as InMemoryDB):
///   basic(address)              → ?AccountInfo
///   codeByHash(code_hash)       → Bytecode
///   storage(address, key)       → StorageValue
///   blockHash(number)           → Hash
pub const WitnessDatabase = struct {
    node_index: *const mpt.NodeIndex,
    pre_state_root: primitives.Hash,
    /// All known bytecodes by keccak256(code). Witness entries borrow the input slices;
    /// in-block entries are copied and listed in `owned_codes`. Content addressing means an entry
    /// never changes, so adding one needs no revert handling.
    /// EIP-8025: the verifier derives in-block code from execution, so it need not be in the witness.
    codes: std.HashMap(primitives.Hash, []const u8, primitives.HashContext, 80),
    /// Copies backing the in-block entries, freed in deinit. Not an arena: ArenaAllocator
    /// crashes the zkvm guest's freestanding allocator (ZisK vector, Sepolia 11856500).
    owned_codes: std.ArrayList([]u8) = .empty,
    alloc: std.mem.Allocator,
    block_hashes: []const types.BlockHashEntry,
    /// Cache of address → pre-state account (storage root, nonce, balance, code hash),
    /// populated by basic() and storage() during execution. Eliminates redundant account
    /// trie walks in storage() and in the post-execution batch update (storageRootFor), and
    /// lets that update skip accounts the block left unchanged (originalAccount). Accounts
    /// absent from pre-state are cached with exists = false and EMPTY_TRIE_HASH.
    original_accounts: std.HashMap(primitives.Address, OriginalAccount, primitives.AddressContext, 80),
    /// Set only while a system call runs. Its origin is SYSTEM_ADDRESS, whose account the
    /// reference never reads, so a missing proof for it is accepted only then.
    system_call_origin: bool = false,

    /// Pre-state account fields as proven by the witness.
    pub const OriginalAccount = struct {
        storage_root: primitives.Hash,
        exists: bool = false,
        nonce: u64 = 0,
        balance: u256 = 0,
        code_hash: primitives.Hash = primitives.KECCAK_EMPTY,

        fn of(as: ?mpt.AccountState) OriginalAccount {
            const a = as orelse return .{ .storage_root = EMPTY_TRIE_HASH };
            return .{ .storage_root = a.storage_root, .exists = true, .nonce = a.nonce, .balance = a.balance, .code_hash = a.code_hash };
        }

        /// True when writing the post-state account back would leave the trie as the witness
        /// proved it, so the batch update can leave it out. `post_is_empty` is the EIP-161
        /// emptiness of the post-state account (zero nonce/balance, no code, empty storage).
        pub fn unchangedBy(
            self: OriginalAccount,
            nonce: u64,
            balance: u256,
            code_hash: primitives.Hash,
            storage_root: primitives.Hash,
            post_is_empty: bool,
        ) bool {
            // Absent before: still empty means nothing to insert.
            if (!self.exists) return post_is_empty;
            // Present before but empty now: EIP-161 clearing must delete it, even if its
            // pre-state fields happen to match (a pre-existing empty account).
            if (post_is_empty) return false;
            return self.nonce == nonce and self.balance == balance and
                std.mem.eql(u8, &self.code_hash, &code_hash) and
                std.mem.eql(u8, &self.storage_root, &storage_root);
        }
    };

    const Self = @This();

    pub fn init(
        alloc: std.mem.Allocator,
        node_index: *const mpt.NodeIndex,
        pre_state_root: primitives.Hash,
        codes: []const []const u8,
        block_hashes: []const types.BlockHashEntry,
    ) !Self {
        var codes_map = std.HashMap(primitives.Hash, []const u8, primitives.HashContext, 80).init(alloc);
        try codes_map.ensureTotalCapacity(@intCast(codes.len));
        for (codes) |code_bytes| {
            const h = mpt.keccak256(code_bytes);
            try codes_map.put(h, code_bytes);
        }
        return .{
            .node_index = node_index,
            .pre_state_root = pre_state_root,
            .codes = codes_map,
            .alloc = alloc,
            .block_hashes = block_hashes,
            .original_accounts = std.HashMap(primitives.Address, OriginalAccount, primitives.AddressContext, 80).init(alloc),
        };
    }

    pub fn deinit(self: *Self) void {
        self.codes.deinit();
        for (self.owned_codes.items) |c| self.alloc.free(c);
        self.owned_codes.deinit(self.alloc);
        self.original_accounts.deinit();
    }

    /// Called by the journal for every code write (CREATE, EIP-7702 delegations), so
    /// codeByHash can serve it without requiring it in the witness, including to another
    /// account whose code has the same hash. Callers skip empty code.
    pub fn notifyCodeDeployed(self: *Self, code_hash: primitives.Hash, code: []const u8) void {
        // Same hash ⟹ same bytes, so an existing entry is always correct.
        // OOM panics rather than propagates: see basic()'s comment below for why.
        const gop = self.codes.getOrPut(code_hash) catch @panic("out of memory");
        if (!gop.found_existing) {
            const copy = self.alloc.dupe(u8, code) catch @panic("out of memory");
            self.owned_codes.append(self.alloc, copy) catch @panic("out of memory");
            gop.value_ptr.* = copy;
        }
    }

    // ── basic ───────────────────────────────────────────────────────────────

    pub fn basic(self: *Self, address: primitives.Address) !?state.AccountInfo {
        const account_state = mpt.verifyAccountIndexed(
            self.pre_state_root,
            address,
            self.node_index,
        ) catch |err| switch (err) {
            // EIP-8025 witness completeness: InvalidProof means a trie node needed to
            // resolve this account is missing from the witness. A COMPLETE witness proves
            // every touched account's (non-)existence — a truly-absent account resolves to
            // null via an exclusion proof, never InvalidProof — so a missing node means the
            // witness is incomplete for a touched account and replay must fail.
            // Exception: a system call's origin, SYSTEM_ADDRESS, is never read from
            // pre-state by the reference, so its proof is legitimately absent. Any other
            // read of SYSTEM_ADDRESS (a withdrawal, BALANCE) must be proved.
            error.InvalidProof => {
                if (self.system_call_origin and std.mem.eql(u8, &address, &SYSTEM_ADDRESS)) return null;
                return DbError.InvalidWitness;
            },
            else => return DbError.InvalidWitness,
        };

        // These puts must not be dropped: storageRootFor() is a bare cache `get()`,
        // so a dropped entry reads as "account never loaded", and the post-execution
        // batch trie update (executor/output.zig) rebuilds the storage trie from only
        // the touched slots for that case -- a wrong state root reported as success.
        // Nor may a put failure propagate as a plain error: the generic
        // `catch { ctx_error = .database_error }` wrappers in context.zig/host.zig
        // can't tell OOM apart from DbError.InvalidWitness, so it would misreport a
        // host allocator failure as "the witness is incomplete". Panic on OOM instead.
        self.original_accounts.put(address, OriginalAccount.of(account_state)) catch @panic("out of memory");
        const as = account_state orelse return null;
        return state.AccountInfo{
            .balance = as.balance,
            .nonce = as.nonce,
            .code_hash = as.code_hash,
            .code = null,
        };
    }

    // ── codeByHash ──────────────────────────────────────────────────────────

    pub fn codeByHash(self: *Self, code_hash: primitives.Hash) !bytecode.Bytecode {
        if (std.mem.eql(u8, &code_hash, &primitives.KECCAK_EMPTY)) {
            return bytecode.Bytecode.newLegacy(&.{});
        }
        const code_bytes = self.codes.get(code_hash) orelse return DbError.InvalidWitness;
        // Detect EIP-7702 delegation pointer: 0xEF 0x01 0x00 + 20-byte address (23 bytes total).
        // Must return Bytecode.eip7702 so that setupCall detects it and loads the delegation target.
        if (code_bytes.len == 23 and code_bytes[0] == 0xEF and code_bytes[1] == 0x01 and code_bytes[2] == 0x00) {
            var delegation_addr: primitives.Address = [_]u8{0} ** 20;
            @memcpy(&delegation_addr, code_bytes[3..23]);
            return bytecode.Bytecode{ .eip7702 = bytecode.Eip7702Bytecode.new(delegation_addr) };
        }
        return bytecode.Bytecode.newLegacy(code_bytes);
    }

    // ── storage ─────────────────────────────────────────────────────────────

    pub fn storage(
        self: *Self,
        address: primitives.Address,
        index: primitives.StorageKey,
    ) !primitives.StorageValue {
        const storage_root = if (self.original_accounts.get(address)) |o| o.storage_root else blk: {
            const account_state = mpt.verifyAccountIndexed(
                self.pre_state_root,
                address,
                self.node_index,
            ) catch |err| switch (err) {
                // InvalidProof means the witness lacks the node needed to prove
                // anything here — genuine absence is reported as a null
                // account_state below ("valid non-inclusion" in mpt/main.zig).
                // Defaulting to EMPTY_TRIE_HASH would make every subsequent slot
                // read on this account return 0, i.e. a wrong execution result
                // from an incomplete witness. Matches basic()'s handling.
                error.InvalidProof => return DbError.InvalidWitness,
                else => return DbError.InvalidWitness,
            };
            const orig = OriginalAccount.of(account_state);
            // OOM panics rather than propagates: see basic()'s comment above for why.
            self.original_accounts.put(address, orig) catch @panic("out of memory");
            break :blk orig.storage_root;
        };
        const slot = u256ToHash(index);
        const value = mpt.verifyStorageIndexed(storage_root, slot, self.node_index) catch |err| switch (err) {
            // A slot that is genuinely unset yields null from verifyStorageIndexed
            // (valid non-inclusion), which becomes 0 without an error. Reaching
            // InvalidProof means the storage node is missing from the witness, so
            // returning 0 would fabricate a value — the slot's real contents are
            // unknown and may be non-zero.
            error.InvalidProof => return DbError.InvalidWitness,
            else => return DbError.InvalidWitness,
        };
        return value;
    }

    // ── hasNonZeroStorageForAddress ─────────────────────────────────────────

    /// Fallible: this feeds the CREATE collision check, so "I cannot prove it"
    /// must not collapse into "no storage here". Doing so would let a CREATE
    /// succeed at an address the reference rejects — a consensus-level wrong
    /// result from an incomplete witness. A genuinely absent account still
    /// resolves to null (valid non-inclusion) and returns false without error.
    pub fn hasNonZeroStorageForAddress(self: *const Self, address: primitives.Address) !bool {
        if (self.original_accounts.get(address)) |o| {
            return !std.mem.eql(u8, &o.storage_root, &EMPTY_TRIE_HASH);
        }
        const account_state = mpt.verifyAccountIndexed(
            self.pre_state_root,
            address,
            self.node_index,
        ) catch return DbError.InvalidWitness;
        const as = account_state orelse return false;
        return !std.mem.eql(u8, &as.storage_root, &EMPTY_TRIE_HASH);
    }

    // ── blockHash ───────────────────────────────────────────────────────────

    pub fn blockHash(self: *Self, number: u64) !primitives.Hash {
        for (self.block_hashes) |bhe| {
            if (bhe.number == number) return bhe.hash;
        }
        return DbError.InvalidWitness;
    }

    // ── storageRootFor ──────────────────────────────────────────────────────

    /// Returns the pre-state storage root for an address from the execution-time cache.
    /// Called by the post-execution batch trie update to avoid re-walking the account trie.
    /// Returns null for accounts not loaded during execution; batch update falls back to
    /// building the storage trie from scratch (correct for new accounts with no pre-state).
    pub fn storageRootFor(self: *const Self, address: primitives.Address) ?primitives.Hash {
        return if (self.original_accounts.get(address)) |o| o.storage_root else null;
    }

    /// Pre-state account as loaded during execution, or null if it was never loaded.
    pub fn originalAccount(self: *const Self, address: primitives.Address) ?OriginalAccount {
        return self.original_accounts.get(address);
    }
};

// ─── Private helpers ───────────────────────────────────────────────────────────

fn u256ToHash(value: u256) primitives.Hash {
    var out: primitives.Hash = @splat(0);
    var n = value;
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        out[i] = @intCast(n & 0xff);
        n >>= 8;
    }
    return out;
}
