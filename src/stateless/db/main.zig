//! WitnessDatabase: stateless EVM database backed by a pre-built MPT NodeIndex.
//!
//! Serves account/storage reads via live MPT proof verification (O(log n) per read
//! via NodeIndex O(1) node lookups). Contract bytecodes are served from two sources:
//! the witness codes pool (linear scan over a bounded set) and the deployed_codes map
//! (O(1) lookup for bytecodes produced by CREATE during the current block).
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
    /// Witness bytecodes indexed by keccak256(code) for O(1) lookup.
    witness_codes: std.HashMap(primitives.Hash, []const u8, primitives.HashContext, 80),
    block_hashes: []const types.BlockHashEntry,
    /// Bytecodes deployed by CREATE in the current block, keyed by code hash.
    /// EIP-8025: verifier derives these from execution, so they need not be in the witness.
    deployed_codes: std.HashMap(primitives.Hash, bytecode.Bytecode, primitives.HashContext, 80),
    /// Cache of address → storage_root populated by basic() during execution.
    /// Eliminates redundant account trie walks in storage() and in the post-execution
    /// batch update (storageRootFor). Accounts absent from pre-state are cached as
    /// EMPTY_TRIE_HASH so the batch output phase skips verifyAccountIndexed for them.
    storage_root_cache: std.HashMap(primitives.Address, primitives.Hash, primitives.AddressContext, 80),

    const Self = @This();

    pub fn init(
        alloc: std.mem.Allocator,
        node_index: *const mpt.NodeIndex,
        pre_state_root: primitives.Hash,
        codes: []const []const u8,
        block_hashes: []const types.BlockHashEntry,
    ) !Self {
        var witness_codes = std.HashMap(primitives.Hash, []const u8, primitives.HashContext, 80).init(alloc);
        try witness_codes.ensureTotalCapacity(@intCast(codes.len));
        for (codes) |code_bytes| {
            const h = mpt.keccak256(code_bytes);
            try witness_codes.put(h, code_bytes);
        }
        return .{
            .node_index = node_index,
            .pre_state_root = pre_state_root,
            .witness_codes = witness_codes,
            .block_hashes = block_hashes,
            .deployed_codes = std.HashMap(primitives.Hash, bytecode.Bytecode, primitives.HashContext, 80).init(alloc),
            .storage_root_cache = std.HashMap(primitives.Address, primitives.Hash, primitives.AddressContext, 80).init(alloc),
        };
    }

    pub fn deinit(self: *Self) void {
        self.witness_codes.deinit();
        self.deployed_codes.deinit();
        self.storage_root_cache.deinit();
    }

    /// Called by the journal after each committed transaction to register bytecodes
    /// deployed by CREATE in that transaction. Allows codeByHash to serve them without
    /// requiring them in the witness (EIP-8025: the verifier derives them from execution).
    pub fn notifyCodeDeployed(self: *Self, code_hash: primitives.Hash, code: bytecode.Bytecode) !void {
        try self.deployed_codes.put(code_hash, code);
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
            // Exception: SYSTEM_ADDRESS (EIP-4788/7002/7251 system-call caller) is never
            // read from pre-state by the reference (process_message_call with
            // should_transfer_value=false), so its proof is legitimately absent.
            error.InvalidProof => {
                if (std.mem.eql(u8, &address, &SYSTEM_ADDRESS)) return null;
                return DbError.InvalidWitness;
            },
            else => return DbError.InvalidWitness,
        };

        const as = account_state orelse {
            self.storage_root_cache.put(address, EMPTY_TRIE_HASH) catch {};
            return null;
        };
        self.storage_root_cache.put(address, as.storage_root) catch {};
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
        if (self.witness_codes.get(code_hash)) |code_bytes| {
            // Detect EIP-7702 delegation pointer: 0xEF 0x01 0x00 + 20-byte address (23 bytes total).
            // Must return Bytecode.eip7702 so that setupCall detects it and loads the delegation target.
            if (code_bytes.len == 23 and code_bytes[0] == 0xEF and code_bytes[1] == 0x01 and code_bytes[2] == 0x00) {
                var delegation_addr: primitives.Address = [_]u8{0} ** 20;
                @memcpy(&delegation_addr, code_bytes[3..23]);
                return bytecode.Bytecode{ .eip7702 = bytecode.Eip7702Bytecode.new(delegation_addr) };
            }
            return bytecode.Bytecode.newLegacy(code_bytes);
        }
        if (self.deployed_codes.get(code_hash)) |code| return code;
        return DbError.InvalidWitness;
    }

    // ── storage ─────────────────────────────────────────────────────────────

    pub fn storage(
        self: *Self,
        address: primitives.Address,
        index: primitives.StorageKey,
    ) !primitives.StorageValue {
        const storage_root = self.storage_root_cache.get(address) orelse blk: {
            const account_state = mpt.verifyAccountIndexed(
                self.pre_state_root,
                address,
                self.node_index,
            ) catch |err| switch (err) {
                error.InvalidProof => break :blk EMPTY_TRIE_HASH,
                else => return DbError.InvalidWitness,
            };
            const root = if (account_state) |as| as.storage_root else EMPTY_TRIE_HASH;
            self.storage_root_cache.put(address, root) catch {};
            break :blk root;
        };
        const slot = u256ToHash(index);
        const value = mpt.verifyStorageIndexed(storage_root, slot, self.node_index) catch |err| switch (err) {
            error.InvalidProof => return 0,
            else => return DbError.InvalidWitness,
        };
        return value;
    }

    // ── hasNonZeroStorageForAddress ─────────────────────────────────────────

    pub fn hasNonZeroStorageForAddress(self: *const Self, address: primitives.Address) bool {
        if (self.storage_root_cache.get(address)) |root| {
            return !std.mem.eql(u8, &root, &EMPTY_TRIE_HASH);
        }
        const account_state = mpt.verifyAccountIndexed(
            self.pre_state_root,
            address,
            self.node_index,
        ) catch return false;
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
        return self.storage_root_cache.get(address);
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
