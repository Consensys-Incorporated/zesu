/// Canonical EVM state transition types.
///
/// Defines the core types used by the executor, t8n tool, and spec-test runner.
/// JSON parsing lives in t8n/input.zig; these are pure data definitions.
const std = @import("std");

// ─── Primitive aliases ────────────────────────────────────────────────────────

pub const Address = [20]u8;
pub const Hash = [32]u8;
pub const U256 = u256;

// ─── State types ──────────────────────────────────────────────────────────────

pub const AllocAccount = struct {
    balance: U256 = 0,
    nonce: u64 = 0,
    code: []const u8 = &.{},
    storage: std.AutoHashMapUnmanaged(U256, U256) = .{},
    /// Pre-execution storage root (proven via MPT witness).
    /// When non-null, `storage` is treated as a delta: only touched slots are stored,
    /// and 0-valued entries indicate deletions.  computeStorageRoot() applies these
    /// deltas to this root instead of building a new trie from scratch.
    pre_storage_root: ?[32]u8 = null,
    /// Authoritative code hash from EVM state.  Set by extractPostState() so that
    /// computeStateRootDelta() uses the correct hash even when `code` bytes are absent
    /// (e.g. a touched contract whose code is not included in the stateless witness).
    /// When null, the hash is computed from `code` (backwards-compatible).
    code_hash: ?[32]u8 = null,
};

pub const AccessListEntry = struct {
    address: Address,
    storage_keys: []const Hash,
};

pub const Withdrawal = struct {
    index: u64,
    validator_index: u64,
    address: Address,
    amount: u64, // gwei
};

pub const BlockHashEntry = struct {
    number: u64,
    hash: Hash,
};

// ─── Block environment ────────────────────────────────────────────────────────

pub const Env = struct {
    coinbase: Address = [_]u8{0} ** 20,
    gas_limit: u64 = 30_000_000,
    number: u64 = 0,
    timestamp: u64 = 0,
    difficulty: U256 = 0,
    base_fee: ?u64 = null,
    random: ?Hash = null,
    excess_blob_gas: ?u64 = null,
    parent_difficulty: ?U256 = null,
    parent_base_fee: ?u64 = null,
    parent_gas_used: ?u64 = null,
    parent_gas_limit: ?u64 = null,
    parent_timestamp: ?u64 = null,
    parent_uncle_hash: ?Hash = null,
    parent_excess_blob_gas: ?u64 = null,
    parent_blob_gas_used: ?u64 = null,
    parent_beacon_block_root: ?Hash = null,
    /// Per-block blob base fee update fraction override.
    /// When set, used instead of the spec-derived default in buildBlockEnv.
    /// Read from config.blobSchedule[fork].baseFeeUpdateFraction in test fixtures.
    blob_base_fee_update_fraction: ?u64 = null,
    /// EIP-2935: parent block hash for history storage contract (Prague+).
    parent_hash: ?Hash = null,
    block_hashes: []BlockHashEntry = &.{},
    withdrawals: []Withdrawal = &.{},
    /// EIP-7843 (Amsterdam+): beacon chain slot number.
    /// `null` when the block header does not carry a slot number (pre-Amsterdam).
    slot_number: ?u64 = null,
    /// Block header's declared gasUsed field. When set, validated post-execution
    /// against the actual cumulative gas used by all transactions.
    gas_used_header: ?u64 = null,
    /// Block header's declared blobGasUsed field (Cancun+). When set, validated
    /// post-execution against the actual blob gas consumed by type-3 transactions.
    blob_gas_used_header: ?u64 = null,
    /// Full RLP-encoded block size in bytes (EIP-7934, Osaka+). When set,
    /// validated in validateBlock against MAX_RLP_BLOCK_SIZE (8 MiB).
    block_rlp_size: ?u64 = null,
};

// ─── Receipt / log types ──────────────────────────────────────────────────────

/// Bloom filter: 2048-bit (256-byte) log accumulator.
pub const Bloom = [256]u8;

pub const Log = struct {
    address: Address,
    topics: []Hash,
    data: []const u8,
    block_number: u64,
    tx_hash: Hash,
    tx_index: u64,
    block_hash: Hash,
    log_index: u64,
    removed: bool = false,
};

pub const Receipt = struct {
    type: u8,
    tx_hash: Hash,
    tx_index: u64,
    block_hash: Hash,
    block_number: u64,
    from: Address,
    to: ?Address,
    cumulative_gas_used: u64,
    gas_used: u64,
    contract_address: ?Address,
    logs: []Log,
    logs_bloom: Bloom,
    status: u8,
    /// Pre-Byzantium (EIP-658): intermediate state root after this tx. Null = post-Byzantium.
    state_root: ?[32]u8 = null,
    effective_gas_price: u128,
    blob_gas_used: ?u64 = null,
    blob_gas_price: ?u128 = null,
};

// ─── Transaction types ────────────────────────────────────────────────────────

/// EIP-7702 authorization item (pre-recovered: signer known from fixture).
pub const AuthorizationItem = struct {
    chain_id: U256 = 0,
    address: Address = [_]u8{0} ** 20,
    nonce: u64 = 0,
    /// The recovered signer (authority). If null, treated as Invalid.
    signer: ?Address = null,
    /// Signature fields (needed for tx signing hash and signer recovery).
    y_parity: u256 = 0,
    r: u256 = 0,
    s: u256 = 0,
};

// ─── Block access list types ──────────────────────────────────────────────────

/// One storage slot change recorded in the block access list.
pub const StorageChange = struct { slot: Hash, post_value: u256 };

/// All state accesses on a single address during block execution.
/// Produced by WitnessDatabase tracking; consumed by validateBlockAccessList.
pub const AccessedEntry = struct {
    address: Address,
    /// Account state BEFORE execution (from WitnessDatabase pre-state).
    pre_nonce: u64,
    pre_balance: u256,
    pre_code_hash: Hash,
    /// Account state AFTER execution (from post-state alloc).
    post_nonce: u64,
    post_balance: u256,
    post_code_hash: Hash,
    /// Storage slots whose value changed (pre_val != post_val).
    storage_changes: []StorageChange,
    /// Storage slots that were read but whose value did not change.
    storage_reads: []Hash,
};

pub const TxInput = struct {
    type: u8 = 0,
    nonce: ?u64 = null,
    gas_price: ?u128 = null,
    max_fee_per_gas: ?u128 = null,
    max_priority_fee_per_gas: ?u128 = null,
    gas: u64 = 21_000,
    to: ?Address = null,
    from: ?Address = null,
    value: U256 = 0,
    data: []const u8 = &.{},
    v: ?U256 = null,
    r: ?U256 = null,
    s: ?U256 = null,
    secret_key: ?[32]u8 = null,
    protected: bool = true,
    chain_id: ?u64 = null,
    access_list: []AccessListEntry = &.{},
    blob_versioned_hashes: []Hash = &.{},
    max_fee_per_blob_gas: ?u128 = null,
    /// EIP-7702: authorization list for type 4 transactions.
    authorization_list: []AuthorizationItem = &.{},
};
