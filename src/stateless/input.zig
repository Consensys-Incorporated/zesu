//! StatelessInput: everything needed to execute a block without full state.
//!
//! The witness format mirrors debug_executionWitness (EL JSON-RPC):
//!   - nodes:   flat pool of RLP-encoded trie node preimages
//!   - codes:   flat array of contract bytecodes
//!   - keys:    20-byte account addresses or 52-byte address+storage_slot pairs
//!   - headers: RLP-encoded block headers (for BLOCKHASH opcode)
//!
//! Proof verification works by hash lookup in the pool: given the state_root,
//! the verifier walks the trie by finding each node via keccak256(node) == expected_hash.

const primitives = @import("primitives");

/// EIP-2930 access list entry.
pub const AccessListEntry = struct {
    address: primitives.Address,
    storage_keys: []const primitives.Hash,
};

/// EIP-7702 authorization tuple (raw — signer recovered in transition()).
pub const AuthorizationTuple = struct {
    chain_id: u256,
    address: primitives.Address,
    nonce: u64,
    /// y_parity (0 or 1).
    v: u64,
    r: u256,
    s: u256,
};

/// Ethereum transaction (all types — Legacy through EIP-7702).
pub const Transaction = struct {
    tx_type: u8,
    chain_id: ?u64,
    nonce: u64,
    /// max_fee_per_gas for EIP-1559/4844/7702; gas_price for Legacy/EIP-2930.
    gas_price: u128,
    /// max_priority_fee_per_gas (EIP-1559/4844/7702 only).
    gas_priority_fee: ?u128,
    gas_limit: u64,
    /// null = contract creation.
    to: ?primitives.Address,
    value: u256,
    data: []const u8,
    access_list: []const AccessListEntry,
    /// EIP-4844 blob versioned hashes.
    blob_hashes: []const primitives.Hash,
    max_fee_per_blob_gas: u128,
    /// EIP-7702 authorization list.
    authorization_list: []const AuthorizationTuple,
    /// Signature fields.
    v: u64,
    r: u256,
    s: u256,
};

/// Full Ethereum block header (post-Cancun, up to and including Amsterdam).
///
/// Fields are listed in their canonical RLP order (indices 0–22).
/// Optional fields (15+) are absent in pre-London blocks.
/// Amsterdam adds block_access_list_hash [21] (EIP-7917) and slot_number [22].
pub const BlockHeader = struct {
    parent_hash: primitives.Hash, // [0]
    ommers_hash: primitives.Hash, // [1]  always KECCAK_EMPTY_LIST in PoS
    beneficiary: primitives.Address, // [2]
    state_root: primitives.Hash, // [3]  post-execution root
    transactions_root: primitives.Hash, // [4]
    receipts_root: primitives.Hash, // [5]
    logs_bloom: [256]u8, // [6]
    difficulty: u256, // [7]  always 0 for PoS
    number: u64, // [8]
    gas_limit: u64, // [9]
    gas_used: u64, // [10]
    timestamp: u64, // [11]
    extra_data: []const u8, // [12]
    mix_hash: primitives.Hash, // [13] prevRandao in PoS
    nonce: u64, // [14] always 0 in PoS
    // EIP-1559 (London+)
    base_fee_per_gas: ?u64, // [15]
    // EIP-4895 (Shanghai+)
    withdrawals_root: ?primitives.Hash, // [16]
    // EIP-4844 (Cancun+)
    blob_gas_used: ?u64, // [17]
    excess_blob_gas: ?u64, // [18]
    // EIP-4788 (Cancun+)
    parent_beacon_block_root: ?primitives.Hash, // [19]
    // EIP-7685 (Prague+)
    requests_hash: ?primitives.Hash, // [20]
    // Amsterdam+
    block_access_list_hash: ?primitives.Hash = null, // [21]
    slot_number: ?u64 = null, // [22]
};

/// EIP-4895 withdrawal (Shanghai+).
pub const Withdrawal = struct {
    index: u64,
    validator_index: u64,
    address: primitives.Address,
    amount: u64, // gwei
};

// ─── Amsterdam spec types ─────────────────────────────────────────────────────

/// Spec-matching execution payload (Amsterdam+).
/// Transactions are stored decoded (ready for execution).
/// parent_beacon_block_root lives in NewPayloadRequest (one level up).
pub const ExecutionPayload = struct {
    parent_hash: primitives.Hash,
    fee_recipient: primitives.Address,
    state_root: primitives.Hash, // POST-execution root (for output verification)
    receipts_root: primitives.Hash,
    logs_bloom: [256]u8,
    prev_randao: primitives.Hash,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8,
    base_fee_per_gas: u64,
    block_hash: primitives.Hash,
    transactions: []const Transaction,
    /// Raw RLP bytes for each transaction, parallel to `transactions`.
    /// Populated by the SSZ decoder; empty slice on JSON/RLP paths.
    /// Used to compute the SSZ hash_tree_root of the execution payload.
    raw_transactions: []const []const u8 = &.{},
    withdrawals: []const Withdrawal,
    blob_gas_used: u64,
    excess_blob_gas: u64,
    slot_number: ?u64 = null,
    /// Raw bytes of the block_access_list field (RLP-encoded).
    /// Populated by the SSZ decoder; empty on JSON/RLP paths.
    /// TODO: decode and use for actual BAL processing.
    block_access_list: []const u8 = &.{},
};

/// EIP-7685 typed execution requests (SszExecutionRequests container).
/// Each field holds the packed fixed-size items of that request type.
/// Populated by the SSZ decoder; all fields are empty on JSON/RLP paths.
pub const ExecutionRequests = struct {
    deposits: []const u8 = &.{}, // packed SszDepositRequest items (192 bytes each)
    withdrawals: []const u8 = &.{}, // packed SszWithdrawalRequest items (76 bytes each)
    consolidations: []const u8 = &.{}, // packed SszConsolidationRequest items (116 bytes each)
};

pub const NewPayloadRequest = struct {
    execution_payload: ExecutionPayload,
    parent_beacon_block_root: primitives.Hash,
    /// EIP-4844 blob versioned hashes from all transactions in the block.
    /// Populated by the SSZ decoder; empty slice on JSON/RLP paths.
    versioned_hashes: []const primitives.Hash = &.{},
    /// EIP-7685 execution requests (SszExecutionRequests container).
    /// Populated by the SSZ decoder; zero-value on JSON/RLP paths.
    execution_requests: ExecutionRequests = .{},
};

/// Execution witness (spec-matching Amsterdam ExecutionWitness).
/// state_root is NOT stored here — derived in stateless/main.zig via findPreStateRoot.
pub const ExecutionWitness = struct {
    nodes: []const []const u8, // trie node preimages (spec field: `state`)
    codes: []const []const u8, // contract bytecodes
    headers: []const []const u8, // RLP ancestor block headers
};

/// Witness with an explicit pre-state root and key list, used by the MPT
/// proof verifier (mpt.verifyWitness) and unit tests.
pub const StateWitness = struct {
    state_root: primitives.Hash,
    nodes: []const []const u8,
    codes: []const []const u8,
    keys: []const []const u8,
    headers: []const []const u8,
};

pub const ChainConfig = struct {
    chain_id: u64 = 1,
    /// Fork hint carried by the input (e.g. populated by the SSZ extended layout).
    /// Precedence at the executor entry points: an explicit `fork_name` argument
    /// (e.g. the `--fork` CLI override) wins; otherwise this field is used; if both
    /// are null, the executor falls back to mainnet timestamp-based spec lookup.
    fork_name: ?[]const u8 = null,
    /// EIP-8025: the input's active_fork enum index (ProtocolFork). Amsterdam-specific
    /// validation (see the runner) rejects a chain config whose active fork is not Amsterdam.
    active_fork_idx: u64 = 0,
    /// EIP-8025: active_fork.activation block/timestamp (SSZ optionals; null = unset). The
    /// fork must be active for the target payload — payload block/timestamp >= these.
    activation_block: ?u64 = null,
    activation_timestamp: ?u64 = null,
};

/// Top-level input (matches Amsterdam spec StatelessInput).
pub const StatelessInput = struct {
    new_payload_request: NewPayloadRequest,
    witness: ExecutionWitness,
    chain_config: ChainConfig = .{},
    /// Pre-recovered secp256k1 public keys, one per transaction in order.
    /// Each entry is 64 bytes (uncompressed, no 0x04 prefix); empty slice = not provided.
    /// When provided, used to derive sender address instead of calling ecrecover.
    public_keys: []const []const u8 = &.{},
};

/// Build an ExecutionPayload from a BlockHeader + decoded transactions + withdrawals.
/// Used by RLP and JSON decoders. Maps consensus-layer field names to execution-payload names.
pub fn payloadFromBlock(
    block: BlockHeader,
    transactions: []const Transaction,
    withdrawals: []const Withdrawal,
) ExecutionPayload {
    return .{
        .parent_hash = block.parent_hash,
        .fee_recipient = block.beneficiary,
        .state_root = block.state_root,
        .receipts_root = block.receipts_root,
        .logs_bloom = block.logs_bloom,
        .prev_randao = block.mix_hash,
        .block_number = block.number,
        .gas_limit = block.gas_limit,
        .gas_used = block.gas_used,
        .timestamp = block.timestamp,
        .extra_data = block.extra_data,
        .base_fee_per_gas = block.base_fee_per_gas orelse 0,
        .block_hash = @splat(0), // not stored in BlockHeader
        .transactions = transactions,
        .withdrawals = withdrawals,
        .blob_gas_used = block.blob_gas_used orelse 0,
        .excess_blob_gas = block.excess_blob_gas orelse 0,
        .slot_number = block.slot_number,
    };
}
