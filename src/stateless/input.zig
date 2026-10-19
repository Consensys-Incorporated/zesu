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
    /// Decoded transactions. The SSZ decoder leaves this empty; executeStatelessInput
    /// decodes `raw_transactions` after checking the block hash.
    transactions: []const Transaction,
    /// Raw RLP bytes for each transaction, parallel to `transactions`.
    /// Populated by the SSZ decoder.
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
    // EIP-8282 (Amsterdam+): builder execution requests.
    builder_deposits: []const u8 = &.{}, // packed SszBuilderDepositRequest items (184 bytes each)
    builder_exits: []const u8 = &.{}, // packed SszBuilderExitRequest items (68 bytes each)
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

/// Addresses of the protocol system contracts the executor calls or reads logs from.
/// Every field defaults to the canonical mainnet address; chains whose genesis config
/// overrides them (e.g. Besu `depositContractAddress`, `withdrawalRequestContractAddress`,
/// `consolidationRequestContractAddress`) supply their own.
pub const SystemContracts = struct {
    /// EIP-4788 beacon roots contract (pre-block, Cancun+).
    beacon_roots: primitives.Address = MAINNET_BEACON_ROOTS,
    /// EIP-2935 history storage contract (pre-block, Prague+).
    history_storage: primitives.Address = MAINNET_HISTORY_STORAGE,
    /// EIP-6110 deposit contract whose `DepositEvent` logs become deposit requests (Prague+).
    deposit: primitives.Address = MAINNET_DEPOSIT,
    /// EIP-7002 withdrawal requests contract (post-block, Prague+).
    withdrawal_request: primitives.Address = MAINNET_WITHDRAWAL_REQUEST,
    /// EIP-7251 consolidation requests contract (post-block, Prague+).
    consolidation_request: primitives.Address = MAINNET_CONSOLIDATION_REQUEST,
    /// EIP-8282 builder deposit requests contract (post-block, Amsterdam+).
    builder_deposit_request: primitives.Address = MAINNET_BUILDER_DEPOSIT_REQUEST,
    /// EIP-8282 builder exit requests contract (post-block, Amsterdam+).
    builder_exit_request: primitives.Address = MAINNET_BUILDER_EXIT_REQUEST,

    /// Mainnet addresses, with the deposit contract of known public testnets that deploy
    /// their own (only Sepolia so far). Used when the caller supplies no override.
    pub fn forChainId(chain_id: u64) SystemContracts {
        return switch (chain_id) {
            11155111 => .{ .deposit = SEPOLIA_DEPOSIT },
            else => .{},
        };
    }

    // 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02
    pub const MAINNET_BEACON_ROOTS: primitives.Address = .{
        0x00, 0x0f, 0x3d, 0xf6, 0xd7, 0x32, 0x80, 0x7e, 0xf1, 0x31,
        0x9f, 0xb7, 0xb8, 0xbb, 0x85, 0x22, 0xd0, 0xbe, 0xac, 0x02,
    };
    // 0x0000F90827F1C53a10cb7A02335B175320002935
    pub const MAINNET_HISTORY_STORAGE: primitives.Address = .{
        0x00, 0x00, 0xf9, 0x08, 0x27, 0xf1, 0xc5, 0x3a, 0x10, 0xcb,
        0x7a, 0x02, 0x33, 0x5b, 0x17, 0x53, 0x20, 0x00, 0x29, 0x35,
    };
    // 0x00000000219ab540356cBB839Cbe05303d7705Fa
    pub const MAINNET_DEPOSIT: primitives.Address = .{
        0x00, 0x00, 0x00, 0x00, 0x21, 0x9a, 0xb5, 0x40, 0x35, 0x6c,
        0xbb, 0x83, 0x9c, 0xbe, 0x05, 0x30, 0x3d, 0x77, 0x05, 0xfa,
    };
    // 0x7f02C3E3c98b133055B8B348B2Ac625669Ed295D
    pub const SEPOLIA_DEPOSIT: primitives.Address = .{
        0x7f, 0x02, 0xc3, 0xe3, 0xc9, 0x8b, 0x13, 0x30, 0x55, 0xb8,
        0xb3, 0x48, 0xb2, 0xac, 0x62, 0x56, 0x69, 0xed, 0x29, 0x5d,
    };
    // 0x00000961Ef480Eb55e80D19ad83579A64c007002
    pub const MAINNET_WITHDRAWAL_REQUEST: primitives.Address = .{
        0x00, 0x00, 0x09, 0x61, 0xef, 0x48, 0x0e, 0xb5, 0x5e, 0x80,
        0xd1, 0x9a, 0xd8, 0x35, 0x79, 0xa6, 0x4c, 0x00, 0x70, 0x02,
    };
    // 0x0000BBdDc7CE488642fb579F8B00f3a590007251
    pub const MAINNET_CONSOLIDATION_REQUEST: primitives.Address = .{
        0x00, 0x00, 0xbb, 0xdd, 0xc7, 0xce, 0x48, 0x86, 0x42, 0xfb,
        0x57, 0x9f, 0x8b, 0x00, 0xf3, 0xa5, 0x90, 0x00, 0x72, 0x51,
    };
    // 0x0000BFF46984E3725691FA540A8C7589300D8282 (glamsterdam-devnet-7 predeploy)
    pub const MAINNET_BUILDER_DEPOSIT_REQUEST: primitives.Address = .{
        0x00, 0x00, 0xbf, 0xf4, 0x69, 0x84, 0xe3, 0x72, 0x56, 0x91,
        0xfa, 0x54, 0x0a, 0x8c, 0x75, 0x89, 0x30, 0x0d, 0x82, 0x82,
    };
    // 0x000064D678505AD48F8CCB093BC65613800E8282 (glamsterdam-devnet-7 predeploy)
    pub const MAINNET_BUILDER_EXIT_REQUEST: primitives.Address = .{
        0x00, 0x00, 0x64, 0xd6, 0x78, 0x50, 0x5a, 0xd4, 0x8f, 0x8c,
        0xcb, 0x09, 0x3b, 0xc6, 0x56, 0x13, 0x80, 0x0e, 0x82, 0x82,
    };
};

pub const ChainConfig = struct {
    chain_id: u64 = 1,
    /// Fork hint carried by the input (e.g. populated by the SSZ extended layout).
    /// Precedence at the executor entry points: an explicit `fork_name` argument
    /// (e.g. the `--fork` CLI override) wins; otherwise this field is used; if both
    /// are null, the executor falls back to mainnet timestamp-based spec lookup.
    fork_name: ?[]const u8 = null,
    /// The stateless input schema the guest decoded: fork_index << 8 | revision.
    /// Echoed verbatim in the SSZ validation result (zkevm@v0.8.4).
    schema_id: u16 = 0,
};

/// Top-level input (matches Amsterdam spec StatelessInput).
pub const StatelessInput = struct {
    new_payload_request: NewPayloadRequest,
    witness: ExecutionWitness,
    chain_config: ChainConfig = .{},
};
