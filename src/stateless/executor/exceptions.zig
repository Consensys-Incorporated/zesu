/// Canonical exception type identifiers matching the execution-spec-tests vocabulary.
///
/// Used in `expectException` fixture fields and in `RejectedTx.err` strings.
/// Call `.name()` to produce the `"TransactionException.FOO"` string expected by
/// the test runner's exception-matching logic.
pub const TransactionException = enum {
    GAS_ALLOWANCE_EXCEEDED,
    GAS_LIMIT_EXCEEDS_MAXIMUM,
    INITCODE_SIZE_EXCEEDED,
    INSUFFICIENT_ACCOUNT_FUNDS,
    INSUFFICIENT_MAX_FEE_PER_BLOB_GAS,
    INSUFFICIENT_MAX_FEE_PER_GAS,
    INTRINSIC_GAS_TOO_LOW,
    INVALID_CHAIN_ID,
    NONCE_IS_MAX,
    NONCE_MISMATCH_TOO_HIGH,
    NONCE_MISMATCH_TOO_LOW,
    PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS,
    SENDER_NOT_EOA,
    TYPE_1_TX_PRE_FORK,
    TYPE_2_TX_PRE_FORK,
    TYPE_3_TX_BLOB_COUNT_EXCEEDED,
    TYPE_3_TX_CONTRACT_CREATION,
    TYPE_3_TX_INVALID_BLOB_VERSIONED_HASH,
    TYPE_3_TX_MAX_BLOB_GAS_ALLOWANCE_EXCEEDED,
    TYPE_3_TX_PRE_FORK,
    TYPE_3_TX_ZERO_BLOBS,
    TYPE_4_EMPTY_AUTHORIZATION_LIST,
    TYPE_4_TX_CONTRACT_CREATION,
    TYPE_4_TX_PRE_FORK,
    TYPE_UNKNOWN_TX_PRE_FORK,

    pub fn name(self: TransactionException) []const u8 {
        return switch (self) {
            inline else => |tag| "TransactionException." ++ @tagName(tag),
        };
    }
};

/// Prefix for block-level exception strings in fixture `expectException` fields.
pub const block_exception_prefix = "BlockException.";

pub const BlockException = enum {
    TOO_MANY_UNCLES,
    UNCLE_IN_CHAIN,
    UNCLE_IS_ANCESTOR,
    UNCLE_IS_BROTHER,
    UNCLE_PARENT_INCORRECT,
    EXTRA_DATA_TOO_BIG,
    EXTRA_DATA_INVALID_DAO,
    UNKNOWN_PARENT,
    UNCLE_UNKNOWN_PARENT,
    UNKNOWN_PARENT_ZERO,
    GASLIMIT_TOO_BIG,
    INVALID_BLOCK_NUMBER,
    INVALID_BLOCK_TIMESTAMP_OLDER_THAN_PARENT,
    INVALID_DIFFICULTY,
    INVALID_LOG_BLOOM,
    INVALID_STATE_ROOT,
    INVALID_RECEIPTS_ROOT,
    INVALID_TRANSACTIONS_ROOT,
    INVALID_UNCLES_HASH,
    GAS_USED_OVERFLOW,
    INVALID_GASLIMIT,
    INVALID_BASEFEE_PER_GAS,
    INVALID_GAS_USED,
    INVALID_GAS_USED_ABOVE_LIMIT,
    INVALID_WITHDRAWALS_ROOT,
    INCORRECT_BLOCK_FORMAT,
    BLOB_GAS_USED_ABOVE_LIMIT,
    INCORRECT_BLOB_GAS_USED,
    INCORRECT_EXCESS_BLOB_GAS,
    BLOCK_RLP_TOO_LARGE,
    INVALID_VERSIONED_HASHES,
    RLP_STRUCTURES_ENCODING,
    RLP_WITHDRAWALS_NOT_READ,
    RLP_INVALID_FIELD_OVERFLOW_64,
    RLP_INVALID_ADDRESS,
    RLP_BLOCK_LIMIT_EXCEEDED,
    INVALID_REQUESTS,
    IMPORT_IMPOSSIBLE_LEGACY,
    IMPORT_IMPOSSIBLE_LEGACY_WRONG_PARENT,
    IMPORT_IMPOSSIBLE_LONDON_WRONG_PARENT,
    IMPORT_IMPOSSIBLE_PARIS_WRONG_POW,
    IMPORT_IMPOSSIBLE_PARIS_WRONG_POS,
    IMPORT_IMPOSSIBLE_LONDON_OVER_PARIS,
    IMPORT_IMPOSSIBLE_PARIS_OVER_SHANGHAI,
    IMPORT_IMPOSSIBLE_SHANGHAI,
    IMPORT_IMPOSSIBLE_UNCLES_OVER_PARIS,
    IMPORT_IMPOSSIBLE_DIFFICULTY_OVER_PARIS,
    SYSTEM_CONTRACT_EMPTY,
    SYSTEM_CONTRACT_CALL_FAILED,
    INVALID_BLOCK_HASH,
    INVALID_DEPOSIT_EVENT_LAYOUT,
    INVALID_BLOCK_ACCESS_LIST,
    INVALID_BAL_HASH,
    INVALID_BAL_EXTRA_ACCOUNT,
    INVALID_BAL_MISSING_ACCOUNT,
    BLOCK_ACCESS_LIST_GAS_LIMIT_EXCEEDED,

    pub fn name(self: BlockException) []const u8 {
        return switch (self) {
            inline else => |tag| "BlockException." ++ @tagName(tag),
        };
    }
};

/// Maps a block validation error to its canonical BlockException string.
/// Returns null if `err` is not a known block-level error.
pub fn mapBlockError(err: anyerror) ?[]const u8 {
    const E = BlockException;
    return switch (err) {
        error.IncorrectExcessBlobGas => E.INCORRECT_EXCESS_BLOB_GAS.name(),
        error.GasLimitTooBig => E.GASLIMIT_TOO_BIG.name(),
        error.InvalidBlockTimestampOlderThanParent => E.INVALID_BLOCK_TIMESTAMP_OLDER_THAN_PARENT.name(),
        error.InvalidBaseFeePerGas => E.INVALID_BASEFEE_PER_GAS.name(),
        error.InvalidGasLimit => E.INVALID_GASLIMIT.name(),
        error.BlobGasUsedAboveLimit => E.BLOB_GAS_USED_ABOVE_LIMIT.name(),
        error.IncorrectBlobGasUsed => E.INCORRECT_BLOB_GAS_USED.name(),
        error.InvalidGasUsed => E.INVALID_GAS_USED.name(),
        error.InvalidGasUsedAboveLimit => E.INVALID_GAS_USED_ABOVE_LIMIT.name(),
        error.GasUsedOverflow => E.GAS_USED_OVERFLOW.name(),
        error.InvalidBlockAccessList => E.INVALID_BLOCK_ACCESS_LIST.name(),
        error.BalGasLimitExceeded => E.BLOCK_ACCESS_LIST_GAS_LIMIT_EXCEEDED.name(),
        error.BlockRlpTooLarge => E.BLOCK_RLP_TOO_LARGE.name(),
        error.InvalidBlockHash => E.INVALID_BLOCK_HASH.name(),
        error.InvalidRequests => E.INVALID_REQUESTS.name(),
        else => null,
    };
}

/// Maps a transition error to the canonical TransactionException string expected
/// by the execution-spec-tests exception vocabulary.
/// Used by runner.zig (and t8n) to classify errors returned by transition().
pub fn mapTransactionError(err: anyerror) []const u8 {
    const E = TransactionException;
    return switch (err) {
        error.TxGasLimitExceedsBlockLimit => E.GAS_ALLOWANCE_EXCEEDED.name(),
        error.InvalidBlobVersionedHash => E.TYPE_3_TX_INVALID_BLOB_VERSIONED_HASH.name(),
        error.EmptyBlobList => E.TYPE_3_TX_ZERO_BLOBS.name(),
        error.TooManyBlobs => E.TYPE_3_TX_BLOB_COUNT_EXCEEDED.name(),
        error.BlobGasPriceTooLow => E.INSUFFICIENT_MAX_FEE_PER_BLOB_GAS.name(),
        error.BlobCreateTransaction => E.TYPE_3_TX_CONTRACT_CREATION.name(),
        error.GasPriceLessThanBaseFee => E.INSUFFICIENT_MAX_FEE_PER_GAS.name(),
        error.InsufficientGas => E.INTRINSIC_GAS_TOO_LOW.name(),
        error.SenderHasCode => E.SENDER_NOT_EOA.name(),
        error.CreateInitcodeOverLimit => E.INITCODE_SIZE_EXCEEDED.name(),
        error.PriorityFeeGreaterThanMaxFee => E.PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS.name(),
        error.NonceMismatch => E.NONCE_MISMATCH_TOO_LOW.name(),
        error.NonceMismatchTooHigh => E.NONCE_MISMATCH_TOO_HIGH.name(),
        error.NonceIsMax => E.NONCE_IS_MAX.name(),
        error.BalanceOverflow, error.BlobFeeOverflow, error.InsufficientBalance => E.INSUFFICIENT_ACCOUNT_FUNDS.name(),
        error.InvalidChainId => E.INVALID_CHAIN_ID.name(),
        error.GasLimitExceedsCap => E.GAS_LIMIT_EXCEEDS_MAXIMUM.name(),
        error.Type4TxContractCreation => E.TYPE_4_TX_CONTRACT_CREATION.name(),
        error.EmptyAuthorizationList => E.TYPE_4_EMPTY_AUTHORIZATION_LIST.name(),
        error.BlobGasLimitExceeded => E.TYPE_3_TX_MAX_BLOB_GAS_ALLOWANCE_EXCEEDED.name(),
        error.Type1TxPreFork => E.TYPE_1_TX_PRE_FORK.name(),
        error.Type2TxPreFork => E.TYPE_2_TX_PRE_FORK.name(),
        error.Type3TxPreFork => E.TYPE_3_TX_PRE_FORK.name(),
        error.Type4TxPreFork => E.TYPE_4_TX_PRE_FORK.name(),
        error.TypeUnknownTxPreFork => E.TYPE_UNKNOWN_TX_PRE_FORK.name(),
        else => @errorName(err),
    };
}
