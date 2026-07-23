const std = @import("std");
const primitives = @import("primitives");

/// EVM configuration
pub const CfgEnv = struct {
    /// Chain ID of the EVM. Used in CHAINID opcode and transaction's chain ID check.
    ///
    /// Chain ID is introduced EIP-155.
    chain_id: u64,
    /// Whether to check the transaction's chain ID.
    ///
    /// If set to `false`, the transaction's chain ID check will be skipped.
    tx_chain_id_check: bool,
    /// Specification for EVM represent the hardfork
    spec: primitives.SpecId,
    /// Contract code size limit override.
    ///
    /// If None, the limit will be determined by the SpecId (EIP-170 or EIP-7907) at runtime.
    /// If Some, this specific limit will be used regardless of SpecId.
    ///
    /// Useful to increase this because of tests.
    limit_contract_code_size: ?usize,
    /// Contract initcode size limit override.
    ///
    /// If None, the limit will check if `limit_contract_code_size` is set.
    /// If it is set, it will double it for a limit.
    /// If it is not set, the limit will be determined by the SpecId (EIP-170 or EIP-7907) at runtime.
    ///
    /// Useful to increase this because of tests.
    limit_contract_initcode_size: ?usize,
    /// Skips the nonce validation against the account's nonce
    disable_nonce_check: bool,
    /// Blob max count. EIP-7840 Add blob schedule to EL config files.
    ///
    /// If this config is not set, the check for max blobs will be skipped.
    max_blobs_per_tx: ?u64,
    /// Blob base fee update fraction. EIP-4844 Blob base fee update fraction.
    ///
    /// If this config is not set, the blob base fee update fraction will be set to the default value.
    /// See also [CfgEnv::blob_base_fee_update_fraction].
    ///
    /// Default values: Cancun (3338477), Prague/Osaka (5007716), BPO1 (8346193), BPO2 (11684671).
    /// See [`CfgEnv::blobBaseFeeUpdateFraction`] for the resolution logic.
    blob_base_fee_update_fraction: ?u64,
    /// Configures the gas limit cap for the transaction.
    ///
    /// If `None`, default value defined by spec will be used.
    ///
    /// Introduced in Osaka in EIP-7825: Transaction Gas Limit Cap
    /// with initials cap of 30M.
    tx_gas_limit_cap: ?u64,
    /// A hard memory limit in bytes beyond which
    /// OutOfGasError::Memory cannot be resized.
    ///
    /// In cases where the gas limit may be extraordinarily high, it is recommended to set this to
    /// a sane value to prevent memory allocation panics.
    ///
    /// Defaults to `2^32 - 1` bytes per EIP-1985.
    memory_limit: u64,
    /// Skip balance checks if `true`
    ///
    /// Adds transaction cost to balance to ensure execution doesn't fail.
    ///
    /// By default, it is set to `false`.
    disable_balance_check: bool,
    /// There are use cases where it's allowed to provide a gas limit that's higher than a block's gas limit.
    ///
    /// To that end, you can disable the block gas limit validation.
    ///
    /// By default, it is set to `false`.
    disable_block_gas_limit: bool,
    /// EIP-3541 rejects the creation of contracts that starts with 0xEF
    ///
    /// This is useful for chains that do not implement EIP-3541.
    ///
    /// By default, it is set to `false`.
    disable_eip3541: bool,
    /// EIP-3607 rejects transactions from senders with deployed code
    ///
    /// In development, it can be desirable to simulate calls from contracts, which this setting allows.
    ///
    /// By default, it is set to `false`.
    disable_eip3607: bool,
    /// EIP-7623 increases calldata cost.
    ///
    /// This EIP can be considered irrelevant in the context of an EVM-compatible L2 rollup,
    /// if it does not make use of blobs.
    ///
    /// By default, it is set to `false`.
    disable_eip7623: bool,
    /// Disables base fee checks for EIP-1559 transactions
    ///
    /// This is useful for testing method calls with zero gas price.
    ///
    /// By default, it is set to `false`.
    disable_base_fee: bool,
    /// Disables "max fee must be less than or equal to max priority fee" check for EIP-1559 transactions.
    /// This is useful because some chains (e.g. Arbitrum) do not enforce this check.
    /// By default, it is set to `false`.
    disable_priority_fee_check: bool,
    /// Disables fee charging for transactions.
    /// This is useful when executing `eth_call` for example, on OP-chains where setting the base fee
    /// to 0 isn't sufficient.
    /// By default, it is set to `false`.
    disable_fee_charge: bool,

    pub fn default() CfgEnv {
        return CfgEnv.newWithSpec(primitives.SpecId.prague);
    }

    /// Creates new `CfgEnv` with default values.
    pub fn new() CfgEnv {
        return CfgEnv.default();
    }

    /// Create new `CfgEnv` with default values and specified spec.
    pub fn newWithSpec(spec: primitives.SpecId) CfgEnv {
        return .{
            .chain_id = 1,
            .tx_chain_id_check = true,
            .limit_contract_code_size = null,
            .limit_contract_initcode_size = null,
            .spec = spec,
            .disable_nonce_check = false,
            .max_blobs_per_tx = null,
            .tx_gas_limit_cap = null,
            .blob_base_fee_update_fraction = null,
            .memory_limit = (1 << 32) - 1,
            .disable_balance_check = false,
            .disable_block_gas_limit = false,
            .disable_eip3541 = false,
            .disable_eip3607 = false,
            .disable_eip7623 = false,
            .disable_base_fee = false,
            .disable_priority_fee_check = false,
            .disable_fee_charge = false,
        };
    }

    /// Consumes `self` and returns a new `CfgEnv` with the specified chain ID.
    pub fn withChainId(self: CfgEnv, chain_id: u64) CfgEnv {
        return .{
            .chain_id = chain_id,
            .tx_chain_id_check = self.tx_chain_id_check,
            .limit_contract_code_size = self.limit_contract_code_size,
            .limit_contract_initcode_size = self.limit_contract_initcode_size,
            .spec = self.spec,
            .disable_nonce_check = self.disable_nonce_check,
            .tx_gas_limit_cap = self.tx_gas_limit_cap,
            .max_blobs_per_tx = self.max_blobs_per_tx,
            .blob_base_fee_update_fraction = self.blob_base_fee_update_fraction,
            .memory_limit = self.memory_limit,
            .disable_balance_check = self.disable_balance_check,
            .disable_block_gas_limit = self.disable_block_gas_limit,
            .disable_eip3541 = self.disable_eip3541,
            .disable_eip3607 = self.disable_eip3607,
            .disable_eip7623 = self.disable_eip7623,
            .disable_base_fee = self.disable_base_fee,
            .disable_priority_fee_check = self.disable_priority_fee_check,
            .disable_fee_charge = self.disable_fee_charge,
        };
    }

    /// Enables the transaction's chain ID check.
    pub fn enableTxChainIdCheck(self: CfgEnv) CfgEnv {
        return .{
            .chain_id = self.chain_id,
            .tx_chain_id_check = true,
            .limit_contract_code_size = self.limit_contract_code_size,
            .limit_contract_initcode_size = self.limit_contract_initcode_size,
            .spec = self.spec,
            .disable_nonce_check = self.disable_nonce_check,
            .tx_gas_limit_cap = self.tx_gas_limit_cap,
            .max_blobs_per_tx = self.max_blobs_per_tx,
            .blob_base_fee_update_fraction = self.blob_base_fee_update_fraction,
            .memory_limit = self.memory_limit,
            .disable_balance_check = self.disable_balance_check,
            .disable_block_gas_limit = self.disable_block_gas_limit,
            .disable_eip3541 = self.disable_eip3541,
            .disable_eip3607 = self.disable_eip3607,
            .disable_eip7623 = self.disable_eip7623,
            .disable_base_fee = self.disable_base_fee,
            .disable_priority_fee_check = self.disable_priority_fee_check,
            .disable_fee_charge = self.disable_fee_charge,
        };
    }

    /// Disables the transaction's chain ID check.
    pub fn disableTxChainIdCheck(self: CfgEnv) CfgEnv {
        return .{
            .chain_id = self.chain_id,
            .tx_chain_id_check = false,
            .limit_contract_code_size = self.limit_contract_code_size,
            .limit_contract_initcode_size = self.limit_contract_initcode_size,
            .spec = self.spec,
            .disable_nonce_check = self.disable_nonce_check,
            .tx_gas_limit_cap = self.tx_gas_limit_cap,
            .max_blobs_per_tx = self.max_blobs_per_tx,
            .blob_base_fee_update_fraction = self.blob_base_fee_update_fraction,
            .memory_limit = self.memory_limit,
            .disable_balance_check = self.disable_balance_check,
            .disable_block_gas_limit = self.disable_block_gas_limit,
            .disable_eip3541 = self.disable_eip3541,
            .disable_eip3607 = self.disable_eip3607,
            .disable_eip7623 = self.disable_eip7623,
            .disable_base_fee = self.disable_base_fee,
            .disable_priority_fee_check = self.disable_priority_fee_check,
            .disable_fee_charge = self.disable_fee_charge,
        };
    }

    /// Consumes `self` and returns a new `CfgEnv` with the specified spec.
    pub fn withSpec(self: CfgEnv, spec: primitives.SpecId) CfgEnv {
        return .{
            .chain_id = self.chain_id,
            .tx_chain_id_check = self.tx_chain_id_check,
            .limit_contract_code_size = self.limit_contract_code_size,
            .limit_contract_initcode_size = self.limit_contract_initcode_size,
            .spec = spec,
            .disable_nonce_check = self.disable_nonce_check,
            .tx_gas_limit_cap = self.tx_gas_limit_cap,
            .max_blobs_per_tx = self.max_blobs_per_tx,
            .blob_base_fee_update_fraction = self.blob_base_fee_update_fraction,
            .memory_limit = self.memory_limit,
            .disable_balance_check = self.disable_balance_check,
            .disable_block_gas_limit = self.disable_block_gas_limit,
            .disable_eip3541 = self.disable_eip3541,
            .disable_eip3607 = self.disable_eip3607,
            .disable_eip7623 = self.disable_eip7623,
            .disable_base_fee = self.disable_base_fee,
            .disable_priority_fee_check = self.disable_priority_fee_check,
            .disable_fee_charge = self.disable_fee_charge,
        };
    }

    /// Sets the blob target
    pub fn withMaxBlobsPerTx(self: CfgEnv, max_blobs_per_tx: u64) CfgEnv {
        return .{
            .chain_id = self.chain_id,
            .tx_chain_id_check = self.tx_chain_id_check,
            .limit_contract_code_size = self.limit_contract_code_size,
            .limit_contract_initcode_size = self.limit_contract_initcode_size,
            .spec = self.spec,
            .disable_nonce_check = self.disable_nonce_check,
            .tx_gas_limit_cap = self.tx_gas_limit_cap,
            .max_blobs_per_tx = max_blobs_per_tx,
            .blob_base_fee_update_fraction = self.blob_base_fee_update_fraction,
            .memory_limit = self.memory_limit,
            .disable_balance_check = self.disable_balance_check,
            .disable_block_gas_limit = self.disable_block_gas_limit,
            .disable_eip3541 = self.disable_eip3541,
            .disable_eip3607 = self.disable_eip3607,
            .disable_eip7623 = self.disable_eip7623,
            .disable_base_fee = self.disable_base_fee,
            .disable_priority_fee_check = self.disable_priority_fee_check,
            .disable_fee_charge = self.disable_fee_charge,
        };
    }

    /// Sets the blob target
    pub fn setMaxBlobsPerTx(self: *CfgEnv, max_blobs_per_tx: u64) void {
        self.max_blobs_per_tx = max_blobs_per_tx;
    }

    /// Clears the blob target and max count over hardforks.
    pub fn clearMaxBlobsPerTx(self: *CfgEnv) void {
        self.max_blobs_per_tx = null;
    }

    /// Sets the disable priority fee check flag.
    pub fn withDisablePriorityFeeCheck(self: CfgEnv, disable: bool) CfgEnv {
        return .{
            .chain_id = self.chain_id,
            .tx_chain_id_check = self.tx_chain_id_check,
            .limit_contract_code_size = self.limit_contract_code_size,
            .limit_contract_initcode_size = self.limit_contract_initcode_size,
            .spec = self.spec,
            .disable_nonce_check = self.disable_nonce_check,
            .tx_gas_limit_cap = self.tx_gas_limit_cap,
            .max_blobs_per_tx = self.max_blobs_per_tx,
            .blob_base_fee_update_fraction = self.blob_base_fee_update_fraction,
            .memory_limit = self.memory_limit,
            .disable_balance_check = self.disable_balance_check,
            .disable_block_gas_limit = self.disable_block_gas_limit,
            .disable_eip3541 = self.disable_eip3541,
            .disable_eip3607 = self.disable_eip3607,
            .disable_eip7623 = self.disable_eip7623,
            .disable_base_fee = self.disable_base_fee,
            .disable_priority_fee_check = disable,
            .disable_fee_charge = self.disable_fee_charge,
        };
    }

    /// Sets the disable fee charge flag.
    pub fn withDisableFeeCharge(self: CfgEnv, disable: bool) CfgEnv {
        return .{
            .chain_id = self.chain_id,
            .tx_chain_id_check = self.tx_chain_id_check,
            .limit_contract_code_size = self.limit_contract_code_size,
            .limit_contract_initcode_size = self.limit_contract_initcode_size,
            .spec = self.spec,
            .disable_nonce_check = self.disable_nonce_check,
            .tx_gas_limit_cap = self.tx_gas_limit_cap,
            .max_blobs_per_tx = self.max_blobs_per_tx,
            .blob_base_fee_update_fraction = self.blob_base_fee_update_fraction,
            .memory_limit = self.memory_limit,
            .disable_balance_check = self.disable_balance_check,
            .disable_block_gas_limit = self.disable_block_gas_limit,
            .disable_eip3541 = self.disable_eip3541,
            .disable_eip3607 = self.disable_eip3607,
            .disable_eip7623 = self.disable_eip7623,
            .disable_base_fee = self.disable_base_fee,
            .disable_priority_fee_check = self.disable_priority_fee_check,
            .disable_fee_charge = disable,
        };
    }

    /// Sets the disable eip7623 flag.
    pub fn withDisableEip7623(self: CfgEnv, disable: bool) CfgEnv {
        return .{
            .chain_id = self.chain_id,
            .tx_chain_id_check = self.tx_chain_id_check,
            .limit_contract_code_size = self.limit_contract_code_size,
            .limit_contract_initcode_size = self.limit_contract_initcode_size,
            .spec = self.spec,
            .disable_nonce_check = self.disable_nonce_check,
            .tx_gas_limit_cap = self.tx_gas_limit_cap,
            .max_blobs_per_tx = self.max_blobs_per_tx,
            .blob_base_fee_update_fraction = self.blob_base_fee_update_fraction,
            .memory_limit = self.memory_limit,
            .disable_balance_check = self.disable_balance_check,
            .disable_block_gas_limit = self.disable_block_gas_limit,
            .disable_eip3541 = self.disable_eip3541,
            .disable_eip3607 = self.disable_eip3607,
            .disable_eip7623 = disable,
            .disable_base_fee = self.disable_base_fee,
            .disable_priority_fee_check = self.disable_priority_fee_check,
            .disable_fee_charge = self.disable_fee_charge,
        };
    }

    /// Returns the blob base fee update fraction from [CfgEnv::blob_base_fee_update_fraction].
    ///
    /// If this field is not set, the default is derived from the active spec:
    /// - BPO2+:   11684671 (`BLOB_BASE_FEE_UPDATE_FRACTION_BPO2`)
    /// - BPO1:    8346193 (`BLOB_BASE_FEE_UPDATE_FRACTION_BPO1`)
    /// - Prague+:   5007716 (`BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE`, EIP-7691)
    /// - Cancun:  3338477 (`BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN`)
    pub fn blobBaseFeeUpdateFraction(self: CfgEnv) u64 {
        return self.blob_base_fee_update_fraction orelse
            if (primitives.isEnabledIn(self.spec, .bpo2))
                primitives.BLOB_BASE_FEE_UPDATE_FRACTION_BPO2
            else if (primitives.isEnabledIn(self.spec, .bpo1))
                primitives.BLOB_BASE_FEE_UPDATE_FRACTION_BPO1
            else if (primitives.isEnabledIn(self.spec, .prague))
                primitives.BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE
            else
                primitives.BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN;
    }

    pub fn chainId(self: CfgEnv) u64 {
        return self.chain_id;
    }

    pub fn getSpec(self: CfgEnv) primitives.SpecId {
        return self.spec;
    }

    pub fn txChainIdCheck(self: CfgEnv) bool {
        return self.tx_chain_id_check;
    }

    pub fn txGasLimitCap(self: CfgEnv) u64 {
        return self.tx_gas_limit_cap orelse if (self.spec.isEnabledIn(primitives.SpecId.Osaka))
            primitives.TX_GAS_LIMIT_CAP
        else
            std.math.maxInt(u64);
    }

    pub fn maxBlobsPerTx(self: CfgEnv) ?u64 {
        return self.max_blobs_per_tx;
    }

    pub fn maxCodeSize(self: CfgEnv) usize {
        return self.limit_contract_code_size orelse primitives.MAX_CODE_SIZE;
    }

    pub fn maxInitcodeSize(self: CfgEnv) usize {
        return self.limit_contract_initcode_size orelse if (self.limit_contract_code_size) |size|
            size * 2
        else
            primitives.MAX_INITCODE_SIZE;
    }

    pub fn isEip3541Disabled(self: CfgEnv) bool {
        return self.disable_eip3541;
    }

    pub fn isEip3607Disabled(self: CfgEnv) bool {
        return self.disable_eip3607;
    }

    pub fn isEip7623Disabled(self: CfgEnv) bool {
        return self.disable_eip7623;
    }

    pub fn isBalanceCheckDisabled(self: CfgEnv) bool {
        return self.disable_balance_check;
    }

    /// Returns `true` if the block gas limit is disabled.
    pub fn isBlockGasLimitDisabled(self: CfgEnv) bool {
        return self.disable_block_gas_limit;
    }

    pub fn isNonceCheckDisabled(self: CfgEnv) bool {
        return self.disable_nonce_check;
    }

    pub fn isBaseFeeCheckDisabled(self: CfgEnv) bool {
        return self.disable_base_fee;
    }

    pub fn isPriorityFeeCheckDisabled(self: CfgEnv) bool {
        return self.disable_priority_fee_check;
    }

    pub fn isFeeChargeDisabled(self: CfgEnv) bool {
        return self.disable_fee_charge;
    }
};
