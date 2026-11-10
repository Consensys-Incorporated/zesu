const std = @import("std");
const primitives = @import("primitives");

/// Gas grant for an EIP-8037 system call (see `CfgEnv.system_call_gas`).
pub const SystemCallGas = struct {
    execution: u64,
    reservoir: u64,
};

/// EVM configuration
pub const CfgEnv = struct {
    /// Returned by CHAINID and checked against the tx chain ID (EIP-155).
    chain_id: u64,
    /// Whether to check the transaction's chain ID.
    tx_chain_id_check: bool,
    /// Active hardfork.
    spec: primitives.SpecId,
    /// Code size override read by `maxCodeSize()`. The deployment and initcode checks
    /// (interpreter/host.zig, validation.zig) use the spec constants and ignore it.
    limit_contract_code_size: ?usize,
    /// Initcode size override read by `maxInitcodeSize()` (defaults to twice
    /// `limit_contract_code_size` when only that is set).
    limit_contract_initcode_size: ?usize,
    /// Skips the tx-nonce vs account-nonce check.
    disable_nonce_check: bool,
    /// Max blobs per transaction (EIP-7840 blob schedule); null skips the check.
    max_blobs_per_tx: ?u64,
    /// Blob base fee update fraction override; null means the spec default
    /// (see `blobBaseFeeUpdateFraction()`).
    blob_base_fee_update_fraction: ?u64,
    /// Per-transaction gas limit cap (EIP-7825). Opt-in: validation enforces it only
    /// when set.
    tx_gas_limit_cap: ?u64,
    /// Memory size limit in bytes (EIP-1985: 2^32 - 1). Not read: the interpreter's
    /// Memory carries its own limit.
    memory_limit: u64,
    /// Skips the balance check; an underfunded caller is topped up to the max tx cost.
    disable_balance_check: bool,
    /// Skips the tx gas limit <= block gas limit check (used for system calls).
    disable_block_gas_limit: bool,
    /// Disables EIP-3541 (reject deployed code starting with 0xEF).
    disable_eip3541: bool,
    /// Disables EIP-3607 (reject transactions from senders with deployed code).
    disable_eip3607: bool,
    /// Disables the EIP-7623 calldata floor cost.
    disable_eip7623: bool,
    /// Skips the gas price >= base fee check (set when the block has no base fee,
    /// and for system calls).
    disable_base_fee: bool,
    /// Skips the EIP-1559 "max priority fee <= max fee" check.
    disable_priority_fee_check: bool,
    /// EIP-8037 (Amsterdam+): fixed execution grant and state-gas reservoir for a system call,
    /// replacing the TX_MAX_GAS_LIMIT split of the tx gas limit. Null for ordinary transactions.
    system_call_gas: ?SystemCallGas = null,
    /// Skips the upfront fee deduction, refund and beneficiary payment (system calls).
    disable_fee_charge: bool,

    pub fn default() CfgEnv {
        return CfgEnv.newWithSpec(primitives.SpecId.prague);
    }

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

    /// Returns a copy with `chain_id` replaced.
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

    /// Returns a copy with `spec` replaced.
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

    pub fn setMaxBlobsPerTx(self: *CfgEnv, max_blobs_per_tx: u64) void {
        self.max_blobs_per_tx = max_blobs_per_tx;
    }

    pub fn clearMaxBlobsPerTx(self: *CfgEnv) void {
        self.max_blobs_per_tx = null;
    }

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

    /// The override if set, else the active spec's default (Cancun, Prague/EIP-7691,
    /// BPO1, BPO2).
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
