const std = @import("std");
const primitives = @import("primitives");

/// The block environment
pub const BlockEnv = struct {
    /// The number of ancestor blocks of this block (block height).
    number: primitives.U256,
    /// Beneficiary (Coinbase or miner) is a address that have signed the block.
    ///
    /// This is the receiver address of all the gas spent in the block.
    beneficiary: primitives.Address,
    /// The timestamp of the block in seconds since the UNIX epoch
    timestamp: primitives.U256,
    /// The gas limit of the block
    gas_limit: u64,
    /// The base fee per gas, added in the London upgrade with EIP-1559
    basefee: u64,
    /// The difficulty of the block
    ///
    /// Unused after the Paris (AKA the merge) upgrade, and replaced by `prevrandao`.
    difficulty: primitives.U256,
    /// The output of the randomness beacon provided by the beacon chain
    ///
    /// Replaces `difficulty` after the Paris (AKA the merge) upgrade with EIP-4399.
    ///
    /// Note: `prevrandao` can be found in a block in place of `mix_hash`.
    prevrandao: ?primitives.Hash,
    /// Excess blob gas and blob gasprice
    ///
    /// Incorporated as part of the Cancun upgrade via EIP-4844.
    blob_excess_gas_and_price: ?BlobExcessGasAndPrice,
    /// Beacon chain slot number (EIP-7843, Amsterdam+).
    ///
    /// `null` when the block header does not carry a slot number (pre-Amsterdam or
    /// non-beacon chains).  `SLOTNUM` halts with `invalid_opcode` in that case.
    slot_number: ?u64,

    pub fn default() BlockEnv {
        return .{
            .number = @as(primitives.U256, 0),
            .beneficiary = [_]u8{0} ** 20,
            .timestamp = @as(primitives.U256, 1),
            .gas_limit = std.math.maxInt(u64),
            .basefee = 0,
            .difficulty = @as(primitives.U256, 0),
            .prevrandao = null,
            .blob_excess_gas_and_price = BlobExcessGasAndPrice.new(0, primitives.BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE),
            .slot_number = null,
        };
    }

    /// Takes `blob_excess_gas` saves it inside env
    /// and calculates `blob_fee` with [`BlobExcessGasAndPrice`].
    pub fn setBlobExcessGasAndPrice(self: *BlockEnv, excess_blob_gas: u64, base_fee_update_fraction: u64) void {
        self.blob_excess_gas_and_price = BlobExcessGasAndPrice.new(excess_blob_gas, base_fee_update_fraction);
    }

    pub fn getNumber(self: BlockEnv) primitives.U256 {
        return self.number;
    }

    pub fn getBeneficiary(self: BlockEnv) primitives.Address {
        return self.beneficiary;
    }

    pub fn getTimestamp(self: BlockEnv) primitives.U256 {
        return self.timestamp;
    }

    pub fn getGasLimit(self: BlockEnv) u64 {
        return self.gas_limit;
    }

    pub fn getBasefee(self: BlockEnv) u64 {
        return self.basefee;
    }

    pub fn getDifficulty(self: BlockEnv) primitives.U256 {
        return self.difficulty;
    }

    pub fn getPrevrandao(self: BlockEnv) ?primitives.Hash {
        return self.prevrandao;
    }

    pub fn blobExcessGasAndPrice(self: BlockEnv) ?BlobExcessGasAndPrice {
        return self.blob_excess_gas_and_price;
    }
};

/// Excess blob gas and blob gasprice
pub const BlobExcessGasAndPrice = struct {
    excess_blob_gas: u64,
    blob_gasprice: u128,

    pub fn new(excess_blob_gas: u64, base_fee_update_fraction: u64) BlobExcessGasAndPrice {
        return .{
            .excess_blob_gas = excess_blob_gas,
            .blob_gasprice = calculateBlobGasprice(excess_blob_gas, base_fee_update_fraction),
        };
    }

    pub fn excessBlobGas(self: BlobExcessGasAndPrice) u64 {
        return self.excess_blob_gas;
    }

    pub fn blobGasprice(self: BlobExcessGasAndPrice) u128 {
        return self.blob_gasprice;
    }
};

/// Calculate blob gasprice using the fake_exponential function from EIP-4844.
/// blob_gasprice = fake_exponential(MIN_BLOB_GASPRICE=1, excess_blob_gas, base_fee_update_fraction)
fn calculateBlobGasprice(excess_blob_gas: u64, base_fee_update_fraction: u64) u128 {
    // fake_exponential(factor=1, numerator=excess_blob_gas, denominator=base_fee_update_fraction)
    // Implements: https://eips.ethereum.org/EIPS/eip-4844#helpers
    //
    // Saturating arithmetic (+|=, *|) is used throughout to prevent u128 overflow panics.
    // When excess_blob_gas/base_fee_update_fraction exceeds ~88 (reachable after sustained
    // max-blob usage), intermediate products exceed u128 max. Saturation clamps to u128::MAX
    // instead of panicking; the result saturates at u128::MAX for astronomically high excess.

    if (base_fee_update_fraction == 0) {
        return std.math.maxInt(u128);
    }

    const factor: u128 = 1;
    const numerator: u128 = excess_blob_gas;
    const denominator: u128 = base_fee_update_fraction;
    var i: u128 = 1;
    var output: u128 = 0;
    var numerator_accum: u128 = factor * denominator;
    while (numerator_accum > 0) {
        output +|= numerator_accum;
        numerator_accum = (numerator_accum *| numerator) / (denominator * i);
        i += 1;
        if (i > 512) break; // safety bound; convergent series exits naturally before this
    }
    return output / denominator;
}
