/// Core precompile types — no external module dependencies.
///
/// Defined here (rather than in main.zig) so that a "precompile_overrides"
/// module can import these types without creating a circular module dependency.
/// main.zig re-exports everything from this file for backward compatibility.
/// Precompile error type
pub const PrecompileError = error{
    OutOfGas,
    Other,
    Blake2WrongLength,
    Blake2WrongFinalIndicatorFlag,
    ModexpExpOverflow,
    ModexpBaseOverflow,
    ModexpModOverflow,
    ModexpEip7823LimitSize,
    Bn254FieldPointNotAMember,
    Bn254AffineGFailedToCreate,
    Bn254PairLength,
    BlobInvalidInputLength,
    BlobMismatchedVersion,
    BlobVerifyKzgProofFailed,
    NonCanonicalFp,
    Bls12381G1NotOnCurve,
    Bls12381G1NotInSubgroup,
    Bls12381G2NotOnCurve,
    Bls12381G2NotInSubgroup,
    Bls12381ScalarInputLength,
    Bls12381G1AddInputLength,
    Bls12381G2AddInputLength,
    Bls12381G1MsmInputLength,
    Bls12381G2MsmInputLength,
    Bls12381PairingInputLength,
    Bls12381MapFpToG1InputLength,
    Bls12381MapFp2ToG2InputLength,
    Secp256k1RecoverFailed,
    P256VerifyFailed,
};

/// Precompile execution output.
///
/// Ownership rule, module-wide: **a non-empty `bytes` is always heap-allocated
/// from `zesu_allocator`, and the caller frees it** once the frame can no longer
/// observe it. Empty outputs are the static `&[_]u8{}` and are exempt by their
/// length, so the caller's check is simply `if (bytes.len > 0) free(bytes)`.
///
/// One rule for the module rather than a per-precompile ownership flag: a
/// precompile should not have to know who frees its output. Any new precompile
/// returning a non-empty static must duplicate it (see the KZG return value).
///
/// Before this rule existed nothing freed these buffers at all: a 30M-gas
/// identity block retained 1,773 outputs totalling 300 MiB and exhausted the
/// guest heap at 60M.
pub const PrecompileOutput = struct {
    /// Gas used by the precompile
    gas_used: u64,
    /// Output bytes
    bytes: []const u8,
    /// Whether the precompile reverted
    reverted: bool,

    pub fn new(gas_used: u64, bytes: []const u8) PrecompileOutput {
        return PrecompileOutput{
            .gas_used = gas_used,
            .bytes = bytes,
            .reverted = false,
        };
    }

    pub fn newReverted(gas_used: u64, bytes: []const u8) PrecompileOutput {
        return PrecompileOutput{
            .gas_used = gas_used,
            .bytes = bytes,
            .reverted = true,
        };
    }
};

/// Precompile result type
pub const PrecompileResult = union(enum) {
    success: PrecompileOutput,
    err: PrecompileError,
};

/// Precompile function signature
pub const PrecompileFn = *const fn (input: []const u8, gas_limit: u64) PrecompileResult;

/// Calculate the linear cost of a precompile
pub fn calcLinearCost(len: usize, base: u64, word: u64) u64 {
    return (len + 31) / 32 * word + base;
}
