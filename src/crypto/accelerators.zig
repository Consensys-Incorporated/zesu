/// zkVM Cryptographic Accelerators Interface
///
/// Thin Zig adapter delegating to the `accel_impl` module injected at build time.
///
/// Build variants:
///   zesu (native):     accel_impl = default.zig        (std.crypto + C libs)
///   zesu-core (zkvm):  accel_impl = extern_bridge.zig  (extern fn zkvm_* → zisk_accel.o)
const impl = @import("accel_impl");

// ── Type aliases ──────────────────────────────────────────────────────────────

pub const Hash32 = [32]u8;
pub const Bytes16 = [16]u8;
pub const Bytes48 = [48]u8;
pub const Bytes64 = [64]u8;
pub const Bytes96 = [96]u8;
pub const Bytes128 = [128]u8;
pub const Bytes192 = [192]u8;

/// BN254 (alt_bn128) G1 + G2 pair for pairing check (precompile 0x08).
pub const Bn254PairingPair = extern struct {
    g1: Bytes64,
    g2: Bytes128,

    comptime {
        if (@sizeOf(Bn254PairingPair) != 192) @compileError("Bn254PairingPair size mismatch");
    }
};

/// BLS12-381 G1 point + scalar pair for G1 MSM (precompile 0x0c).
pub const Bls12G1MsmPair = extern struct {
    point: Bytes96,
    scalar: Hash32,
};

/// BLS12-381 G2 point + scalar pair for G2 MSM (precompile 0x0e).
pub const Bls12G2MsmPair = extern struct {
    point: Bytes192,
    scalar: Hash32,
};

/// BLS12-381 G1 + G2 pair for pairing check (precompile 0x0f).
pub const Bls12PairingPair = extern struct {
    g1: Bytes96,
    g2: Bytes192,
};

// ── Public API — delegating to accel_impl ─────────────────────────────────────

pub inline fn keccak256(data: []const u8, output: *Hash32) void {
    impl.keccak256(data, output);
}

pub inline fn secp256k1_verify(
    msg: *const Hash32,
    sig: *const Bytes64,
    pubkey: *const Bytes64,
    verified: *bool,
) void {
    impl.secp256k1_verify(msg, sig, pubkey, verified);
}

/// ECRECOVER (precompile 0x01) — recovers uncompressed secp256k1 public key.
pub inline fn ecrecover(
    msg: *const Hash32,
    sig: *const Bytes64,
    recid: u8,
    output: *Bytes64,
) bool {
    return impl.ecrecover(msg, sig, recid, output);
}

/// SHA-256 (precompile 0x02).
pub inline fn sha256(data: []const u8, output: *Hash32) void {
    impl.sha256(data, output);
}

/// RIPEMD-160 (precompile 0x03). Writes the EVM output layout directly:
/// 12 zero bytes followed by the 20-byte digest (output[12..32] = digest).
pub inline fn ripemd160(data: []const u8, output: *Hash32) void {
    impl.ripemd160(data, output);
}

/// ModExp (precompile 0x05): (base ^ exp) % modulus. `output` must be modulus.len bytes.
pub inline fn modexp(
    base: []const u8,
    exp: []const u8,
    modulus: []const u8,
    output: []u8,
) bool {
    return impl.modexp(base, exp, modulus, output);
}

/// BN254 G1 point addition (precompile 0x06, EIP-196).
pub inline fn bn254_g1_add(p1: *const Bytes64, p2: *const Bytes64, result: *Bytes64) bool {
    return impl.bn254_g1_add(p1, p2, result);
}

/// BN254 G1 scalar multiplication (precompile 0x07, EIP-196).
pub inline fn bn254_g1_mul(point: *const Bytes64, scalar: *const Hash32, result: *Bytes64) bool {
    return impl.bn254_g1_mul(point, scalar, result);
}

/// BN254 pairing check (precompile 0x08, EIP-197).
pub inline fn bn254_pairing(pairs: []const Bn254PairingPair, verified: *bool) bool {
    return impl.bn254_pairing(pairs, verified);
}

/// BLAKE2f compression (precompile 0x09, EIP-152). `h` updated in place.
pub inline fn blake2f(
    rounds: u32,
    h: *Bytes64,
    m: *const Bytes128,
    t: *const Bytes16,
    f: u8,
) bool {
    return impl.blake2f(rounds, h, m, t, f);
}

/// KZG point evaluation (precompile 0x0a, EIP-4844).
pub inline fn kzg_point_eval(
    commitment: *const Bytes48,
    z: *const Hash32,
    y: *const Hash32,
    proof: *const Bytes48,
    verified: *bool,
) bool {
    return impl.kzg_point_eval(commitment, z, y, proof, verified);
}

/// BLS12-381 G1 point addition (precompile 0x0b, EIP-2537).
pub inline fn bls12_g1_add(p1: *const Bytes96, p2: *const Bytes96, result: *Bytes96) bool {
    return impl.bls12_g1_add(p1, p2, result);
}

/// BLS12-381 G1 multi-scalar multiplication (precompile 0x0c, EIP-2537).
pub inline fn bls12_g1_msm(pairs: []const Bls12G1MsmPair, result: *Bytes96) bool {
    return impl.bls12_g1_msm(pairs, result);
}

/// BLS12-381 G2 point addition (precompile 0x0d, EIP-2537).
pub inline fn bls12_g2_add(p1: *const Bytes192, p2: *const Bytes192, result: *Bytes192) bool {
    return impl.bls12_g2_add(p1, p2, result);
}

/// BLS12-381 G2 multi-scalar multiplication (precompile 0x0e, EIP-2537).
pub inline fn bls12_g2_msm(pairs: []const Bls12G2MsmPair, result: *Bytes192) bool {
    return impl.bls12_g2_msm(pairs, result);
}

/// BLS12-381 pairing check (precompile 0x0f, EIP-2537).
pub inline fn bls12_pairing(pairs: []const Bls12PairingPair, verified: *bool) bool {
    return impl.bls12_pairing(pairs, verified);
}

/// BLS12-381 map Fp → G1 (precompile 0x10, EIP-2537).
pub inline fn bls12_map_fp_to_g1(field_element: *const Bytes48, result: *Bytes96) bool {
    return impl.bls12_map_fp_to_g1(field_element, result);
}

/// BLS12-381 map Fp2 → G2 (precompile 0x11, EIP-2537).
pub inline fn bls12_map_fp2_to_g2(field_element: *const Bytes96, result: *Bytes192) bool {
    return impl.bls12_map_fp2_to_g2(field_element, result);
}

/// secp256r1 (P-256) signature verification (precompile 0x100, EIP-7212).
pub inline fn secp256r1_verify(
    msg: *const Hash32,
    sig: *const Bytes64,
    pubkey: *const Bytes64,
    verified: *bool,
) void {
    impl.secp256r1_verify(msg, sig, pubkey, verified);
}
