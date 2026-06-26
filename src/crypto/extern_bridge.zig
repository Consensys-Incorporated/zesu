/// accel_impl bridge for zesu-core (zkvm builds only).
///
/// Translates the accel_impl module interface into extern fn zkvm_* C symbols
/// that are resolved at link time from zisk_accel.o (ZisK CSR implementations).

// Local pair types — same binary layout as accelerators.zig pub pair types.
const Bn254PairingPair = extern struct { g1: [64]u8, g2: [128]u8 };
const Bls12G1MsmPair = extern struct { point: [96]u8, scalar: [32]u8 };
const Bls12G2MsmPair = extern struct { point: [192]u8, scalar: [32]u8 };
const Bls12PairingPair = extern struct { g1: [96]u8, g2: [192]u8 };

// ── extern fn declarations — resolved by zisk_accel.o at link time ────────────

extern fn zkvm_keccak256(data: [*]const u8, len: usize, output: *[32]u8) i32;
extern fn zkvm_sha256(data: [*]const u8, len: usize, output: *[32]u8) i32;
extern fn zkvm_secp256k1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) i32;
extern fn zkvm_secp256k1_ecrecover(msg: *const [32]u8, sig: *const [64]u8, recid: u8, output: *[64]u8) i32;
extern fn zkvm_ripemd160(data: [*]const u8, len: usize, output: *[32]u8) i32;
extern fn zkvm_modexp(base: [*]const u8, base_len: usize, exp: [*]const u8, exp_len: usize, modulus: [*]const u8, mod_len: usize, output: [*]u8) i32;
extern fn zkvm_bn254_g1_add(p1: *const [64]u8, p2: *const [64]u8, result: *[64]u8) i32;
extern fn zkvm_bn254_g1_mul(point: *const [64]u8, scalar: *const [32]u8, result: *[64]u8) i32;
extern fn zkvm_bn254_pairing(pairs: [*]const Bn254PairingPair, num_pairs: usize, verified: *bool) i32;
extern fn zkvm_blake2f(rounds: u32, h: *[64]u8, m: *const [128]u8, t: *const [16]u8, f: u8) i32;
extern fn zkvm_kzg_point_eval(commitment: *const [48]u8, z: *const [32]u8, y: *const [32]u8, proof: *const [48]u8, verified: *bool) i32;
extern fn zkvm_bls12_g1_add(p1: *const [96]u8, p2: *const [96]u8, result: *[96]u8) i32;
extern fn zkvm_bls12_g1_msm(pairs: [*]const Bls12G1MsmPair, num_pairs: usize, result: *[96]u8) i32;
extern fn zkvm_bls12_g2_add(p1: *const [192]u8, p2: *const [192]u8, result: *[192]u8) i32;
extern fn zkvm_bls12_g2_msm(pairs: [*]const Bls12G2MsmPair, num_pairs: usize, result: *[192]u8) i32;
extern fn zkvm_bls12_pairing(pairs: [*]const Bls12PairingPair, num_pairs: usize, verified: *bool) i32;
extern fn zkvm_bls12_map_fp_to_g1(field_element: *const [48]u8, result: *[96]u8) i32;
extern fn zkvm_bls12_map_fp2_to_g2(field_element: *const [96]u8, result: *[192]u8) i32;
extern fn zkvm_secp256r1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) i32;

// ── accel_impl interface ───────────────────────────────────────────────────────

pub fn keccak256(data: []const u8, output: *[32]u8) void {
    _ = zkvm_keccak256(data.ptr, data.len, output);
}

pub fn sha256(data: []const u8, output: *[32]u8) void {
    _ = zkvm_sha256(data.ptr, data.len, output);
}

pub fn secp256k1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) void {
    _ = zkvm_secp256k1_verify(msg, sig, pubkey, verified);
}

pub fn ecrecover(msg: *const [32]u8, sig: *const [64]u8, recid: u8, output: *[64]u8) bool {
    return zkvm_secp256k1_ecrecover(msg, sig, recid, output) == 0;
}

pub fn ripemd160(data: []const u8, output: *[32]u8) void {
    // ZisK's zkvm_ripemd160 writes the 20-byte digest right-aligned in the
    // 32-byte word (12 leading zero bytes) — exactly the accel contract's EVM
    // output layout. Pass through directly: no marshalling steps on the guest.
    _ = zkvm_ripemd160(data.ptr, data.len, output);
}

pub fn modexp(base: []const u8, exp: []const u8, modulus: []const u8, output: []u8) bool {
    return zkvm_modexp(base.ptr, base.len, exp.ptr, exp.len, modulus.ptr, modulus.len, output.ptr) == 0;
}

pub fn bn254_g1_add(p1: *const [64]u8, p2: *const [64]u8, result: *[64]u8) bool {
    return zkvm_bn254_g1_add(p1, p2, result) == 0;
}

pub fn bn254_g1_mul(point: *const [64]u8, scalar: *const [32]u8, result: *[64]u8) bool {
    return zkvm_bn254_g1_mul(point, scalar, result) == 0;
}

// pairs is []const accelerators.Bn254PairingPair — same binary layout as local Bn254PairingPair.
pub fn bn254_pairing(pairs: anytype, verified: *bool) bool {
    const ptr: [*]const Bn254PairingPair = @ptrCast(pairs.ptr);
    return zkvm_bn254_pairing(ptr, pairs.len, verified) == 0;
}

pub fn blake2f(rounds: u32, h: *[64]u8, m: *const [128]u8, t: *const [16]u8, f: u8) bool {
    return zkvm_blake2f(rounds, h, m, t, f) == 0;
}

pub fn kzg_point_eval(commitment: *const [48]u8, z: *const [32]u8, y: *const [32]u8, proof: *const [48]u8, verified: *bool) bool {
    return zkvm_kzg_point_eval(commitment, z, y, proof, verified) == 0;
}

pub fn bls12_g1_add(p1: *const [96]u8, p2: *const [96]u8, result: *[96]u8) bool {
    return zkvm_bls12_g1_add(p1, p2, result) == 0;
}

pub fn bls12_g1_msm(pairs: anytype, result: *[96]u8) bool {
    const ptr: [*]const Bls12G1MsmPair = @ptrCast(pairs.ptr);
    return zkvm_bls12_g1_msm(ptr, pairs.len, result) == 0;
}

pub fn bls12_g2_add(p1: *const [192]u8, p2: *const [192]u8, result: *[192]u8) bool {
    return zkvm_bls12_g2_add(p1, p2, result) == 0;
}

pub fn bls12_g2_msm(pairs: anytype, result: *[192]u8) bool {
    const ptr: [*]const Bls12G2MsmPair = @ptrCast(pairs.ptr);
    return zkvm_bls12_g2_msm(ptr, pairs.len, result) == 0;
}

pub fn bls12_pairing(pairs: anytype, verified: *bool) bool {
    const ptr: [*]const Bls12PairingPair = @ptrCast(pairs.ptr);
    return zkvm_bls12_pairing(ptr, pairs.len, verified) == 0;
}

pub fn bls12_map_fp_to_g1(field_element: *const [48]u8, result: *[96]u8) bool {
    return zkvm_bls12_map_fp_to_g1(field_element, result) == 0;
}

pub fn bls12_map_fp2_to_g2(field_element: *const [96]u8, result: *[192]u8) bool {
    return zkvm_bls12_map_fp2_to_g2(field_element, result) == 0;
}

pub fn secp256r1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) void {
    _ = zkvm_secp256r1_verify(msg, sig, pubkey, verified);
}
