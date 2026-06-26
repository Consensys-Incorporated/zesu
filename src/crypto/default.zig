/// Native cryptographic accelerator implementation (accel_impl interface).
///
/// Provides pub functions matching the accel_impl interface consumed by accelerators.zig.
/// Include paths and C library links are added by build.zig to each exe/test step.
const std = @import("std");

const secp256k1_wrapper = @import("backends/secp256k1_wrapper.zig");
const mcl_wrapper = @import("backends/mcl_wrapper.zig");
const blst_wrapper = @import("backends/blst_wrapper.zig");
const openssl_wrapper = @import("backends/openssl_wrapper.zig");
const blake2f_impl = @import("backends/blake2f_impl.zig");
const modexp_impl = @import("backends/modexp_impl.zig");
const ripemd160_impl = @import("backends/ripemd160_impl.zig");

pub fn keccak256(data: []const u8, output: *[32]u8) void {
    std.crypto.hash.sha3.Keccak256.hash(data, output, .{});
}

pub fn sha256(data: []const u8, output: *[32]u8) void {
    std.crypto.hash.sha2.Sha256.hash(data, output, .{});
}

pub fn secp256k1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) void {
    verified.* = secp256k1_wrapper.verify(msg.*, sig.*, pubkey.*);
}

pub fn ecrecover(msg: *const [32]u8, sig: *const [64]u8, recid: u8, output: *[64]u8) bool {
    const pubkey = secp256k1_wrapper.ecrecoverPubkey(msg.*, sig.*, recid) orelse return false;
    output.* = pubkey;
    return true;
}

pub fn ripemd160(data: []const u8, output: *[32]u8) void {
    const hash = ripemd160_impl.ripemd160(data);
    // EVM output layout: 12 zero bytes followed by the 20-byte digest.
    output.* = [_]u8{0} ** 32;
    @memcpy(output[12..32], &hash);
}

pub fn modexp(base: []const u8, exp: []const u8, modulus: []const u8, output: []u8) bool {
    return modexp_impl.modexp(base, exp, modulus, output);
}

pub fn bn254_g1_add(p1: *const [64]u8, p2: *const [64]u8, result: *[64]u8) bool {
    result.* = mcl_wrapper.g1Add(p1.*, p2.*) catch return false;
    return true;
}

pub fn bn254_g1_mul(point: *const [64]u8, scalar: *const [32]u8, result: *[64]u8) bool {
    result.* = mcl_wrapper.g1Mul(point.*, scalar.*) catch return false;
    return true;
}

// pairs is []const accelerators.Bn254PairingPair — same binary layout as mcl_wrapper.PairingPair.
pub fn bn254_pairing(pairs: anytype, verified: *bool) bool {
    const ptr: [*]const mcl_wrapper.PairingPair = @ptrCast(pairs.ptr);
    verified.* = mcl_wrapper.pairingCheck(ptr[0..pairs.len]) catch return false;
    return true;
}

pub fn blake2f(rounds: u32, h: *[64]u8, m: *const [128]u8, t: *const [16]u8, f: u8) bool {
    return blake2f_impl.compress(rounds, h, m, t, f);
}

pub fn kzg_point_eval(commitment: *const [48]u8, z: *const [32]u8, y: *const [32]u8, proof: *const [48]u8, verified: *bool) bool {
    verified.* = blst_wrapper.verifyKzgProof(commitment.*, z.*, y.*, proof.*) catch return false;
    return true;
}

pub fn bls12_g1_add(p1: *const [96]u8, p2: *const [96]u8, result: *[96]u8) bool {
    result.* = blst_wrapper.g1Add(p1.*, p2.*) catch return false;
    return true;
}

pub fn bls12_g1_msm(pairs: anytype, result: *[96]u8) bool {
    const ptr: [*]const blst_wrapper.G1MsmPair = @ptrCast(pairs.ptr);
    result.* = blst_wrapper.g1Msm(ptr[0..pairs.len]) catch return false;
    return true;
}

pub fn bls12_g2_add(p1: *const [192]u8, p2: *const [192]u8, result: *[192]u8) bool {
    result.* = blst_wrapper.g2Add(p1.*, p2.*) catch return false;
    return true;
}

pub fn bls12_g2_msm(pairs: anytype, result: *[192]u8) bool {
    const ptr: [*]const blst_wrapper.G2MsmPair = @ptrCast(pairs.ptr);
    result.* = blst_wrapper.g2Msm(ptr[0..pairs.len]) catch return false;
    return true;
}

pub fn bls12_pairing(pairs: anytype, verified: *bool) bool {
    const ptr: [*]const blst_wrapper.PairingPair = @ptrCast(pairs.ptr);
    verified.* = blst_wrapper.pairingCheck(ptr[0..pairs.len]) catch return false;
    return true;
}

pub fn bls12_map_fp_to_g1(field_element: *const [48]u8, result: *[96]u8) bool {
    result.* = blst_wrapper.mapFpToG1(field_element.*) catch return false;
    return true;
}

pub fn bls12_map_fp2_to_g2(field_element: *const [96]u8, result: *[192]u8) bool {
    result.* = blst_wrapper.mapFp2ToG2(field_element.*) catch return false;
    return true;
}

pub fn secp256r1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) void {
    verified.* = openssl_wrapper.verifyP256(msg.*, sig.*, pubkey.*);
}
