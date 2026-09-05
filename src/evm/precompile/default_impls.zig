/// Default precompile implementations — calls through the accelerators interface.
///
/// This file is the "precompile_implementations" module root for zesu native builds.
/// It wraps src/crypto/accelerators.zig (which in turn calls src/crypto/default.zig
/// using C libraries) in PrecompileFn-compatible wrappers that handle EVM ABI encoding.
///
/// For zkVM builds that need to override specific precompiles, override the
/// `accelerators` module instead (src/crypto/accelerators.zig, import "accel_impl").
const std = @import("std");
const T = @import("precompile_types");
const accel = @import("accelerators");
const alloc_mod = @import("zesu_allocator");

// ── BLS12-381 EIP-2537 padding constants ─────────────────────────────────────

const FP_LENGTH: usize = 48;
const PADDED_FP_LENGTH: usize = 64;
const G1_LENGTH: usize = 2 * FP_LENGTH; // 96  bytes (unpadded)
const PADDED_G1_LENGTH: usize = 2 * PADDED_FP_LENGTH; // 128 bytes (padded)
const FP2_LENGTH: usize = 2 * FP_LENGTH; // 96  bytes
const PADDED_FP2_LENGTH: usize = 2 * PADDED_FP_LENGTH; // 128 bytes
const G2_LENGTH: usize = 2 * FP2_LENGTH; // 192 bytes (unpadded)
const PADDED_G2_LENGTH: usize = 2 * PADDED_FP2_LENGTH; // 256 bytes (padded)
const SCALAR_LENGTH: usize = 32;

// Discount tables for BLS12-381 MSM (EIP-2537)
const DISCOUNT_TABLE_G1_MSM: [128]u16 = .{
    1000, 949, 848, 797, 764, 750, 738, 728, 719, 712, 705, 698, 692, 687, 682, 677, 673, 669, 665,
    661,  658, 654, 651, 648, 645, 642, 640, 637, 635, 632, 630, 627, 625, 623, 621, 619, 617, 615,
    613,  611, 609, 608, 606, 604, 603, 601, 599, 598, 596, 595, 593, 592, 591, 589, 588, 586, 585,
    584,  582, 581, 580, 579, 577, 576, 575, 574, 573, 572, 570, 569, 568, 567, 566, 565, 564, 563,
    562,  561, 560, 559, 558, 557, 556, 555, 554, 553, 552, 551, 550, 549, 548, 547, 547, 546, 545,
    544,  543, 542, 541, 540, 540, 539, 538, 537, 536, 536, 535, 534, 533, 532, 532, 531, 530, 529,
    528,  528, 527, 526, 525, 525, 524, 523, 522, 522, 521, 520, 520, 519,
};

const DISCOUNT_TABLE_G2_MSM: [128]u16 = .{
    1000, 1000, 923, 884, 855, 832, 812, 796, 782, 770, 759, 749, 740, 732, 724, 717, 711, 704,
    699,  693,  688, 683, 679, 674, 670, 666, 663, 659, 655, 652, 649, 646, 643, 640, 637, 634,
    632,  629,  627, 624, 622, 620, 618, 615, 613, 611, 609, 607, 606, 604, 602, 600, 598, 597,
    595,  593,  592, 590, 589, 587, 586, 584, 583, 582, 580, 579, 578, 576, 575, 574, 573, 571,
    570,  569,  568, 567, 566, 565, 563, 562, 561, 560, 559, 558, 557, 556, 555, 554, 553, 552,
    552,  551,  550, 549, 548, 547, 546, 545, 545, 544, 543, 542, 541, 541, 540, 539, 538, 537,
    537,  536,  535, 535, 534, 533, 532, 532, 531, 530, 530, 529, 528, 528, 527, 526, 526, 525,
    524,  524,
};

/// Remove padding from a G1 point (128 bytes → two 48-byte Fp elements).
/// EIP-2537: the leading 16 bytes of each 64-byte field element must be zero.
fn removeG1Padding(padded: []const u8) T.PrecompileError![2][FP_LENGTH]u8 {
    if (padded.len < PADDED_G1_LENGTH) return T.PrecompileError.Bls12381G1AddInputLength;
    const zero16 = [_]u8{0} ** 16;
    if (!std.mem.eql(u8, padded[0..16], &zero16) or !std.mem.eql(u8, padded[64..80], &zero16))
        return T.PrecompileError.Bls12381G1AddInputLength;
    var result: [2][FP_LENGTH]u8 = undefined;
    @memcpy(&result[0], padded[16..][0..FP_LENGTH]);
    @memcpy(&result[1], padded[80..][0..FP_LENGTH]);
    return result;
}

/// Pad a G1 point (96 bytes → 128 bytes).
fn padG1Point(unpadded: []const u8) [PADDED_G1_LENGTH]u8 {
    var result: [PADDED_G1_LENGTH]u8 = [_]u8{0} ** PADDED_G1_LENGTH;
    @memcpy(result[16..][0..FP_LENGTH], unpadded[0..FP_LENGTH]);
    @memcpy(result[80..][0..FP_LENGTH], unpadded[FP_LENGTH..][0..FP_LENGTH]);
    return result;
}

/// Remove padding from a G2 point (256 bytes → four 48-byte Fp elements).
/// EIP-2537: the leading 16 bytes of each 64-byte field element must be zero.
fn removeG2Padding(padded: []const u8) T.PrecompileError![4][FP_LENGTH]u8 {
    if (padded.len < PADDED_G2_LENGTH) return T.PrecompileError.Bls12381G2AddInputLength;
    const zero16 = [_]u8{0} ** 16;
    if (!std.mem.eql(u8, padded[0..16], &zero16) or !std.mem.eql(u8, padded[64..80], &zero16) or
        !std.mem.eql(u8, padded[128..144], &zero16) or !std.mem.eql(u8, padded[192..208], &zero16))
        return T.PrecompileError.Bls12381G2AddInputLength;
    var result: [4][FP_LENGTH]u8 = undefined;
    @memcpy(&result[0], padded[16..][0..FP_LENGTH]);
    @memcpy(&result[1], padded[80..][0..FP_LENGTH]);
    @memcpy(&result[2], padded[144..][0..FP_LENGTH]);
    @memcpy(&result[3], padded[208..][0..FP_LENGTH]);
    return result;
}

/// Pad a G2 point (192 bytes → 256 bytes).
fn padG2Point(unpadded: []const u8) [PADDED_G2_LENGTH]u8 {
    var result: [PADDED_G2_LENGTH]u8 = [_]u8{0} ** PADDED_G2_LENGTH;
    @memcpy(result[16..][0..FP_LENGTH], unpadded[0..FP_LENGTH]);
    @memcpy(result[80..][0..FP_LENGTH], unpadded[FP_LENGTH..][0..FP_LENGTH]);
    @memcpy(result[144..][0..FP_LENGTH], unpadded[FP2_LENGTH..][0..FP_LENGTH]);
    @memcpy(result[208..][0..FP_LENGTH], unpadded[FP2_LENGTH + FP_LENGTH ..][0..FP_LENGTH]);
    return result;
}

// BN254 field prime (big-endian)
const BN254_PRIME: [32]u8 = .{
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
    0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
};

fn bn254FieldElemValid(elem: *const [32]u8) bool {
    return std.mem.order(u8, elem, &BN254_PRIME) == .lt;
}

// ── Homestead ───────────────────────────────────────────────────────────────

pub const ecrecover: T.PrecompileFn = ecRecoverRun;

fn ecRecoverRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    const GAS_COST: u64 = 3000;
    if (GAS_COST > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };

    if (input.len < 128) {
        // EVM pads input — treat short input as zero-padded
        var padded: [128]u8 = [_]u8{0} ** 128;
        @memcpy(padded[0..input.len], input);
        return ecRecoverPadded(&padded, GAS_COST);
    }
    return ecRecoverPadded(input[0..128], GAS_COST);
}

fn ecRecoverPadded(input: *const [128]u8, gas_cost: u64) T.PrecompileResult {
    const msg: *const [32]u8 = input[0..32];
    // v is bytes 32-63: the full 256-bit value must be exactly 27 or 28.
    const v_low = input[63];
    if (v_low != 27 and v_low != 28) {
        return .{ .success = T.PrecompileOutput.new(gas_cost, &[_]u8{}) };
    }
    for (input[32..63]) |b| {
        if (b != 0) return .{ .success = T.PrecompileOutput.new(gas_cost, &[_]u8{}) };
    }
    const recid: u8 = v_low - 27;
    const sig: *const [64]u8 = input[64..128];

    var pubkey: [64]u8 = undefined;
    if (!accel.ecrecover(msg, sig, recid, &pubkey)) {
        return .{ .success = T.PrecompileOutput.new(gas_cost, &[_]u8{}) };
    }

    // keccak256(pubkey) → take last 20 bytes as address, zero-pad to 32
    var hash: [32]u8 = undefined;
    accel.keccak256(&pubkey, &hash);
    var result: [32]u8 = [_]u8{0} ** 32;
    @memcpy(result[12..], hash[12..]);

    const output = alloc_mod.get().dupe(u8, &result) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    return .{ .success = T.PrecompileOutput.new(gas_cost, output) };
}

// ── Byzantium ───────────────────────────────────────────────────────────────

pub const bn254_add_byzantium: T.PrecompileFn = bn254AddByzantiumRun;
pub const bn254_mul_byzantium: T.PrecompileFn = bn254MulByzantiumRun;
pub const bn254_pairing_byzantium: T.PrecompileFn = bn254PairingByzantiumRun;

fn bn254AddByzantiumRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    const GAS: u64 = 500;
    if (GAS > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };
    return bn254AddImpl(input, GAS);
}

fn bn254AddImpl(input: []const u8, gas_cost: u64) T.PrecompileResult {
    var padded: [128]u8 = [_]u8{0} ** 128;
    const copy_len = @min(input.len, 128);
    @memcpy(padded[0..copy_len], input[0..copy_len]);
    // EIP-196: reject coordinates >= BN254 field prime.
    if (!bn254FieldElemValid(padded[0..32]) or !bn254FieldElemValid(padded[32..64]) or
        !bn254FieldElemValid(padded[64..96]) or !bn254FieldElemValid(padded[96..128]))
        return .{ .err = T.PrecompileError.Bn254FieldPointNotAMember };
    const p1: *const [64]u8 = padded[0..64];
    const p2: *const [64]u8 = padded[64..128];
    var result: [64]u8 = undefined;
    if (!accel.bn254_g1_add(p1, p2, &result))
        return .{ .err = T.PrecompileError.Bn254FieldPointNotAMember };
    const output = alloc_mod.get().dupe(u8, &result) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    return .{ .success = T.PrecompileOutput.new(gas_cost, output) };
}

fn bn254MulByzantiumRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    const GAS: u64 = 40000;
    if (GAS > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };
    return bn254MulImpl(input, GAS);
}

fn bn254MulImpl(input: []const u8, gas_cost: u64) T.PrecompileResult {
    var padded: [96]u8 = [_]u8{0} ** 96;
    const copy_len = @min(input.len, 96);
    @memcpy(padded[0..copy_len], input[0..copy_len]);
    // EIP-196: reject coordinates >= BN254 field prime.
    if (!bn254FieldElemValid(padded[0..32]) or !bn254FieldElemValid(padded[32..64]))
        return .{ .err = T.PrecompileError.Bn254FieldPointNotAMember };
    const point: *const [64]u8 = padded[0..64];
    const scalar: *const [32]u8 = padded[64..96];
    var result: [64]u8 = undefined;
    if (!accel.bn254_g1_mul(point, scalar, &result))
        return .{ .err = T.PrecompileError.Bn254FieldPointNotAMember };
    const output = alloc_mod.get().dupe(u8, &result) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    return .{ .success = T.PrecompileOutput.new(gas_cost, output) };
}

fn bn254PairingByzantiumRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    if (input.len % 192 != 0) return .{ .err = T.PrecompileError.Bn254PairLength };
    const n_pairs = input.len / 192;
    const GAS: u64 = 100000 + 80000 * @as(u64, @intCast(n_pairs));
    if (GAS > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };
    return bn254PairingImpl(input, GAS);
}

fn bn254PairingImpl(input: []const u8, gas_cost: u64) T.PrecompileResult {
    const Pair = accel.Bn254PairingPair;
    const n_pairs = input.len / 192;
    // EIP-197: reject G1 coordinates >= BN254 field prime.
    var pi: usize = 0;
    while (pi < n_pairs) : (pi += 1) {
        const off = pi * 192;
        if (!bn254FieldElemValid(input[off..][0..32]) or !bn254FieldElemValid(input[off + 32 ..][0..32]))
            return .{ .err = T.PrecompileError.Bn254FieldPointNotAMember };
    }
    const pairs = std.mem.bytesAsSlice(Pair, input[0 .. n_pairs * 192]);
    var verified: bool = false;
    if (!accel.bn254_pairing(pairs, &verified))
        return .{ .err = T.PrecompileError.Bn254FieldPointNotAMember };
    var result: [32]u8 = [_]u8{0} ** 32;
    if (verified) result[31] = 1;
    const output = alloc_mod.get().dupe(u8, &result) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    return .{ .success = T.PrecompileOutput.new(gas_cost, output) };
}

// ── Istanbul (reduced gas) ───────────────────────────────────────────────────

pub const bn254_add_istanbul: T.PrecompileFn = bn254AddIstanbulRun;
pub const bn254_mul_istanbul: T.PrecompileFn = bn254MulIstanbulRun;
pub const bn254_pairing_istanbul: T.PrecompileFn = bn254PairingIstanbulRun;

fn bn254AddIstanbulRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    const GAS: u64 = 150;
    if (GAS > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };
    return bn254AddImpl(input, GAS);
}

fn bn254MulIstanbulRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    const GAS: u64 = 6000;
    if (GAS > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };
    return bn254MulImpl(input, GAS);
}

fn bn254PairingIstanbulRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    if (input.len % 192 != 0) return .{ .err = T.PrecompileError.Bn254PairLength };
    const n_pairs = input.len / 192;
    const GAS: u64 = 45000 + 34000 * @as(u64, @intCast(n_pairs));
    if (GAS > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };
    return bn254PairingImpl(input, GAS);
}

// ── Cancun: KZG ─────────────────────────────────────────────────────────────

pub const kzg_point_evaluation: T.PrecompileFn = kzgPointEvalRun;

// KZG input: | versioned_hash (32) | z (32) | y (32) | commitment (48) | proof (48) |
// Total: 192 bytes
const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

const BLS_MODULUS: [32]u8 = .{
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
};

const KZG_RETURN_VALUE: [64]u8 = .{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, // 4096
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
};

fn kzgPointEvalRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    const GAS: u64 = 50000;
    if (GAS > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };
    if (input.len != 192) return .{ .err = T.PrecompileError.BlobInvalidInputLength };

    const versioned_hash = input[0..32];
    const z = input[32..64];
    const y = input[64..96];
    const commitment: *const [48]u8 = input[96..144];
    const proof: *const [48]u8 = input[144..192];

    // z and y must be valid BLS12-381 scalar field elements (< BLS_MODULUS)
    if (std.mem.order(u8, z, &BLS_MODULUS) != .lt)
        return .{ .err = T.PrecompileError.BlobVerifyKzgProofFailed };
    if (std.mem.order(u8, y, &BLS_MODULUS) != .lt)
        return .{ .err = T.PrecompileError.BlobVerifyKzgProofFailed };

    // versioned_hash must equal SHA-256(commitment) with version byte prepended
    var computed_hash: [32]u8 = undefined;
    accel.sha256(commitment, &computed_hash);
    computed_hash[0] = VERSIONED_HASH_VERSION_KZG;
    if (!std.mem.eql(u8, versioned_hash, &computed_hash))
        return .{ .err = T.PrecompileError.BlobMismatchedVersion };

    const z32: *const [32]u8 = input[32..64];
    const y32: *const [32]u8 = input[64..96];
    var verified: bool = false;
    if (!accel.kzg_point_eval(commitment, z32, y32, proof, &verified))
        return .{ .err = T.PrecompileError.BlobVerifyKzgProofFailed };
    if (!verified) return .{ .err = T.PrecompileError.BlobVerifyKzgProofFailed };

    return .{ .success = T.PrecompileOutput.new(GAS, &KZG_RETURN_VALUE) };
}

// ── Prague / BLS12-381 ────────────────────────────────────────────────────────

pub const bls12_g1_add: T.PrecompileFn = bls12G1AddRun;
pub const bls12_g1_msm: T.PrecompileFn = bls12G1MsmRun;
pub const bls12_g2_add: T.PrecompileFn = bls12G2AddRun;
pub const bls12_g2_msm: T.PrecompileFn = bls12G2MsmRun;
pub const bls12_pairing: T.PrecompileFn = bls12PairingRun;
pub const bls12_map_fp_to_g1: T.PrecompileFn = bls12MapFpToG1Run;
pub const bls12_map_fp2_to_g2: T.PrecompileFn = bls12MapFp2ToG2Run;

fn bls12G1AddRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    const GAS: u64 = 375;
    if (GAS > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };
    if (input.len != PADDED_G1_LENGTH * 2)
        return .{ .err = T.PrecompileError.Bls12381G1AddInputLength };

    const a_coords = removeG1Padding(input[0..PADDED_G1_LENGTH]) catch |e|
        return .{ .err = e };
    const b_coords = removeG1Padding(input[PADDED_G1_LENGTH..][0..PADDED_G1_LENGTH]) catch |e|
        return .{ .err = e };

    var a: [G1_LENGTH]u8 = undefined;
    @memcpy(a[0..FP_LENGTH], &a_coords[0]);
    @memcpy(a[FP_LENGTH..G1_LENGTH], &a_coords[1]);
    var b: [G1_LENGTH]u8 = undefined;
    @memcpy(b[0..FP_LENGTH], &b_coords[0]);
    @memcpy(b[FP_LENGTH..G1_LENGTH], &b_coords[1]);

    var raw: [G1_LENGTH]u8 = undefined;
    if (!accel.bls12_g1_add(&a, &b, &raw))
        return .{ .err = T.PrecompileError.Bls12381G1NotOnCurve };

    const padded = padG1Point(&raw);
    const heap_out = alloc_mod.get().dupe(u8, &padded) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    return .{ .success = T.PrecompileOutput.new(GAS, heap_out) };
}

fn bls12G1MsmRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    // EIP-2537: G1MSM pair = 128-byte padded G1 point + 32-byte scalar = 160 bytes
    const PAIR_LEN = PADDED_G1_LENGTH + SCALAR_LENGTH; // 160
    if (input.len == 0 or input.len % PAIR_LEN != 0)
        return .{ .err = T.PrecompileError.Bls12381G1MsmInputLength };

    const k = input.len / PAIR_LEN;
    const discount = if (k <= DISCOUNT_TABLE_G1_MSM.len)
        DISCOUNT_TABLE_G1_MSM[k - 1]
    else
        DISCOUNT_TABLE_G1_MSM[DISCOUNT_TABLE_G1_MSM.len - 1];
    const gas_used = (@as(u64, k) * 12000 * @as(u64, discount)) / 1000;
    if (gas_used > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };

    const pairs = alloc_mod.get().alloc(accel.Bls12G1MsmPair, k) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    defer alloc_mod.get().free(pairs);

    var i: usize = 0;
    while (i < k) : (i += 1) {
        const off = i * PAIR_LEN;
        const coords = removeG1Padding(input[off..][0..PADDED_G1_LENGTH]) catch
            return .{ .err = T.PrecompileError.Bls12381G1MsmInputLength };
        @memcpy(pairs[i].point[0..FP_LENGTH], &coords[0]);
        @memcpy(pairs[i].point[FP_LENGTH..G1_LENGTH], &coords[1]);
        @memcpy(&pairs[i].scalar, input[off + PADDED_G1_LENGTH ..][0..SCALAR_LENGTH]);
    }

    var raw: [G1_LENGTH]u8 = undefined;
    if (!accel.bls12_g1_msm(pairs, &raw))
        return .{ .err = T.PrecompileError.Bls12381G1NotOnCurve };

    const padded = padG1Point(&raw);
    const heap_out = alloc_mod.get().dupe(u8, &padded) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    return .{ .success = T.PrecompileOutput.new(gas_used, heap_out) };
}

fn bls12G2AddRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    const GAS: u64 = 600;
    if (GAS > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };
    if (input.len != PADDED_G2_LENGTH * 2)
        return .{ .err = T.PrecompileError.Bls12381G2AddInputLength };

    const a_coords = removeG2Padding(input[0..PADDED_G2_LENGTH]) catch |e|
        return .{ .err = e };
    const b_coords = removeG2Padding(input[PADDED_G2_LENGTH..][0..PADDED_G2_LENGTH]) catch |e|
        return .{ .err = e };

    var a: [G2_LENGTH]u8 = undefined;
    @memcpy(a[0..FP_LENGTH], &a_coords[0]);
    @memcpy(a[FP_LENGTH..][0..FP_LENGTH], &a_coords[1]);
    @memcpy(a[FP2_LENGTH..][0..FP_LENGTH], &a_coords[2]);
    @memcpy(a[FP2_LENGTH + FP_LENGTH ..][0..FP_LENGTH], &a_coords[3]);
    var b: [G2_LENGTH]u8 = undefined;
    @memcpy(b[0..FP_LENGTH], &b_coords[0]);
    @memcpy(b[FP_LENGTH..][0..FP_LENGTH], &b_coords[1]);
    @memcpy(b[FP2_LENGTH..][0..FP_LENGTH], &b_coords[2]);
    @memcpy(b[FP2_LENGTH + FP_LENGTH ..][0..FP_LENGTH], &b_coords[3]);

    var raw: [G2_LENGTH]u8 = undefined;
    if (!accel.bls12_g2_add(&a, &b, &raw))
        return .{ .err = T.PrecompileError.Bls12381G2NotOnCurve };

    const padded = padG2Point(&raw);
    const heap_out = alloc_mod.get().dupe(u8, &padded) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    return .{ .success = T.PrecompileOutput.new(GAS, heap_out) };
}

fn bls12G2MsmRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    // EIP-2537: G2MSM pair = 256-byte padded G2 point + 32-byte scalar = 288 bytes
    const PAIR_LEN = PADDED_G2_LENGTH + SCALAR_LENGTH; // 288
    if (input.len == 0 or input.len % PAIR_LEN != 0)
        return .{ .err = T.PrecompileError.Bls12381G2MsmInputLength };

    const k = input.len / PAIR_LEN;
    const discount = if (k <= DISCOUNT_TABLE_G2_MSM.len)
        DISCOUNT_TABLE_G2_MSM[k - 1]
    else
        DISCOUNT_TABLE_G2_MSM[DISCOUNT_TABLE_G2_MSM.len - 1];
    const gas_used = (@as(u64, k) * 22500 * @as(u64, discount)) / 1000;
    if (gas_used > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };

    const pairs = alloc_mod.get().alloc(accel.Bls12G2MsmPair, k) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    defer alloc_mod.get().free(pairs);

    var i: usize = 0;
    while (i < k) : (i += 1) {
        const off = i * PAIR_LEN;
        const coords = removeG2Padding(input[off..][0..PADDED_G2_LENGTH]) catch
            return .{ .err = T.PrecompileError.Bls12381G2MsmInputLength };
        @memcpy(pairs[i].point[0..FP_LENGTH], &coords[0]);
        @memcpy(pairs[i].point[FP_LENGTH..][0..FP_LENGTH], &coords[1]);
        @memcpy(pairs[i].point[FP2_LENGTH..][0..FP_LENGTH], &coords[2]);
        @memcpy(pairs[i].point[FP2_LENGTH + FP_LENGTH ..][0..FP_LENGTH], &coords[3]);
        @memcpy(&pairs[i].scalar, input[off + PADDED_G2_LENGTH ..][0..SCALAR_LENGTH]);
    }

    var raw: [G2_LENGTH]u8 = undefined;
    if (!accel.bls12_g2_msm(pairs, &raw))
        return .{ .err = T.PrecompileError.Bls12381G2NotOnCurve };

    const padded = padG2Point(&raw);
    const heap_out = alloc_mod.get().dupe(u8, &padded) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    return .{ .success = T.PrecompileOutput.new(gas_used, heap_out) };
}

fn bls12PairingRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    // EIP-2537: pair = 128-byte padded G1 + 256-byte padded G2 = 384 bytes
    const PAIR_LEN = PADDED_G1_LENGTH + PADDED_G2_LENGTH; // 384
    // Empty input is explicitly invalid per EIP-2537 and execution-spec-tests.
    if (input.len == 0 or input.len % PAIR_LEN != 0)
        return .{ .err = T.PrecompileError.Bls12381PairingInputLength };

    const n: usize = input.len / PAIR_LEN;
    const gas_used: u64 = @as(u64, n) * 32600 + 37700;
    if (gas_used > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };

    const pairs = alloc_mod.get().alloc(accel.Bls12PairingPair, n) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    defer alloc_mod.get().free(pairs);

    var i: usize = 0;
    while (i < n) : (i += 1) {
        const off = i * PAIR_LEN;
        const g1_coords = removeG1Padding(input[off..][0..PADDED_G1_LENGTH]) catch
            return .{ .err = T.PrecompileError.Bls12381PairingInputLength };
        @memcpy(pairs[i].g1[0..FP_LENGTH], &g1_coords[0]);
        @memcpy(pairs[i].g1[FP_LENGTH..G1_LENGTH], &g1_coords[1]);

        const g2_coords = removeG2Padding(input[off + PADDED_G1_LENGTH ..][0..PADDED_G2_LENGTH]) catch
            return .{ .err = T.PrecompileError.Bls12381PairingInputLength };
        @memcpy(pairs[i].g2[0..FP_LENGTH], &g2_coords[0]);
        @memcpy(pairs[i].g2[FP_LENGTH..][0..FP_LENGTH], &g2_coords[1]);
        @memcpy(pairs[i].g2[FP2_LENGTH..][0..FP_LENGTH], &g2_coords[2]);
        @memcpy(pairs[i].g2[FP2_LENGTH + FP_LENGTH ..][0..FP_LENGTH], &g2_coords[3]);
    }

    var verified: bool = false;
    if (!accel.bls12_pairing(pairs, &verified))
        return .{ .err = T.PrecompileError.Bls12381G1NotOnCurve };
    var result: [32]u8 = [_]u8{0} ** 32;
    if (verified) result[31] = 1;
    const heap_out = alloc_mod.get().dupe(u8, &result) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    return .{ .success = T.PrecompileOutput.new(gas_used, heap_out) };
}

fn bls12MapFpToG1Run(input: []const u8, gas_limit: u64) T.PrecompileResult {
    const GAS: u64 = 5500;
    if (GAS > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };
    if (input.len != PADDED_FP_LENGTH)
        return .{ .err = T.PrecompileError.Bls12381MapFpToG1InputLength };

    // EIP-2537: top 16 bytes must be zero
    const zero16 = [_]u8{0} ** 16;
    if (!std.mem.eql(u8, input[0..16], &zero16))
        return .{ .err = T.PrecompileError.Bls12381MapFpToG1InputLength };

    const fe: *const [FP_LENGTH]u8 = input[16..][0..FP_LENGTH];
    var raw: [G1_LENGTH]u8 = undefined;
    if (!accel.bls12_map_fp_to_g1(fe, &raw))
        return .{ .err = T.PrecompileError.NonCanonicalFp };

    const padded = padG1Point(&raw);
    const heap_out = alloc_mod.get().dupe(u8, &padded) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    return .{ .success = T.PrecompileOutput.new(GAS, heap_out) };
}

fn bls12MapFp2ToG2Run(input: []const u8, gas_limit: u64) T.PrecompileResult {
    const GAS: u64 = 23800;
    if (GAS > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };
    if (input.len != PADDED_FP2_LENGTH)
        return .{ .err = T.PrecompileError.Bls12381MapFp2ToG2InputLength };

    // EIP-2537: top 16 bytes of each 64-byte element must be zero
    const zero16 = [_]u8{0} ** 16;
    if (!std.mem.eql(u8, input[0..16], &zero16) or !std.mem.eql(u8, input[64..80], &zero16))
        return .{ .err = T.PrecompileError.Bls12381MapFp2ToG2InputLength };

    // Fp2 is two 48-byte Fp elements, each padded to 64 bytes (16 zeros + 48 bytes)
    var fe2: [FP2_LENGTH]u8 = undefined;
    @memcpy(fe2[0..FP_LENGTH], input[16..][0..FP_LENGTH]);
    @memcpy(fe2[FP_LENGTH..FP2_LENGTH], input[80..][0..FP_LENGTH]);

    var raw: [G2_LENGTH]u8 = undefined;
    if (!accel.bls12_map_fp2_to_g2(&fe2, &raw))
        return .{ .err = T.PrecompileError.NonCanonicalFp };

    const padded = padG2Point(&raw);
    const heap_out = alloc_mod.get().dupe(u8, &padded) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    return .{ .success = T.PrecompileOutput.new(GAS, heap_out) };
}

// ── Osaka / P-256 ────────────────────────────────────────────────────────────

pub const p256verify: T.PrecompileFn = p256VerifyRun;
pub const p256verify_osaka: T.PrecompileFn = p256VerifyOsakaRun;

fn p256VerifyImpl(input: []const u8, gas_cost: u64) T.PrecompileResult {
    if (input.len != 160) return .{ .success = T.PrecompileOutput.new(gas_cost, &[_]u8{}) };
    const msg: *const [32]u8 = input[0..32];
    const r: *const [32]u8 = input[32..64];
    const s: *const [32]u8 = input[64..96];
    const x: *const [32]u8 = input[96..128];
    const y: *const [32]u8 = input[128..160];
    var sig: [64]u8 = undefined;
    @memcpy(sig[0..32], r);
    @memcpy(sig[32..64], s);
    var pubkey: [64]u8 = undefined;
    @memcpy(pubkey[0..32], x);
    @memcpy(pubkey[32..64], y);
    var verified: bool = false;
    accel.secp256r1_verify(msg, &sig, &pubkey, &verified);
    // EIP-7951: invalid sig → empty return (like ecrecover); valid → 32-byte 0x00..01.
    if (!verified) return .{ .success = T.PrecompileOutput.new(gas_cost, &[_]u8{}) };
    var result: [32]u8 = [_]u8{0} ** 32;
    result[31] = 1;
    const output = alloc_mod.get().dupe(u8, &result) catch {
        // OOM must not masquerade as a gas failure; see zesu_allocator's OOM channel.
        alloc_mod.recordOom();
        return .{ .err = T.PrecompileError.OutOfGas };
    };
    return .{ .success = T.PrecompileOutput.new(gas_cost, output) };
}

fn p256VerifyRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    const GAS: u64 = 3450;
    if (GAS > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };
    return p256VerifyImpl(input, GAS);
}

fn p256VerifyOsakaRun(input: []const u8, gas_limit: u64) T.PrecompileResult {
    const GAS: u64 = 6900;
    if (GAS > gas_limit) return .{ .err = T.PrecompileError.OutOfGas };
    return p256VerifyImpl(input, GAS);
}
