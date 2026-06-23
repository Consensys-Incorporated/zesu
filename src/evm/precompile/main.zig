const std = @import("std");
const primitives = @import("primitives");

// Core types come from the precompile_types module so that a
// "precompile_overrides" build module can import them without creating a
// circular module dependency.  main.zig re-exports them for backward compat.
const T = @import("precompile_types");
pub const PrecompileError = T.PrecompileError;
pub const PrecompileOutput = T.PrecompileOutput;
pub const PrecompileResult = T.PrecompileResult;
pub const PrecompileFn = T.PrecompileFn;

// Complete precompile implementation table.  For native builds this is
// native_impls.zig (all host-OS implementations).  Inject a custom module via
//   precompile_module.addImport("precompile_implementations", your_module)
// to supply alternative implementations (e.g. zkVM hardware circuits).
const impls = @import("default_impls.zig");

// Allocator used by Precompiles hash-maps.
// Inject a custom "zevm_allocator" module in build.zig to control this.
const alloc_mod = @import("zesu_allocator");

// Pure-Zig precompile modules — safe to compile on any target (no C deps).
pub const identity = @import("identity.zig");
pub const hash = @import("hash.zig");
pub const modexp = @import("modexp.zig");
pub const blake2 = @import("blake2.zig");

/// Precompile identifier
pub const PrecompileId = union(enum) {
    /// Elliptic curve digital signature algorithm (ECDSA) public key recovery function.
    EcRec,
    /// SHA2-256 hash function.
    Sha256,
    /// RIPEMD-160 hash function.
    Ripemd160,
    /// Identity precompile.
    Identity,
    /// Arbitrary-precision exponentiation under modulo.
    ModExp,
    /// Point addition (ADD) on the elliptic curve 'alt_bn128'.
    Bn254Add,
    /// Scalar multiplication (MUL) on the elliptic curve 'alt_bn128'.
    Bn254Mul,
    /// Bilinear function on groups on the elliptic curve 'alt_bn128'.
    Bn254Pairing,
    /// Compression function F used in the BLAKE2 cryptographic hashing algorithm.
    Blake2F,
    /// Verify p(z) = y given commitment that corresponds to the polynomial p(x) and a KZG proof.
    KzgPointEvaluation,
    /// Point addition in G1 (curve over base prime field).
    Bls12G1Add,
    /// Multi-scalar-multiplication (MSM) in G1 (curve over base prime field).
    Bls12G1Msm,
    /// Point addition in G2 (curve over quadratic extension of the base prime field).
    Bls12G2Add,
    /// Multi-scalar-multiplication (MSM) in G2 (curve over quadratic extension of the base prime field).
    Bls12G2Msm,
    /// Pairing operations between a set of pairs of (G1, G2) points.
    Bls12Pairing,
    /// Base field element mapping into the G1 point.
    Bls12MapFpToGp1,
    /// Extension field element mapping into the G2 point.
    Bls12MapFp2ToGp2,
    /// ECDSA signature verification over the secp256r1 elliptic curve.
    P256Verify,
    /// Custom precompile identifier.
    Custom: []const u8,

    /// Create new custom precompile ID.
    pub fn custom(id: []const u8) PrecompileId {
        return PrecompileId{ .Custom = id };
    }

    /// Returns the name of the precompile as defined in EIP-7910.
    pub fn name(self: PrecompileId) []const u8 {
        return switch (self) {
            .EcRec => "ECREC",
            .Sha256 => "SHA256",
            .Ripemd160 => "RIPEMD160",
            .Identity => "ID",
            .ModExp => "MODEXP",
            .Bn254Add => "BN254_ADD",
            .Bn254Mul => "BN254_MUL",
            .Bn254Pairing => "BN254_PAIRING",
            .Blake2F => "BLAKE2F",
            .KzgPointEvaluation => "KZG_POINT_EVALUATION",
            .Bls12G1Add => "BLS12_G1ADD",
            .Bls12G1Msm => "BLS12_G1MSM",
            .Bls12G2Add => "BLS12_G2ADD",
            .Bls12G2Msm => "BLS12_G2MSM",
            .Bls12Pairing => "BLS12_PAIRING_CHECK",
            .Bls12MapFpToGp1 => "BLS12_MAP_FP_TO_G1",
            .Bls12MapFp2ToGp2 => "BLS12_MAP_FP2_TO_G2",
            .P256Verify => "P256VERIFY",
            .Custom => |id| id,
        };
    }

    /// Returns the precompile for the given spec.
    ///
    /// Returns null for Custom variants.
    /// For precompiles not yet introduced in the given spec, returns the
    /// closest activation fork variant.
    ///
    /// C-dependent precompiles (ecrecover, bn254, kzg, bls12, secp256r1) are
    /// sourced exclusively from the injected "precompile_implementations" module.
    /// Pure-Zig precompiles (sha256, ripemd160, identity, modexp, blake2f) use
    /// their built-in implementations directly.
    pub fn precompile(self: PrecompileId, spec: PrecompileSpecId) ?Precompile {
        return switch (self) {
            .EcRec => Precompile.new(.EcRec, u64ToAddress(1), impls.ecrecover),
            .Sha256 => hash.SHA256,
            .Ripemd160 => hash.RIPEMD160,
            .Identity => identity.FUN,
            .ModExp => blk: {
                const spec_i = @intFromEnum(spec);
                if (spec_i < @intFromEnum(PrecompileSpecId.Berlin)) {
                    break :blk modexp.BYZANTIUM;
                } else if (spec_i < @intFromEnum(PrecompileSpecId.Osaka)) {
                    break :blk modexp.BERLIN;
                } else {
                    break :blk modexp.OSAKA;
                }
            },
            .Bn254Add => if (@intFromEnum(spec) < @intFromEnum(PrecompileSpecId.Istanbul))
                Precompile.new(.Bn254Add, u64ToAddress(6), impls.bn254_add_byzantium)
            else
                Precompile.new(.Bn254Add, u64ToAddress(6), impls.bn254_add_istanbul),
            .Bn254Mul => if (@intFromEnum(spec) < @intFromEnum(PrecompileSpecId.Istanbul))
                Precompile.new(.Bn254Mul, u64ToAddress(7), impls.bn254_mul_byzantium)
            else
                Precompile.new(.Bn254Mul, u64ToAddress(7), impls.bn254_mul_istanbul),
            .Bn254Pairing => if (@intFromEnum(spec) < @intFromEnum(PrecompileSpecId.Istanbul))
                Precompile.new(.Bn254Pairing, u64ToAddress(8), impls.bn254_pairing_byzantium)
            else
                Precompile.new(.Bn254Pairing, u64ToAddress(8), impls.bn254_pairing_istanbul),
            .Blake2F => blake2.FUN,
            .KzgPointEvaluation => Precompile.new(.KzgPointEvaluation, u64ToAddress(0x0A), impls.kzg_point_evaluation),
            .Bls12G1Add => Precompile.new(.Bls12G1Add, u64ToAddress(0x0B), impls.bls12_g1_add),
            .Bls12G1Msm => Precompile.new(.Bls12G1Msm, u64ToAddress(0x0C), impls.bls12_g1_msm),
            .Bls12G2Add => Precompile.new(.Bls12G2Add, u64ToAddress(0x0D), impls.bls12_g2_add),
            .Bls12G2Msm => Precompile.new(.Bls12G2Msm, u64ToAddress(0x0E), impls.bls12_g2_msm),
            .Bls12Pairing => Precompile.new(.Bls12Pairing, u64ToAddress(0x0F), impls.bls12_pairing),
            .Bls12MapFpToGp1 => Precompile.new(.Bls12MapFpToGp1, u64ToAddress(0x10), impls.bls12_map_fp_to_g1),
            .Bls12MapFp2ToGp2 => Precompile.new(.Bls12MapFp2ToGp2, u64ToAddress(0x11), impls.bls12_map_fp2_to_g2),
            .P256Verify => if (@intFromEnum(spec) < @intFromEnum(PrecompileSpecId.Osaka))
                Precompile.new(.P256Verify, u64ToAddress(256), impls.p256verify)
            else
                Precompile.new(.P256Verify, u64ToAddress(256), impls.p256verify_osaka),
            .Custom => return null,
        };
    }
};

/// Precompile specification ID
pub const PrecompileSpecId = enum {
    /// Homestead spec
    Homestead,
    /// Byzantium spec
    Byzantium,
    /// Istanbul spec
    Istanbul,
    /// Berlin spec
    Berlin,
    /// Cancun spec
    Cancun,
    /// Prague spec
    Prague,
    /// Osaka spec
    Osaka,

    /// Map from full SpecId to PrecompileSpecId
    /// Groups similar specs together since precompiles only change at certain hardforks
    pub fn fromSpec(spec: primitives.SpecId) PrecompileSpecId {
        return switch (spec) {
            .frontier, .frontier_thawing, .homestead, .dao_fork, .tangerine, .spurious_dragon => .Homestead,
            .byzantium, .constantinople, .petersburg => .Byzantium,
            .istanbul, .muir_glacier => .Istanbul,
            .berlin, .london, .arrow_glacier, .gray_glacier, .merge, .shanghai => .Berlin,
            .cancun => .Cancun,
            .prague => .Prague,
            .osaka, .bpo1, .bpo2, .amsterdam => .Osaka,
        };
    }
};

/// Precompile structure
pub const Precompile = struct {
    /// Unique identifier
    id: PrecompileId,
    /// Precompile address
    address: primitives.Address,
    /// Precompile implementation
    func: PrecompileFn,

    /// Create new precompile
    pub fn new(id: PrecompileId, address: primitives.Address, func: PrecompileFn) Precompile {
        return Precompile{
            .id = id,
            .address = address,
            .func = func,
        };
    }

    /// Execute the precompile
    pub fn execute(self: Precompile, input: []const u8, gas_limit: u64) PrecompileResult {
        return self.func(input, gas_limit);
    }
};

pub const calcLinearCost = T.calcLinearCost;

/// Convert u64 to address
pub fn u64ToAddress(value: u64) primitives.Address {
    var address: primitives.Address = [_]u8{0} ** 20;
    std.mem.writeInt(u64, address[12..20], value, .big);
    return address;
}

/// Precompiles collection
pub const Precompiles = struct {
    /// Inner HashMap of precompiles
    inner: std.HashMap(primitives.Address, Precompile, primitives.AddressContext, 80),
    /// Addresses of precompiles
    addresses: std.HashMap(primitives.Address, void, primitives.AddressContext, 80),
    /// Optimized access for short addresses
    optimized_access: [256]?Precompile,
    /// Whether all precompiles are short addresses
    all_short_addresses: bool,

    /// Create new precompiles collection
    pub fn new() Precompiles {
        return Precompiles{
            .inner = std.HashMap(primitives.Address, Precompile, primitives.AddressContext, 80).init(alloc_mod.get()),
            .addresses = std.HashMap(primitives.Address, void, primitives.AddressContext, 80).init(alloc_mod.get()),
            .optimized_access = [_]?Precompile{null} ** 256,
            .all_short_addresses = true,
        };
    }

    /// Add a precompile to the collection
    pub fn add(self: *Precompiles, precompile: Precompile) !void {
        try self.inner.put(precompile.address, precompile);
        try self.addresses.put(precompile.address, {});

        // Update optimized access for short addresses
        if (precompile.address[0] == 0 and precompile.address[1] == 0 and precompile.address[2] == 0 and precompile.address[3] == 0) {
            const index = std.mem.readInt(u32, precompile.address[16..20], .big);
            if (index < 256) {
                self.optimized_access[index] = precompile;
            }
        }
    }

    /// Get precompile by address
    pub fn get(self: *const Precompiles, address: primitives.Address) ?Precompile {
        return self.inner.get(address);
    }

    /// Check if address is a precompile
    pub fn contains(self: *const Precompiles, address: primitives.Address) bool {
        return self.addresses.contains(address);
    }

    /// Get precompiles for a specific spec
    pub fn forSpec(spec: PrecompileSpecId) Precompiles {
        var precompiles = Precompiles.new();

        switch (spec) {
            .Homestead => {
                precompiles.add(identity.FUN) catch {};
                precompiles.add(hash.SHA256) catch {};
                precompiles.add(hash.RIPEMD160) catch {};
                precompiles.add(Precompile.new(.EcRec, u64ToAddress(1), impls.ecrecover)) catch {};
            },
            .Byzantium => {
                precompiles.add(identity.FUN) catch {};
                precompiles.add(hash.SHA256) catch {};
                precompiles.add(hash.RIPEMD160) catch {};
                precompiles.add(Precompile.new(.EcRec, u64ToAddress(1), impls.ecrecover)) catch {};
                precompiles.add(modexp.BYZANTIUM) catch {};
                precompiles.add(Precompile.new(.Bn254Add, u64ToAddress(6), impls.bn254_add_byzantium)) catch {};
                precompiles.add(Precompile.new(.Bn254Mul, u64ToAddress(7), impls.bn254_mul_byzantium)) catch {};
                precompiles.add(Precompile.new(.Bn254Pairing, u64ToAddress(8), impls.bn254_pairing_byzantium)) catch {};
            },
            .Istanbul => {
                precompiles.add(identity.FUN) catch {};
                precompiles.add(hash.SHA256) catch {};
                precompiles.add(hash.RIPEMD160) catch {};
                precompiles.add(Precompile.new(.EcRec, u64ToAddress(1), impls.ecrecover)) catch {};
                precompiles.add(modexp.BYZANTIUM) catch {};
                precompiles.add(Precompile.new(.Bn254Add, u64ToAddress(6), impls.bn254_add_istanbul)) catch {};
                precompiles.add(Precompile.new(.Bn254Mul, u64ToAddress(7), impls.bn254_mul_istanbul)) catch {};
                precompiles.add(Precompile.new(.Bn254Pairing, u64ToAddress(8), impls.bn254_pairing_istanbul)) catch {};
                precompiles.add(blake2.FUN) catch {};
            },
            .Berlin => {
                precompiles.add(identity.FUN) catch {};
                precompiles.add(hash.SHA256) catch {};
                precompiles.add(hash.RIPEMD160) catch {};
                precompiles.add(Precompile.new(.EcRec, u64ToAddress(1), impls.ecrecover)) catch {};
                precompiles.add(modexp.BERLIN) catch {};
                precompiles.add(Precompile.new(.Bn254Add, u64ToAddress(6), impls.bn254_add_istanbul)) catch {};
                precompiles.add(Precompile.new(.Bn254Mul, u64ToAddress(7), impls.bn254_mul_istanbul)) catch {};
                precompiles.add(Precompile.new(.Bn254Pairing, u64ToAddress(8), impls.bn254_pairing_istanbul)) catch {};
                precompiles.add(blake2.FUN) catch {};
            },
            .Cancun => {
                precompiles.add(identity.FUN) catch {};
                precompiles.add(hash.SHA256) catch {};
                precompiles.add(hash.RIPEMD160) catch {};
                precompiles.add(Precompile.new(.EcRec, u64ToAddress(1), impls.ecrecover)) catch {};
                precompiles.add(modexp.BERLIN) catch {};
                precompiles.add(Precompile.new(.Bn254Add, u64ToAddress(6), impls.bn254_add_istanbul)) catch {};
                precompiles.add(Precompile.new(.Bn254Mul, u64ToAddress(7), impls.bn254_mul_istanbul)) catch {};
                precompiles.add(Precompile.new(.Bn254Pairing, u64ToAddress(8), impls.bn254_pairing_istanbul)) catch {};
                precompiles.add(blake2.FUN) catch {};
                precompiles.add(Precompile.new(.KzgPointEvaluation, u64ToAddress(0x0A), impls.kzg_point_evaluation)) catch {};
            },
            .Prague => {
                precompiles.add(identity.FUN) catch {};
                precompiles.add(hash.SHA256) catch {};
                precompiles.add(hash.RIPEMD160) catch {};
                precompiles.add(Precompile.new(.EcRec, u64ToAddress(1), impls.ecrecover)) catch {};
                precompiles.add(modexp.BERLIN) catch {};
                precompiles.add(Precompile.new(.Bn254Add, u64ToAddress(6), impls.bn254_add_istanbul)) catch {};
                precompiles.add(Precompile.new(.Bn254Mul, u64ToAddress(7), impls.bn254_mul_istanbul)) catch {};
                precompiles.add(Precompile.new(.Bn254Pairing, u64ToAddress(8), impls.bn254_pairing_istanbul)) catch {};
                precompiles.add(blake2.FUN) catch {};
                precompiles.add(Precompile.new(.KzgPointEvaluation, u64ToAddress(0x0A), impls.kzg_point_evaluation)) catch {};
                precompiles.add(Precompile.new(.Bls12G1Add, u64ToAddress(0x0B), impls.bls12_g1_add)) catch {};
                precompiles.add(Precompile.new(.Bls12G1Msm, u64ToAddress(0x0C), impls.bls12_g1_msm)) catch {};
                precompiles.add(Precompile.new(.Bls12G2Add, u64ToAddress(0x0D), impls.bls12_g2_add)) catch {};
                precompiles.add(Precompile.new(.Bls12G2Msm, u64ToAddress(0x0E), impls.bls12_g2_msm)) catch {};
                precompiles.add(Precompile.new(.Bls12Pairing, u64ToAddress(0x0F), impls.bls12_pairing)) catch {};
                precompiles.add(Precompile.new(.Bls12MapFpToGp1, u64ToAddress(0x10), impls.bls12_map_fp_to_g1)) catch {};
                precompiles.add(Precompile.new(.Bls12MapFp2ToGp2, u64ToAddress(0x11), impls.bls12_map_fp2_to_g2)) catch {};
            },
            .Osaka => {
                precompiles.add(identity.FUN) catch {};
                precompiles.add(hash.SHA256) catch {};
                precompiles.add(hash.RIPEMD160) catch {};
                precompiles.add(Precompile.new(.EcRec, u64ToAddress(1), impls.ecrecover)) catch {};
                precompiles.add(modexp.OSAKA) catch {};
                precompiles.add(Precompile.new(.Bn254Add, u64ToAddress(6), impls.bn254_add_istanbul)) catch {};
                precompiles.add(Precompile.new(.Bn254Mul, u64ToAddress(7), impls.bn254_mul_istanbul)) catch {};
                precompiles.add(Precompile.new(.Bn254Pairing, u64ToAddress(8), impls.bn254_pairing_istanbul)) catch {};
                precompiles.add(blake2.FUN) catch {};
                precompiles.add(Precompile.new(.KzgPointEvaluation, u64ToAddress(0x0A), impls.kzg_point_evaluation)) catch {};
                precompiles.add(Precompile.new(.Bls12G1Add, u64ToAddress(0x0B), impls.bls12_g1_add)) catch {};
                precompiles.add(Precompile.new(.Bls12G1Msm, u64ToAddress(0x0C), impls.bls12_g1_msm)) catch {};
                precompiles.add(Precompile.new(.Bls12G2Add, u64ToAddress(0x0D), impls.bls12_g2_add)) catch {};
                precompiles.add(Precompile.new(.Bls12G2Msm, u64ToAddress(0x0E), impls.bls12_g2_msm)) catch {};
                precompiles.add(Precompile.new(.Bls12Pairing, u64ToAddress(0x0F), impls.bls12_pairing)) catch {};
                precompiles.add(Precompile.new(.Bls12MapFpToGp1, u64ToAddress(0x10), impls.bls12_map_fp_to_g1)) catch {};
                precompiles.add(Precompile.new(.Bls12MapFp2ToGp2, u64ToAddress(0x11), impls.bls12_map_fp2_to_g2)) catch {};
                precompiles.add(Precompile.new(.P256Verify, u64ToAddress(256), impls.p256verify_osaka)) catch {};
            },
        }

        return precompiles;
    }
};

// Import test module
pub const tests = @import("tests.zig");

test {
    _ = @import("tests.zig");
}

// Placeholder for testing
pub const testing = struct {
    pub fn testPrecompile() !void {
        std.log.info("Testing precompile module...", .{});

        // Test basic precompiles
        try testIdentity();
        try testHash();
        try testSecp256k1();

        std.log.info("Precompile module test passed!", .{});
    }

    fn testIdentity() !void {
        const input = "Hello, World!";
        const result = identity.identityRun(input, 1000);
        switch (result) {
            .success => |output| {
                std.debug.assert(output.gas_used == 15 + 3); // base + word cost
                std.debug.assert(std.mem.eql(u8, output.bytes, input));
            },
            .err => return error.TestUnexpectedResult,
        }
    }

    fn testHash() !void {
        const input = "Hello, World!";
        const sha256_result = hash.sha256Run(input, 1000);
        switch (sha256_result) {
            .success => |output| {
                std.debug.assert(output.gas_used == 60 + 12); // base + word cost
            },
            .err => return error.TestUnexpectedResult,
        }

        const ripemd160_result = hash.ripemd160Run(input, 1000);
        switch (ripemd160_result) {
            .success => |output| {
                std.debug.assert(output.gas_used == 600 + 120); // base + word cost
            },
            .err => return error.TestUnexpectedResult,
        }
    }

    fn testSecp256k1() !void {
        // Test with invalid input (should return empty result)
        const invalid_input = [_]u8{0} ** 128;
        const result = impls.ecrecover(&invalid_input, 10000);
        switch (result) {
            .success => |output| {
                std.debug.assert(output.gas_used == 3000);
                std.debug.assert(output.bytes.len == 0);
            },
            .err => return error.TestUnexpectedResult,
        }
    }
};
