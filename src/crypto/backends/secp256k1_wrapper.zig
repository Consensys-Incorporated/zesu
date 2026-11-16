const std = @import("std");

const c = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_recovery.h");
});

/// Wrapper for secp256k1 ECDSA signature recovery
pub const Secp256k1 = struct {
    ctx: *c.secp256k1_context,

    pub fn init() Secp256k1 {
        const ctx = c.secp256k1_context_create(c.SECP256K1_CONTEXT_VERIFY | c.SECP256K1_CONTEXT_SIGN);
        std.debug.assert(ctx != null);
        return Secp256k1{ .ctx = ctx.? };
    }

    pub fn deinit(self: *Secp256k1) void {
        c.secp256k1_context_destroy(self.ctx);
        self.ctx = undefined;
    }

    /// Sign a 32-byte message hash with a private key.
    /// Returns the compact 64-byte signature and recovery ID, or null on failure.
    pub fn sign(self: Secp256k1, msg: [32]u8, seckey: [32]u8) ?struct { sig: [64]u8, recid: u8 } {
        var rec_sig: c.secp256k1_ecdsa_recoverable_signature = undefined;
        if (c.secp256k1_ecdsa_sign_recoverable(
            self.ctx,
            &rec_sig,
            &msg,
            &seckey,
            null,
            null,
        ) == 0) return null;

        var sig_bytes: [64]u8 = undefined;
        var recid: c_int = undefined;
        _ = c.secp256k1_ecdsa_recoverable_signature_serialize_compact(self.ctx, &sig_bytes, &recid, &rec_sig);

        return .{ .sig = sig_bytes, .recid = @intCast(recid) };
    }

    /// Recover the signer's Ethereum address (last 20 bytes of keccak256(pubkey)),
    /// or null if recovery fails.
    pub fn ecrecover(
        self: Secp256k1,
        msg: [32]u8,
        sig: [64]u8,
        recid: u8,
    ) ?[20]u8 {
        var recoverable_sig: c.secp256k1_ecdsa_recoverable_signature = undefined;
        const mut_recid: c_int = @intCast(recid);

        if (c.secp256k1_ecdsa_recoverable_signature_parse_compact(
            self.ctx,
            &recoverable_sig,
            &sig,
            mut_recid,
        ) == 0) {
            return null;
        }

        var pubkey: c.secp256k1_pubkey = undefined;
        if (c.secp256k1_ecdsa_recover(
            self.ctx,
            &pubkey,
            &recoverable_sig,
            &msg,
        ) == 0) {
            return null;
        }

        // Uncompressed form: 0x04 || x || y.
        var pubkey_serialized: [65]u8 = undefined;
        var output_len: usize = 65;
        if (c.secp256k1_ec_pubkey_serialize(
            self.ctx,
            &pubkey_serialized,
            &output_len,
            &pubkey,
            c.SECP256K1_EC_UNCOMPRESSED,
        ) == 0) {
            return null;
        }

        // Address = keccak256(x || y)[12..32].
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(pubkey_serialized[1..], &hash, .{});

        var address: [20]u8 = undefined;
        @memcpy(&address, hash[12..32]);
        return address;
    }
};

var global_ctx_done: std.atomic.Value(bool) = .init(false);
var global_ctx: ?Secp256k1 = null;

pub fn getContext() ?Secp256k1 {
    if (!global_ctx_done.load(.acquire)) {
        global_ctx = Secp256k1.init();
        global_ctx_done.store(true, .release);
    }
    return global_ctx;
}

/// Recover raw uncompressed public key bytes from a recoverable signature.
/// Returns 64 bytes (x||y, no 0x04 prefix), or null on failure.
/// Used by the accelerators interface; the caller derives the address.
pub fn ecrecoverPubkey(msg: [32]u8, sig: [64]u8, recid: u8) ?[64]u8 {
    const ctx = getContext() orelse return null;

    var recoverable_sig: c.secp256k1_ecdsa_recoverable_signature = undefined;
    const mut_recid: c_int = @intCast(recid);
    if (c.secp256k1_ecdsa_recoverable_signature_parse_compact(ctx.ctx, &recoverable_sig, &sig, mut_recid) == 0)
        return null;

    var pubkey: c.secp256k1_pubkey = undefined;
    if (c.secp256k1_ecdsa_recover(ctx.ctx, &pubkey, &recoverable_sig, &msg) == 0)
        return null;

    var pubkey_serialized: [65]u8 = undefined;
    var output_len: usize = 65;
    if (c.secp256k1_ec_pubkey_serialize(ctx.ctx, &pubkey_serialized, &output_len, &pubkey, c.SECP256K1_EC_UNCOMPRESSED) == 0)
        return null;

    var result: [64]u8 = undefined;
    @memcpy(&result, pubkey_serialized[1..65]);
    return result;
}

/// Verify a secp256k1 ECDSA signature against a message hash and public key.
/// msg:         32-byte message hash
/// sig:         64-byte compact signature (r||s)
/// pubkey_bytes: 64-byte uncompressed public key (x||y, no 0x04 prefix)
pub fn verify(msg: [32]u8, sig: [64]u8, pubkey_bytes: [64]u8) bool {
    const ctx = getContext() orelse return false;

    var parsed_sig: c.secp256k1_ecdsa_signature = undefined;
    if (c.secp256k1_ecdsa_signature_parse_compact(ctx.ctx, &parsed_sig, &sig) == 0)
        return false;

    // secp256k1_ec_pubkey_parse expects the 0x04-prefixed uncompressed form.
    var pubkey_uncompressed: [65]u8 = undefined;
    pubkey_uncompressed[0] = 0x04;
    @memcpy(pubkey_uncompressed[1..], &pubkey_bytes);

    var parsed_pubkey: c.secp256k1_pubkey = undefined;
    if (c.secp256k1_ec_pubkey_parse(ctx.ctx, &parsed_pubkey, &pubkey_uncompressed, 65) == 0)
        return false;

    return c.secp256k1_ecdsa_verify(ctx.ctx, &parsed_sig, &msg, &parsed_pubkey) == 1;
}
