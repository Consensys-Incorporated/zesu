//! SSZ serialization for SszStatelessValidationResult (glamsterdam-devnet-8 / zkevm@v0.8.0).
//!
//! Output layout (43 bytes, all fields fixed-size):
//!   [0..32]  new_payload_request_root  Bytes32  SSZ hash_tree_root of SszNewPayloadRequest
//!   [32]     successful_validation     boolean  0x01 = valid
//!   [33..41] chain_id                  uint64
//!   [41..43] schema_id                 uint16   0x1501 (fork_index || revision)
//!
//! zkevm@v0.8.0 replaced the SszChainConfig trailer with a flat chain_id + schema_id,
//! and switched the payload containers to EIP-7495 `ProgressiveContainer` /
//! EIP-7916 `ProgressiveList`. Serialization of those is byte-identical to the
//! stable forms, but `hash_tree_root` is not — see `progressiveRoot`.

const std = @import("std");
const input = @import("input");
const accel = @import("accelerators");

// ── SHA-256 ───────────────────────────────────────────────────────────────────

fn sha2(a: [32]u8, b: [32]u8) [32]u8 {
    var buf: [64]u8 = undefined;
    @memcpy(buf[0..32], &a);
    @memcpy(buf[32..64], &b);
    var out: [32]u8 = undefined;
    accel.sha256(&buf, &out);
    return out;
}

fn sha2Bytes(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    accel.sha256(data, &out);
    return out;
}

// ── Zero hash tree ────────────────────────────────────────────────────────────

/// Precomputed SSZ zero hashes: z[k] = SHA256(z[k-1] || z[k-1]), z[0] = 0x00*32.
/// Covers depths 0..25 (sufficient for all Amsterdam SSZ list limits).
/// Computing these on-demand is O(k) SHA256 calls; a table lookup is O(1) and
/// eliminates the O(D²) blowup in sparseRoot (which calls zeroHash at every depth).
const ZERO_HASHES: [26][32]u8 = .{
    // z[0] = 0x00 * 32
    [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    // z[1] = sha256(z[0] || z[0])
    [_]u8{ 0xf5, 0xa5, 0xfd, 0x42, 0xd1, 0x6a, 0x20, 0x30, 0x27, 0x98, 0xef, 0x6e, 0xd3, 0x09, 0x97, 0x9b, 0x43, 0x00, 0x3d, 0x23, 0x20, 0xd9, 0xf0, 0xe8, 0xea, 0x98, 0x31, 0xa9, 0x27, 0x59, 0xfb, 0x4b },
    // z[2] = sha256(z[1] || z[1])
    [_]u8{ 0xdb, 0x56, 0x11, 0x4e, 0x00, 0xfd, 0xd4, 0xc1, 0xf8, 0x5c, 0x89, 0x2b, 0xf3, 0x5a, 0xc9, 0xa8, 0x92, 0x89, 0xaa, 0xec, 0xb1, 0xeb, 0xd0, 0xa9, 0x6c, 0xde, 0x60, 0x6a, 0x74, 0x8b, 0x5d, 0x71 },
    // z[3] = sha256(z[2] || z[2])
    [_]u8{ 0xc7, 0x80, 0x09, 0xfd, 0xf0, 0x7f, 0xc5, 0x6a, 0x11, 0xf1, 0x22, 0x37, 0x06, 0x58, 0xa3, 0x53, 0xaa, 0xa5, 0x42, 0xed, 0x63, 0xe4, 0x4c, 0x4b, 0xc1, 0x5f, 0xf4, 0xcd, 0x10, 0x5a, 0xb3, 0x3c },
    // z[4] = sha256(z[3] || z[3])
    [_]u8{ 0x53, 0x6d, 0x98, 0x83, 0x7f, 0x2d, 0xd1, 0x65, 0xa5, 0x5d, 0x5e, 0xea, 0xe9, 0x14, 0x85, 0x95, 0x44, 0x72, 0xd5, 0x6f, 0x24, 0x6d, 0xf2, 0x56, 0xbf, 0x3c, 0xae, 0x19, 0x35, 0x2a, 0x12, 0x3c },
    // z[5] = sha256(z[4] || z[4])
    [_]u8{ 0x9e, 0xfd, 0xe0, 0x52, 0xaa, 0x15, 0x42, 0x9f, 0xae, 0x05, 0xba, 0xd4, 0xd0, 0xb1, 0xd7, 0xc6, 0x4d, 0xa6, 0x4d, 0x03, 0xd7, 0xa1, 0x85, 0x4a, 0x58, 0x8c, 0x2c, 0xb8, 0x43, 0x0c, 0x0d, 0x30 },
    // z[6] = sha256(z[5] || z[5])
    [_]u8{ 0xd8, 0x8d, 0xdf, 0xee, 0xd4, 0x00, 0xa8, 0x75, 0x55, 0x96, 0xb2, 0x19, 0x42, 0xc1, 0x49, 0x7e, 0x11, 0x4c, 0x30, 0x2e, 0x61, 0x18, 0x29, 0x0f, 0x91, 0xe6, 0x77, 0x29, 0x76, 0x04, 0x1f, 0xa1 },
    // z[7] = sha256(z[6] || z[6])
    [_]u8{ 0x87, 0xeb, 0x0d, 0xdb, 0xa5, 0x7e, 0x35, 0xf6, 0xd2, 0x86, 0x67, 0x38, 0x02, 0xa4, 0xaf, 0x59, 0x75, 0xe2, 0x25, 0x06, 0xc7, 0xcf, 0x4c, 0x64, 0xbb, 0x6b, 0xe5, 0xee, 0x11, 0x52, 0x7f, 0x2c },
    // z[8] = sha256(z[7] || z[7])
    [_]u8{ 0x26, 0x84, 0x64, 0x76, 0xfd, 0x5f, 0xc5, 0x4a, 0x5d, 0x43, 0x38, 0x51, 0x67, 0xc9, 0x51, 0x44, 0xf2, 0x64, 0x3f, 0x53, 0x3c, 0xc8, 0x5b, 0xb9, 0xd1, 0x6b, 0x78, 0x2f, 0x8d, 0x7d, 0xb1, 0x93 },
    // z[9] = sha256(z[8] || z[8])
    [_]u8{ 0x50, 0x6d, 0x86, 0x58, 0x2d, 0x25, 0x24, 0x05, 0xb8, 0x40, 0x01, 0x87, 0x92, 0xca, 0xd2, 0xbf, 0x12, 0x59, 0xf1, 0xef, 0x5a, 0xa5, 0xf8, 0x87, 0xe1, 0x3c, 0xb2, 0xf0, 0x09, 0x4f, 0x51, 0xe1 },
    // z[10] = sha256(z[9] || z[9])
    [_]u8{ 0xff, 0xff, 0x0a, 0xd7, 0xe6, 0x59, 0x77, 0x2f, 0x95, 0x34, 0xc1, 0x95, 0xc8, 0x15, 0xef, 0xc4, 0x01, 0x4e, 0xf1, 0xe1, 0xda, 0xed, 0x44, 0x04, 0xc0, 0x63, 0x85, 0xd1, 0x11, 0x92, 0xe9, 0x2b },
    // z[11] = sha256(z[10] || z[10])
    [_]u8{ 0x6c, 0xf0, 0x41, 0x27, 0xdb, 0x05, 0x44, 0x1c, 0xd8, 0x33, 0x10, 0x7a, 0x52, 0xbe, 0x85, 0x28, 0x68, 0x89, 0x0e, 0x43, 0x17, 0xe6, 0xa0, 0x2a, 0xb4, 0x76, 0x83, 0xaa, 0x75, 0x96, 0x42, 0x20 },
    // z[12] = sha256(z[11] || z[11])
    [_]u8{ 0xb7, 0xd0, 0x5f, 0x87, 0x5f, 0x14, 0x00, 0x27, 0xef, 0x51, 0x18, 0xa2, 0x24, 0x7b, 0xbb, 0x84, 0xce, 0x8f, 0x2f, 0x0f, 0x11, 0x23, 0x62, 0x30, 0x85, 0xda, 0xf7, 0x96, 0x0c, 0x32, 0x9f, 0x5f },
    // z[13] = sha256(z[12] || z[12])
    [_]u8{ 0xdf, 0x6a, 0xf5, 0xf5, 0xbb, 0xdb, 0x6b, 0xe9, 0xef, 0x8a, 0xa6, 0x18, 0xe4, 0xbf, 0x80, 0x73, 0x96, 0x08, 0x67, 0x17, 0x1e, 0x29, 0x67, 0x6f, 0x8b, 0x28, 0x4d, 0xea, 0x6a, 0x08, 0xa8, 0x5e },
    // z[14] = sha256(z[13] || z[13])
    [_]u8{ 0xb5, 0x8d, 0x90, 0x0f, 0x5e, 0x18, 0x2e, 0x3c, 0x50, 0xef, 0x74, 0x96, 0x9e, 0xa1, 0x6c, 0x77, 0x26, 0xc5, 0x49, 0x75, 0x7c, 0xc2, 0x35, 0x23, 0xc3, 0x69, 0x58, 0x7d, 0xa7, 0x29, 0x37, 0x84 },
    // z[15] = sha256(z[14] || z[14])
    [_]u8{ 0xd4, 0x9a, 0x75, 0x02, 0xff, 0xcf, 0xb0, 0x34, 0x0b, 0x1d, 0x78, 0x85, 0x68, 0x85, 0x00, 0xca, 0x30, 0x81, 0x61, 0xa7, 0xf9, 0x6b, 0x62, 0xdf, 0x9d, 0x08, 0x3b, 0x71, 0xfc, 0xc8, 0xf2, 0xbb },
    // z[16] = sha256(z[15] || z[15])
    [_]u8{ 0x8f, 0xe6, 0xb1, 0x68, 0x92, 0x56, 0xc0, 0xd3, 0x85, 0xf4, 0x2f, 0x5b, 0xbe, 0x20, 0x27, 0xa2, 0x2c, 0x19, 0x96, 0xe1, 0x10, 0xba, 0x97, 0xc1, 0x71, 0xd3, 0xe5, 0x94, 0x8d, 0xe9, 0x2b, 0xeb },
    // z[17] = sha256(z[16] || z[16])
    [_]u8{ 0x8d, 0x0d, 0x63, 0xc3, 0x9e, 0xba, 0xde, 0x85, 0x09, 0xe0, 0xae, 0x3c, 0x9c, 0x38, 0x76, 0xfb, 0x5f, 0xa1, 0x12, 0xbe, 0x18, 0xf9, 0x05, 0xec, 0xac, 0xfe, 0xcb, 0x92, 0x05, 0x76, 0x03, 0xab },
    // z[18] = sha256(z[17] || z[17])
    [_]u8{ 0x95, 0xee, 0xc8, 0xb2, 0xe5, 0x41, 0xca, 0xd4, 0xe9, 0x1d, 0xe3, 0x83, 0x85, 0xf2, 0xe0, 0x46, 0x61, 0x9f, 0x54, 0x49, 0x6c, 0x23, 0x82, 0xcb, 0x6c, 0xac, 0xd5, 0xb9, 0x8c, 0x26, 0xf5, 0xa4 },
    // z[19] = sha256(z[18] || z[18])
    [_]u8{ 0xf8, 0x93, 0xe9, 0x08, 0x91, 0x77, 0x75, 0xb6, 0x2b, 0xff, 0x23, 0x29, 0x4d, 0xbb, 0xe3, 0xa1, 0xcd, 0x8e, 0x6c, 0xc1, 0xc3, 0x5b, 0x48, 0x01, 0x88, 0x7b, 0x64, 0x6a, 0x6f, 0x81, 0xf1, 0x7f },
    // z[20] = sha256(z[19] || z[19])
    [_]u8{ 0xcd, 0xdb, 0xa7, 0xb5, 0x92, 0xe3, 0x13, 0x33, 0x93, 0xc1, 0x61, 0x94, 0xfa, 0xc7, 0x43, 0x1a, 0xbf, 0x2f, 0x54, 0x85, 0xed, 0x71, 0x1d, 0xb2, 0x82, 0x18, 0x3c, 0x81, 0x9e, 0x08, 0xeb, 0xaa },
    // z[21] = sha256(z[20] || z[20])
    [_]u8{ 0x8a, 0x8d, 0x7f, 0xe3, 0xaf, 0x8c, 0xaa, 0x08, 0x5a, 0x76, 0x39, 0xa8, 0x32, 0x00, 0x14, 0x57, 0xdf, 0xb9, 0x12, 0x8a, 0x80, 0x61, 0x14, 0x2a, 0xd0, 0x33, 0x56, 0x29, 0xff, 0x23, 0xff, 0x9c },
    // z[22] = sha256(z[21] || z[21])
    [_]u8{ 0xfe, 0xb3, 0xc3, 0x37, 0xd7, 0xa5, 0x1a, 0x6f, 0xbf, 0x00, 0xb9, 0xe3, 0x4c, 0x52, 0xe1, 0xc9, 0x19, 0x5c, 0x96, 0x9b, 0xd4, 0xe7, 0xa0, 0xbf, 0xd5, 0x1d, 0x5c, 0x5b, 0xed, 0x9c, 0x11, 0x67 },
    // z[23] = sha256(z[22] || z[22])
    [_]u8{ 0xe7, 0x1f, 0x0a, 0xa8, 0x3c, 0xc3, 0x2e, 0xdf, 0xbe, 0xfa, 0x9f, 0x4d, 0x3e, 0x01, 0x74, 0xca, 0x85, 0x18, 0x2e, 0xec, 0x9f, 0x3a, 0x09, 0xf6, 0xa6, 0xc0, 0xdf, 0x63, 0x77, 0xa5, 0x10, 0xd7 },
    // z[24] = sha256(z[23] || z[23])
    [_]u8{ 0x31, 0x20, 0x6f, 0xa8, 0x0a, 0x50, 0xbb, 0x6a, 0xbe, 0x29, 0x08, 0x50, 0x58, 0xf1, 0x62, 0x12, 0x21, 0x2a, 0x60, 0xee, 0xc8, 0xf0, 0x49, 0xfe, 0xcb, 0x92, 0xd8, 0xc8, 0xe0, 0xa8, 0x4b, 0xc0 },
    // z[25] = sha256(z[24] || z[24])
    [_]u8{ 0x21, 0x35, 0x2b, 0xfe, 0xcb, 0xed, 0xdd, 0xe9, 0x93, 0x83, 0x9f, 0x61, 0x4c, 0x3d, 0xac, 0x0a, 0x3e, 0xe3, 0x75, 0x43, 0xf9, 0xb4, 0x12, 0xb1, 0x61, 0x99, 0xdc, 0x15, 0x8e, 0x23, 0xb5, 0x44 },
};

fn zeroHash(depth: u8) [32]u8 {
    return ZERO_HASHES[depth];
}

// ── mix_in_length ─────────────────────────────────────────────────────────────

/// SSZ: hash_tree_root(list) = sha256(merkle_root || uint256_le(length))
fn mixInLength(root: [32]u8, length: u64) [32]u8 {
    var buf: [64]u8 = [_]u8{0} ** 64;
    @memcpy(buf[0..32], &root);
    std.mem.writeInt(u64, buf[32..40], length, .little);
    return sha2Bytes(&buf);
}

// ── Sparse Merkle tree ────────────────────────────────────────────────────────

/// Compute the Merkle root of `2^depth` virtual leaves where:
///   leaves[0..len] are the actual values
///   leaves[len..2^depth] are all zero chunks.
///
/// Uses precomputed zero subtree hashes for efficiency — O(len * depth) time.
fn sparseRoot(leaves: []const [32]u8, depth: u8) [32]u8 {
    if (depth == 0) {
        return if (leaves.len >= 1) leaves[0] else [_]u8{0} ** 32;
    }
    const half: usize = @as(usize, 1) << @intCast(depth - 1);
    const left_leaves = if (leaves.len > half) leaves[0..half] else leaves;
    const right_leaves = if (leaves.len > half) leaves[half..] else &[_][32]u8{};
    const left = sparseRoot(left_leaves, depth - 1);
    const right = if (leaves.len <= half) zeroHash(depth - 1) else sparseRoot(right_leaves, depth - 1);
    return sha2(left, right);
}

/// Merkleize exactly N chunks (N must be a power of two).
fn merkleizeExact(chunks: []const [32]u8) [32]u8 {
    std.debug.assert(chunks.len > 0);
    var n = chunks.len;
    // Must be power of 2 — caller is responsible
    while (n > 1) : (n /= 2) {}
    std.debug.assert(n == 1); // assert power of 2

    if (chunks.len == 1) return chunks[0];
    // Use simple in-place reduction on a stack buffer for small sizes (≤ 32).
    // Caller uses small fixed sizes (4, 8, 32) for container fields.
    var buf: [32][32]u8 = undefined;
    @memcpy(buf[0..chunks.len], chunks);
    var len = chunks.len;
    while (len > 1) {
        const half = len / 2;
        for (0..half) |i| buf[i] = sha2(buf[2 * i], buf[2 * i + 1]);
        len = half;
    }
    return buf[0];
}

// ── Progressive Merkle tree (EIP-7916 / EIP-7495) ────────────────────────────

/// `subtree_fill_progressive`: the tree is a right-leaning spine of subtrees
/// holding 1, 4, 16, 64, ... leaves. The spine terminates in a single zero
/// chunk (not a zero subtree), so the root grows with the actual element count
/// instead of a fixed capacity.
fn progressiveRoot(nodes: []const [32]u8) [32]u8 {
    return progressiveRootAt(nodes, 0);
}

fn progressiveRootAt(nodes: []const [32]u8, depth: u8) [32]u8 {
    if (nodes.len == 0) return ZERO_HASHES[0];
    const base = @as(usize, 1) << @intCast(depth);
    const n = @min(base, nodes.len);
    return sha2(sparseRoot(nodes[0..n], depth), progressiveRootAt(nodes[n..], depth + 2));
}

/// hash_tree_root of a `ProgressiveList` whose elements are not packed
/// (each element contributes one node): mix_in_length over the progressive root.
fn progressiveListRoot(roots: []const [32]u8) [32]u8 {
    return mixInLength(progressiveRoot(roots), roots.len);
}

/// hash_tree_root of a `ProgressiveByteList` — bytes packed into 32-byte chunks,
/// then mix_in_length with the *byte* length.
fn htProgressiveByteList(alloc: std.mem.Allocator, data: []const u8) ![32]u8 {
    if (data.len == 0) return mixInLength(ZERO_HASHES[0], 0);
    const nchunks = (data.len + 31) / 32;
    const chunks = try alloc.alloc([32]u8, nchunks);
    defer alloc.free(chunks);
    for (0..nchunks) |i| {
        chunks[i] = [_]u8{0} ** 32;
        const start = i * 32;
        const end = @min(start + 32, data.len);
        @memcpy(chunks[i][0 .. end - start], data[start..end]);
    }
    return mixInLength(progressiveRoot(chunks), data.len);
}

/// hash_tree_root of `Bitvector[256]` holding `n` leading 1 bits — the
/// active_fields mix-in of a `ProgressiveContainer`. One chunk, so the packed
/// bits *are* the root.
fn activeFields(comptime n: u8) [32]u8 {
    return comptime blk: {
        var b: [32]u8 = .{0} ** 32;
        for (0..n) |i| b[i / 8] |= @as(u8, 1) << @intCast(i % 8);
        break :blk b;
    };
}

/// hash_tree_root of a `ProgressiveContainer`: progressive root of the field
/// nodes, paired with the active_fields bitvector.
fn progressiveContainerRoot(fields: []const [32]u8, comptime n_active: u8) [32]u8 {
    return sha2(progressiveRoot(fields), activeFields(n_active));
}

// ── Primitive hash_tree_root helpers ─────────────────────────────────────────

fn htU64(v: u64) [32]u8 {
    var out: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u64, out[0..8], v, .little);
    return out;
}

/// uint256 stored as u64 (high bytes are zero) — same encoding as htU64.
fn htU256AsU64(v: u64) [32]u8 {
    return htU64(v);
}

fn htBytes32(b: [32]u8) [32]u8 {
    return b;
}

fn htBytes20(b: [20]u8) [32]u8 {
    var out: [32]u8 = [_]u8{0} ** 32;
    @memcpy(out[0..20], &b);
    return out;
}

/// ByteVector[256]: merkleize 8 chunks of 32 bytes.
fn htBytes256(b: [256]u8) [32]u8 {
    var chunks: [8][32]u8 = undefined;
    for (0..8) |i| @memcpy(&chunks[i], b[i * 32 ..][0..32]);
    return merkleizeExact(&chunks);
}

/// ByteList[32]: max 32 bytes → 1 chunk limit.
fn htByteList32(data: []const u8) [32]u8 {
    var chunk: [32]u8 = [_]u8{0} ** 32;
    const n = @min(data.len, 32);
    @memcpy(chunk[0..n], data[0..n]);
    // merkleize([chunk], limit=1) = chunk (single chunk, no reduction needed)
    return mixInLength(chunk, data.len);
}

// ── SszWithdrawal hash_tree_root ──────────────────────────────────────────────

fn htWithdrawal(w: input.Withdrawal) [32]u8 {
    // SszWithdrawal: 4 fields → merkleize 4 chunks (power of 2, no padding)
    //   index: uint64, validator_index: uint64, address: ByteVector[20], amount: uint64
    const chunks: [4][32]u8 = .{
        htU64(w.index),
        htU64(w.validator_index),
        htBytes20(w.address),
        htU64(w.amount),
    };
    return merkleizeExact(&chunks);
}

// ── SszExecutionPayload hash_tree_root ────────────────────────────────────────

fn htExecutionPayload(alloc: std.mem.Allocator, ep: input.ExecutionPayload) !([32]u8) {
    // ProgressiveContainer(active_fields=[1] * 19).
    var chunks: [19][32]u8 = undefined;

    // f0..f5: simple fixed fields
    chunks[0] = htBytes32(ep.parent_hash);
    chunks[1] = htBytes20(ep.fee_recipient);
    chunks[2] = htBytes32(ep.state_root);
    chunks[3] = htBytes32(ep.receipts_root);
    chunks[4] = htBytes256(ep.logs_bloom);
    chunks[5] = htBytes32(ep.prev_randao);

    // f6..f9: uint64 fields
    chunks[6] = htU64(ep.block_number);
    chunks[7] = htU64(ep.gas_limit);
    chunks[8] = htU64(ep.gas_used);
    chunks[9] = htU64(ep.timestamp);

    // f10: extra_data: ByteList[32]
    chunks[10] = htByteList32(ep.extra_data);

    // f11: base_fee_per_gas: uint256 (stored as u64, high bytes = 0)
    chunks[11] = htU256AsU64(ep.base_fee_per_gas);

    // f12: block_hash: Bytes32
    chunks[12] = htBytes32(ep.block_hash);

    // f13: transactions: ProgressiveList[ProgressiveByteList]
    chunks[13] = try htTransactionList(alloc, ep.raw_transactions);

    // f14: withdrawals: ProgressiveList[SszWithdrawal]
    chunks[14] = try htWithdrawalList(alloc, ep.withdrawals);

    // f15..f16: blob gas fields
    chunks[15] = htU64(ep.blob_gas_used);
    chunks[16] = htU64(ep.excess_blob_gas);

    // f17..f18: block_access_list: ProgressiveByteList, slot_number: uint64
    chunks[17] = try htProgressiveByteList(alloc, ep.block_access_list);
    chunks[18] = htU64(ep.slot_number orelse 0);

    return progressiveContainerRoot(&chunks, 19);
}

fn htTransactionList(alloc: std.mem.Allocator, raw_txs: []const []const u8) !([32]u8) {
    if (raw_txs.len == 0) return progressiveListRoot(&.{});

    const tx_roots = try alloc.alloc([32]u8, raw_txs.len);
    defer alloc.free(tx_roots);
    for (raw_txs, 0..) |tx, i| tx_roots[i] = try htProgressiveByteList(alloc, tx);

    return progressiveListRoot(tx_roots);
}

fn htWithdrawalList(alloc: std.mem.Allocator, withdrawals: []const input.Withdrawal) !([32]u8) {
    if (withdrawals.len == 0) return progressiveListRoot(&.{});

    const roots = try alloc.alloc([32]u8, withdrawals.len);
    defer alloc.free(roots);
    for (withdrawals, 0..) |w, i| roots[i] = htWithdrawal(w);

    return progressiveListRoot(roots);
}

// ── SszNewPayloadRequest hash_tree_root ───────────────────────────────────────

/// hash_tree_root for ProgressiveList[Bytes32] (versioned_hashes).
/// Bytes32 is a ByteVector, not a basic type, so elements are unpacked —
/// each hash is already exactly one chunk.
fn htVersionedHashes(hashes: []const [32]u8) [32]u8 {
    return progressiveListRoot(hashes);
}

// ── SszExecutionRequests hash_tree_root ──────────────────────────────────────
//
// SszExecutionRequests is a ProgressiveContainer(active_fields=[1] * 5) whose
// fields are all ProgressiveLists — so no per-list capacity enters the root:
//   deposits, withdrawals, consolidations, builder_deposits, builder_exits
//
// Fixed item sizes:
//   SszDepositRequest:       pubkey(48)+withdrawal_creds(32)+amount(8)+signature(96)+index(8) = 192
//   SszWithdrawalRequest:    source_address(20)+validator_pubkey(48)+amount(8) = 76
//   SszConsolidationRequest: source_address(20)+source_pubkey(48)+target_pubkey(48) = 116
//   SszBuilderDepositRequest:pubkey(48)+withdrawal_creds(32)+amount(8)+signature(96) = 184
//   SszBuilderExitRequest:   source_address(20)+pubkey(48) = 68

/// ByteVector[48]: 2 chunks — sha2(bytes[0..32], bytes[32..48] || 0*16).
fn htBytes48(b: *const [48]u8) [32]u8 {
    var c1: [32]u8 = [_]u8{0} ** 32;
    @memcpy(c1[0..16], b[32..48]);
    return sha2(b[0..32].*, c1);
}

/// ByteVector[96]: 3 chunks → merkleize(c0, c1, c2, 0).
fn htBytes96(b: *const [96]u8) [32]u8 {
    return sha2(sha2(b[0..32].*, b[32..64].*), sha2(b[64..96].*, [_]u8{0} ** 32));
}

fn htDepositRequest(bytes: *const [192]u8) [32]u8 {
    // 5 fields → pad to 8 chunks
    const chunks: [8][32]u8 = .{
        htBytes48(bytes[0..48]),
        bytes[48..80].*,
        htU64(std.mem.readInt(u64, bytes[80..88], .little)),
        htBytes96(bytes[88..184]),
        htU64(std.mem.readInt(u64, bytes[184..192], .little)),
        [_]u8{0} ** 32,
        [_]u8{0} ** 32,
        [_]u8{0} ** 32,
    };
    return merkleizeExact(&chunks);
}

fn htWithdrawalRequest(bytes: *const [76]u8) [32]u8 {
    // 3 fields → pad to 4 chunks
    const chunks: [4][32]u8 = .{
        htBytes20(bytes[0..20].*),
        htBytes48(bytes[20..68]),
        htU64(std.mem.readInt(u64, bytes[68..76], .little)),
        [_]u8{0} ** 32,
    };
    return merkleizeExact(&chunks);
}

fn htConsolidationRequest(bytes: *const [116]u8) [32]u8 {
    // 3 fields → pad to 4 chunks
    const chunks: [4][32]u8 = .{
        htBytes20(bytes[0..20].*),
        htBytes48(bytes[20..68]),
        htBytes48(bytes[68..116]),
        [_]u8{0} ** 32,
    };
    return merkleizeExact(&chunks);
}

fn htBuilderDepositRequest(bytes: *const [184]u8) [32]u8 {
    // 4 fields → 4 chunks (pubkey, withdrawal_credentials, amount, signature)
    const chunks: [4][32]u8 = .{
        htBytes48(bytes[0..48]),
        bytes[48..80].*,
        htU64(std.mem.readInt(u64, bytes[80..88], .little)),
        htBytes96(bytes[88..184]),
    };
    return merkleizeExact(&chunks);
}

fn htBuilderExitRequest(bytes: *const [68]u8) [32]u8 {
    // 2 fields → 2 chunks (source_address, pubkey)
    const chunks: [2][32]u8 = .{
        htBytes20(bytes[0..20].*),
        htBytes48(bytes[20..68]),
    };
    return merkleizeExact(&chunks);
}

/// hash_tree_root of a ProgressiveList over the flat, packed request bytes of
/// one request type. `itemRoot` hashes a single fixed-size request.
fn htRequestList(
    alloc: std.mem.Allocator,
    data: []const u8,
    comptime SIZE: usize,
    comptime itemRoot: fn (*const [SIZE]u8) [32]u8,
) ![32]u8 {
    if (data.len == 0) return progressiveListRoot(&.{});
    if (data.len % SIZE != 0) return error.InvalidSsz;
    const n = data.len / SIZE;
    const roots = try alloc.alloc([32]u8, n);
    defer alloc.free(roots);
    for (0..n) |i| roots[i] = itemRoot(data[i * SIZE ..][0..SIZE]);
    return progressiveListRoot(roots);
}

/// hash_tree_root for the SszExecutionRequests ProgressiveContainer.
fn htExecutionRequests(alloc: std.mem.Allocator, er: input.ExecutionRequests) ![32]u8 {
    const chunks: [5][32]u8 = .{
        try htRequestList(alloc, er.deposits, 192, htDepositRequest),
        try htRequestList(alloc, er.withdrawals, 76, htWithdrawalRequest),
        try htRequestList(alloc, er.consolidations, 116, htConsolidationRequest),
        try htRequestList(alloc, er.builder_deposits, 184, htBuilderDepositRequest),
        try htRequestList(alloc, er.builder_exits, 68, htBuilderExitRequest),
    };
    return progressiveContainerRoot(&chunks, 5);
}

/// Compute the SSZ hash_tree_root of SszNewPayloadRequest.
/// This is the `new_payload_request_root` field in the output.
///
/// SszNewPayloadRequest is a plain Container with 4 fields (already power of 2):
///   execution_payload:        SszExecutionPayload
///   versioned_hashes:         ProgressiveList[Bytes32]
///   parent_beacon_block_root: Bytes32
///   execution_requests:       SszExecutionRequests
pub fn newPayloadRequestRoot(
    alloc: std.mem.Allocator,
    req: input.NewPayloadRequest,
) ![32]u8 {
    const h0 = try htExecutionPayload(alloc, req.execution_payload);
    const h1 = htVersionedHashes(req.versioned_hashes);
    const h2 = htBytes32(req.parent_beacon_block_root);
    const h3 = try htExecutionRequests(alloc, req.execution_requests);

    // merkleize([h0, h1, h2, h3]): 4 chunks, power of 2
    return sha2(sha2(h0, h1), sha2(h2, h3));
}

// ── Serialize output ──────────────────────────────────────────────────────────

/// Serialized size of SszStatelessValidationResult: 32 + 1 + 8 + 2.
pub const OUTPUT_SIZE: usize = 43;

/// EIP-8025: canonical "default failed" stateless output, emitted when the SSZ
/// input cannot be decoded (reference stateless_guest `_default_failed_stateless_output`):
/// root=0, successful_validation=false, chain_id=0, schema_id=0 — i.e. all zeroes.
/// The guest must commit exactly these bytes for a rejected input to match the
/// reference output.
pub const DEFAULT_FAILED_OUTPUT: [OUTPUT_SIZE]u8 = .{0} ** OUTPUT_SIZE;

/// Serialize SszStatelessValidationResult (glamsterdam-devnet-8 / zkevm@v0.8.0):
///   [0..32]  new_payload_request_root  Bytes32
///   [32]     successful_validation     boolean (0x01 = valid, 0x00 = invalid)
///   [33..41] chain_id                  uint64
///   [41..43] schema_id                 uint16
pub fn serialize(
    alloc: std.mem.Allocator,
    chain_config: input.ChainConfig,
    req: input.NewPayloadRequest,
    successful_validation: bool,
) ![OUTPUT_SIZE]u8 {
    const root = try newPayloadRequestRoot(alloc, req);
    var out: [OUTPUT_SIZE]u8 = undefined;
    @memcpy(out[0..32], &root);
    out[32] = if (successful_validation) 0x01 else 0x00;
    std.mem.writeInt(u64, out[33..41], chain_config.chain_id, .little);
    std.mem.writeInt(u16, out[41..43], chain_config.schema_id, .little);
    return out;
}
