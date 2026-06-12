/// Ethereum 2048-bit (256-byte) Bloom filter.
///
/// Algorithm: for each input byte sequence, compute keccak256, then take
/// 3 pairs of bytes (bytes 0-1, 2-3, 4-5) and interpret each pair as a
/// big-endian 11-bit index into the 2048-bit field.
const std = @import("std");
const accel = @import("accelerators");

pub const Bloom = [256]u8;
pub const ZERO: Bloom = [_]u8{0} ** 256;

/// Add a byte sequence to the bloom filter.
pub fn add(bloom: *Bloom, data: []const u8) void {
    var hash: [32]u8 = undefined;
    accel.keccak256(data, &hash);

    inline for (0..3) |i| {
        // Ethereum uses big-endian 11-bit indexing: high byte first (matches geth)
        const hi: u16 = hash[2 * i];
        const lo: u16 = hash[2 * i + 1];
        const bit_idx: u11 = @intCast(((hi << 8) | lo) & 0x7FF);
        // Bit numbering: bit 0 of the filter is the MSB of byte 255
        bloom[255 - bit_idx / 8] |= @as(u8, 1) << @intCast(bit_idx % 8);
    }
}

/// Add all log data for a single log entry (address + all topics).
pub fn addLog(bloom: *Bloom, address: [20]u8, topics: []const [32]u8) void {
    add(bloom, &address);
    for (topics) |topic| add(bloom, &topic);
}

/// OR two bloom filters together in place. src passed by pointer to avoid 256-byte copy.
pub fn merge(dst: *Bloom, src: *const Bloom) void {
    const d64: *[32]u64 = @ptrCast(@alignCast(dst));
    const s64: *const [32]u64 = @ptrCast(@alignCast(src));
    for (d64, s64) |*d, s| d.* |= s;
}
