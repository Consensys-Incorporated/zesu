//! Input loaders for zevm_stateless: SSZ (zkVM stream / file).

const std = @import("std");
const input_mod = @import("input");
const ssz = @import("ssz_decode");
const zkvm_io = @import("zkvm_io");

/// SSZ from zkvm_io.read_input().
pub fn fromSszStream(allocator: std.mem.Allocator) !input_mod.StatelessInput {
    var buf_ptr: [*]const u8 = undefined;
    var buf_size: usize = 0;
    zkvm_io.read_input(&buf_ptr, &buf_size);
    const data = buf_ptr[0..buf_size];
    return ssz.decode(allocator, data);
}

/// SSZ from a binary file.
pub fn fromSszFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !input_mod.StatelessInput {
    const data = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 30));
    return ssz.decode(allocator, data);
}
