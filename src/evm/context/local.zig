const std = @import("std");
const alloc_mod = @import("zesu_allocator");

/// Local context that is filled by execution.
pub const LocalContext = struct {
    /// Interpreter shared memory buffer. A reused memory buffer for calls.
    shared_memory_buffer: ?std.ArrayList(u8),
    /// Optional precompile error message to bubble up.
    precompile_error_message: ?[]const u8,

    pub fn default() LocalContext {
        return .{
            .shared_memory_buffer = null,
            .precompile_error_message = null,
        };
    }

    pub fn deinit(self: *LocalContext) void {
        self.shared_memory_buffer.deinit();
        if (self.precompile_error_message) |msg| {
            alloc_mod.get().free(msg);
        }
    }

    pub fn new() LocalContext {
        return LocalContext.default();
    }

    pub fn clear(self: *LocalContext) void {
        // Sets len to 0 but it will not shrink to drop the capacity.
        if (self.shared_memory_buffer) |*buffer| {
            buffer.clearRetainingCapacity();
        }
        if (self.precompile_error_message) |msg| {
            alloc_mod.get().free(msg);
        }
        self.precompile_error_message = null;
    }

    pub fn sharedMemoryBuffer(self: LocalContext) []const u8 {
        return if (self.shared_memory_buffer) |buffer| buffer.items else &[_]u8{};
    }

    pub fn setPrecompileErrorContext(self: *LocalContext, output: []const u8) !void {
        if (self.precompile_error_message) |msg| {
            alloc_mod.get().free(msg);
        }
        self.precompile_error_message = try alloc_mod.get().dupe(u8, output);
    }

    pub fn takePrecompileErrorContext(self: *LocalContext) ?[]const u8 {
        const result = self.precompile_error_message;
        self.precompile_error_message = null;
        return result;
    }
};
