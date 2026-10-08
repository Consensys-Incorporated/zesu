const std = @import("std");
const primitives = @import("primitives");
const context = @import("context");
const interpreter = @import("interpreter");
const precompile = @import("precompile");
const database = @import("database");
const alloc_mod = @import("zesu_allocator");

// Import handler modules
const mainnet_builder = @import("mainnet_builder.zig");
const validation = @import("validation.zig");

// Re-export main components
pub const MainnetEvm = mainnet_builder.MainnetEvm;
pub const MainnetContext = mainnet_builder.MainnetContext;
pub const MainBuilder = mainnet_builder.MainBuilder;
pub const MainContext = mainnet_builder.MainContext;
pub const MainnetHandler = mainnet_builder.MainnetHandler;
pub const ExecuteEvm = mainnet_builder.ExecuteEvm;
pub const ExecuteCommitEvm = mainnet_builder.ExecuteCommitEvm;

// Re-export validation components
pub const Validation = validation.Validation;
pub const InitialAndFloorGas = validation.InitialAndFloorGas;
pub const ValidationError = validation.ValidationError;

/// EVM execution result
pub const ExecutionResult = struct {
    /// Execution status
    status: ExecutionStatus,
    /// Gas used for receipt cumulativeGasUsed (= regular + state for Amsterdam+).
    gas_used: u64,
    /// EIP-8037 (Amsterdam+): the block's execution-gas lane (pre-refund, floored).
    /// Equals gas_used for pre-Amsterdam.
    block_gas_used: u64,
    /// EIP-8037 (Amsterdam+): the block's state-gas lane — net state gas consumed, floored at 0.
    state_gas_used: u64,
    /// Gas refunded (final capped refund, set in postExecution)
    gas_refunded: u64,
    /// Logs emitted during execution
    logs: std.ArrayList(primitives.Log),
    /// Return data (heap-allocated copy; freed in deinit)
    return_data: []u8,
    /// Halt reason if execution halted
    halt_reason: ?HaltReason,

    /// Create new execution result
    pub fn new(status: ExecutionStatus, gas_used: u64) ExecutionResult {
        return ExecutionResult{
            .status = status,
            .gas_used = gas_used,
            .block_gas_used = gas_used,
            .state_gas_used = 0,
            .gas_refunded = 0,
            .logs = std.ArrayList(primitives.Log).empty,
            .return_data = @constCast(&[_]u8{}),
            .halt_reason = null,
        };
    }

    /// Deinitialize execution result
    pub fn deinit(self: *ExecutionResult) void {
        for (self.logs.items) |log| log.deinit(alloc_mod.get());
        self.logs.deinit(alloc_mod.get());
        // Free heap-allocated return data copy (len==0 means static empty slice, skip).
        if (self.return_data.len > 0) {
            alloc_mod.get().free(self.return_data);
        }
    }
};

/// Execution status
pub const ExecutionStatus = enum {
    /// Execution succeeded
    Success,
    /// Execution reverted
    Revert,
    /// Execution halted
    Halt,
    /// Execution failed
    Fail,
};

/// Halt reason
pub const HaltReason = enum {
    /// Out of gas
    OutOfGas,
    /// Invalid opcode
    InvalidOpcode,
    /// Stack overflow
    StackOverflow,
    /// Stack underflow
    StackUnderflow,
    /// Invalid jump destination
    InvalidJump,
    /// Invalid memory access
    InvalidMemoryAccess,
    /// Call depth exceeded
    CallDepthExceeded,
    /// Precompile error
    PrecompileError,
    /// Other error
    Other,
};

/// Log entry
pub const Log = struct {
    /// Address that emitted the log
    address: primitives.Address,
    /// Topics
    topics: std.ArrayList(primitives.Hash),
    /// Data
    data: []const u8,

    /// Create new log entry
    pub fn new(address: primitives.Address, topics: std.ArrayList(primitives.Hash), data: []const u8) Log {
        return Log{
            .address = address,
            .topics = topics,
            .data = data,
        };
    }

    /// Deinitialize log entry
    pub fn deinit(self: *Log) void {
        self.topics.deinit();
    }
};

/// Frame result
pub const FrameResult = struct {
    /// Execution result
    result: ExecutionResult,
    /// Gas remaining
    gas_remaining: u64,
    /// Raw refund counter from interpreter (before capping)
    gas_refunded: i64,
    /// EIP-8037 (Amsterdam+): state gas reservoir remaining after execution.
    /// Used in gasUsed formula: gas_used = tx.gas_limit - gas_remaining - reservoir_remaining.
    reservoir_remaining: u64,
    /// EIP-8037 (Amsterdam+): state gas the transaction drew from regular gas and still owes
    /// (reference `state_gas_spilled` + `state_gas_committed_spill` of the top frame).
    state_gas_spilled: u64 = 0,
    /// Memory
    memory: interpreter.Memory,

    /// Create new frame result
    pub fn new(result: ExecutionResult, gas_remaining: u64, gas_refunded: i64) FrameResult {
        return FrameResult{
            .result = result,
            .gas_remaining = gas_remaining,
            .gas_refunded = gas_refunded,
            .reservoir_remaining = 0,
            .memory = interpreter.Memory.new(),
        };
    }

    /// Deinitialize frame result
    pub fn deinit(self: *FrameResult) void {
        self.result.deinit();
        self.memory.deinit();
    }
};

/// Generic EVM parametrised over a DB type.
/// `Evm = EvmFor(database.InMemoryDB)` is the default used throughout zevm.
/// External users (zevm-stateless) can instantiate EvmFor(their_db) directly.
pub fn EvmFor(comptime DB: type) type {
    return struct {
        ctx: *context.Context(DB),
        inspector: ?*Inspector,
        instructions: *Instructions,
        precompiles: *Precompiles,

        pub fn init(
            ctx: *context.Context(DB),
            inspector: ?*Inspector,
            instructions: *Instructions,
            precompiles: *Precompiles,
        ) @This() {
            return .{
                .ctx = ctx,
                .inspector = inspector,
                .instructions = instructions,
                .precompiles = precompiles,
            };
        }

        pub fn getContext(self: *@This()) *context.Context(DB) {
            return self.ctx;
        }
    };
}

/// Default EVM for InMemoryDB — drop-in for all existing zevm code.
pub const Evm = EvmFor(database.InMemoryDB);

/// Instructions provider for EVM execution
pub const Instructions = struct {
    /// Instruction table for the configured spec
    table: interpreter.protocol_schedule.InstructionTable,
    /// Hardfork specification
    spec: primitives.SpecId,

    /// Create instructions provider for a specific hardfork spec
    pub fn new(spec: primitives.SpecId) Instructions {
        return Instructions{
            .table = interpreter.protocol_schedule.makeInstructionTable(spec),
            .spec = spec,
        };
    }

    /// Get instruction entry for an opcode
    pub fn getInstruction(self: *const Instructions, opcode: u8) interpreter.protocol_schedule.InstructionEntry {
        return self.table[opcode];
    }

    /// Get static gas cost for an opcode
    pub fn getStaticGas(self: *const Instructions, opcode: u8) u64 {
        return self.table[opcode].static_gas;
    }
};

/// Precompiles implementation
pub const Precompiles = struct {
    /// Precompiles collection
    precompiles: precompile.Precompiles,
    /// Hardfork specification
    spec: primitives.SpecId,

    /// Create precompiles provider for a specific hardfork spec
    pub fn new(spec: primitives.SpecId) Precompiles {
        // Map full SpecId to PrecompileSpecId (groups similar specs)
        const precompile_spec = precompile.PrecompileSpecId.fromSpec(spec);
        return Precompiles{
            .precompiles = precompile.Precompiles.forSpec(precompile_spec),
            .spec = spec,
        };
    }

    /// Get precompile by address
    pub fn get(self: *Precompiles, address: primitives.Address) ?precompile.Precompile {
        return self.precompiles.get(address);
    }
};

/// Inspector for execution monitoring
pub const Inspector = struct {
    /// Inspect before execution
    pub fn inspectBefore(self: *Inspector, evm: *Evm) !void {
        _ = self;
        _ = evm;
    }

    /// Inspect after execution
    pub fn inspectAfter(self: *Inspector, evm: *Evm, result: *FrameResult) !void {
        _ = self;
        _ = evm;
        _ = result;
    }
};

// Placeholder for testing
pub const testing = struct {
    pub fn testHandler() !void {
        std.log.info("Testing handler module...", .{});

        // Test basic handler components
        try testExecutionResult();

        // Test mainnet builder
        try mainnet_builder.testing.testMainnetBuilder();
        try mainnet_builder.testing.testMainnetHandler();

        std.log.info("Handler module test passed!", .{});
    }

    fn testExecutionResult() !void {
        var result = ExecutionResult.new(.Success, 1000);
        defer result.deinit();

        std.debug.assert(result.status == .Success);
        std.debug.assert(result.gas_used == 1000);
        std.debug.assert(result.logs.items.len == 0);
    }
};

// Pull in tests from submodules
test {
    _ = @import("validation.zig");
    _ = @import("validation_tests.zig");
    _ = @import("mainnet_builder.zig");
    _ = @import("postexecution_tests.zig");
}
