const std = @import("std");
const primitives = @import("primitives");
const bytecode = @import("bytecode");
const context = @import("context");
const alloc_mod = @import("zesu_allocator");
const gas_costs = @import("gas_costs.zig");
const opcodes = @import("opcodes/main.zig");
const Gas = @import("gas.zig").Gas;
const Stack = @import("stack.zig").Stack;
const stack_mod = @import("stack.zig");
const Memory = @import("memory.zig").Memory;
const InstructionResult = @import("instruction_result.zig").InstructionResult;
const InterpreterAction = @import("interpreter_action.zig").InterpreterAction;
const CallScheme = @import("interpreter_action.zig").CallScheme;
const CallInputs = @import("interpreter_action.zig").CallInputs;
const CreateInputs = @import("interpreter_action.zig").CreateInputs;
const HostCallInputs = @import("host.zig").CallInputs;
const JournalCheckpoint = @import("context").JournalCheckpoint;
// Lazy imports for dispatch types — pointer-only usage prevents circular dependency issues.
const InstructionContext = @import("instruction_context.zig").InstructionContext;
const Host = @import("host.zig").Host;
const host_mod = @import("host.zig");

/// Input data for current execution context
pub const InputsImpl = struct {
    /// Caller address
    caller: primitives.Address,
    /// Target address
    target: primitives.Address,
    /// Value
    value: primitives.U256,
    /// Data
    data: primitives.Bytes,
    /// Gas limit
    gas_limit: u64,
    /// Call scheme
    scheme: CallScheme,
    /// Is static call
    is_static: bool,
    /// Depth
    depth: usize,

    /// Create new inputs
    pub fn new(
        caller: primitives.Address,
        target: primitives.Address,
        value: primitives.U256,
        data: primitives.Bytes,
        gas_limit: u64,
        scheme: CallScheme,
        is_static: bool,
        depth: usize,
    ) InputsImpl {
        return InputsImpl{
            .caller = caller,
            .target = target,
            .value = value,
            .data = data,
            .gas_limit = gas_limit,
            .scheme = scheme,
            .is_static = is_static,
            .depth = depth,
        };
    }

    /// Create default inputs
    pub fn default() InputsImpl {
        return InputsImpl{
            .caller = [_]u8{0} ** 20,
            .target = [_]u8{0} ** 20,
            .value = 0,
            .data = @as(primitives.Bytes, @constCast(&[_]u8{})),
            .gas_limit = 0,
            .scheme = .call,
            .is_static = false,
            .depth = 0,
        };
    }

    pub fn getCaller(self: InputsImpl) primitives.Address {
        return self.caller;
    }

    pub fn getTarget(self: InputsImpl) primitives.Address {
        return self.target;
    }

    pub fn getValue(self: InputsImpl) primitives.U256 {
        return self.value;
    }

    pub fn getData(self: InputsImpl) primitives.Bytes {
        return self.data;
    }

    pub fn getGasLimit(self: InputsImpl) u64 {
        return self.gas_limit;
    }

    pub fn getScheme(self: InputsImpl) CallScheme {
        return self.scheme;
    }

    pub fn getIsStatic(self: InputsImpl) bool {
        return self.is_static;
    }

    pub fn getDepth(self: InputsImpl) usize {
        return self.depth;
    }
};

/// Return data buffer
pub const ReturnDataImpl = struct {
    data: primitives.Bytes,
    gas_used: u64,
    success: bool,

    pub fn new(data: primitives.Bytes, gas_used: u64, success: bool) ReturnDataImpl {
        return ReturnDataImpl{
            .data = data,
            .gas_used = gas_used,
            .success = success,
        };
    }

    pub fn default() ReturnDataImpl {
        return ReturnDataImpl{
            .data = &[_]u8{},
            .gas_used = 0,
            .success = false,
        };
    }

    pub fn getData(self: ReturnDataImpl) primitives.Bytes {
        return self.data;
    }

    pub fn getGasUsed(self: ReturnDataImpl) u64 {
        return self.gas_used;
    }

    pub fn getSuccess(self: ReturnDataImpl) bool {
        return self.success;
    }

    pub fn setData(self: *ReturnDataImpl, data: primitives.Bytes) void {
        self.data = data;
    }

    pub fn setGasUsed(self: *ReturnDataImpl, gas_used: u64) void {
        self.gas_used = gas_used;
    }

    pub fn setSuccess(self: *ReturnDataImpl, success: bool) void {
        self.success = success;
    }
};

/// Runtime flags controlling execution behavior
pub const RuntimeFlags = struct {
    is_static: bool,
    spec_id: primitives.SpecId,

    pub fn new(is_static: bool, spec_id: primitives.SpecId) RuntimeFlags {
        return RuntimeFlags{
            .is_static = is_static,
            .spec_id = spec_id,
        };
    }

    pub fn default() RuntimeFlags {
        return RuntimeFlags{
            .is_static = false,
            .spec_id = .prague,
        };
    }

    pub fn getIsStatic(self: RuntimeFlags) bool {
        return self.is_static;
    }

    pub fn getSpecId(self: RuntimeFlags) primitives.SpecId {
        return self.spec_id;
    }

    pub fn setIsStatic(self: *RuntimeFlags, is_static: bool) void {
        self.is_static = is_static;
    }

    pub fn setSpecId(self: *RuntimeFlags, spec_id: primitives.SpecId) void {
        self.spec_id = spec_id;
    }
};

/// Extended bytecode functionality
pub const ExtBytecode = struct {
    inner: bytecode.Bytecode,
    pc: usize,
    /// Whether execution is still running (false after halt/stop/return)
    continue_execution: bool,
    /// If true, deinit() will free the bytecode's heap allocations.
    /// CALL frames share bytecode with account state (DB) and must NOT free it.
    /// CREATE init-code frames and test frames own their bytecode.
    owns_bytecode: bool,

    /// Borrow semantics: bytecode is shared with account state, will NOT be freed on deinit.
    pub fn new(bytecode_data: bytecode.Bytecode) ExtBytecode {
        return ExtBytecode{
            .inner = bytecode_data,
            .pc = 0,
            .continue_execution = true,
            .owns_bytecode = false,
        };
    }

    /// Ownership semantics: bytecode is owned by this frame and freed on deinit.
    /// Use for CREATE init-code frames and test frames with locally-created bytecodes.
    pub fn newOwned(bytecode_data: bytecode.Bytecode) ExtBytecode {
        return ExtBytecode{
            .inner = bytecode_data,
            .pc = 0,
            .continue_execution = true,
            .owns_bytecode = true,
        };
    }

    pub fn default() ExtBytecode {
        return ExtBytecode{
            .inner = bytecode.Bytecode.new(),
            .pc = 0,
            .continue_execution = true,
            .owns_bytecode = false,
        };
    }

    pub fn deinit(self: *ExtBytecode) void {
        if (self.owns_bytecode) {
            self.inner.deinit();
        }
    }

    /// Read current opcode byte (returns 0x00/STOP if past end)
    pub fn opcode(self: *const ExtBytecode) u8 {
        const b = self.inner.bytes();
        if (self.pc >= b.len) return 0x00;
        return b[self.pc];
    }

    /// Advance PC by delta bytes
    pub fn relativeJump(self: *ExtBytecode, delta: usize) void {
        self.pc += delta;
    }

    /// Set PC to absolute destination
    pub fn absoluteJump(self: *ExtBytecode, dest: usize) void {
        self.pc = dest;
    }

    /// Check if jump destination is a valid JUMPDEST
    pub fn isValidJump(self: *const ExtBytecode, dest: usize) bool {
        return self.inner.isValidJump(dest);
    }

    /// Read a single immediate byte at current PC (returns 0 if past end of code)
    pub fn readImmediate(self: *const ExtBytecode) u8 {
        const b = self.inner.bytes();
        if (self.pc >= b.len) return 0;
        return b[self.pc];
    }

    pub fn isNotEnd(self: *const ExtBytecode) bool {
        return self.continue_execution;
    }

    pub fn getBytecode(self: ExtBytecode) bytecode.Bytecode {
        return self.inner;
    }

    pub fn setBytecode(self: *ExtBytecode, bytecode_data: bytecode.Bytecode) void {
        self.inner = bytecode_data;
    }

    pub fn bytes(self: *const ExtBytecode) []const u8 {
        return self.inner.bytes();
    }
};

// ---------------------------------------------------------------------------
// Dispatch table types
// ---------------------------------------------------------------------------

/// Function pointer type for opcode handlers (re-exported from instruction_context.zig).
pub const InstructionFn = @import("instruction_context.zig").InstructionFn;

/// One entry in the dispatch table: a handler function and its static gas cost.
pub const InstructionEntry = struct {
    func: InstructionFn,
    static_gas: u64,

    pub fn unknown() InstructionEntry {
        return .{ .func = opUnknown, .static_gas = 0 };
    }
};

/// 256-entry dispatch table indexed by opcode byte.
pub const InstructionTable = [256]InstructionEntry;

/// Handler for unknown/disabled opcodes.
fn opUnknown(ctx: *InstructionContext) void {
    ctx.interpreter.halt(.invalid_opcode);
}

// ---------------------------------------------------------------------------
// Pending sub-call suspension types
// ---------------------------------------------------------------------------

/// Data stored when a CALL/CALLCODE/DELEGATECALL/STATICCALL suspends the interpreter.
pub const PendingCallData = struct {
    inputs: HostCallInputs,
    code: bytecode.Bytecode,
    checkpoint: JournalCheckpoint,
    ret_off: usize,
    ret_size: usize,
    /// EIP-8037 (Amsterdam+): state gas charged for a new account created by a
    /// value-bearing CALL. Refunded to the parent reservoir if the call fails
    /// (the account is not created), matching credit_state_gas_refund(NEW_ACCOUNT).
    new_account_state_gas: u64 = 0,
};

/// Data stored when a CREATE/CREATE2 suspends the interpreter.
pub const PendingCreateData = struct {
    inputs: CreateInputs,
    new_addr: primitives.Address,
    checkpoint: JournalCheckpoint,
    /// EIP-8037 (Amsterdam+): state gas charged for new account creation.
    /// On child CREATE halt/invalid, this is returned to the parent's reservoir.
    new_account_state_gas: u64 = 0,
    /// EIP-8037 (Amsterdam+): the CREATE target address was already alive (pre-funded
    /// balance) before creation. On success the NEW_ACCOUNT state gas is refunded,
    /// mirroring the reference `credit_state_gas_refund` when `target_alive`.
    target_alive: bool = false,
};

/// Pending sub-call state: set by CALL/CREATE opcodes, cleared by frame runner.
pub const PendingSubCall = union(enum) {
    none,
    call: PendingCallData,
    create: PendingCreateData,
};

// ---------------------------------------------------------------------------
// Main interpreter
// ---------------------------------------------------------------------------

/// Main interpreter structure that contains all components
pub const Interpreter = struct {
    bytecode: ExtBytecode,
    gas: Gas,
    stack: Stack,
    return_data: ReturnDataImpl,
    memory: Memory,
    input: InputsImpl,
    runtime_flags: RuntimeFlags,
    /// Execution result (set by halt())
    result: InstructionResult,
    extend: void,
    last_opcode: ?u8 = null,
    /// Pending sub-call: set by CALL/CREATE opcodes, cleared by frame runner.
    pending: PendingSubCall = .none,

    pub fn new(
        memory: Memory,
        bytecode_data: ExtBytecode,
        input: InputsImpl,
        is_static: bool,
        spec_id: primitives.SpecId,
        gas_limit: u64,
    ) Interpreter {
        return Interpreter{
            .bytecode = bytecode_data,
            .gas = Gas.new(gas_limit),
            .stack = Stack.new(),
            .return_data = ReturnDataImpl.default(),
            .memory = memory,
            .input = input,
            .runtime_flags = RuntimeFlags.new(is_static, spec_id),
            .result = .stop,
            .extend = {},
        };
    }

    pub fn defaultExt() Interpreter {
        return Interpreter.new(
            Memory.new(),
            ExtBytecode.default(),
            InputsImpl.default(),
            false,
            .prague,
            std.math.maxInt(u64),
        );
    }

    pub fn invalid() Interpreter {
        return Interpreter.new(
            Memory.new(),
            ExtBytecode.default(),
            InputsImpl.default(),
            false,
            .prague,
            0,
        );
    }

    /// Push a word the caller already has in hand (the code length, the pc, a data length),
    /// halting on stack overflow. Shared by the opcode handlers and runDispatch's inlined
    /// arms so the two paths cannot drift apart.
    pub inline fn pushWord(self: *Interpreter, v: usize) void {
        if (!self.stack.hasSpace(1)) {
            self.halt(.stack_overflow);
            return;
        }
        self.stack.pushUnsafe(@intCast(v));
    }

    /// Halt execution with the given result
    pub fn halt(self: *Interpreter, r: InstructionResult) void {
        self.bytecode.continue_execution = false;
        self.result = r;
        // EVM spec: all remaining gas is consumed on any error (OOG, invalid opcode, etc.).
        // Revert and success are NOT errors — they preserve remaining gas for refund/return.
        if (r.isError()) {
            self.gas.remaining = 0;
        }
    }

    pub fn deinit(self: *Interpreter) void {
        self.stack.deinit();
        self.bytecode.deinit();
        self.memory.deinit();
    }

    pub fn clear(
        self: *Interpreter,
        memory: Memory,
        bytecode_data: ExtBytecode,
        input: InputsImpl,
        is_static: bool,
        spec_id: primitives.SpecId,
        gas_limit: u64,
    ) void {
        self.bytecode = bytecode_data;
        self.gas = Gas.new(gas_limit);
        self.stack.clear();
        self.return_data = ReturnDataImpl.default();
        self.memory = memory;
        self.input = input;
        self.runtime_flags = RuntimeFlags.new(is_static, spec_id);
        self.result = .stop;
        self.extend = {};
        self.pending = .none;
    }

    // -----------------------------------------------------------------------
    // Dispatch methods
    // -----------------------------------------------------------------------

    /// Execute one opcode: read opcode at PC, advance PC, charge static gas, call handler.
    pub fn step(self: *Interpreter, table: *const InstructionTable) void {
        const op = self.bytecode.opcode();
        self.bytecode.relativeJump(1);
        const ins = table[op];
        if (!self.gas.spend(ins.static_gas)) {
            self.halt(.out_of_gas);
            return;
        }
        var ctx = InstructionContext{ .interpreter = self };
        ins.func(&ctx);
    }

    /// Run the interpreter until execution halts (no host).
    pub fn run(self: *Interpreter, table: *const InstructionTable) InstructionResult {
        var ctx = InstructionContext{ .interpreter = self };
        runDispatch(self, table, &ctx, false);
        return self.result;
    }

    /// Execute one opcode with a host for state access.
    pub fn stepWithHost(self: *Interpreter, table: *const InstructionTable, host: *Host) void {
        const op = self.bytecode.opcode();
        self.bytecode.relativeJump(1);
        const ins = table[op];
        if (!self.gas.spend(ins.static_gas)) {
            self.halt(.out_of_gas);
            return;
        }
        var ctx = InstructionContext{ .interpreter = self, .host = host };
        ins.func(&ctx);
    }

    /// Run the interpreter until execution halts or a sub-call is pending, with full host access.
    pub fn runWithHost(self: *Interpreter, table: *const InstructionTable, host: *Host) InstructionResult {
        var ctx = InstructionContext{ .interpreter = self, .host = host };
        runDispatch(self, table, &ctx, true);
        return self.result;
    }

    /// Reset this interpreter for a new frame without freeing the memory buffer.
    /// The memory buffer grows to its high-water mark and is reused across frames.
    pub fn clearReusingMemory(
        self: *Interpreter,
        bytecode_data: ExtBytecode,
        input: InputsImpl,
        is_static: bool,
        spec_id: primitives.SpecId,
        gas_limit: u64,
    ) void {
        self.memory.clear();
        self.clear(self.memory, bytecode_data, input, is_static, spec_id, gas_limit);
    }
};

// ---------------------------------------------------------------------------
// Labeled-switch computed-goto dispatch (Tier 1 hot path)
// ---------------------------------------------------------------------------
//
// Hot opcodes are inlined directly in switch cases — no per-opcode function
// call or InstructionContext construction. `continue :sw` compiles to a
// computed goto (single indirect branch). ctx is built once per runWithHost
// call and lives in registers across iterations.
//
// comptime check_pending=false (run):         pending check is folded away.
// comptime check_pending=true  (runWithHost): checks after every op.
//
// Cold opcodes fall to `else` which calls through InstructionTable as before.
//
// INVARIANT: only add opcodes here that are:
//   1. Valid since Frontier (no fork gate needed), AND
//   2. Behavior-stable across all forks (no semantic changes per EIP).
// Fork-*modified* opcodes (e.g. SELFDESTRUCT post-EIP-6780) must stay in the
// cold `else` path where the InstructionTable enforces the correct per-fork
// handler — a single flag cannot express "different handler per fork".
//
// A fork-*gated* opcode — one that is either the same handler or invalid, never
// a different handler — is admissible under a narrow exception: hoist the fork
// test out of the loop into a `const` below and guard the case with it, falling
// through to `else` when the gate is closed so the table still supplies
// opUnknown. This is sound because the spec is fixed for the lifetime of a
// frame. It is worth doing only for opcodes hot enough that a register-resident
// branch beats a table load plus an indirect call; SHL/SHR/SAR qualified on the
// Amsterdam benchmark tiers, where they measured 3,500-4,810 cost-per-gas
// against a median of 1,962 with ~80% of it in dispatch rather than the shift.
// PUSH0 and the rest stay cold.

/// Fetch the opcode at `pc` from an already-resolved code slice.
///
/// `ExtBytecode.opcode()` goes through `Bytecode.bytes()`, which switches on the
/// Bytecode union tag and reloads ptr/len from the payload — on every single opcode
/// fetch. The bytecode of a frame cannot change while its dispatch loop runs (CALL and
/// CREATE build new frames; JUMP only moves pc), so runDispatch resolves the slice once
/// and fetches through this instead.
///
/// `code` is the zero-padded `exec` copy: running off the end reads STOP, so the fetch
/// needs no bounds check.
inline fn opcodeAt(code: []const u8, pc: usize) u8 {
    return code[pc];
}

/// Interpreter state the dispatch loop keeps in registers. `self.gas.remaining`,
/// `self.stack.length` and `self.bytecode.pc` are STALE while an inlined arm runs:
/// anything that reads or writes them through `self`/`ctx` (every handler outside
/// the inlined arms) must be bracketed by `spill` and `reload`.
///
/// They were reloaded from memory on every opcode: a pushed word's four limb
/// stores may alias `stack.length` (Zig has no type-based alias analysis), and the
/// handlers reach the stack and gas through `ctx`, so LLVM could not keep either
/// in a register across an arm.
const Regs = struct {
    pc: usize,
    gas: u64,
    /// Stack length.
    sp: usize,
    /// Stack base; the backing store is fixed for the frame.
    sb: [*]primitives.U256,
};

inline fn spill(self: *Interpreter, r: *const Regs) void {
    self.bytecode.pc = r.pc;
    self.gas.remaining = r.gas;
    self.stack.length = r.sp;
}

inline fn reload(self: *Interpreter, r: *Regs) void {
    r.pc = self.bytecode.pc;
    r.gas = self.gas.remaining;
    r.sp = self.stack.length;
}

/// Halt from an inlined arm. Errors consume all gas, as `halt` does.
inline fn fail(self: *Interpreter, r: *Regs, res: InstructionResult) void {
    if (res.isError()) r.gas = 0;
    spill(self, r);
    self.halt(res);
}

/// Charge static gas; on out-of-gas halt and return false.
inline fn charge(self: *Interpreter, r: *Regs, cost: u64) bool {
    if (r.gas < cost) {
        fail(self, r, .out_of_gas);
        return false;
    }
    r.gas -= cost;
    return true;
}

/// Pop two, push f(top, second). Gas before the stack check, as the handlers did.
inline fn binop(self: *Interpreter, r: *Regs, comptime cost: u64, comptime f: fn (primitives.U256, primitives.U256) primitives.U256) bool {
    if (!charge(self, r, cost)) return false;
    if (r.sp < 2) {
        fail(self, r, .stack_underflow);
        return false;
    }
    const a = r.sb[r.sp - 1];
    const b = r.sb[r.sp - 2];
    r.sp -= 1;
    r.sb[r.sp - 1] = f(a, b);
    return true;
}

/// Replace the top with f(top).
inline fn unop(self: *Interpreter, r: *Regs, comptime cost: u64, comptime f: fn (primitives.U256) primitives.U256) bool {
    if (!charge(self, r, cost)) return false;
    if (r.sp < 1) {
        fail(self, r, .stack_underflow);
        return false;
    }
    r.sb[r.sp - 1] = f(r.sb[r.sp - 1]);
    return true;
}

/// Push `v` after charging `cost`.
inline fn pushReg(self: *Interpreter, r: *Regs, comptime cost: u64, v: primitives.U256) bool {
    if (!charge(self, r, cost)) return false;
    if (r.sp >= stack_mod.STACK_LIMIT) {
        fail(self, r, .stack_overflow);
        return false;
    }
    r.sb[r.sp] = v;
    r.sp += 1;
    return true;
}

/// Run a handler that goes through `self`/`ctx`. Returns false if it halted.
inline fn viaSelf(self: *Interpreter, r: *Regs, comptime cost: u64, comptime handler: anytype, args: anytype) bool {
    if (!charge(self, r, cost)) return false;
    spill(self, r);
    @call(.always_inline, handler, args);
    reload(self, r);
    return self.bytecode.isNotEnd();
}

const ops = struct {
    fn add(a: primitives.U256, b: primitives.U256) primitives.U256 {
        return a +% b;
    }
    fn sub(a: primitives.U256, b: primitives.U256) primitives.U256 {
        return a -% b;
    }
    fn mul(a: primitives.U256, b: primitives.U256) primitives.U256 {
        return a *% b;
    }
    fn lt(a: primitives.U256, b: primitives.U256) primitives.U256 {
        return @intFromBool(a < b);
    }
    fn gt(a: primitives.U256, b: primitives.U256) primitives.U256 {
        return @intFromBool(a > b);
    }
    fn eq(a: primitives.U256, b: primitives.U256) primitives.U256 {
        return @intFromBool(a == b);
    }
    fn band(a: primitives.U256, b: primitives.U256) primitives.U256 {
        return a & b;
    }
    fn bor(a: primitives.U256, b: primitives.U256) primitives.U256 {
        return a | b;
    }
    fn bxor(a: primitives.U256, b: primitives.U256) primitives.U256 {
        return a ^ b;
    }
    fn shl(shift: primitives.U256, value: primitives.U256) primitives.U256 {
        return if (shift < 256) value << @intCast(shift) else 0;
    }
    fn shr(shift: primitives.U256, value: primitives.U256) primitives.U256 {
        return if (shift < 256) value >> @intCast(shift) else 0;
    }
    fn slt(a: primitives.U256, b: primitives.U256) primitives.U256 {
        return @intFromBool(@as(i256, @bitCast(a)) < @as(i256, @bitCast(b)));
    }
    fn sgt(a: primitives.U256, b: primitives.U256) primitives.U256 {
        return @intFromBool(@as(i256, @bitCast(a)) > @as(i256, @bitCast(b)));
    }
    fn byte(i: primitives.U256, x: primitives.U256) primitives.U256 {
        return if (i < 32) (x >> @intCast((31 - i) * 8)) & 0xFF else 0;
    }
    fn iszero(a: primitives.U256) primitives.U256 {
        return @intFromBool(a == 0);
    }
    fn not(a: primitives.U256) primitives.U256 {
        return ~a;
    }
};

/// A 32-byte word at `offset` lies inside the current memory (no expansion needed).
inline fn inMemory(self: *Interpreter, offset: primitives.U256) bool {
    const size = self.memory.size();
    return size >= 32 and offset <= size - 32;
}

/// Validate a jump destination popped from the stack.
inline fn jumpTarget(self: *Interpreter, dest: primitives.U256) ?usize {
    if (dest > std.math.maxInt(usize)) return null;
    const d: usize = @intCast(dest);
    if (!self.bytecode.isValidJump(d)) return null;
    return d;
}

fn runDispatch(
    self: *Interpreter,
    table: *const InstructionTable,
    ctx: *InstructionContext,
    comptime check_pending: bool,
) void {
    if (!self.bytecode.isNotEnd()) return;
    // Hoisted once per frame — see opcodeAt. Fetch from the zero-padded executable copy,
    // so neither opcode fetch nor PUSH immediates check bounds.
    // A delegation designator is executable too (a delegation that points at a
    // delegated account runs the target's 0xef01.. bytes, and halts on 0xef); its
    // 23 bytes are padded here, on the stack, for the length of this call.
    var designator: [23 + bytecode.EXEC_PAD]u8 = undefined;
    const code: []const u8 = switch (self.bytecode.inner) {
        .legacy_analyzed => |*a| a.exec,
        .eip7702 => |*d| blk: {
            @memset(&designator, bytecode.STOP);
            @memcpy(designator[0..23], &d.raw_bytes);
            break :blk &designator;
        },
    };
    // CODESIZE is the real length, not the padded one.
    const code_len = self.bytecode.bytes().len;
    // EIP-145. Loop-invariant: spec_id is fixed for the frame.
    const has_shifts = primitives.isEnabledIn(self.runtime_flags.spec_id, .constantinople);
    // EIP-3855. Loop-invariant like has_shifts.
    const has_push0 = primitives.isEnabledIn(self.runtime_flags.spec_id, .shanghai);
    // EIP-211. Loop-invariant like has_shifts.
    const has_returndata = primitives.isEnabledIn(self.runtime_flags.spec_id, .byzantium);

    var r = Regs{
        .pc = self.bytecode.pc,
        .gas = self.gas.remaining,
        .sp = self.stack.length,
        .sb = self.stack.data.ptr,
    };

    // Inlined arms return on any halt (through `fail`), so they continue without
    // re-testing `continue_execution`. `pending` is set only by the CALL/CREATE
    // family, reached through the cold path, which is the one arm that re-checks it.
    sw: switch (opcodeAt(code, r.pc)) {
        0x00 => { // STOP
            r.pc += 1;
            spill(self, &r);
            opcodes.opStop(ctx);
        },
        0x01 => { // ADD
            r.pc += 1;
            if (!binop(self, &r, gas_costs.G_VERYLOW, ops.add)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x02 => { // MUL
            r.pc += 1;
            if (!binop(self, &r, gas_costs.G_LOW, ops.mul)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x03 => { // SUB
            r.pc += 1;
            if (!binop(self, &r, gas_costs.G_VERYLOW, ops.sub)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x10 => { // LT
            r.pc += 1;
            if (!binop(self, &r, gas_costs.G_VERYLOW, ops.lt)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x11 => { // GT
            r.pc += 1;
            if (!binop(self, &r, gas_costs.G_VERYLOW, ops.gt)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x12 => { // SLT
            r.pc += 1;
            if (!binop(self, &r, gas_costs.G_VERYLOW, ops.slt)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x13 => { // SGT
            r.pc += 1;
            if (!binop(self, &r, gas_costs.G_VERYLOW, ops.sgt)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x1A => { // BYTE
            r.pc += 1;
            if (!binop(self, &r, gas_costs.G_VERYLOW, ops.byte)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x35 => { // CALLDATALOAD: 32 bytes of calldata at offset, zero-filled past the end
            r.pc += 1;
            if (!charge(self, &r, gas_costs.G_VERYLOW)) return;
            if (r.sp < 1) {
                fail(self, &r, .stack_underflow);
                return;
            }
            const offset = r.sb[r.sp - 1];
            const data = self.input.data;
            var word: [32]u8 = [_]u8{0} ** 32;
            if (offset < data.len) {
                const off: usize = @intCast(offset);
                const n = @min(data.len - off, 32);
                @memcpy(word[0..n], data[off..][0..n]);
            }
            r.sb[r.sp - 1] = std.mem.readInt(primitives.U256, &word, .big);
            continue :sw opcodeAt(code, r.pc);
        },
        0x14 => { // EQ
            r.pc += 1;
            if (!binop(self, &r, gas_costs.G_VERYLOW, ops.eq)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x15 => { // ISZERO
            r.pc += 1;
            if (!unop(self, &r, gas_costs.G_VERYLOW, ops.iszero)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x16 => { // AND
            r.pc += 1;
            if (!binop(self, &r, gas_costs.G_VERYLOW, ops.band)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x17 => { // OR
            r.pc += 1;
            if (!binop(self, &r, gas_costs.G_VERYLOW, ops.bor)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x18 => { // XOR
            r.pc += 1;
            if (!binop(self, &r, gas_costs.G_VERYLOW, ops.bxor)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x19 => { // NOT
            r.pc += 1;
            if (!unop(self, &r, gas_costs.G_VERYLOW, ops.not)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        // SHL/SHR/SAR — fork-gated on Constantinople (EIP-145), see the note above.
        // When the gate is closed the table holds opUnknown for them.
        0x1B => { // SHL
            r.pc += 1;
            if (has_shifts) {
                if (!binop(self, &r, gas_costs.G_VERYLOW, ops.shl)) return;
            } else if (!coldReg(self, table, ctx, 0x1B, &r)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x1C => { // SHR
            r.pc += 1;
            if (has_shifts) {
                if (!binop(self, &r, gas_costs.G_VERYLOW, ops.shr)) return;
            } else if (!coldReg(self, table, ctx, 0x1C, &r)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x1D => { // SAR
            r.pc += 1;
            if (has_shifts) {
                if (!viaSelf(self, &r, gas_costs.G_VERYLOW, opcodes.opSar, .{ctx})) return;
            } else if (!coldReg(self, table, ctx, 0x1D, &r)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x50 => { // POP
            r.pc += 1;
            if (!charge(self, &r, gas_costs.G_BASE)) return;
            if (r.sp < 1) {
                fail(self, &r, .stack_underflow);
                return;
            }
            r.sp -= 1;
            continue :sw opcodeAt(code, r.pc);
        },
        // MLOAD/MSTORE/MSTORE8 — Frontier, behaviour-stable, G_VERYLOW static with
        // memory expansion billed inside the handler (through `self.gas`).
        // MLOAD/MSTORE stay in registers when the word is already inside memory
        // (no expansion, so no gas beyond the static G_VERYLOW). Anything else, including
        // every error, goes through the handler unchanged.
        0x51 => { // MLOAD
            r.pc += 1;
            if (r.sp >= 1 and r.gas >= gas_costs.G_VERYLOW and inMemory(self, r.sb[r.sp - 1])) {
                r.gas -= gas_costs.G_VERYLOW;
                const off: usize = @intCast(r.sb[r.sp - 1]);
                r.sb[r.sp - 1] = std.mem.readInt(primitives.U256, self.memory.buffer.items[off..][0..32], .big);
            } else if (!viaSelf(self, &r, gas_costs.G_VERYLOW, opcodes.opMload, .{ctx})) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x52 => { // MSTORE
            r.pc += 1;
            if (r.sp >= 2 and r.gas >= gas_costs.G_VERYLOW and inMemory(self, r.sb[r.sp - 1])) {
                r.gas -= gas_costs.G_VERYLOW;
                const off: usize = @intCast(r.sb[r.sp - 1]);
                std.mem.writeInt(primitives.U256, self.memory.buffer.items[off..][0..32], r.sb[r.sp - 2], .big);
                r.sp -= 2;
            } else if (!viaSelf(self, &r, gas_costs.G_VERYLOW, opcodes.opMstore, .{ctx})) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x53 => { // MSTORE8
            r.pc += 1;
            if (!viaSelf(self, &r, gas_costs.G_VERYLOW, opcodes.opMstore8, .{ctx})) return;
            continue :sw opcodeAt(code, r.pc);
        },
        // JUMP lands one past the JUMPDEST and charges its gas here, so a taken
        // jump never dispatches the JUMPDEST. Same outcome as running it: JUMPDEST
        // costs G_JUMPDEST and does nothing else.
        0x56 => { // JUMP
            r.pc += 1;
            if (!charge(self, &r, gas_costs.G_MID)) return;
            if (r.sp < 1) {
                fail(self, &r, .stack_underflow);
                return;
            }
            r.sp -= 1;
            const d = jumpTarget(self, r.sb[r.sp]) orelse {
                fail(self, &r, .invalid_jump);
                return;
            };
            r.pc = d + 1;
            if (!charge(self, &r, gas_costs.G_JUMPDEST)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x57 => { // JUMPI
            r.pc += 1;
            if (!charge(self, &r, gas_costs.G_HIGH)) return;
            if (r.sp < 2) {
                fail(self, &r, .stack_underflow);
                return;
            }
            const dest = r.sb[r.sp - 1];
            const cond = r.sb[r.sp - 2];
            r.sp -= 2;
            if (cond != 0) {
                const d = jumpTarget(self, dest) orelse {
                    fail(self, &r, .invalid_jump);
                    return;
                };
                r.pc = d + 1;
                if (!charge(self, &r, gas_costs.G_JUMPDEST)) return;
            }
            continue :sw opcodeAt(code, r.pc);
        },
        0x5B => { // JUMPDEST (reached by falling through, not by a jump)
            r.pc += 1;
            if (!charge(self, &r, gas_costs.G_JUMPDEST)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        // PUSH1..PUSH32: immediates read straight from the code slice.
        inline 0x60...0x7F => |push_op| {
            const n = push_op - 0x60 + 1;
            r.pc += 1;
            if (!charge(self, &r, gas_costs.G_VERYLOW)) return;
            if (r.sp >= stack_mod.STACK_LIMIT) {
                fail(self, &r, .stack_overflow);
                return;
            }
            var buf: [32]u8 = .{0} ** 32;
            // Immediates past the end read the zero padding.
            @memcpy(buf[32 - n ..], code[r.pc..][0..n]);
            const U = primitives.U256;
            r.sb[r.sp] = (@as(U, std.mem.readInt(u64, buf[0..8], .big)) << 192) |
                (@as(U, std.mem.readInt(u64, buf[8..16], .big)) << 128) |
                (@as(U, std.mem.readInt(u64, buf[16..24], .big)) << 64) |
                @as(U, std.mem.readInt(u64, buf[24..32], .big));
            r.sp += 1;
            r.pc += n;
            continue :sw opcodeAt(code, r.pc);
        },
        // DUP1..DUP16: comptime N folds the depth checks.
        inline 0x80...0x8F => |dup_op| {
            const n = dup_op - 0x80 + 1;
            r.pc += 1;
            if (!charge(self, &r, gas_costs.G_VERYLOW)) return;
            if (r.sp < n) {
                fail(self, &r, .stack_underflow);
                return;
            }
            if (r.sp >= stack_mod.STACK_LIMIT) {
                fail(self, &r, .stack_overflow);
                return;
            }
            r.sb[r.sp] = r.sb[r.sp - n];
            r.sp += 1;
            continue :sw opcodeAt(code, r.pc);
        },
        // SWAP1..SWAP16: comptime N folds the depth checks.
        inline 0x90...0x9F => |swap_op| {
            const n = swap_op - 0x90 + 1;
            r.pc += 1;
            if (!charge(self, &r, gas_costs.G_VERYLOW)) return;
            if (r.sp < n + 1) {
                fail(self, &r, .stack_underflow);
                return;
            }
            const t = r.sb[r.sp - 1];
            r.sb[r.sp - 1] = r.sb[r.sp - 1 - n];
            r.sb[r.sp - 1 - n] = t;
            continue :sw opcodeAt(code, r.pc);
        },
        0x5A => { // GAS: pushes the gas left after its own charge
            r.pc += 1;
            if (!charge(self, &r, gas_costs.G_BASE)) return;
            if (r.sp >= stack_mod.STACK_LIMIT) {
                fail(self, &r, .stack_overflow);
                return;
            }
            r.sb[r.sp] = r.gas;
            r.sp += 1;
            continue :sw opcodeAt(code, r.pc);
        },
        0x3D => { // RETURNDATASIZE (EIP-211, Byzantium)
            r.pc += 1;
            if (has_returndata) {
                if (!pushReg(self, &r, gas_costs.G_BASE, self.return_data.data.len)) return;
            } else if (!coldReg(self, table, ctx, 0x3D, &r)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        0x5F => { // PUSH0 (EIP-3855, Shanghai)
            r.pc += 1;
            if (has_push0) {
                if (!pushReg(self, &r, gas_costs.G_BASE, 0)) return;
            } else if (!coldReg(self, table, ctx, 0x5F, &r)) return;
            continue :sw opcodeAt(code, r.pc);
        },
        // ADDRESS, CALLER, CALLVALUE, CALLDATASIZE, CODESIZE, PC, MSIZE: Frontier,
        // G_BASE in every fork, one value pushed. One arm, not seven: each extra arm
        // is another predecessor of the dispatch tail, and past LLVM's
        // tail-duplication limit every inlined arm pays a jump to a shared tail.
        0x30, 0x33, 0x34, 0x36, 0x38, 0x58, 0x59 => |op| {
            r.pc += 1;
            switch (op) {
                0x38 => if (!pushReg(self, &r, gas_costs.G_BASE, code_len)) return,
                0x58 => if (!pushReg(self, &r, gas_costs.G_BASE, r.pc - 1)) return,
                0x30 => if (!pushReg(self, &r, gas_costs.G_BASE, host_mod.addressToU256(self.input.target))) return,
                0x33 => if (!pushReg(self, &r, gas_costs.G_BASE, host_mod.addressToU256(self.input.caller))) return,
                0x34 => if (!pushReg(self, &r, gas_costs.G_BASE, self.input.value)) return,
                0x36 => if (!pushReg(self, &r, gas_costs.G_BASE, self.input.data.len)) return,
                0x59 => if (!pushReg(self, &r, gas_costs.G_BASE, self.memory.size())) return,
                else => unreachable,
            }
            continue :sw opcodeAt(code, r.pc);
        },
        // Cold path: table lookup + indirect call.
        // Fork-gated opcodes (PUSH0, TLOAD/TSTORE etc.) land here and are handled
        // correctly via the table — opUnknown on old forks, real handler on new
        // forks. SHL/SHR/SAR and PUSH0 reach it too whenever their fork gate is closed.
        // Naming every cold value explicitly (rather than using `else`) keeps the jump
        // table dense over the whole u8 domain — no upper-bound compare needed.
        0x04...0x0f, 0x1e, 0x1f, 0x20...0x2f, 0x31, 0x32, 0x37, 0x39...0x3c, 0x3e, 0x3f...0x4f, 0x54, 0x55, 0x5c...0x5e, 0xa0...0xff => |op| {
            r.pc += 1;
            if (!coldReg(self, table, ctx, op, &r)) return;
            // Only the cold path can suspend the frame, so this is the one arm
            // that has to re-check `pending`.
            if (self.bytecode.isNotEnd() and (!check_pending or self.pending == .none))
                continue :sw opcodeAt(code, r.pc);
        },
    }
}

/// The cold path with the register state published for the handler and read back
/// afterwards. Returns false if the interpreter halted (on gas or in the handler).
inline fn coldReg(
    self: *Interpreter,
    table: *const InstructionTable,
    ctx: *InstructionContext,
    op: u8,
    r: *Regs,
) bool {
    const entry = table[op];
    if (r.gas < entry.static_gas) {
        fail(self, r, .out_of_gas);
        return false;
    }
    r.gas -= entry.static_gas;
    spill(self, r);
    entry.func(ctx);
    reload(self, r);
    return self.bytecode.isNotEnd();
}

/// Calculate number of words from bytes
pub fn numWords(bytes: usize) usize {
    return (bytes + 31) / 32;
}
