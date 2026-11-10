const std = @import("std");
const primitives = @import("primitives");
const bytecode = @import("bytecode");

/// Types for interpreter actions like calls and contract creation.
pub const InterpreterAction = union(enum) {
    call: CallAction,
    create: CreateAction,
    @"return": ReturnAction,
    selfdestruct: SelfdestructAction,
    stop: StopAction,
    revert: RevertAction,
};

/// Call action for CALL, CALLCODE, DELEGATECALL, STATICCALL
pub const CallAction = struct {
    scheme: CallScheme,
    inputs: CallInputs,
    outcome: ?CallOutcome,
};

/// Create action for CREATE, CREATE2
pub const CreateAction = struct {
    scheme: CreateScheme,
    inputs: CreateInputs,
    outcome: ?CreateOutcome,
};

pub const ReturnAction = struct {
    data: primitives.Bytes,
    gas_used: u64,
};

pub const SelfdestructAction = struct {
    target: primitives.Address,
    refund_address: primitives.Address,
    balance: primitives.U256,
};

pub const StopAction = struct {
    gas_used: u64,
};

pub const RevertAction = struct {
    data: primitives.Bytes,
    gas_used: u64,
};

pub const CallScheme = enum {
    call,
    callcode,
    delegatecall,
    staticcall,
};

pub const CreateScheme = enum {
    create,
    create2,
};

pub const CallInputs = struct {
    caller: primitives.Address,
    target: primitives.Address,
    value: primitives.U256,
    data: primitives.Bytes,
    gas_limit: u64,
    scheme: CallScheme,
    is_static: bool,
};

pub const CallOutcome = struct {
    data: primitives.Bytes,
    gas_used: u64,
    success: bool,
};

pub const CreateInputs = struct {
    caller: primitives.Address,
    value: primitives.U256,
    init_code: primitives.Bytes,
    gas_limit: u64,
    scheme: CreateScheme,
    /// Salt for CREATE2
    salt: ?primitives.Hash,
    /// EIP-8037 (Amsterdam+): state gas reservoir forwarded from parent to child.
    reservoir: u64,
};

pub const CreateOutcome = struct {
    address: primitives.Address,
    data: primitives.Bytes,
    gas_used: u64,
    success: bool,
};

pub const FrameInput = struct {
    caller: primitives.Address,
    target: primitives.Address,
    value: primitives.U256,
    data: primitives.Bytes,
    gas_limit: u64,
    scheme: CallScheme,
    is_static: bool,
    depth: usize,
};

pub const CallValue = struct {
    value: primitives.U256,
    is_zero: bool,
};
