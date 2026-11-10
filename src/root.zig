/// zesu — Ethereum EVM + stateless block executor.
///
/// Not referenced by build.zig: consumers import the individual modules that build.zig
/// exposes (primitives, handler, executor, runner, ...).
///
///   evm        — EVM core (primitives, bytecode, state, interpreter, precompile, handler)
///   stateless  — Stateless block executor (MPT witness verification, WitnessDatabase)
///   crypto     — Accelerator interface (backend chosen by -Dcrypto-backend)
///   io         — Native read/write interface per zkvm-standards io-interface
pub const evm = @import("evm/main.zig");
pub const stateless = @import("stateless/root.zig");
pub const crypto = @import("crypto/accelerators.zig");
pub const io = @import("io/interface.zig");

pub const primitives = evm.primitives;
