# Migrating zevm-stateless-zisk to zesu

zesu merges the former `zevm` (EVM) and `zevm-stateless` (stateless executor) repos into one.
This document describes every change needed to migrate a Zisk zkVM guest that previously
depended on both sibling repos.

---

## 1. `build.zig.zon` — two deps → one

```diff
 .dependencies = .{
-    .zevm = .{ .path = "../zevm" },
-    .zevm_stateless = .{ .path = "../zevm-stateless" },
+    .zesu = .{ .path = "../zesu" },
 },
```

---

## 2. `build.zig` changes

### 2a. Dep handles

```diff
-const zevm_dep = b.dependency("zevm", .{ .target = target, .optimize = optimize });
-const zs_dep   = b.dependency("zevm_stateless", .{});
+const zesu_dep  = b.dependency("zesu", .{ .target = target, .optimize = optimize });
```

### 2b. EVM modules — same names, one dep

```diff
-const primitives   = zevm_dep.module("primitives");
-const bytecode     = zevm_dep.module("bytecode");
-const state        = zevm_dep.module("state");
-const database     = zevm_dep.module("database");
-const context      = zevm_dep.module("context");
-const interpreter  = zevm_dep.module("interpreter");
-const precompile   = zevm_dep.module("precompile");
-const handler      = zevm_dep.module("handler");
-const inspector    = zevm_dep.module("inspector");
+const primitives   = zesu_dep.module("primitives");
+const bytecode     = zesu_dep.module("bytecode");
+const state        = zesu_dep.module("state");
+const database     = zesu_dep.module("database");
+const context      = zesu_dep.module("context");
+const interpreter  = zesu_dep.module("interpreter");
+const precompile   = zesu_dep.module("precompile");
+const handler      = zesu_dep.module("handler");
```

There is no `inspector` module in zesu; the `Inspector` type lives in `handler`
(`src/evm/handler/main.zig`).

`precompile_types` is also exposed as a named module:

```diff
-const precompile_types = zevm_dep.module("precompile_types");
+const precompile_types = zesu_dep.module("precompile_types");
```

### 2c. Stateless modules — use zesu paths under `src/stateless/`

Old code accessed zevm-stateless source via `zs_dep.path("src/...")`. In zesu the same files
live under `src/stateless/`. You can either use `zesu_dep.module()` for the top-level named
modules, or `zesu_dep.path()` to re-create modules with freestanding-safe wiring. The table
below covers both cases.

| Old `zs_dep.path(...)` | New `zesu_dep.path(...)` | zesu named module |
|---|---|---|
| `src/input.zig` | `src/stateless/input.zig` | `zesu_dep.module("input")` |
| `src/output.zig` | `src/stateless/output.zig` | `zesu_dep.module("output")` |
| `src/hardfork.zig` | `src/stateless/hardfork.zig` | `zesu_dep.module("hardfork")` |
| `src/rlp_decode.zig` | `src/stateless/rlp_decode.zig` | `zesu_dep.module("rlp_decode")` |
| `src/mpt/main.zig` | `src/stateless/mpt/main.zig` | `zesu_dep.module("mpt")` |
| `src/mpt/builder.zig` | `src/stateless/mpt/builder.zig` | *(anonymous, path only)* |
| `src/mpt/nibbles.zig` | `src/stateless/mpt/nibbles.zig` | *(anonymous, path only)* |
| `src/db/main.zig` | `src/stateless/db/main.zig` | `zesu_dep.module("db")` |
| `src/executor/main.zig` | `src/stateless/executor/main.zig` | `zesu_dep.module("executor")` |
| `src/executor/types.zig` | `src/stateless/executor/types.zig` | *(private `executor_types`; via `executor.executor_types` re-export)* |
| `src/executor/rlp_encode.zig` | `src/stateless/executor/rlp_encode.zig` | *(via executor re-export)* |
| `src/executor/transition.zig` | `src/stateless/executor/transition.zig` | *(via executor re-export)* |
| `src/executor/output.zig` | `src/stateless/executor/output.zig` | *(via executor re-export)* |
| `src/executor/bal.zig` | `src/stateless/executor/bal.zig` | *(internal)* |
| `src/executor/block_validation.zig` | `src/stateless/executor/block_validation.zig` | *(via executor re-export)* |
| `src/executor/tx_decode.zig` | `src/stateless/executor/tx_decode.zig` | *(via executor re-export)* |

**Important**: every file under `src/stateless/executor/` except `types.zig` and
`block_rlp_size.zig` is pulled in by `executor/main.zig` through relative
`@import("./X.zig")` imports, so the whole executor (transition, output, bal, rlp_encode,
block_validation, tx_decode, tx_signing, executor_allocator, …) is a single compilation
unit. It can no longer be re-created file-by-file as separate `executor_X` modules, and
there is no `mpt_builder` module (`mpt/builder.zig` is a relative import of `mpt`).

The allocator is also no longer injected at build time (see 2f), so there is no reason
to re-create the executor from path. If you do create it from `zesu_dep.path(...)`, the
`executor` module needs these named imports (as wired in zesu's `build.zig`):

```
executor_types, block_rlp_size, zesu_allocator, primitives, input, output, mpt,
rlp_decode, hardfork, db, context, state, bytecode, database, handler, interpreter,
precompile, accelerators
```

`executor_types` (`executor/types.zig`) and `block_rlp_size` (`executor/block_rlp_size.zig`)
are separate modules; `types.zig` needs no imports (std only).

### 2d. Crypto injection — unified `accel_impl`

**This is the most significant architectural change.**

Previously there were two separate injection points:
- `mpt` had `@import("zkvm_accelerators")` for keccak256
- `executor/transition.zig` had `@import("secp256k1_wrapper")` for ecrecover

In zesu both are replaced by a single `accel_impl` leaf behind the `accelerators` module.
`accel_impl` is **private** — it is not exposed and is not meant to be overridden with
`.addImport()`. Instead it is selected with the `-Dcrypto-backend` build option:

| `crypto-backend` | `accel_impl` root | Crypto provided by |
|---|---|---|
| `default` | `src/crypto/default.zig` | native C libs (secp256k1, OpenSSL, blst, mcl) |
| `extern` | `src/crypto/extern_bridge.zig` | `zkvm_*` C symbols resolved at link time |

For ZisK use the `extern` backend (freestanding targets require it). The guest object
from `zig build zisk-object` (or `addGuestObject`, see 2g) is always built this way.

```diff
-// Old: separate zkvm_accelerators for mpt
-const zkvm_accelerators_mod = b.createModule(.{
-    .root_source_file = zs_dep.path("src/zkvm/zkvm_accelerators.zig"), ...
-});
-mpt_mod.addImport("zkvm_accelerators", zkvm_accelerators_mod);
-
-// Old: secp256k1_wrapper for transition
-executor_transition_mod.addImport("secp256k1_wrapper", secp256k1_mod);

+// New: extern crypto backend; ZisK supplies the zkvm_* symbols at link time
+const zesu_dep = b.dependency("zesu", .{
+    .target = target,
+    .optimize = optimize,
+    .@"crypto-backend" = .@"extern",
+});
```

`extern_bridge.zig` maps every `pub fn` in `src/crypto/accelerators.zig`:

```
keccak256, secp256k1_verify, ecrecover, sha256, ripemd160, modexp,
bn254_g1_add, bn254_g1_mul, bn254_pairing,
blake2f, kzg_point_eval,
bls12_g1_add, bls12_g1_msm, bls12_g2_add, bls12_g2_msm,
bls12_pairing, bls12_map_fp_to_g1, bls12_map_fp2_to_g2,
secp256r1_verify
```

onto the zkvm-standards C symbols the ZisK side must provide (`zkvm_keccak256`,
`zkvm_sha256`, `zkvm_secp256k1_verify`, `zkvm_secp256k1_ecrecover`, `zkvm_ripemd160`,
`zkvm_modexp`, `zkvm_bn254_g1_add`, `zkvm_bn254_g1_mul`, `zkvm_bn254_pairing`,
`zkvm_blake2f`, `zkvm_kzg_point_eval`, `zkvm_bls12_*`, `zkvm_secp256r1_verify`; each
returns `i32`, 0 on success — see the declarations at the top of `extern_bridge.zig`).
For operations without a Zisk circuit, the symbol still has to exist; return a non-zero
status.

The `precompile_implementations` injection point no longer exists. The precompile module
imports `src/evm/precompile/default_impls.zig` directly, and those wrappers call through
the `accelerators` module — so a ZisK circuit reaches every precompile (including BN254)
through its `zkvm_*` symbol, with no separate precompile override.

### 2e. zkvm_accelerators.zig removal

The file `src/zkvm/zkvm_accelerators.zig` from zevm-stateless is no longer needed.
Its keccak256 declaration is replaced by the `zkvm_keccak256` extern in
`src/crypto/extern_bridge.zig`. Remove the module
definition and its import into mpt:

```diff
-const zkvm_accelerators_mod = b.createModule(.{ ... });
-mpt_mod.addImport("zkvm_accelerators", zkvm_accelerators_mod);
```

### 2f. Simplified executor module wiring (preferred)

If you can use `zesu_dep.module("executor")` directly (injecting overrides rather than
re-creating from source), the entire executor sub-module section collapses to:

```zig
const executor_mod = zesu_dep.module("executor");
// (No individual executor_X modules needed)
```

This works because zesu's executor module already has all internal deps wired. Nothing
is overridden by `.addImport()` any more:
- Allocator: call `zesu_allocator.set(your_allocator)` once at startup, before any zesu
  code runs (`src/evm/allocator.zig`; a freestanding build panics if it is never set).
  This replaces injecting a `zevm_allocator` module into every EVM module.
- Crypto: `-Dcrypto-backend=extern` plus the `zkvm_*` symbols (see 2d), instead of an
  `accel_impl` module.
- Precompiles: no override (see 2d).

### 2g. Prebuilt guest object (alternative to module wiring)

zesu can build the whole guest itself as a relocatable rv64im ELF with IO, crypto, heap
and logging left as unresolved externs:

- `zig build zisk-object` → `zig-out/lib/zesu-zisk.o` (rv64im + Zbb + Zbs, ZisK DMA on)
- `zig build rv64im-object` → `zig-out/lib/zesu.o` (portable baseline)
- From a dependent's `build.zig`: `@import("zesu").addGuestObject(zesu_dep.builder,
  target, optimize, .{ .dma = true, ... })`, where `GuestFeatures` has `dma`,
  `jump_dest` and `arith256_mod` (all default false).

The object exports `main()` and expects the linking ZisK project to provide `read_input`,
`write_output` (`src/zkvm/extern_io.zig`), `zkvm_log`, `zkvm_abort` (`src/zkvm/root.zig`),
`ZKVM_HEAP_POS` / `ZKVM_HEAP_TOP` (heap for `src/zkvm/alt_fl_alloc.zig`), the `zkvm_*`
crypto symbols, and — with `arith256_mod` — `reduce_mod256_c`, `add_mod256_c` and
`mul_mod256_c` (used for MOD/ADDMOD/MULMOD, `src/evm/interpreter/opcodes/arithmetic.zig`;
provided by libziskos). The `zisk-object` step enables only `dma`.

---

## 3. Source changes in zevm-stateless-zisk

### 3a. `src/deserialize.zig` — path update only

If it imports from zevm-stateless source via relative paths, update to the `src/stateless/`
layout. No logic changes needed.

### 3b. `src/zisk/accel_impl.zig` — replaced by `zkvm_*` C symbols

Consolidate the old `zkvm_accelerators_zisk.zig` (keccak) and `secp256k1.zig` (ecrecover)
into implementations of the `zkvm_*` C-ABI symbols declared in
`src/crypto/extern_bridge.zig` (not a Zig `accel_impl` module, which zesu no longer
accepts). Each returns `i32`, 0 on success.

Scaffold (all ops not yet wired should return a non-zero status):

```zig
// src/zisk/accel_impl.zig
const zisk = @import("zisk");

export fn zkvm_keccak256(data: [*]const u8, len: usize, output: *[32]u8) i32 {
    zisk.keccak256(data[0..len], output);
    return 0;
}

export fn zkvm_secp256k1_ecrecover(msg: *const [32]u8, sig: *const [64]u8, recid: u8, output: *[64]u8) i32 {
    return if (zisk.secp256k1Recover(msg, sig, recid, output)) 0 else 1;
}

export fn zkvm_bn254_g1_add(p1: *const [64]u8, p2: *const [64]u8, result: *[64]u8) i32 {
    return if (zisk.bn254Add(p1, p2, result)) 0 else 1;
}
// ... etc.
```

### 3c. `src/zisk/precompile_overrides.zig` — remove

zesu no longer has a `precompile_implementations` injection point (see 2d). Drop
`precompile_overrides.zig` and its wiring; anything it did through ZisK circuits now
goes through the corresponding `zkvm_*` symbol.

---

## 4. Named modules exposed by zesu

These are available via `zesu_dep.module("name")`:

| Module name | Source |
|---|---|
| `primitives` | `src/evm/primitives/main.zig` |
| `bytecode` | `src/evm/bytecode/main.zig` |
| `state` | `src/evm/state/main.zig` |
| `database` | `src/evm/database/main.zig` |
| `context` | `src/evm/context/main.zig` |
| `precompile` | `src/evm/precompile/main.zig` |
| `precompile_types` | `src/evm/precompile/types.zig` |
| `interpreter` | `src/evm/interpreter/main.zig` |
| `handler` | `src/evm/handler/main.zig` |
| `zesu_allocator` | `src/evm/allocator.zig` |
| `accelerators` | `src/crypto/accelerators.zig` |
| `input` | `src/stateless/input.zig` |
| `output` | `src/stateless/output.zig` |
| `hardfork` | `src/stateless/hardfork.zig` |
| `rlp_decode` | `src/stateless/rlp_decode.zig` |
| `mpt` | `src/stateless/mpt/main.zig` |
| `ssz_decode` | `src/stateless/stateless/ssz.zig` |
| `ssz_output` | `src/stateless/stateless/ssz_output.zig` |
| `db` | `src/stateless/db/main.zig` |
| `block_rlp_size` | `src/stateless/executor/block_rlp_size.zig` |
| `executor` | `src/stateless/executor/main.zig` |
| `runner` | `src/stateless/stateless/run.zig` |

Customization points (there are no `.addImport()` overrides any more):

| What | How | Purpose |
|---|---|---|
| Crypto (keccak, secp256k1, BN254, BLS, …) | `-Dcrypto-backend=extern` + `zkvm_*` link symbols | All crypto ops and crypto precompiles |
| Heap allocator | `zesu_allocator.set(...)` at runtime | All internal allocations |
| ZisK opcode/memory features | `GuestFeatures` (`dma`, `jump_dest`, `arith256_mod`) via `addGuestObject` | DMA copies, JUMPDEST analysis, MOD/ADDMOD/MULMOD |
