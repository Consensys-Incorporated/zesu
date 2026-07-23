# zesu

Zesu is a stateless Ethereum block executor written in Zig, designed to run as a **zkVM guest program**.

It takes an SSZ-encoded stateless block bundle (execution payload + witness), re-executes the block against the witness, and emits a 41-byte SSZ commitment (post-state root + receipts root + success flag) as its public output.

## Architecture

Zesu produces a **relocatable rv64im ELF object** (`zesu.rv64im.o`) with all EVM and stateless execution logic. All platform symbols are left as unresolved extern references that each zkVM host must satisfy.

**IO**

| Symbol | Signature | Description |
|---|---|---|
| `read_input` | `(*[*]const u8, *usize) void` | Fill pointer + length with the zkVM private input |
| `write_output` | `([*]const u8, usize) void` | Emit public output bytes |

**Runtime**

| Symbol | Signature | Description |
|---|---|---|
| `zkvm_log` | `(u8, [*]const u8, usize) void` | Log a message at the given level |
| `zkvm_exit` | `(i32) noreturn` | Terminate execution with exit code |
| `ZKVM_HEAP_POS` | `usize` (var) | Bump heap cursor; allocator advances this |
| `ZKVM_HEAP_TOP` | `usize` (var) | Heap upper bound; allocator checks against this |

**Accelerators** — all return `i32` (0 = success, −1 = failure)

| Symbol | Precompile | Description |
|---|---|---|
| `zkvm_keccak256` | — | Keccak-256 hash |
| `zkvm_sha256` | `0x02` | SHA-256 hash |
| `zkvm_secp256k1_ecrecover` | `0x01` | secp256k1 signature recovery |
| `zkvm_secp256k1_verify` | — | secp256k1 signature verification |
| `zkvm_ripemd160` | `0x03` | RIPEMD-160 hash |
| `zkvm_modexp` | `0x05` | Modular exponentiation (EIP-198) |
| `zkvm_bn254_g1_add` | `0x06` | BN254 G1 point addition (EIP-196) |
| `zkvm_bn254_g1_mul` | `0x07` | BN254 G1 scalar multiplication (EIP-196) |
| `zkvm_bn254_pairing` | `0x08` | BN254 pairing check (EIP-197) |
| `zkvm_blake2f` | `0x09` | BLAKE2f compression (EIP-152) |
| `zkvm_kzg_point_eval` | `0x0a` | KZG point evaluation (EIP-4844) |
| `zkvm_bls12_g1_add` | `0x0b` | BLS12-381 G1 addition (EIP-2537) |
| `zkvm_bls12_g1_msm` | `0x0c` | BLS12-381 G1 multi-scalar multiplication (EIP-2537) |
| `zkvm_bls12_g2_add` | `0x0d` | BLS12-381 G2 addition (EIP-2537) |
| `zkvm_bls12_g2_msm` | `0x0e` | BLS12-381 G2 multi-scalar multiplication (EIP-2537) |
| `zkvm_bls12_pairing` | `0x0f` | BLS12-381 pairing check (EIP-2537) |
| `zkvm_bls12_map_fp_to_g1` | `0x10` | BLS12-381 Fp → G1 map (EIP-2537) |
| `zkvm_bls12_map_fp2_to_g2` | `0x11` | BLS12-381 Fp2 → G2 map (EIP-2537) |
| `zkvm_secp256r1_verify` | `0x100` | P-256 signature verification (EIP-7212) |

Each zkVM target in [zesu-zkvm](https://github.com/consensys/zesu-zkvm) provides a host object that satisfies these references using platform-native circuits or software fallbacks, then links it against `zesu.rv64im.o` to produce the final guest binary. This decouples EVM logic from zkVM specifics at the ELF/ABI level.

There are two ways to consume zesu:

**1. Turnkey relocatable object.** `zig build rv64im-object` produces `zig-out/lib/zesu.o`, and pre-built `zesu.rv64im.o` artifacts are published as GitHub Releases so consumers can avoid a source dependency. This object wires the bump allocator (over `ZKVM_HEAP_POS`/`ZKVM_HEAP_TOP`), extern IO, and the extern accelerator bridge — no runtime setup beyond satisfying the extern symbols above.

**2. Module graph.** The `zesu` package exposes its modules via `addModule`, so a build script can depend on it and import modules by name — `zesu.module("executor")`, `"input"`, `"mpt"`, `"rlp_decode"`, `"precompile"`, etc. Backends are selected by target: a **freestanding** target wires the extern accelerator bridge (the `zkvm_*` symbols the host resolves at link), a **native** target wires `default.zig` (linking secp256k1/mcl/blst/openssl). The exposed `zesu_allocator` is a runtime-settable singleton, so a guest that drives execution itself **must** install an allocator once at startup with `zesu_allocator.set(...)` before any execution (a freestanding default panics if left unset) and provide the `zkvm_*` accelerator symbols at link time.

## Input formats

All inputs are read from **stdin** by default, or from the file at `$ZESU_INPUT` when that env var is set.

| Format | Description |
|---|---|
| **SSZ** | Raw SSZ-encoded `SszStatelessInput`. This is the canonical zkVM input format. |
| **SSZ/Ere** | Same SSZ payload prefixed with a 4-byte u32 LE length field, as produced by the [Ere](https://github.com/eqlabs/ere) test framework's `Input::with_prefixed_stdin`. The prefix is stripped automatically. |
| **JSON** | Development/debug only (`--json` flag). Accepts a `debug_getRawBlock` JSON-RPC response and a witness JSON file. |

### SSZ schema

```
SszStatelessInput
  new_payload_request: SszNewPayloadRequest
    execution_payload: SszExecutionPayload   (V3: 528B fixed / V4: 540B fixed)
    parent_beacon_block_root: Bytes32
    execution_requests: SszExecutionRequests
  witness: SszExecutionWitness
  chain_config: SszChainConfig
  public_keys: List[BLSPubkey]
```

### Output schema

```
[0..32]  new_payload_request HashTreeRoot  (Bytes32)
[32..40] chain_id                          (uint64 LE)
[40]     success flag                      (0x00 / 0x01)
```

## Building for host OS

The native build requires Zig ≥ 0.14 plus **libsecp256k1**, **libblst**, and **libmcl**.

```sh
# Install dependencies (macOS or Debian/Ubuntu)
make install-deps

# Build the zesu binary
zig build

# Binary lands at:
./zig-out/bin/zesu
```

## CLI usage

```
zesu [--fork <name>]                               # SSZ from stdin / $ZESU_INPUT  (default)
zesu --ssz <file> [--fork <name>]                  # SSZ from a binary file
zesu --json <block.json> <witness.json> [--fork <name>]
```

`--fork` overrides the fork name embedded in the input (useful when the SSZ chain config is absent or you want to pin a specific EIP set, e.g. `Prague`, `Amsterdam`).

## Running against devnet blocks

`r2-stateless` fetches the latest stateless-input batches from a public R2 devnet catalog and executes each block natively through the same path the zkVM guest uses. No external tools required — all HTTP, zstd decompression, and JSON parsing are handled by the Zig standard library.

```sh
# Build
zig build

# Run the latest batch from the default catalog (glamsterdam-devnet-7)
./zig-out/bin/r2-stateless

# Run the latest N batches
./zig-out/bin/r2-stateless --batches 5

# Override catalog, require all blocks to pass
./zig-out/bin/r2-stateless --catalog <URL> --batches 1 --strict

# Write a Markdown / JSON summary (useful in CI)
./zig-out/bin/r2-stateless --summary-md result.md --summary-json result.json
```

Each block is considered a pass iff execution succeeds **and** the computed SSZ output matches the fixture's `statelessOutputBytes` byte-for-byte. With `--strict` the process exits non-zero if any block fails or no blocks were executed.

## Running tests

```sh
# Download execution-spec-tests fixtures and run everything
make spec-tests

# State tests only
make state-tests

# Blockchain tests only
make blockchain-tests

# Filter to a specific test directory
make state-tests ARGS="--filter Prague"
```

Fixtures are cached under `spec-tests/fixtures/` after the first download.

## Repository layout

```
src/
  evm/          EVM interpreter, state, precompiles, handler
  stateless/    Block executor, SSZ codec, MPT, witness DB
  io/           Platform-neutral I/O interface (overridden per zkVM)
  crypto/       Accelerator dispatch layer (extern_bridge.zig for zkVM builds)
  zkvm/
    root.zig        — rv64im object root: std_options, panic, export fn main
    bump_alloc.zig  — bump allocator over ZKVM_HEAP_POS/TOP extern vars
    extern_io.zig   — read_input/write_output as C-ABI extern refs
build.zig       Builds the apps/tools/tests + rv64im object; exposes the module graph via addModule
tools/          Spec-test runners, Hive adapter, t8n tool
spec-tests/     Downloaded execution-spec-tests fixtures (gitignored)
```
