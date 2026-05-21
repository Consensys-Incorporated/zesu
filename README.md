# zesu

Zesu is a stateless Ethereum block executor written in Zig, designed to run as a **zkVM guest program**.

It takes an SSZ-encoded stateless block bundle (execution payload + witness), re-executes the block against the witness, and emits a 41-byte SSZ commitment (post-state root + receipts root + success flag) as its public output.

## Architecture

Zesu produces a **relocatable rv64im ELF object** (`zesu.rv64im.o`) with all EVM and stateless execution logic. All platform symbols are left as unresolved extern references:

| Extern symbol(s) | Purpose |
|---|---|
| `read_input`, `write_output` | zkvm-standards IO interface |
| `zkvm_keccak256` … `zkvm_secp256r1_verify` | 19 cryptographic accelerators |
| `zkvm_log`, `zkvm_exit` | Logging and termination |
| `ZISK_BUMP_HEAP_POS`, `ZISK_BUMP_HEAP_TOP` | Bump heap region (initialized by host before `main`) |

Each zkVM target in [zesu-zkvm](https://github.com/consensys/zesu-zkvm) provides a host object that satisfies these references using platform-native circuits or software fallbacks, then links it against `zesu.rv64im.o` to produce the final guest binary. This decouples EVM logic from zkVM specifics at the ELF/ABI level.

`core/build.zig` exposes the `"zkvm_root"` named module for freestanding targets, which wires the bump allocator, extern IO, and extern accelerator bridge automatically:

```zig
// In zesu-zkvm/*/build.zig
const zesu_obj = b.addObject(.{
    .name = "zesu",
    .root_module = zesu_core_dep.module("zkvm_root"),
});
```

Pre-built `zesu.rv64im.o` artifacts are published as GitHub Releases so zkVM consumers can avoid a source dependency on this repo.

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
    bump_alloc.zig  — bump allocator over ZISK_BUMP_HEAP_POS/TOP extern vars
    extern_io.zig   — read_input/write_output as C-ABI extern refs
core/           Module library build.zig (consumed by zesu-zkvm)
tools/          Spec-test runners, Hive adapter, t8n tool
spec-tests/     Downloaded execution-spec-tests fixtures (gitignored)
```
