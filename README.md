# zesu

Zesu is a stateless Ethereum block executor written in Zig, designed to run as a **zkVM guest program**.

It takes an SSZ-encoded stateless block bundle (execution payload + witness), re-executes the block against the witness, and emits a 41-byte SSZ commitment (post-state root + receipts root + success flag) as its public output.

## Architecture

Zesu builds a **position-independent ELF** that is then linked by each target zkVM's linker script to produce the final guest binary.  Bespoke builds for specific proving systems live in [zesu-zkvm](https://github.com/consensys/zesu-zkvm), which depends on this repo and overrides three injection points:

| Injection point | Purpose |
|---|---|
| `accel_impl` → `accelerators` module | zkVM-native crypto (keccak, ecrecover, BN254, …) |
| `precompile_implementations` → `precompile` module | Per-precompile function overrides |
| `zevm_allocator` (all EVM modules) | Bump / arena allocator for the prover heap |

The `core/build.zig` library exposes all named modules (`executor`, `runner`, `ssz_decode`, `ssz_output`, `input`, `mpt`, …) so that a zkVM consumer can depend on zesu via `build.zig.zon` and wire the overrides without touching zesu source.

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
  crypto/       Accelerator dispatch layer
core/           Module library build.zig (consumed by zesu-zkvm)
tools/          Spec-test runners, Hive adapter, t8n tool
spec-tests/     Downloaded execution-spec-tests fixtures (gitignored)
```
