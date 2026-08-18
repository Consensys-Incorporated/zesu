# zesu Hive Client

This directory contains the Hive client implementation for `zesu` using the `ethereum/eels/consume-rlp` simulator.

The client (`hive-rlp`) reads a genesis JSON and a sequence of RLP-encoded blocks injected by Hive, executes them, and serves `eth_getBlockByNumber` on `:8545`.

## Prerequisites

- [Hive](https://github.com/ethereum/hive) checked out somewhere on your machine
- Docker

## 1. Build the Docker image

Run from the `zesu` repo root:

```bash
docker build -t zesu:latest -f ./tools/hive/Dockerfile .
```

The first build takes ~5 minutes (downloads and compiles Zig, blst, mcl). Subsequent builds with only source changes are ~30s due to Docker layer caching.

## 2. Run the Hive tests

From the Hive repo root:

```bash
./hive \
  --sim ethereum/eels/consume-rlp \
  --client-file=./zesu.yaml \
  --client.checktimelimit=300s \
  --docker.buildoutput \
  --sim.parallelism=6 \
  --sim.buildarg fixtures=https://github.com/ethereum/execution-specs/releases/download/tests-glamsterdam-devnet%40v8.1.0/fixtures_glamsterdam-devnet.tar.gz \
  --sim.buildarg branch=devnets/glamsterdam/8 \
  --sim.loglevel=3
```

To run a subset of tests (e.g. specific EIPs), add `--sim.limit` with a regex:

```bash
./hive \
  --sim ethereum/eels/consume-rlp \
  --client-file=./zesu.yaml \
  --client.checktimelimit=300s \
  --docker.buildoutput \
  --sim.parallelism=6 \
  --sim.buildarg fixtures=https://github.com/ethereum/execution-specs/releases/download/tests-glamsterdam-devnet%40v8.1.0/fixtures_glamsterdam-devnet.tar.gz \
  --sim.buildarg branch=devnets/glamsterdam/8 \
  --sim.limit=".*(8024|7708|7778|7843|7928|7954|8037).*" \
  --sim.loglevel=3
```

The `zesu.yaml` client file lives in the Hive repo root and wraps the pre-built image:

```yaml
clients:
  - name: zesu
    baseimage: zesu
    tag: latest
```

## 3. Iterating on changes

After editing source files, rebuild from the `zesu` repo root:

```bash
docker build -t zesu:latest -f ./tools/hive/Dockerfile .
```

Then re-run the Hive command.

## Architecture

| File | Purpose |
|------|---------|
| `main.zig` | Entry point: loads genesis, imports blocks, starts RPC server |
| `genesis.zig` | Parses `/genesis.json` (geth format), computes state root and block hash |
| `chain.zig` | In-memory chain: decodes RLP blocks, executes via zesu, verifies roots |
| `fork_env.zig` | Reads `HIVE_*` env vars to build the fork schedule |
| `rpc.zig` | Minimal HTTP/JSON-RPC server on `:8545` (`eth_blockNumber`, `eth_getBlockByNumber`) |
| `Dockerfile` | Multi-stage build: Zig 0.16.0 + blst + mcl (shared lib) |

## Known issues / notes

- **mcl is linked as a shared library** (`libmcl.so`). Static linking fails because Zig's LLD cannot resolve C++ symbols from libstdc++/libc++. The runtime image includes `libc++1` and copies `libmcl.so*`.
- The `zesu.yaml` in Hive uses `baseimage: zesu, tag: latest` — it does not build from source itself, it wraps the pre-built image.
