# CLAUDE.md

Notes for AI coding assistants working in this repo. Project overview, build steps and
the guest ABI are in README.md; allocator design is in src/zkvm/FREELIST_ALLOC.md.

## Build and test

- Zig 0.16.0 (`minimum_zig_version` in build.zig.zon).
- `zig build test` runs unit tests (~4 min cold). `zig build rv64im-object zisk-object`
  builds the guest objects; build both when touching anything reachable from the guest.
- Spec fixtures come from three independently versioned execution-specs release series
  (`tests@`, `tests-zkevm@`, `tests-zkevm-benchmark@`); see the table in README.md.
  `fetch-fixtures` wipes `spec-tests/fixtures/` including `zkevm/` when its version
  changes, so re-run `fetch-zkevm-fixtures` afterwards.

## Tests only run if a test root reaches them

`zig build test` only builds the modules listed in build.zig's `test` step loop
(precompile, interpreter, handler, context, bytecode, mpt, db, rlp_decode, executor,
hardfork). A new `*_tests.zig` file must be imported from its module's `test {}` block
(e.g. `src/evm/interpreter/main.zig`, `src/stateless/executor/main.zig`), otherwise it is
silently skipped. Zig also only analyzes functions that are referenced, so dead code can
contain compile errors that never surface — don't assume an unused helper is correct.

## Test placement

Put tests in a sidecar `<name>_tests.zig` file next to the code under test (e.g.
`journal.zig` → `journal_tests.zig`), not in inline `test` blocks in the implementation
file, and wire the sidecar into the module's `test {}` block as described above.

## Interpreter dispatch invariant

`runDispatch` in src/evm/interpreter/interpreter.zig inlines only opcodes that are valid
since Frontier and behave identically in every fork. Fork-gated opcodes may be inlined
only behind a loop-invariant `const` gate with a `coldReg` fallback; fork-modified opcodes
stay on the instruction-table (cold) path. See the INVARIANT comment there.

## Performance-sensitive code

- In a zkVM every executed instruction is proving cost; count instructions, not just
  allocations. The guest is rv64im (no Zbb on the portable object, Zbb/Zbs on
  zisk-object), single-threaded, no atomics.
- `inline` on `limbDivMod` (opcodes/arithmetic.zig) is load-bearing; don't remove it
  without re-benchmarking. Treat other `inline`/register-passing choices in the
  interpreter hot path the same way.

## Design principles

- **Single-threaded.** Don't add atomics, locks, or "parallel test" guards; there is no
  concurrent execution to protect against.
- **Fail fast on terminal errors.** OOM panics — never map it to another error such as
  OOG. A database/witness failure means the witness is invalid: stop and report it rather
  than tracking the failure and continuing to execute the block.
- **zkVM-neutral by default.** The accelerator ABI is the eth-act zkvm-standards C
  interface; describe it in those terms, not as ZisK's API. ZisK-specific code (Zbb/Zbs,
  DMA, `jump_dest`, `arith256_mod`) is opt-in via `GuestFeatures`/`zisk-object` and never
  enabled on the portable `rv64im-object`.
- **No caching behind external interfaces.** Don't memoize in the accelerator layer; the
  zkVM may already cache, and caching a cache just adds cost.
- **Remove dead code** rather than keeping unreachable branches, duplicated `else` arms, or
  "future-proofing" fields that are always zero.

## Comment style

Keep comments short and about the current design: invariants, safety/lifetime rules,
non-obvious "why", and EIP/spec references. Don't add change history ("previously…",
PR numbers), benchmark figures, line-number references (they go stale immediately), or
docs that restate the code — put history and measurements in commit messages or PR
descriptions instead. Call out non-obvious allocator assumptions (e.g. code that relies
on arena-style bulk free). File headers use `//!`, not `///` (a `///` block above
`const std = …` becomes that declaration's doc comment).

## Commits, PRs and CI

- Commit subjects follow `type(scope): summary` (`perf`, `fix`, `build`, `ci`, `test`,
  `chore`), with the summary stating the behavior in plain words, e.g.
  `fix(block): reject a block whose number doesn't follow its parent's`. Keep the body to
  a few sentences of what and why.
- PR descriptions and changelog entries are succinct "what changed" summaries.
- Pin GitHub Actions to a full commit SHA with the version in a trailing comment
  (`uses: actions/checkout@<sha> # v4.3.1`), never a bare tag.
