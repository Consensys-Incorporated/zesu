# zkVM free-list allocator — design & diagrams

Explainer for the segregated free-list allocators used by the relocatable
rv64im object:

- `fl_alloc.zig` — reference design (`@clz`-based size classification).
- `alt_fl_alloc.zig` — **shipped** variant, RV64IM-tuned (branch-ladder
  classification instead of `@clz`).

`addGuestObject` in `build.zig` hardcodes `alt_fl_alloc.zig` as the
`zesu_allocator` root for the guest object (both the `rv64im-object` and
`zisk-object` steps); there is no build option to switch. `fl_alloc.zig` is
not wired into any build. This replaced the earlier bump allocator
(`bump_alloc.zig`, still in the tree but unused) whose `free` was a no-op.
Native/exposed builds don't use any of these: their `zesu_allocator` is the
settable singleton in `src/evm/allocator.zig`.

> The diagrams below are schematic on purpose — they don't bake in the exact
> class count or size cap, so they stay valid across tuning. For the concrete
> numbers (class count, min block size, size cap) read the file headers, which
> are the source of truth.

## Why this exists

The old bump allocator never reclaimed memory (`free` did nothing), so any
workload with heavy alloc/free churn grows the heap monotonically until it
OOMs the fixed guest heap. A segregated free list recycles freed blocks, so
steady-state churn stops consuming fresh heap.

## 1. Heap layout & the segregated free lists

Memory is bucketed into power-of-2 size classes. Each class owns one
**intrusive** singly-linked free list — the "next" pointer of a free block is
stored in that block's own first word, so there is no external metadata table.
This is why the minimum block size equals `@sizeOf(usize)` (8 on rv64): a block
must be large enough to hold that pointer while free.

```
free_lists[]  (one intrusive linked-list head per size class)
┌─────────┬──────────────────────────────────────────────┐
│ class 0 │  min size → head ─┐                            │
│ class 1 │           → 0 (empty)                          │
│ class 2 │           → head ──────┐                       │
│  ...    │  ...                   │                       │
│ class N │  max size → 0 (empty)  │                       │
└─────────┴────────────────────────┼──────────┬───────────┘
                     │              │          │
                     ▼              ▼          ▼
   THE HEAP  [ heap base ..................... ZKVM_HEAP_TOP ]
   ┌──────────────────────────────────────────────────────────┐
   │ used  │ free  │ used │ free  │ used │ free  │ ...   ░░░░░░ │
   │       └─next──┘             │       └─next→ │       ↑      │
   │       (points to another    └─next: 0 (tail)│  bump ptr    │
   │        free block, or 0)                     │  advances→   │
   └──────────────────────────────────────────────────────────┘
```

The bump pointer *is* `ZKVM_HEAP_POS`: the host initialises it to the heap
base, and `sysAllocAligned` advances it in place up to `ZKVM_HEAP_TOP`.

## 2. alloc(len, align)

Round the request up to a size class (of `max(len, alignment)`), then reuse a recycled block if one is
available; otherwise carve a fresh block off the bump pointer. Fresh blocks
are aligned to their own size (`max(alignment, classBytes(class))`), so any
recycled block of a class satisfies any alignment that maps to that class.

```
                    ┌──────────────────────────┐
   alloc(len) ─────▶│ class = sizeClass(len)   │
                    └────────────┬─────────────┘
                                 │
                 ┌───────────────┴────────────────┐
                 ▼                                 ▼
        class in range?                   oversized (> max class)
                 │ yes                             │
                 ▼                                 ▼
        free_lists[class] != 0 ?           bump-allocate exact len
         │yes            │no                (never recycled → leaks)
         ▼               ▼
   ┌──────────┐   ┌───────────────────┐
   │ POP head │   │ bump-allocate a    │
   │ O(1)     │   │ classBytes(class)  │
   │ head =   │   │ block from heap    │
   │  head.next│  └───────────────────┘
   └──────────┘
   reuse recycled memory      grow the heap
```

## 3. free(buf)

Classify by `buf.len` (and `buf_align`), then push the block onto the front of that class's list.
O(1), no coalescing.

```
   free(buf):  class = sizeClass(buf.len)
      ┌─────────────────────────────────────────┐
      │ buf.firstWord = free_lists[class]  (link)│
      │ free_lists[class] = buf            (head)│
      └─────────────────────────────────────────┘

   Before:  free_lists[c] ──▶ B ──▶ C ──▶ 0
   free(A): free_lists[c] ──▶ A ──▶ B ──▶ C ──▶ 0   (pushed on front)
```

## 4. Why two files — the `@clz` cost on RV64IM

`sizeClass()` runs on **every** alloc and free. In a zkVM every executed
instruction is a proving cost, so its instruction count matters directly.
(The `zisk-object` build does enable Zbb, but it ships `alt_fl_alloc.zig` too.)

```
                 sizeClass(size)  — called on EVERY alloc & free
   ┌────────────────────────────┬───────────────────────────────────┐
   │  fl_alloc.zig  (reference)  │  alt_fl_alloc.zig  (SHIPPED)       │
   ├────────────────────────────┼───────────────────────────────────┤
   │  ceilLog2 via @clz          │  branch ladder (binary search)     │
   │                             │                                    │
   │  RV64IM has NO Zbb, so      │  if (size<=T1)                     │
   │  @clz → software bit-smear  │    if (size<=T2)                   │
   │  + popcount                 │      if (size<=T3) ...             │
   │                             │                                    │
   │  many instrs, ALL execute   │  only the matching path runs       │
   │  on every call              │  (a handful of branches)           │
   │                             │                                    │
   │  ⇒ larger zkVM overhead     │  ⇒ smaller zkVM overhead           │
   └────────────────────────────┴───────────────────────────────────┘
                                    │
              parity test: alt's ladder is checked against
              fl's @clz formula at every class boundary × alignment.
```

`alt_fl_alloc.zig` keeps the `@clz` formula as `referenceSizeClass` purely as a
test oracle, so the hand-rolled ladder is verified against the obviously-correct
version. Alt also takes `std.mem.Alignment`'s raw log2 value directly instead of
shifting it to a byte count, and folds alignment in as a separate class
(`max(size_class, align_class)`).

The two are not otherwise identical: the ladder only covers 2^3..2^24, so
`alt_fl_alloc.zig` has fewer classes and a much lower size cap (16 MiB) than
`fl_alloc.zig` (2 GiB) — see the file headers.

## 5. The critical `resize` invariant

A block is classified by `buf.len` at `free()` time. Therefore `resize` may
only shrink **within the same size class** — otherwise `free()` would push the
block onto the wrong list and later hand it out at the wrong size.

```
   block of some class, capacity = classBytes(class)
        │
        ├─ resize to len' where sizeClass(len') == sizeClass(len)  ✓ allowed
        │     (later free still lands in the correct class)
        │
        └─ resize to len' where sizeClass(len') != sizeClass(len)  ✗ rejected
              (else free() pushes onto the wrong list → corruption)
```

`remap` is unsupported and always returns `null` (caller falls back to
alloc + copy).

## Known trade-offs / footguns

- **Oversized path leaks.** Requests larger than the biggest class (16 MiB in
  the shipped variant) are
  bump-allocated and never recycled. Correct only while such sizes don't occur
  in practice (EVM allocations are gas-bounded).
- **Global mutable `free_lists`.** Safe only because the guest is
  single-threaded. Not safe to share across threads as-is.
- **No coalescing / no splitting.** Blocks are recycled only within their exact
  class. Fine for the fixed, repetitive allocation sizes this target sees.
- **Alignment padding is lost.** Because fresh blocks are aligned to their own
  size, the bump pointer may skip a gap before a large block; that gap is never
  reused.
