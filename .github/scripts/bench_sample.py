#!/usr/bin/env python3
"""Sample a tests-zkevm-benchmark gas tier down to N gas-using blocks per suite.

A full tier is ~1200 gas-using blocks at about a minute of emulation each, far
beyond a PR check. A few blocks per suite keep every suite on the board for a
few minutes of runner time; trace costs are deterministic, so each block still
gives an exact delta.

A suite is a fixture directory relative to the tier root, matching the harness's
`suite` column. Within a suite, blocks are taken from its files in turn — the
first gas-using block of each file, then the second, and so on — so a sample of
N covers N different test files where the suite has them, rather than N
variants of one. Files are in sorted path order and blocks in test-name, then
block order, so every run of the same release measures the same blocks. Blocks
with zero gas used (setup blocks) are never picked.

Each sampled block is written as its own one-test, one-block fixture file under
the output root, keeping its suite directory, so the harness can run them in
parallel (it parallelises across files, not blocks).
"""

import argparse
import json
import os
import sys


def gas_used(block):
    try:
        return int(block.get("blockHeader", {}).get("gasUsed", "0x0"), 16)
    except (TypeError, ValueError):
        return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="tier root, e.g. .../for_amsterdam_at_0030M")
    ap.add_argument("out", help="output fixture root")
    ap.add_argument("--per-suite", type=int, default=1)
    args = ap.parse_args()

    suites = {}
    for dirpath, dirnames, filenames in os.walk(args.root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        paths = sorted(os.path.join(dirpath, f) for f in filenames if f.endswith(".json"))
        if paths:
            suites[os.path.relpath(dirpath, args.root)] = paths

    taken = {}
    for suite, paths in sorted(suites.items()):
        # Per file, its gas-using blocks in order, as (stem, label, test, block).
        per_file = []
        for path in paths:
            with open(path) as fh:
                tests = json.load(fh)
            stem = os.path.splitext(os.path.basename(path))[0]
            cands = []
            for name in sorted(tests):
                tc = tests[name]
                for i, block in enumerate(tc.get("blocks") or []):
                    if gas_used(block) == 0 or not block.get("statelessInputBytes"):
                        continue
                    # Keep the harness's label for this block: a multi-block test
                    # labels its blocks `name/blockN`, which a one-block copy loses.
                    label = name if len(tc["blocks"]) == 1 else f"{name}/block{i}"
                    cands.append((stem, label, tc, block))
            per_file.append(cands)

        # Round-robin across files: each file's first block, then each second.
        picks = [c[r] for r in range(max(map(len, per_file), default=0))
                 for c in per_file if r < len(c)][:args.per_suite]
        dst = os.path.join(args.out, suite)
        for n, (stem, label, tc, block) in enumerate(picks):
            os.makedirs(dst, exist_ok=True)
            with open(os.path.join(dst, f"{stem}-{n}.json"), "w") as fh:
                json.dump({label: {**tc, "blocks": [block]}}, fh)
        if picks:
            taken[suite] = len(picks)

    for suite in sorted(taken):
        print(f"{taken[suite]:3d}  {suite}")
    print(f"{sum(taken.values())} block(s) across {len(taken)} suite(s)")
    return 0 if taken else 1


if __name__ == "__main__":
    sys.exit(main())
