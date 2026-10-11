#!/usr/bin/env python3
"""Sample a tests-zkevm-benchmark gas tier down to N measured blocks per file.

A full tier is ~1200 gas-using blocks at about a minute of emulation each, far
beyond a PR check. One block per fixture file keeps every test on the board for
a few minutes of runner time; trace costs are deterministic, so each block still
gives an exact delta.

Per file, not per suite: a suite mixes tests that stress very different paths
(`storage` holds both `tload` and `storage_access_cold`), so a per-suite sample
can miss exactly the test a change targets.

Only a test's last block is measured. Multi-block tests put their setup first,
and setup is not small: `storage_access_cold` fills storage with a 1.36B-gas
block before its 30M benchmark block, and `blockhash` precedes it with 256 empty
ones. A sampled block that is not a test's last would measure the setup.

Files are in sorted path order and tests in name order, so every run of the same
release measures the same blocks. Each sampled block is written as its own
one-test, one-block fixture file under the output root, keeping its suite
directory (the harness's `suite` column), so the harness can run them in
parallel: it parallelises across files, not blocks.
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
    ap.add_argument("--per-file", type=int, default=1)
    args = ap.parse_args()

    files = []
    for dirpath, dirnames, filenames in os.walk(args.root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        files += [os.path.join(dirpath, f) for f in filenames if f.endswith(".json")]
    files.sort()

    taken = {}
    for path in files:
        suite = os.path.relpath(os.path.dirname(path), args.root)
        stem = os.path.splitext(os.path.basename(path))[0]
        with open(path) as fh:
            tests = json.load(fh)
        n = 0
        for name in sorted(tests):
            if n >= args.per_file:
                break
            tc = tests[name]
            blocks = tc.get("blocks") or []
            if not blocks:
                continue
            block = blocks[-1]
            if gas_used(block) == 0 or not block.get("statelessInputBytes"):
                continue
            # Keep the harness's label for this block: a multi-block test labels
            # its blocks `name/blockN`, which a one-block copy would lose.
            label = name if len(blocks) == 1 else f"{name}/block{len(blocks) - 1}"
            dst = os.path.join(args.out, suite)
            os.makedirs(dst, exist_ok=True)
            with open(os.path.join(dst, f"{stem}-{n}.json"), "w") as fh:
                json.dump({label: {**tc, "blocks": [block]}}, fh)
            n += 1
        if n:
            taken[suite] = taken.get(suite, 0) + n

    for suite in sorted(taken):
        print(f"{taken[suite]:3d}  {suite}")
    print(f"{sum(taken.values())} block(s) across {len(taken)} suite(s)")
    return 0 if taken else 1


if __name__ == "__main__":
    sys.exit(main())
