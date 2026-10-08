#!/usr/bin/env python3
"""Diff two guest-benchmark CSVs and render the PR comment.

Trace costs are deterministic — the same ELF on the same input always bills the
same cells — so any non-zero delta here is signal, not runner noise. That is what
makes a single CI run worth reporting at all.

Exits non-zero only when a block fails or the two builds disagree on a payload
root: a broken PR should not read as a clean benchmark. Perf movement never
fails the run.
"""

import argparse
import csv
import os
import statistics
import sys

CHIPS = ("total", "main", "opcodes", "precompiles", "memory", "base")

# GitHub's hard limit on issue-comment bodies.
LIMIT = 65536

# Moves smaller than this are treated as flat.
FLAT = 0.005

# Marks by delta (%), negative being an improvement: (upper bound, mark), first
# match wins. Bands grow ~x10, and regressions get more of them than
# improvements because those are what a reviewer has to triage.
BANDS = (
    (-10.0, "🏆"),
    (-2.0, "⭐"),
    (-0.05, "🟢"),
    (0.05, "⚪"),
    (0.5, "🟡"),
    (2.0, "🟠"),
    (float("inf"), "🔴"),
)
LEGEND = ("🏆 ≤ −10% · ⭐ −10…−2% · 🟢 −2…−0.05% · ⚪ within ±0.05% · "
          "🟡 +0.05…+0.5% · 🟠 +0.5…+2% · 🔴 ≥ +2%")


def mark(delta):
    """Colour cue for a delta, where negative is an improvement.

    Emoji rather than a ```diff fence: in diff syntax `-` renders red and `+`
    green, which is inverted for cost deltas and would colour every speedup as
    if it were a regression. The sign is always shown alongside, so the meaning
    does not rest on hue alone.
    """
    if delta is None:
        return "⚪"
    for bound, m in BANDS:
        if delta <= bound if bound < 0 else delta < bound:
            return m
    return BANDS[-1][1]

def load(path):
    rows = {}
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            # Units share block numbers across suites, so block_num alone
            # collapses distinct rows onto each other.
            rows[f"{r.get('label', '')}|{r.get('block_num', '')}"] = r
    return rows


def num(row, col):
    try:
        return int(row[col])
    except (KeyError, ValueError, TypeError):
        return None


def pct(before, after):
    return None if not before else 100.0 * (after - before) / before


def broken(base, head, keys):
    """Keys that failed in either build, and keys whose payload roots differ."""
    # Only if the harness actually reports the column (the RPC-block schema
    # omits it).
    failed = [
        k for k in keys
        if any("success" in row[k] and row[k]["success"] != "1" for row in (base, head))
    ]
    mismatched = [
        k for k in keys
        if base[k].get("payload_root") and base[k].get("payload_root") != head[k].get("payload_root")
    ]
    return failed, mismatched


def render_tier(name, base, head):
    """Median total cost per suite over a gas tier's sampled blocks.

    Empty blocks are left out: they bill only the fixed per-block overhead, so
    they would pull a suite's median toward a number that says nothing about it.
    """
    keys = sorted(k for k in set(base) & set(head)
                  if (num(base[k], "gas_used") or 0) > 0)
    if not keys:
        return [f"#### {name} tier", "", "No comparable blocks were produced.", ""], [], []
    failed, mismatched = broken(base, head, keys)

    suites = {}
    for k in keys:
        b, h = num(base[k], "total"), num(head[k], "total")
        if b is not None and h is not None:
            suites.setdefault(base[k].get("suite", "."), []).append((b, h))

    total_b = sum(num(base[k], "total") or 0 for k in keys)
    total_h = sum(num(head[k], "total") or 0 for k in keys)
    d = pct(total_b, total_h)
    out = [f"#### {name} tier {mark(d)} {'—' if d is None else f'{d:+.3f}%'}", ""]
    out.append(f"Median total cost by suite over {len(keys)} block(s) "
               f"(empty blocks excluded).")
    out.append("")
    if mismatched:
        out.append(f"> [!CAUTION]")
        out.append(f"> **{len(mismatched)} {name} block(s) produced a different payload root "
                   f"than the merge-base build.**")
        out.append("")
    if failed:
        out.append(f"> [!WARNING]")
        out.append(f"> {len(failed)} {name} block(s) did not execute successfully in one or "
                   f"both builds.")
        out.append("")
    # Drop the directory every suite shares (`compute/` today): it is on every
    # row and says nothing.
    common = os.path.commonpath(list(suites)) if len(suites) > 1 else ""
    out.append("| suite | blocks | merge-base | this PR | delta |")
    out.append("|---|---:|---:|---:|---:|")
    for suite in sorted(suites):
        mb = int(statistics.median(b for b, _ in suites[suite]))
        mh = int(statistics.median(h for _, h in suites[suite]))
        sd = pct(mb, mh)
        out.append(f"| {mark(sd)} {os.path.relpath(suite, common) if common else suite} | {len(suites[suite])} | {mb:,} | {mh:,} "
                   f"| {'—' if sd is None else f'{sd:+.3f}%'} |")
    out.append("")
    return out, failed, mismatched


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--base-sha", default="")
    ap.add_argument("--head-sha", default="")
    ap.add_argument("--corpus", default="")
    ap.add_argument("--label", default="", help="Object/target label, e.g. 'ZisK (rv64im+Zbb+Zbs)'")
    # The PR head as of rendering. A run takes minutes, so the branch can move
    # under it; when it has, say so rather than implying the numbers are current.
    ap.add_argument("--current-head", default="")
    # Optional gas-tier run (tests-zkevm-benchmark), reported per suite.
    ap.add_argument("--tier-base", default="")
    ap.add_argument("--tier-head", default="")
    ap.add_argument("--tier-name", default="gas")
    args = ap.parse_args()

    base, head = load(args.base), load(args.head)
    keys = sorted(set(base) & set(head))
    out = []

    if not keys:
        heading = f"### Benchmark — {args.label}" if args.label else "### Benchmark"
        print(f"{heading}\n\nNo comparable blocks were produced.")
        return 1

    # Correctness first: a perf table for a build that computed the wrong root
    # would be actively misleading. Flag when *either* build failed the block.
    failed, mismatched = broken(base, head, keys)

    deltas = []
    for k in keys:
        b, h = num(base[k], "total"), num(head[k], "total")
        if b and h is not None:
            deltas.append((pct(b, h), k))
    deltas.sort()

    total_b = sum(num(base[k], "total") or 0 for k in keys)
    total_h = sum(num(head[k], "total") or 0 for k in keys)
    headline = pct(total_b, total_h)

    stale = bool(args.current_head and args.head_sha
                 and args.current_head != args.head_sha)

    verdict = "no change"
    if headline is not None and abs(headline) >= FLAT:
        verdict = f"{headline:+.3f}% total"
    # Flag staleness in the heading as well as the note below: the heading is
    # what shows in the PR timeline without expanding anything.
    heading = f"### Benchmark{' — ' + args.label if args.label else ''}"
    out.append(f"{heading} {mark(headline)} {verdict}{' — ⚠️ stale' if stale else ''}")
    out.append("")
    out.append(f"`{args.head_sha[:12]}` vs merge-base `{args.base_sha[:12]}` over "
               f"{len(keys)} block(s){f' of {args.corpus}' if args.corpus else ''}.")
    out.append("")

    if stale:
        out.append("> [!NOTE]")
        out.append(f"> These numbers describe `{args.head_sha[:12]}`, but the PR head is now "
                   f"`{args.current_head[:12]}` — new commits landed while the benchmark was "
                   f"running. Re-run `/benchmark` for the current head.")
        out.append("")

    if mismatched:
        out.append(f"> [!CAUTION]")
        out.append(f"> **{len(mismatched)} block(s) produced a different payload root than the "
                   f"merge-base build.** This PR changes consensus output — the numbers below are "
                   f"not a like-for-like comparison.")
        out.append("")
    if failed:
        out.append(f"> [!WARNING]")
        out.append(f"> {len(failed)} block(s) did not execute successfully in one or both builds.")
        out.append("")

    out.append("| | component | merge-base | this PR | delta |")
    out.append("|:--:|---|---:|---:|---:|")
    for c in CHIPS:
        sb = sum(num(base[k], c) or 0 for k in keys)
        sh = sum(num(head[k], c) or 0 for k in keys)
        if sb == 0 and sh == 0:
            continue
        d = pct(sb, sh)
        cell = "—" if d is None else (f"**{d:+.3f}%**" if c == "total" else f"{d:+.3f}%")
        out.append(
            f"| {mark(d)} | {'**' + c + '**' if c == 'total' else c} "
            f"| {sb:,} | {sh:,} | {cell} |"
        )
    out.append("")
    out.append(f"<sub>{LEGEND}</sub>")
    out.append("")

    if deltas:
        improved = sum(1 for d, _ in deltas if d < 0)
        regressed = sum(1 for d, _ in deltas if d > 0)
        out.append(f"🟢 {improved} improved · 🔴 {regressed} regressed · "
                   f"⚪ {len(deltas) - improved - regressed} unchanged "
                   f"(best {deltas[0][0]:+.3f}%, worst {deltas[-1][0]:+.3f}%).")
        out.append("")

    out.append(f"<details><summary>Per-block{f' ({args.corpus})' if args.corpus else ''}</summary>")
    out.append("")
    out.append("| block | merge-base | this PR | delta |")
    out.append("|---|---:|---:|---:|")
    for d, k in sorted(deltas, key=lambda x: x[1]):
        label = k.split("|")[-1] or k
        out.append(
            f"| {mark(d)} {label} | {num(base[k], 'total'):,} "
            f"| {num(head[k], 'total'):,} | {d:+.3f}% |"
        )
    out.append("")
    out.append("</details>")
    out.append("")

    if args.tier_base and args.tier_head:
        tier, tier_failed, tier_mismatched = render_tier(
            args.tier_name, load(args.tier_base), load(args.tier_head))
        out += tier
        failed += tier_failed
        mismatched += tier_mismatched

    out.append("<sub>Trace costs are deterministic, so these deltas carry no run-to-run noise. "
               "A handful of blocks is a smoke signal, not a verdict — the full corpus stays the "
               "arbiter for anything perf-sensitive.</sub>")

    body = "\n".join(out)
    # GitHub rejects comments over 65536 characters outright. The sections are
    # all bounded, so this should never trigger — but losing the whole comment
    # to a hard API error is a bad way to find out otherwise.
    if len(body) > LIMIT:
        body = body[: LIMIT - 200] + "\n\n<sub>Output truncated.</sub>\n"

    print(body)
    return 1 if (failed or mismatched) else 0


if __name__ == "__main__":
    sys.exit(main())
