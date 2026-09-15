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
import re
import sys
from collections import defaultdict

CHIPS = ("total", "main", "opcodes", "precompiles", "memory", "base")

# GitHub's hard limit on issue-comment bodies.
LIMIT = 65536

# Moves smaller than this are treated as flat.
FLAT = 0.005


def mark(delta):
    """Colour cue for a delta, where negative is an improvement.

    Emoji rather than a ```diff fence: in diff syntax `-` renders red and `+`
    green, which is inverted for cost deltas and would colour every speedup as
    if it were a regression. The sign is always shown alongside, so the meaning
    does not rest on hue alone.
    """
    if delta is None:
        return "⚪"
    if delta <= -FLAT:
        return "🟢"
    if delta >= FLAT:
        return "🔴"
    return "⚪"

FUNC_ROW = re.compile(r"\s*([\d,]+)\s+[\d.]+%\s+([\d,]+)\s+([\d,]+)\s+(\S+)")


def top_functions(path):
    """Parse the `TOP STEP FUNCTIONS` table out of a `ziskemu -X -S` report."""
    steps = defaultdict(int)
    inside = False
    with open(path) as fh:
        for line in fh:
            if line.startswith("TOP STEP FUNCTIONS"):
                inside = True
                continue
            if not inside or line.startswith("---"):
                continue
            m = FUNC_ROW.match(line)
            if not m:
                if not line.strip() and steps:
                    break
                continue
            # Anonymous-struct ids are assigned per build and shift when
            # unrelated code changes. Without stripping them, every function
            # reads as simultaneously removed and added.
            steps[re.sub(r"__anon_\d+", "", m.group(4))] += int(m.group(1).replace(",", ""))
    return steps


def function_section(base_report, head_report, limit=12):
    base, head = top_functions(base_report), top_functions(head_report)
    common = set(base) & set(head)
    rows = [(head[k] - base[k], base[k], head[k], k) for k in common if base[k] != head[k]]
    if not rows:
        return ["_No per-function step movement._", ""]
    rows.sort(key=lambda r: r[0])
    movers = rows[:limit] + rows[-limit:] if len(rows) > 2 * limit else rows
    seen, out = set(), []
    out.append("| function | merge-base | this PR | delta |")
    out.append("|---|---:|---:|---:|")
    for d, b, h, k in movers:
        if k in seen:
            continue
        seen.add(k)
        out.append(f"| `{k}` | {b:,} | {h:,} | {d:+,} ({100 * d / b:+.2f}%) |")
    out.append("")
    only = (set(base) ^ set(head))
    if only:
        out.append(f"<sub>{len(only)} function(s) appear in only one build.</sub>")
        out.append("")
    return out


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--base-sha", default="")
    ap.add_argument("--head-sha", default="")
    ap.add_argument("--corpus", default="")
    # Detail pass (single vector, `ziskemu -X -S`): optional, so the aggregate
    # comparison still renders if the detail run was skipped or failed.
    ap.add_argument("--base-report")
    ap.add_argument("--head-report")
    ap.add_argument("--opcode-diff")
    ap.add_argument("--detail-label", default="the guest vector")
    # The PR head as of rendering. A run takes minutes, so the branch can move
    # under it; when it has, say so rather than implying the numbers are current.
    ap.add_argument("--current-head", default="")
    args = ap.parse_args()

    base, head = load(args.base), load(args.head)
    keys = sorted(set(base) & set(head))
    out = []

    if not keys:
        print("### Benchmark\n\nNo comparable blocks were produced.")
        return 1

    # Correctness first: a perf table for a build that computed the wrong root
    # would be actively misleading.
    # Flag when *either* build failed the block, and only if the harness
    # actually reports the column (the RPC-block schema omits it).
    failed = [
        k for k in keys
        if any("success" in row[k] and row[k]["success"] != "1" for row in (base, head))
    ]
    mismatched = [
        k for k in keys
        if base[k].get("payload_root") and base[k].get("payload_root") != head[k].get("payload_root")
    ]

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
    out.append(f"### Benchmark {mark(headline)} {verdict}{' — ⚠️ stale' if stale else ''}")
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

    if deltas:
        improved = sum(1 for d, _ in deltas if d < 0)
        regressed = sum(1 for d, _ in deltas if d > 0)
        out.append(f"🟢 {improved} improved · 🔴 {regressed} regressed · "
                   f"⚪ {len(deltas) - improved - regressed} unchanged "
                   f"(best {deltas[0][0]:+.3f}%, worst {deltas[-1][0]:+.3f}%).")
        out.append("")

    out.append("<details><summary>Per-block</summary>")
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

    # Per-opcode and per-function detail come from a single vector rather than
    # the whole set, so label it: it answers "what moved", not "how much".
    if args.base_report and args.head_report:
        out.append(f"<details><summary>What moved — by function ({args.detail_label})</summary>")
        out.append("")
        try:
            out.extend(function_section(args.base_report, args.head_report))
        except OSError as e:
            out.append(f"_Per-function detail unavailable: {e}._")
            out.append("")
        out.append("</details>")
        out.append("")

    if args.opcode_diff:
        out.append(f"<details><summary>What moved — by opcode ({args.detail_label})</summary>")
        out.append("")
        out.append("```")
        try:
            with open(args.opcode_diff) as fh:
                out.append(fh.read().rstrip())
        except OSError as e:
            out.append(f"unavailable: {e}")
        out.append("```")
        out.append("")
        out.append("</details>")
        out.append("")

    out.append("<sub>Trace costs are deterministic, so these deltas carry no run-to-run noise. "
               "A handful of blocks is a smoke signal, not a verdict — the full corpus stays the "
               "arbiter for anything perf-sensitive.</sub>")

    body = "\n".join(out)
    # GitHub rejects comments over 65536 characters outright. The sections are
    # all bounded, so this should never trigger — but losing the whole comment
    # to a hard API error is a bad way to find out otherwise.
    if len(body) > LIMIT:
        keep = body.split("<details><summary>What moved — by opcode")[0]
        body = keep + (
            "<sub>Per-opcode detail omitted to stay under GitHub's comment size "
            "limit — see the workflow artifacts for the full report.</sub>\n"
        )
        if len(body) > LIMIT:
            body = body[: LIMIT - 200] + "\n\n<sub>Output truncated.</sub>\n"

    print(body)
    return 1 if (failed or mismatched) else 0


if __name__ == "__main__":
    sys.exit(main())
