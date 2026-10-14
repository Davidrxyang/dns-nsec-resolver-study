"""Run catalogued experiments against the local pipeline, or render the catalog.

  venv/bin/python -m experiments run [--only N01,N03] [--slow]
  venv/bin/python -m experiments catalog        # rewrite experiments/CATALOG.md

Each run writes results/<UTC time>/: env.json, results.jsonl (one line per
experiment, with every probe), and summary.md. Results are diagnostics.
"""

import argparse
import dataclasses
import json
import time
from pathlib import Path

from . import harness
from .catalog import CATALOG

CATALOG_MD = Path(__file__).with_name("CATALOG.md")


def run(args):
    wanted = set(args.only.split(",")) if args.only else None
    chosen = [e for e in CATALOG if e.run and (wanted is None or e.id in wanted)
              and (args.slow or not e.slow or (wanted and e.id in wanted))]
    out = harness.REPO / "results" / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out.mkdir(parents=True)
    (out / "env.json").write_text(json.dumps(harness.environment(), indent=2) + "\n")

    rows = []
    with (out / "results.jsonl").open("w") as f:
        for e in chosen:
            harness.flush_cache()
            ctx = harness.Context()
            try:
                outcome, matches, notes = e.run(ctx)
            except Exception as ex:
                outcome, matches, notes = f"error: {type(ex).__name__}: {ex}", None, ""
            rec = {"id": e.id, "title": e.title, "expected": e.expected, "outcome": outcome,
                   "matches_expectation": matches, "notes": notes,
                   "probes": [dataclasses.asdict(p) for p in ctx.probes]}
            f.write(json.dumps(rec) + "\n")
            mark = {True: "yes", False: "NO", None: "-"}[matches]
            rows.append((e.id, e.title, outcome, mark, notes))
            print(f"{e.id}  {outcome:<14} expected? {mark:<4} {e.title}" + (f"  [{notes}]" if notes else ""))

    lines = ["| ID | Experiment | Outcome | Matches expectation | Notes |", "|---|---|---|---|---|"]
    lines += [f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} |" for r in rows]
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    print(f"\nresults: {out.relative_to(harness.REPO)}")


def catalog(_args):
    lines = [
        "# Experiment catalog",
        "",
        "Generated from `experiments/catalog.py` by `venv/bin/python -m experiments catalog`; edit that file, not this one.",
        "Zone: `nsec.test` (vanilla NSEC). Resolver: BIND in the local Docker pipeline. Results are diagnostics, written to `results/<time>/` (gitignored).",
        "",
        "| ID | Status | Title | Expected | Sources |",
        "|---|---|---|---|---|",
    ]
    for e in CATALOG:
        status = "planned" if e.run is None else ("runnable (slow)" if e.slow else "runnable")
        lines.append(f"| {e.id} | {status} | {e.title} | {e.expected} | {e.sources} |")
    lines.append("")
    for e in CATALOG:
        lines += [f"## {e.id}: {e.title}", "",
                  f"- **Question:** {e.question}",
                  f"- **Method:** {e.method}",
                  f"- **Expected:** {e.expected}",
                  f"- **Sources:** {e.sources}", ""]
    CATALOG_MD.write_text("\n".join(lines))
    print(f"wrote {CATALOG_MD.relative_to(harness.REPO)} ({len(CATALOG)} entries)")


def main():
    p = argparse.ArgumentParser(prog="python -m experiments")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run experiments against the running pipeline")
    r.add_argument("--only", help="comma-separated IDs, e.g. N01,N06")
    r.add_argument("--slow", action="store_true", help="include slow experiments (N12 waits 65 s)")
    r.set_defaults(fn=run)
    sub.add_parser("catalog", help="rewrite experiments/CATALOG.md").set_defaults(fn=catalog)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
