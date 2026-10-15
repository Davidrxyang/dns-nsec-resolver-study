"""Run catalogued experiments against the local pipeline, or render the catalog.

  venv/bin/python -m experiments run [--resolver bind|knot|all] [--only N01,N03] [--slow]
  venv/bin/python -m experiments catalog        # rewrite experiments/CATALOG.md

Each run writes results/<UTC time>/: env.json, results.jsonl (one line per
experiment and resolver, with every probe), and summary.md. Results are
diagnostics. With --resolver all (the default), each resolver runs the whole
selection in turn, so a resolver's cache is never touched by another's probes.
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
    names = list(harness.RESOLVERS) if args.resolver == "all" else [args.resolver]
    resolvers = [harness.RESOLVERS[n] for n in names]
    out = harness.REPO / "results" / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out.mkdir(parents=True)
    (out / "env.json").write_text(json.dumps(harness.environment(resolvers), indent=2) + "\n")

    rows = []
    with (out / "results.jsonl").open("w") as f:
        for resolver in resolvers:
            print(f"== {resolver.name} ({resolver.ip})")
            for e in chosen:
                harness.flush_cache(resolver)
                ctx = harness.Context(resolver)
                try:
                    outcome, matches, notes = e.run(ctx)
                except Exception as ex:
                    outcome, matches, notes = f"error: {type(ex).__name__}: {ex}", None, ""
                expected = e.expected_by.get(resolver.name, e.expected)
                if e.anc and not resolver.anc_in_lab:
                    matches = None
                    notes = f"[lab artifact: {resolver.lab_note}] " + notes
                rec = {"resolver": resolver.name, "id": e.id, "title": e.title, "expected": expected,
                       "outcome": outcome, "matches_expectation": matches, "notes": notes,
                       "probes": [dataclasses.asdict(p) for p in ctx.probes]}
                f.write(json.dumps(rec) + "\n")
                mark = {True: "yes", False: "NO", None: "-"}[matches]
                rows.append((resolver.name, e.id, e.title, outcome, mark, notes))
                print(f"{e.id:<6} {outcome:<14} expected? {mark:<4} {e.title}" + (f"  [{notes}]" if notes else ""))

    lines = ["| Resolver | ID | Experiment | Outcome | Matches expectation | Notes |",
             "|---|---|---|---|---|---|"]
    lines += [f"| {' | '.join(r)} |" for r in rows]
    if len(resolvers) > 1:                      # side-by-side outcomes
        by = {(r[0], r[1]): r[3] for r in rows}
        lines += ["", "| ID | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
        lines += [f"| {e.id} | " + " | ".join(by[(n, e.id)] for n in names) + " |" for e in chosen]
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    print(f"\nresults: {out.relative_to(harness.REPO)}")


def catalog(_args):
    lines = [
        "# Experiment catalog",
        "",
        "Generated from `experiments/catalog.py` by `venv/bin/python -m experiments catalog`; edit that file, not this one.",
        "Zones: see the ID prefixes in `experiments/catalog.py`. Resolvers: BIND, Knot Resolver and PowerDNS Recursor in the local Docker pipeline (`run --resolver bind|knot|pdns|all`). Results are diagnostics, written to `results/<time>/` (gitignored).",
        "",
        "Expected applies to every resolver unless a resolver-specific expectation is listed. ANC experiments are reported as lab artifacts for resolvers whose lab routing disables aggressive caching (see `RESOLVERS` in experiments/harness.py).",
        "",
        "| ID | Status | Title | Expected | Resolver-specific | ANC | Sources |",
        "|---|---|---|---|---|---|---|",
    ]
    for e in CATALOG:
        status = "planned" if e.run is None else ("runnable (slow)" if e.slow else "runnable")
        specific = "; ".join(f"**{k}**: {v}" for k, v in e.expected_by.items()) or "—"
        lines.append(f"| {e.id} | {status} | {e.title} | {e.expected} | {specific} | {'yes' if e.anc else 'no'} | {e.sources} |")
    lines.append("")
    for e in CATALOG:
        lines += [f"## {e.id}: {e.title}", "",
                  f"- **Question:** {e.question}",
                  f"- **Method:** {e.method}",
                  f"- **Expected:** {e.expected}"]
        lines += [f"- **Expected ({k}):** {v}" for k, v in e.expected_by.items()]
        lines += [f"- **Tests aggressive negative caching:** {'yes' if e.anc else 'no'}",
                  f"- **Sources:** {e.sources}", ""]
    CATALOG_MD.write_text("\n".join(lines))
    print(f"wrote {CATALOG_MD.relative_to(harness.REPO)} ({len(CATALOG)} entries)")


def main():
    p = argparse.ArgumentParser(prog="python -m experiments")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run experiments against the running pipeline")
    r.add_argument("--resolver", default="all", choices=[*harness.RESOLVERS, "all"],
                   help="resolver to test (default: all, one after another)")
    r.add_argument("--only", help="comma-separated IDs, e.g. N01,N06")
    r.add_argument("--slow", action="store_true", help="include slow experiments (N12 waits 65 s)")
    r.set_defaults(fn=run)
    sub.add_parser("catalog", help="rewrite experiments/CATALOG.md").set_defaults(fn=catalog)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
