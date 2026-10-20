#!/usr/bin/env python3
"""ZeroTrustVault attack-lab runner.

Usage:
    python runner.py --both-modes
    python runner.py --mode zerotrustvault
    python runner.py --mode baseline --only a1,a4

Switches the server MODE (POST /api/admin/mode), waits for /api/health, runs the
six attacks, prints a table (Attack | Baseline | ZeroTrustVault | PASS), writes
eval/results/attack_results.{json,md}, and exits non-zero if any row is not PASS.

A row PASSES when the attack SUCCEEDS in baseline AND is BLOCKED in zerotrustvault.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import common as C
from attacks import ATTACKS, resolve

RESULTS_DIR = Path("/eval/results")
if not RESULTS_DIR.parent.exists():
    RESULTS_DIR = C._repo_root() / "eval" / "results"


def run_mode(mode: str, modules) -> dict:
    switched = C.set_mode(mode)
    healthy = C.wait_for_health(timeout=90)
    out = {}
    for m in modules:
        if not healthy:
            out[m.NAME] = C.Result(m.NAME, mode, detail="server never became healthy", error="no health")
            continue
        try:
            res = m.run(mode)
        except Exception as e:  # noqa: BLE001  (defensive; attacks already guard)
            res = C.errored(m.NAME, mode, e)
        out[m.NAME] = res
        print(f"  [{mode}] {m.NAME:16s} -> {res.status:9s} {'(as expected)' if res.as_expected else '(UNEXPECTED)' if res.as_expected is not None else '(error)'}")
    out["_meta"] = {"mode": mode, "mode_switch_ok": switched, "healthy": healthy}
    return out


def build_rows(modules, by_mode: dict) -> list[dict]:
    rows = []
    for m in modules:
        base = by_mode.get("baseline", {}).get(m.NAME)
        ztv = by_mode.get("zerotrustvault", {}).get(m.NAME)
        base_ok = base is not None and base.succeeded and base.error is None
        ztv_ok = ztv is not None and (not ztv.succeeded) and ztv.error is None
        if "baseline" in by_mode and "zerotrustvault" in by_mode:
            passed = base_ok and ztv_ok
        elif "zerotrustvault" in by_mode:
            passed = ztv_ok
        else:
            passed = base_ok
        rows.append({
            "attack": m.NAME, "title": getattr(m, "TITLE", m.NAME),
            "baseline": base.status if base else "-",
            "zerotrustvault": ztv.status if ztv else "-",
            "blocked_by": (ztv.blocked_by if ztv else "") or "",
            "pass": passed,
            "baseline_detail": base.detail if base else "",
            "ztv_detail": ztv.detail if ztv else "",
        })
    return rows


def print_table(rows: list[dict]) -> None:
    headers = ["Attack", "Baseline", "ZeroTrustVault", "Blocked by", "PASS"]
    data = [[r["attack"], r["baseline"], r["zerotrustvault"], r["blocked_by"][:38],
             "PASS" if r["pass"] else "FAIL"] for r in rows]
    try:
        from rich.console import Console
        from rich.table import Table
        t = Table(title="ZeroTrustVault — attack simulation", show_lines=False)
        for h in headers:
            t.add_column(h)
        for r, d in zip(rows, data):
            style = "green" if r["pass"] else "red"
            t.add_row(*d, style=style)
        Console().print(t)
    except Exception:
        from tabulate import tabulate
        print(tabulate(data, headers=headers, tablefmt="github"))


def write_reports(rows: list[dict], by_mode: dict) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "summary": {"total": len(rows), "passed": sum(1 for r in rows if r["pass"])},
        "rows": rows,
        "raw": {mode: {k: (v.as_dict() if isinstance(v, C.Result) else v) for k, v in res.items()}
                for mode, res in by_mode.items()},
    }
    (RESULTS_DIR / "attack_results.json").write_text(json.dumps(payload, indent=2))
    md = ["# ZeroTrustVault — attack simulation results", "",
          f"**{payload['summary']['passed']}/{payload['summary']['total']} attacks PASS** "
          "(baseline SUCCEEDS and zerotrustvault BLOCKS).", "",
          "| Attack | Baseline | ZeroTrustVault | Blocked by | PASS |",
          "|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['title']} (`{r['attack']}`) | {r['baseline']} | {r['zerotrustvault']} "
                  f"| {r['blocked_by']} | {'✅' if r['pass'] else '❌'} |")
    md += ["", "## Detail", ""]
    for r in rows:
        md.append(f"### {r['title']} (`{r['attack']}`)")
        md.append(f"- baseline: {r['baseline_detail']}")
        md.append(f"- zerotrustvault: {r['ztv_detail']}")
        md.append("")
    (RESULTS_DIR / "attack_results.md").write_text("\n".join(md))
    print(f"\nwrote {RESULTS_DIR/'attack_results.json'} and .md")


def main() -> int:
    ap = argparse.ArgumentParser(description="ZeroTrustVault attack lab")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--both-modes", action="store_true")
    g.add_argument("--mode", choices=C.MODES)
    ap.add_argument("--only", help="comma list of attack keys, e.g. a1,a4 or a1_idor")
    args = ap.parse_args()

    modules = ATTACKS
    if args.only:
        modules = [resolve(tok) for tok in args.only.split(",") if tok.strip()]

    modes = list(C.MODES) if (args.both_modes or not args.mode) else [args.mode]
    by_mode = {}
    for mode in modes:
        print(f"\n=== MODE: {mode} ===")
        by_mode[mode] = run_mode(mode, modules)

    rows = build_rows(modules, by_mode)
    print()
    print_table(rows)
    write_reports(rows, by_mode)

    all_pass = all(r["pass"] for r in rows)
    print(f"\n{'ALL ROWS PASS' if all_pass else 'SOME ROWS FAILED'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
