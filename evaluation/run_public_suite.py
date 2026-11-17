"""
Public URL demonstration suite (evaluation/datasets/public_urls.json).

Runs every case through the dashboard's Live URL Analyzer, i.e. the same
pipeline the extension uses, with the real BERT model and live page fetching.

    # in-process, real models, from this computer's network
    python -m evaluation.run_public_suite
    # against a deployed server (e.g. the Hugging Face Space)
    python -m evaluation.run_public_suite --base-url https://<user>-phishguard-backend.hf.space

Results: evaluation/results/public_suite_<tag>/results.json and results.csv.
A case passes when the verdict equals ``expect`` (``NOT_SAFE`` accepts
WARNING or BLOCK_RENDER).  Network failures are recorded, not hidden.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUITE = ROOT / "evaluation" / "datasets" / "public_urls.json"


def passes(expect: str, verdict: str) -> bool:
    return verdict in ("WARNING", "BLOCK_RENDER") if expect == "NOT_SAFE" else verdict == expect


def run(client, cases: list[dict]) -> list[dict]:
    rows = []
    for case in cases:
        body = {"url": case["url"], "page_text": case.get("text"), "fetch_page": "text" not in case}
        started = time.perf_counter()
        response = client.post("/api/v1/dashboard/analyze", json=body)
        wall = round((time.perf_counter() - started) * 1000, 1)
        data = response.json()
        if response.status_code != 200:
            rows.append({**case, "verdict": f"HTTP {response.status_code}", "passed": False, "note": str(data)[:200]})
            continue
        fetch = next((s for s in data["steps"] if s["name"] == "Live page fetch"), None)
        rows.append({
            "id": case["id"], "group": case["group"], "url": case["url"], "expect": case["expect"],
            "verdict": data["verdict"], "rule": data["rule"] or "", "headline": data["headline"],
            "risk_score": data["risk_score"],
            "bert_p_phishing": None if data["bert"].get("skipped") else data["bert"]["phishing_probability"],
            "fetch": "" if fetch is None else f"{fetch['status']}: {fetch['detail']}",
            "passed": passes(case["expect"], data["verdict"]),
            "server_ms": data["processing_time_ms"], "wall_ms": wall,
        })
        print(f"{case['id']} {'PASS' if rows[-1]['passed'] else 'FAIL'} {data['verdict']:12} {data['rule'] or '':32} {case['url']}")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=None, help="Remote server; omit to run in-process with real models.")
    parser.add_argument("--key", default=os.getenv("PHISHGUARD_ADMIN_KEY", "12345678"))
    parser.add_argument("--tag", default="v4.0.0")
    args = parser.parse_args()
    cases = json.loads(SUITE.read_text(encoding="utf-8"))["cases"]

    if args.base_url:
        import httpx

        with httpx.Client(base_url=args.base_url, timeout=60, headers={"Authorization": f"Bearer {args.key}"}) as client:
            rows = run(client, cases)
        where = args.base_url
    else:
        os.environ.setdefault("PHISHGUARD_DB_PATH", ":memory:")
        os.environ.setdefault("PHISHGUARD_RATE_LIMIT", "1000/minute")
        os.chdir(ROOT)
        from fastapi.testclient import TestClient

        from main import app

        with TestClient(app, base_url="https://local") as client:
            client.headers["Authorization"] = f"Bearer {args.key}"
            rows = run(client, cases)
        where = "in-process (evaluation machine network)"

    out = ROOT / "evaluation" / "results" / f"public_suite_{args.tag}"
    out.mkdir(parents=True, exist_ok=True)
    summary = {
        "where": where, "run_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "cases": len(rows),
        "passed": sum(r["passed"] for r in rows),
        "by_group": {g: {"n": sum(r["group"] == g for r in rows), "passed": sum(r["group"] == g and r["passed"] for r in rows)}
                     for g in dict.fromkeys(r["group"] for r in rows)},
        "rows": rows,
    }
    (out / "results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    with (out / "results.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\n{summary['passed']}/{summary['cases']} cases passed -> {out}")


if __name__ == "__main__":
    main()
