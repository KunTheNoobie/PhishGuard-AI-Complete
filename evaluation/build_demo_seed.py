"""
Build database/demo_threat_intel.json, the curated demonstration dataset loaded into an empty database.

Contents
  * OpenPhish community-feed URLs (https://github.com/openphish/public_feed), analysed by the real
    pipeline from the URL alone: the pages are NOT downloaded, so nothing malicious is fetched.
    Only URLs the pipeline blocks are kept; the verdict, rule and scores stored are the real results.
  * Everyday safe / plain-HTTP rows taken from the public URL suite results (real verdicts).
  * 45 demonstration Malaysian mule-account records (fictitious numbers in valid bank formats).
  * Mule-account and QR rows analysed by the real pipeline.

Run:  python -m evaluation.build_demo_seed        (needs internet for the feed)
"""
from __future__ import annotations

import json
import os
import random
import re
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
FEED = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
OUT = ROOT / "database" / "demo_threat_intel.json"

BANK_FORMATS = [  # (bank, digit length) — typical Malaysian account lengths
    ("Maybank", 12), ("CIMB Bank", 10), ("CIMB Bank", 14), ("Public Bank", 10), ("RHB Bank", 14),
    ("Hong Leong Bank", 11), ("AmBank", 13), ("Bank Islam", 14), ("BSN", 16), ("Bank Rakyat", 12),
    ("Alliance Bank", 15), ("Affin Bank", 12), ("UOB Malaysia", 10), ("OCBC Malaysia", 10),
    ("Agrobank", 12), ("Bank Muamalat", 14), ("MBSB Bank", 14), ("GXBank", 10), ("Touch 'n Go eWallet", 11),
]
PLATFORMS = ["Shopee", "Carousell", "Facebook Marketplace", "WhatsApp", "Telegram", "Mudah.my", "Lazada",
             "Instagram", "PDRM Semakmule", "NSRC 997", "User Report"]


def mules(n: int = 45) -> list[list]:
    rng = random.Random(20261117)
    seen, rows = set(), []
    while len(rows) < n:
        bank, length = BANK_FORMATS[len(rows) % len(BANK_FORMATS)]
        number = str(rng.randint(1, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(length - 1))
        if number in seen:
            continue
        seen.add(number)
        rows.append([number, bank, rng.choice(PLATFORMS), rng.randint(1, 26)])
    return rows


def main() -> None:
    os.environ.setdefault("PHISHGUARD_DB_PATH", ":memory:")
    os.environ.setdefault("PHISHGUARD_RATE_LIMIT", "10000/minute")
    os.chdir(ROOT)
    from fastapi.testclient import TestClient

    from main import app

    feed = urllib.request.urlopen(urllib.request.Request(FEED, headers={"User-Agent": "research-client"}), timeout=30).read().decode()
    urls, seen_hosts = [], set()
    for line in feed.splitlines():
        parts = urlsplit(line.strip())
        if parts.scheme in ("http", "https") and parts.hostname and parts.hostname not in seen_hosts:
            seen_hosts.add(parts.hostname)
            urls.append(f"{parts.scheme}://{parts.netloc}{parts.path}")
    urls = urls[:150]

    rows: list[dict] = []
    with TestClient(app, base_url="https://local") as c:
        c.headers["Authorization"] = "Bearer 12345678"
        for u in urls:
            d = c.post("/api/v1/dashboard/analyze", json={"url": u, "fetch_page": False}).json()
            if d.get("verdict") in ("BLOCK_RENDER", "WARNING"):
                rows.append({"source": "extension", "url": u, "verdict": d["verdict"], "rule": d["rule"], "risk_score": d["risk_score"],
                             "bert_score": None if d["bert"].get("skipped") else d["bert"]["phishing_probability"],
                             "headline": d["headline"], "latency_ms": d["processing_time_ms"], "origin": "OpenPhish feed"})
        feed_rows = sorted(rows, key=lambda r: r["verdict"] != "BLOCK_RENDER")[:14]

        extra = []
        for body, src, label in [
            ({"url": "https://maybank2u.com.my@evil-login.top/login", "fetch_page": False}, "dashboard", "@ spoof"),
            ({"url": "https://parcel-customs-pay.top/", "fetch_page": False, "account_number": "112233445566",
              "page_text": "Pay the customs fee to account 1122 3344 5566 to release your parcel."}, "extension", "mule"),
        ]:
            d = c.post("/api/v1/dashboard/analyze", json=body).json()
            extra.append({"source": src, "url": body["url"], "verdict": d["verdict"], "rule": d["rule"], "risk_score": d["risk_score"],
                          "bert_score": None if d["bert"].get("skipped") else d["bert"]["phishing_probability"],
                          "headline": d["headline"], "latency_ms": d["processing_time_ms"], "origin": label})
        qr = c.post("/api/v1/dashboard/analyze", json={"url": "https://maybank2u.com.my@evil-login.top/secure", "fetch_page": False}).json()
        extra.append({"source": "qr", "url": "https://maybank2u.com.my@evil-login.top/secure", "verdict": qr["verdict"], "rule": qr["rule"],
                      "risk_score": qr["risk_score"], "bert_score": None, "headline": qr["headline"], "latency_ms": qr["processing_time_ms"],
                      "origin": "QR payload"})

    suite = json.loads((ROOT / "evaluation/results/public_suite_v4.0.0/results.json").read_text(encoding="utf-8"))["rows"]
    pub = [r for r in suite if r["group"] in ("live_https_legitimate", "live_http_insecure", "live_tls_error") and r["verdict"] in ("SAFE", "WARNING")]
    pub_rows = [{"source": "extension" if i % 2 else "dashboard", "url": re.sub(r"\?.*", "", r["url"]), "verdict": r["verdict"],
                 "rule": r["rule"] or None, "risk_score": r["risk_score"], "bert_score": r["bert_p_phishing"],
                 "headline": r["headline"], "latency_ms": r["server_ms"], "origin": "public suite"} for i, r in enumerate(pub)]

    scans = extra + feed_rows + pub_rows[:13]
    scans = scans[:30] if len(scans) > 30 else scans
    random.Random(7).shuffle(scans)
    OUT.write_text(json.dumps({
        "note": "Curated evaluation / threat-intelligence demonstration records. OpenPhish URLs come from the public community feed "
                "(pages were not downloaded); mule accounts are fictitious numbers in valid Malaysian bank formats.",
        "feed": FEED, "mule_accounts": mules(), "scans": scans,
        "openphish_urls_analysed": len(urls), "openphish_blocked_from_url_alone": len([r for r in rows if r["verdict"] == "BLOCK_RENDER"]),
    }, indent=1), encoding="utf-8")
    from collections import Counter
    print(len(scans), "scans;", Counter(s["verdict"] for s in scans), Counter(s["origin"] for s in scans))
    print("openphish analysed:", len(urls), "blocked:", len([r for r in rows if r["verdict"] == "BLOCK_RENDER"]))


if __name__ == "__main__":
    main()
