"""
Build database/demo_threat_intel.json, the curated demonstration dataset loaded into an empty database.

Every scan row is produced by the REAL pipeline (real BERT, and the YOLO logo detector for screenshot cases), so
verdicts, rules and scores are genuine. Pages are never downloaded for the phishing-style addresses: they are judged
from the address, the supplied text/form and the screenshot only.

  * about 43 scans across SAFE / WARNING / BLOCK_RENDER, rules R1, R2, R3, R4, R6, R7, R8, R9, H1, H2, W1, W3, and the
    extension / dashboard / qr sources (QR codes are real PNGs decoded by the QR scanner);
  * R8 rows use real bank screenshots (the local YOLO model), on unrelated look-alike addresses;
  * ~65 curated Malaysian mule-account records (banks, e-wallets, DuitNow phone numbers; fictitious numbers);
  * pending user reports for the review queue.

Run:  python -m evaluation.build_demo_seed
"""
from __future__ import annotations

import base64
import json
import os
import random
import sqlite3
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "database" / "demo_threat_intel.json"
# Bank screenshots for the R8 rows are a local input (not in the repository); rows without a screenshot are skipped.
SHOTS = Path(os.environ.get("PHISHGUARD_DEMO_SHOTS", ROOT / "evaluation" / "demo_screenshots"))

BANK_FORMATS = [
    ("Maybank", 12), ("CIMB Bank", 10), ("CIMB Bank", 14), ("Public Bank", 10), ("RHB Bank", 14), ("Hong Leong Bank", 11),
    ("AmBank", 13), ("Bank Islam", 14), ("BSN", 16), ("Bank Rakyat", 12), ("Alliance Bank", 15), ("Affin Bank", 12),
    ("UOB Malaysia", 10), ("OCBC Malaysia", 10), ("Agrobank", 12), ("Bank Muamalat", 14), ("MBSB Bank", 14), ("GXBank", 10),
    ("AEON Bank", 12), ("Boost Bank", 11), ("Touch 'n Go eWallet", 11), ("GrabPay", 11), ("ShopeePay", 12),
]
PLATFORMS = ["Shopee", "Carousell", "Facebook Marketplace", "WhatsApp", "Telegram", "Mudah.my", "Lazada", "Instagram",
             "PDRM Semakmule", "NSRC 997", "User Report", "TikTok Shop", "Pos Laju parcel scam", "Love scam", "Investment scam"]


def mules() -> list[list]:
    rng = random.Random(20261124)
    seen, rows = set(), []
    while len(rows) < 52:                                   # bank and e-wallet accounts
        bank, length = BANK_FORMATS[len(rows) % len(BANK_FORMATS)]
        number = str(rng.randint(1, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(length - 1))
        if number not in seen:
            seen.add(number)
            rows.append([number, bank, rng.choice(PLATFORMS), rng.randint(1, 31), rng.randint(2, 70)])
    for _ in range(13):                                     # DuitNow phone numbers (compact 60-prefixed form)
        number = "601" + str(rng.choice([1, 2, 3, 4, 6, 7, 8, 9])) + "".join(str(rng.randint(0, 9)) for _ in range(7))
        if number not in seen:
            seen.add(number)
            rows.append([number, "DuitNow phone", rng.choice(PLATFORMS), rng.randint(1, 18), rng.randint(2, 70)])
    return rows                                             # [account, bank, platform, report_count, days_ago]


def png_b64(name: str) -> str | None:
    p = SHOTS / name
    return "data:image/png;base64," + base64.b64encode(p.read_bytes()).decode() if p.exists() else None


def main() -> None:
    os.environ["PHISHGUARD_DB_PATH"] = str(Path(tempfile.mkdtemp()) / "build.db")
    os.environ["PHISHGUARD_SEED_DEMO"] = "false"
    os.environ["PHISHGUARD_RATE_LIMIT"] = "10000/minute"
    os.environ["PHISHGUARD_ENABLE_VISUAL"] = "true"
    os.chdir(ROOT)
    import cv2
    import numpy as np
    from fastapi.testclient import TestClient

    from main import app

    form = "<html><body><form><input type='text' name='u'><input type='password' name='p'></form></body></html>"
    login = "Log in to your account. Enter your username and password to continue."
    FOREIGN = "https://secure-login-verify.example/login"

    def qr(text: str) -> str:
        img = cv2.QRCodeEncoder.create().encode(text)
        img = cv2.copyMakeBorder(cv2.resize(img, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST), 32, 32, 32, 32, cv2.BORDER_CONSTANT, value=255)
        return "data:image/png;base64," + base64.b64encode(cv2.imencode(".png", img)[1].tobytes()).decode()

    with TestClient(app, base_url="https://local") as c:
        c.headers["Authorization"] = "Bearer 12345678"
        ext = lambda url, **kw: c.post("/api/v1/analyze", json={"url": url, **kw})                       # noqa: E731
        dash = lambda url, **kw: c.post("/api/v1/dashboard/analyze", json={"url": url, "fetch_page": False, **kw})  # noqa: E731
        qrs = lambda text: c.post("/api/v1/dashboard/qr-scan", json={"image_base64": qr(text)})          # noqa: E731

        # ── SAFE: official and everyday HTTPS sites
        for url in ["https://www.maybank2u.com.my/", "https://www.cimbclicks.com.my/", "https://www.pbebank.com/", "https://www.gxbank.my/",
                    "https://www.hlb.com.my/", "https://www.rhbgroup.com/", "https://www.bnm.gov.my/", "https://www.tngdigital.com.my/"]:
            ext(url, dom_content="<html><body>Welcome</body></html>", text_content="Welcome to online banking")
        dash("https://example.com/")
        dash("https://en.wikipedia.org/wiki/Phishing")
        ext("https://www.example.org/", dom_content="<html><body>hello</body></html>", text_content="hello")
        qrs("https://www.maybank2u.com.my/")
        # ── WARNING: plain HTTP, certificate, uncorroborated
        for url in ["http://neverssl.com/", "http://httpforever.com/", "http://example.com/"]:
            ext(url, dom_content="<html><body>plain page</body></html>", text_content="plain page")
        dash("http://httpforever.com/")
        ext("https://expired.badssl.com/", tls_error="net::ERR_CERT_DATE_INVALID")
        dash("https://self-signed.badssl.com/")
        ext("https://signup-rewards-mart.netlify.app/", dom_content=form, text_content="Create a new account")
        ext("https://cimb-clicks-account.example/", dom_content="<html><body>CIMB Clicks</body></html>", text_content="CIMB Clicks information page")
        # ── BLOCK: mule registry (R1), brand in hostname (R2), look-alike (R3), brand clone (R4), spoof (R7), HTTP login (H1)
        ext("https://parcel-customs-pay.top/track", dom_content=form, text_content="Your parcel is held. Pay the RM2.50 customs fee to Maybank account 1122 3344 5566 now.")
        dash("https://carousell-buyer-protect.cc/pay", page_text="Pay deposit to CIMB account 7600 1234 567890 to secure the item.", account_number="76001234567890")
        ext("https://shopee-refund-claim.top/", dom_content=form, text_content="Refund pending. Transfer RM1 verification fee to Public Bank 3567 8912 34 within 30 minutes.")
        ext("https://maybank2u-secure-login.top/m2u/login", dom_content=form, text_content="Maybank2u secure login. Your account access has been limited. Verify immediately.")
        ext("https://account-security-center.xyz/login", dom_content=form, text_content="Hong Leong Connect: update your security details now. Enter your password and TAC or your account will be frozen.")
        ext("https://rnaybank2u.com.my/login", dom_content=form, text_content="Login to Maybank2u")
        ext("https://identity-confirm-desk.cc/", dom_content=form, text_content="Public Bank PBe alert: confirm your identity with your password to avoid suspension.")
        ext("https://verify-secure-portal.top/signin", dom_content=form, text_content="CIMB Clicks security update. Enter your password and TAC to keep your account active.")
        ext("https://login-account-support.cc/", dom_content=form, text_content="Maybank2u: unusual activity detected. Enter your password to restore access.")
        dash("https://secure-id-check-7781.top/", page_text="URGENT: Your account will be suspended in 24 hours. Verify your password and card number now or lose access.")
        ext("https://wrong.host.badssl.com/", tls_error="net::ERR_CERT_COMMON_NAME_INVALID")
        ext("https://untrusted-root.badssl.com/", tls_error="net::ERR_CERT_AUTHORITY_INVALID")
        ext("http://http.badssl.com/", dom_content="<html><body>plain</body></html>", text_content="plain")
        dash("http://info.cern.ch/")
        ext("https://maybank2u.com.my@evil-login.top/login", dom_content="<html><body>Welcome</body></html>", text_content="Welcome")
        dash("https://cimbclicks.com.my@secure-bank-update.xyz/signin")
        ext("http://testphp.vulnweb.com/login.php", dom_content=form, text_content="Sign in to your account")
        ext("https://ewallet-bonus-claim.top/", dom_content=form, text_content="Touch 'n Go eWallet bonus RM50. Log in and enter your PIN and password to claim.")
        dash("https://lhdn-refund-portal.top/", page_text="LHDN tax refund pending. Verify your identity with your password and TAC to receive RM1,240.")
        dash("https://pos-laju-customs.top/pay", page_text="Pos Laju: your parcel is held at customs. Pay the clearance fee now with your card number and password.")
        qrs("https://maybank2u.com.my@evil-login.top/secure")
        qrs("https://maybank2u-verify-login.top/qr")
        qrs("https://gxbank-promo-claim.top/win")
        # ── BLOCK R8: a real bank screenshot on an unrelated address (YOLO logo detector)
        for name, url in [("gxbank.png", "https://rewards-portal-verify.example/login"), ("uob.png", "https://tmrw-promo-center.example/signin"),
                          ("dbs.png", "https://secure-account-review.example/login"), ("posb.png", "https://savings-bonus-claim.example/login"),
                          ("boost.png", "https://boost-style-rewards.example/login"), ("affin.png", "https://member-update-desk.example/login"),
                          ("public2.png", "https://online-security-check.example/login"), ("rhb2.png", "https://account-review-desk.example/login")]:
            shot = png_b64(name)
            if shot:
                dash(url, page_text="Enter your password to continue", screenshot_b64=shot)

    cx = sqlite3.connect(os.environ["PHISHGUARD_DB_PATH"])
    cx.row_factory = sqlite3.Row
    scans = [dict(r) for r in cx.execute("SELECT source, url, verdict, rule, risk_score, bert_score, headline, latency_ms FROM scan_log ORDER BY scan_id")]
    for s in scans:
        s["hostname"] = None
    # keep the dashboard balanced and readable: drop near-duplicates
    drop = ("savings-bonus-claim", "account-review-desk", "ewallet-bonus-claim", "account-security-center", "www.example.org", "wikipedia.org")
    scans = [x for x in scans if not any(d in x["url"] for d in drop)]
    random.Random(24).shuffle(scans)
    from collections import Counter
    OUT.write_text(json.dumps({
        "note": "Curated evaluation / threat-intelligence demonstration records. Scan rows are real pipeline results for look-alike, "
                "plain-HTTP and official addresses (pages were not downloaded); mule accounts and phone numbers are fictitious.",
        "mule_accounts": mules(), "scans": [{k: v for k, v in s.items() if k != "hostname"} for s in scans],
    }, indent=1), encoding="utf-8")
    print(len(scans), "scans", dict(Counter(s["verdict"] for s in scans)), dict(Counter(s["rule"] for s in scans)), dict(Counter(s["source"] for s in scans)))


if __name__ == "__main__":
    main()
