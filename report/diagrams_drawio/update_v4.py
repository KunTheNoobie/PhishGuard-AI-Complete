"""
Update the report's draw.io diagrams for PhishGuard-AI v4.0.

* Relabels the diagrams whose layout still fits (architecture, deployment,
  module boundary, use case, ERD, decision funnel, security layers).
* Regenerates the activity, sequence and class diagrams, whose structure
  changed (new rules, YOLOv8n inside /api/v1/analyze, new modules).

Run from the repository root:  python report/diagrams_drawio/update_v4.py
Render with the draw.io desktop app or viewer (File > Export > PNG, 300 dpi).
"""

from __future__ import annotations

import html
import re
from pathlib import Path

DIR = Path(__file__).resolve().parent
FONT = "fontFamily=Arial;fontColor=#1A1A1A;"
BLUE, GREEN, YELLOW, RED, PURPLE, GREY = (("#DAE8FC", "#6C8EBF"), ("#D5E8D4", "#82B366"), ("#FFF2CC", "#D6B656"),
                                          ("#F8CECC", "#B85450"), ("#E1D5E7", "#9673A6"), ("#F5F5F5", "#666666"))


def lines(*parts: str, size: int = 11, bold_first: bool = False) -> str:
    out = []
    for i, part in enumerate(parts):
        tag = "b" if bold_first and i == 0 else "span"
        out.append(f'<{tag} style="font-size:{size + (1 if tag == "b" else 0)}px">{html.escape(part)}</{tag}>')
    return "<br>".join(out)


def set_value(xml: str, cid: str, value: str) -> str:
    pattern = re.compile(r'(<mxCell id="%s" value=)("[^"]*"|\'[^\']*\')' % re.escape(cid))
    assert pattern.search(xml), cid
    return pattern.sub(lambda m: m.group(1) + '"' + html.escape(value, quote=True) + '"', xml, count=1)


def edit(name: str, labels: dict[str, str], extra=None) -> None:
    path = DIR / f"{name}.drawio"
    xml = path.read_text(encoding="utf-8")
    for cid, value in labels.items():
        xml = set_value(xml, cid, value)
    if extra:
        xml = extra(xml)
    path.write_text(xml, encoding="utf-8")
    print("updated", name)


# ── Relabelled diagrams ─────────────────────────────────────────────────────
edit("architecture", {
    "architecture-1": "Client tier — any website in Chrome, Manifest V3 extension (Module 2)",
    "architecture-3": lines("page URL · HTML ≤ 3 MB · text", "block screen · HTTP banner (Shadow DOM)"),
    "architecture-5": lines("online HTTPS server, local fallback", "8 s / 12 s with screenshot"),
    "architecture-7": lines("verdict · reasons · steps", "report account · backend switch"),
    "architecture-10": "Gateway — FastAPI on Uvicorn, served over HTTPS (Hugging Face Spaces) or locally",
    "architecture-15": lines("Pydantic v2", "http(s) only · size caps · patterns"),
    "architecture-16": "POST /api/v1/analyze (URL, DOM, screenshot)",
    "architecture-17": "Inference tier — canonicalise, detect in parallel, corroborate, explain",
    "architecture-18": lines("URL canonicaliser + DOM sanitiser", "'@' user names · IDN homoglyphs · numeric IPs · BeautifulSoup text",
                             size=10, bold_first=True),
    "architecture-20": "Trusted list",
    "architecture-21": lines("49 brands · 110 domains", "HTTPS → SAFE, skip BERT"),
    "architecture-24": lines("to_thread · 128 tokens", "P(phishing) · cache 600 s"),
    "architecture-27": lines("spaced · hyphen · phone · NRIC", "compact key → registry"),
    "architecture-32": "Heuristics + HTTPS",
    "architecture-33": lines("structure · free hosting", "forms · lexicon · certificate"),
    "architecture-35": "<br>".join([
        '<b style="font-size:12px">Verdict engine — 17 signals, rules in order, plain-language reasons</b>',
        '<span style="font-size:10px">BLOCK: R1 mule · R7 \'@\' spoof · R2 brand host · R3 look-alike · R8 logo · R4 clone · R5 coercion · R6 evasive · R9 free-hosting form · H1 HTTP + password/card</span>',
        '<span style="font-size:10px">WARNING: H2 plain HTTP · W1 certificate error · W2 uncorroborated impersonation · W3 form on free hosting · else SAFE</span>']),
    "architecture-40": "YOLOv8n logo detector",
    "architecture-41": lines("Module 2 model, same process", "screenshot from the extension", "logo confidence ≥ 0.85",
                             "logo vs official domain", "→ signal R8 / W2", size=10),
    "architecture-42": "screenshot (parallel)",
    "architecture-43": "Data & operations tier",
    "architecture-44": lines("SQLite (WAL, FK on)", "mule_registry · mule_reports", "scan_log (every verdict)", size=10, bold_first=True),
    "architecture-45": "Safe page fetcher",
    "architecture-46": lines("dashboard analyser and QR scanner", "public IPs only · 5 redirects · 1.5 MB", size=10),
    "architecture-47": "SOC dashboard (4 tabs)",
    "architecture-48": lines("Overview · Mule registry", "QR scanner · URL analyzer · CSV/JSON", size=10),
    "architecture-49": "registry lookup · scan_log insert",
    "architecture-50": "live fetch (dashboard / QR)",
}, extra=lambda xml: xml.replace('source="architecture-4" target="architecture-40"', 'source="architecture-17" target="architecture-40"')
   .replace("exitX=0.9;exitY=1;entryX=0.5;entryY=0;", "exitX=1;exitY=0.25;entryX=0;entryY=0.5;"))

edit("deployment", {
    "deployment-1": "«device» User computer",
    "deployment-3": lines("PhishGuard-AI extension (Manifest V3)", "backend: online HTTPS server, local fallback"),
    "deployment-5": lines("/dashboard/ over HTTPS", "HttpOnly, Secure session cookie"),
    "deployment-6": "«cloud» Hugging Face Spaces — Docker container, free CPU tier, HTTPS at the edge",
    "deployment-7": "«process» uvicorn main:app — port 7860, proxy headers trusted",
    "deployment-8": lines("FastAPI event loop · worker threads for BERT and YOLOv8n",
                          "BERT 438 MB in RAM · YOLOv8n 6.2 MB · result cache 600 s",
                          "env / secrets: PHISHGUARD_API_KEY · _ADMIN_KEY · _RATE_LIMIT", size=10),
    "deployment-9": lines("«artifact» phishguard.db", "SQLite in /tmp (reset on restart)", "3 tables · 4 indexes", size=10),
    "deployment-10": lines("«artifact» Model files (Git LFS)", "phishguard_custom_model/", "visual_identity/models/best.pt", size=10),
    "deployment-11": lines("HTTPS :443", "Bearer key"),
    "deployment-12": lines("HTTPS", "session cookie"),
    "deployment-15": ("Development and fallback: the same image runs with docker compose (port 8000) or uvicorn on "
                      "127.0.0.1:8000. The extension tries the online server first and switches to the local one "
                      "automatically. Outbound internet access is used only by the safe page fetcher."),
})

edit("module_boundary", {
    "module_boundary-4": lines("auth · rate limit · validation", "/api/v1 · /api/v1/dashboard"),
    "module_boundary-8": lines("spaced, hyphenated, phone, NRIC", "indexed registry lookup"),
    "module_boundary-10": lines("17 signals · R1–R9 · H1–H2 · W1–W3", "plain-language reasons"),
    "module_boundary-12": lines("mule_registry · mule_reports", "scan_log (every verdict)"),
    "module_boundary-13": "SOC dashboard (4 tabs)",
    "module_boundary-14": lines("overview · registry · QR scanner", "URL analyzer · CSV / JSON export"),
    "module_boundary-16": lines("content script · service worker", "popup · block screen · HTTP banner"),
    "module_boundary-18": lines("5 banks · synthetic dataset", "runs inside /api/v1/analyze"),
    "module_boundary-19": "Backend selection",
    "module_boundary-20": lines("online HTTPS, local fallback", "offline: HTTP never shown as safe"),
    "module_boundary-23": ("Interface contract — POST /api/v1/analyze {url, dom_content, text_content, screenshot} with a "
                           "Bearer key; response: verdict (SAFE | WARNING | BLOCK_RENDER), rule, risk_score, headline, "
                           "explanation, reasons, steps, signals."),
})

edit("use_case", {
    "use_case-6": "Analyse QR-code image",
    "use_case-10": "Detect bank logo (YOLOv8n, Module 2)",
    "use_case-12": "Canonicalise URL, sanitise DOM",
    "use_case-18": "Decide and explain verdict",
    "use_case-22": "View scan statistics (Overview)",
    "use_case-28": "Export scan log (CSV / JSON)",
    "use_case-29": "Analyse any URL (URL Analyzer)",
})

TELEMETRY = "".join([
    '<div style="background:#B85450;color:#fff;padding:5px 8px;font-weight:bold;font-size:12px;font-family:Consolas;">scan_log</div>',
    '<table style="font-size:11px;font-family:Arial;border-collapse:collapse;margin:4px 6px;width:96%;">',
    *[f'<tr><td style="width:34px;color:{"#B85450" if k == "PK" else "#666"};"><b>{k}</b></td>'
      f'<td style="width:140px;font-family:Consolas;">{c}</td><td style="width:70px;color:#3B5B8C;">{t}</td>'
      f'<td style="color:#555;">{n}</td></tr>'
      for k, c, t, n in [
          ("PK", "scan_id", "INTEGER", "AUTOINCREMENT"),
          ("IX", "created_at", "TEXT", "NOT NULL · ISO-8601 UTC"),
          ("", "source", "TEXT", "extension / dashboard / qr / api"),
          ("", "url", "TEXT", "NOT NULL · no query or fragment"),
          ("", "hostname", "TEXT", "NOT NULL"),
          ("", "scheme", "TEXT", "http / https"),
          ("IX", "verdict", "TEXT", "SAFE / WARNING / BLOCK_RENDER"),
          ("", "rule", "TEXT", "NULL when SAFE"),
          ("", "risk_score", "REAL", "CHECK 0.0–1.0"),
          ("", "bert_score", "REAL", "NULL when skipped"),
          ("", "headline", "TEXT", "NOT NULL"),
          ("", "latency_ms", "REAL", "NOT NULL"),
      ]],
    "</table>",
])


def erd_layout(xml: str) -> str:
    xml = xml.replace('<mxGeometry x="10" y="183.0" width="470" height="108.0" as="geometry"/>',
                      '<mxGeometry x="10" y="183.0" width="470" height="236.0" as="geometry"/>')

    def shift(m):
        y = float(m.group(2))
        return m.group(1) + str(y + 135 if y >= 300 else y) + m.group(3)
    return re.sub(r'(<mxGeometry x="[^"]*" y=")([0-9.]+)(")', shift, xml)


edit("erd", {
    "erd-3": TELEMETRY,
    "erd-6": lines("• dashboard sessions: token_urlsafe(32) → expiry (8 h)",
                   "• trusted list: immutable frozenset (110 official domains of 49 brands + global list)",
                   "• BERT result cache: SemanticResultCache (600 s)"),
    "erd-7": "<br>".join(['<b style="font-size:12px">Indexes</b>',
                          *[f'<span style="font-family:Consolas;font-size:11px">{i}</span>' for i in [
                              "UNIQUE (account_number) on mule_registry",
                              "idx_mule_reports_status (status, created_at)",
                              "idx_mule_reports_registry_id (registry_id)",
                              "idx_scan_log_created (created_at)",
                              "idx_scan_log_verdict (verdict, created_at)"]]]),
    "erd-8": ("Writes: registry upsert INSERT … ON CONFLICT(account_number) DO UPDATE with compact digit keys; a "
              "report is promoted only on analyst APPROVE; every analysed page adds one scan_log row (no query "
              "strings stored). PRAGMA journal_mode = WAL, foreign_keys = ON. Key legend: PK primary · UQ unique · "
              "FK foreign · IX indexed."),
}, extra=erd_layout)

edit("decision_funnel", {
    "decision_funnel-6": "Ordered rules (first match decides)",
    "decision_funnel-8": "R1  mule registry match", "decision_funnel-9": "12",
    "decision_funnel-11": "R2  brand in hostname", "decision_funnel-12": "28",
    "decision_funnel-14": "R3  look-alike domain", "decision_funnel-15": "5",
    "decision_funnel-17": "R4  brand clone", "decision_funnel-18": "6",
    "decision_funnel-20": "R5  coercive credential request", "decision_funnel-21": "3",
    "decision_funnel-23": "R6  evasive infrastructure", "decision_funnel-24": "3",
    "decision_funnel-25": "block rule?",
    "decision_funnel-29": "no block rule",
    "decision_funnel-30": ("v4.0 on the 120-page benchmark: blocked 57 of 60 malicious and 0 of 60 legitimate pages; "
                           "one plain-HTTP fake form received an amber WARNING (H2) instead of being missed. "
                           "Rules R7–R9 and H1 did not fire on this benchmark; they are exercised by the public URL "
                           "suite. (*) One phishing form hosted on Google Forms, a trusted platform, bypassed analysis."),
    "decision_funnel-2": lines("Trusted-domain bypass: 19", "18 legitimate · 1 malicious (*)", "HTTPS → SAFE, BERT not invoked"),
    "decision_funnel-3": lines("Analysed: 101", "BERT ║ mule scan ║ logo check", "then brand, heuristics,", "forms, lexicon, HTTPS"),
    "decision_funnel-26": lines("BLOCK_RENDER", "57 pages", "(57 malicious, 0 legit.)"),
    "decision_funnel-28": lines("WARNING (H2): 1 malicious", "SAFE, no rule: 43", "42 legitimate · 1 malicious missed"),
})

edit("security_layers", {
    "security_layers-3": lines("L1  Client (Manifest V3)", "CSP script-src 'self'; UI in closed Shadow DOM, text via textContent; "
                               "HTTPS backend with local fallback; 8 s / 12 s timeouts; offline: HTTP never shown as safe",
                               size=10, bold_first=True),
    "security_layers-6": lines("L2  Edge policy", "HTTPS at the platform edge + HSTS; CORS allow-list (no wildcard); "
                               "nosniff · frame-ancestors · Referrer / Permissions-Policy · no-store", size=10, bold_first=True),
    "security_layers-9": lines("L3  Authentication", "Analysis API: Bearer key, constant-time comparison; 13 dashboard "
                               "operations: admin key or HttpOnly, Secure, SameSite=Strict session (8 h)", size=10, bold_first=True),
    "security_layers-15": lines("L5  Input validation", "Pydantic v2: http(s) only, size caps, account pattern; "
                                "URL canonicalisation; SSRF guard on live fetches (public IPs only)", size=10, bold_first=True),
    "security_layers-16": "Malformed input, '@' spoofing, SSRF",
    "security_layers-18": lines("L6  Data integrity", "Parameterised SQL · CHECK / FK constraints; reports need analyst "
                                "APPROVE; CSV export neutralises formulas", size=10, bold_first=True),
    "security_layers-21": lines("L7  Fault tolerance", "fetch errors reported, never fatal; scan-log failures never block "
                                "a verdict; models loaded once at start-up", size=10, bold_first=True),
})


# ── Generated diagrams ──────────────────────────────────────────────────────
class Drawing:
    def __init__(self, name: str):
        self.name, self.cells, self.n = name, [], 0

    def _id(self) -> str:
        self.n += 1
        return f"{self.name}-{self.n}"

    def box(self, x, y, w, h, label, colours=BLUE, shape="rounded=1;arcSize=10;", size=11, align="center"):
        cid = self._id()
        style = (f"{shape}whiteSpace=wrap;html=1;fillColor={colours[0]};strokeColor={colours[1]};{FONT}"
                 f"fontSize={size};align={align};verticalAlign=middle;spacing=6;strokeWidth=1.1;")
        self.cells.append(f'<mxCell id="{cid}" value="{html.escape(label, quote=True)}" style="{style}" vertex="1" '
                          f'parent="1"><mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        return cid

    def text(self, x, y, w, h, label, size=10, align="center"):
        cid = self._id()
        style = f"text;html=1;whiteSpace=wrap;align={align};verticalAlign=middle;{FONT}fontSize={size};"
        self.cells.append(f'<mxCell id="{cid}" value="{html.escape(label, quote=True)}" style="{style}" vertex="1" '
                          f'parent="1"><mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        return cid

    def edge(self, src, dst, label="", dashed=False, exit_=None, entry=None):
        cid = self._id()
        style = ("edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=block;endFill=1;strokeColor=#333333;"
                 f"strokeWidth=1.2;{FONT}fontSize=10;labelBackgroundColor=#FFFFFF;" + ("dashed=1;" if dashed else ""))
        if exit_:
            style += f"exitX={exit_[0]};exitY={exit_[1]};"
        if entry:
            style += f"entryX={entry[0]};entryY={entry[1]};"
        self.cells.append(f'<mxCell id="{cid}" value="{html.escape(label, quote=True)}" style="{style}" edge="1" '
                          f'parent="1" source="{src}" target="{dst}"><mxGeometry relative="1" as="geometry"/></mxCell>')

    def line(self, x1, y1, x2, y2, label="", dashed=False, arrow=True, open_arrow=False):
        cid = self._id()
        end = ("endArrow=open;endFill=0;" if open_arrow else "endArrow=block;endFill=1;") if arrow else "endArrow=none;"
        style = (f"html=1;{end}strokeColor=#333333;strokeWidth=1.1;{FONT}fontSize=10;labelBackgroundColor=#FFFFFF;"
                 + ("dashed=1;" if dashed else "") + "verticalAlign=bottom;")
        self.cells.append(f'<mxCell id="{cid}" value="{html.escape(label, quote=True)}" style="{style}" edge="1" '
                          f'parent="1"><mxGeometry relative="1" as="geometry"><mxPoint x="{x1}" y="{y1}" as="sourcePoint"/>'
                          f'<mxPoint x="{x2}" y="{y2}" as="targetPoint"/></mxGeometry></mxCell>')

    def save(self):
        body = "".join(self.cells)
        xml = (f'<mxfile host="drawio" type="device"><diagram name="{self.name}" id="{self.name}"><mxGraphModel '
               f'dx="1200" dy="900" grid="0" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" '
               f'page="0" pageScale="1" pageWidth="1169" pageHeight="827" background="#FFFFFF" math="0" shadow="0">'
               f'<root><mxCell id="0"/><mxCell id="1" parent="0"/>{body}</root></mxGraphModel></diagram></mxfile>')
        (DIR / f"{self.name}.drawio").write_text(xml, encoding="utf-8")
        print("generated", self.name)


def activity() -> None:
    d = Drawing("activity")
    x, w = 210, 330
    start = d.box(x + w / 2 - 15, 0, 30, 30, "", ("#1A1A1A", "#1A1A1A"), shape="ellipse;")
    steps = [
        ("Validate API key, rate limit and request schema (http/https only)", BLUE),
        ("Canonicalise URL: user name before '@', IDN homoglyphs, numeric IP", BLUE),
        ("Dashboard / QR only: fetch the live page through the SSRF guard", GREY),
        ("Sanitise DOM to text; find password, card and OTP fields", BLUE),
    ]
    prev, y = start, 55
    for label, col in steps:
        cur = d.box(x, y, w, 44, label, col, size=11)
        d.edge(prev, cur)
        prev, y = cur, y + 70
    trusted = d.box(x + 65, y, 200, 80, "trusted domain?", YELLOW, shape="rhombus;")
    d.edge(prev, trusted)
    t_http = d.box(600, y + 10, 230, 60, "HTTP: form → BLOCK (H1), else WARNING (H2); HTTPS → SAFE, BERT skipped", GREEN, size=10)
    d.edge(trusted, t_http, "yes")
    y += 110
    par = d.box(x - 40, y, w + 80, 56,
                "In parallel (asyncio.gather): BERT URL model ║ mule-registry scan ║ YOLOv8n logo check", PURPLE, size=11)
    d.edge(trusted, par, "no")
    y += 86
    prof = d.box(x, y, w, 44, "URL heuristics (structure, free hosting) and brand-impersonation profile", BLUE, size=11)
    d.edge(par, prof)
    y += 74
    rules = d.box(x - 40, y, w + 80, 70,
                  "Block rules in order: R1 mule · R7 '@' spoof · R2 brand host · R3 look-alike · R8 logo · R4 clone · "
                  "R5 coercion · R6 evasive · R9 free-hosting form · H1 HTTP + sensitive form", RED, size=10)
    d.edge(prof, rules)
    y += 100
    any_block = d.box(x + 65, y, 200, 76, "any block rule?", YELLOW, shape="rhombus;")
    d.edge(rules, any_block)
    block = d.box(600, y + 8, 230, 60, "BLOCK_RENDER · red block screen · reasons", RED, size=11)
    d.edge(any_block, block, "yes")
    y += 106
    warn_rules = d.box(x + 65, y, 200, 86, "H2 plain HTTP · W1 certificate · W2 lone impersonation cue · W3 form on free host?",
                       YELLOW, shape="rhombus;", size=9)
    d.edge(any_block, warn_rules, "no")
    warn = d.box(600, y + 13, 230, 60, "WARNING · amber banner · reasons", YELLOW, size=11)
    d.edge(warn_rules, warn, "yes")
    y += 116
    safe = d.box(x, y, w, 44, "SAFE · advisory score < 0.50 · reasons", GREEN, size=11)
    d.edge(warn_rules, safe, "no")
    y += 74
    log = d.box(x, y, w, 44, "Write scan_log row · return explained verdict with step-by-step breakdown", BLUE, size=11)
    d.edge(safe, log)
    for other in (block, warn, t_http):
        d.edge(other, log, dashed=True, exit_=(1, 0.5), entry=(1, 0.5))
    end = d.box(x + w / 2 - 15, y + 70, 30, 30, "", ("#FFFFFF", "#1A1A1A"), shape="ellipse;double=1;")
    d.edge(log, end)
    d.save()


def sequence() -> None:
    d = Drawing("sequence")
    names = ["Content script", "Service worker", "FastAPI /api/v1/analyze", "analysis_pipeline",
             "BERT (thread)", "Mule scanner + SQLite", "YOLOv8n (thread)", "Verdict engine"]
    xs = [70 + i * 150 for i in range(len(names))]
    top, bottom = 20, 820
    for x, name in zip(xs, names):
        d.box(x - 65, top, 130, 44, name, BLUE, size=11)
        d.line(x, top + 44, x, bottom, dashed=True, arrow=False)
    msgs = [
        (0, 1, "PG_PAGE {url, html ≤ 3 MB, text}", False),
        (1, 1, "captureVisibleTab → JPEG", False),
        (1, 2, "POST /api/v1/analyze + screenshot (abort 12 s)", False),
        (2, 2, "401 key · 429 rate · 422 schema", False),
        (2, 3, "analyze_page(PageInput)", False),
        (3, 3, "canonicalise · sanitise · find form fields", False),
        (3, 4, "predict(model_url)  [gather]", False),
        (3, 5, "scan_and_verify(text)  [gather]", False),
        (3, 6, "detect(screenshot)  [gather]", False),
        (4, 3, "P(phishing)", True),
        (5, 3, "flagged accounts", True),
        (6, 3, "logos, logo-domain risk", True),
        (3, 7, "decide(signals)", False),
        (7, 3, "verdict, rule, headline, reasons", True),
        (3, 5, "INSERT scan_log", False),
        (2, 1, "200 AnalysisResponse (+ steps)", True),
        (1, 0, "PG_SHOW → block screen / HTTP banner / none", False),
    ]
    y = 95
    for a, b, label, ret in msgs:
        if a == b:
            d.box(xs[a] + 6, y - 12, 140, 26, label, GREY, size=9)
        else:
            d.line(xs[a], y, xs[b], y, label, dashed=ret, open_arrow=ret)
        y += 42 if a != b else 38
    d.save()


def class_diagram() -> None:
    d = Drawing("class_diagram")
    W, H = 250, 120

    def cls(col, row, stereo, name, members, colours=BLUE, h=H):
        label = (f'<span style="font-size:10px">«{stereo}»</span><br><b style="font-size:12px">{name}</b>'
                 f'<hr style="margin:3px 0">'
                 + "<br>".join(f'<span style="font-size:10px">{html.escape(m)}</span>' for m in members))
        return d.box(20 + col * 290, 20 + row * 150, W, h, label, colours, shape="rounded=0;", size=10)

    request = cls(0, 0, "pydantic", "AnalyzeRequest", ["url: str (http/https)", "dom_content ≤ 3 MB · text_content",
                                                       "screenshot (base64, optional)"], GREY)
    pipeline = cls(1, 0, "module", "analysis_pipeline", ["PageInput (dataclass)", "+ async analyze_page(input, state)",
                                                         "+ async scan_qr_code(image, state)", "+ is_trusted_host(host)"], RED)
    response = cls(2, 0, "pydantic", "AnalysisResponse", ["verdict · risk_level · risk_score · rule",
                                                          "headline · explanation · reasons", "steps · signals · bert · mule"], GREY)
    canon = cls(0, 1, "dataclass", "CanonicalURL", ["hostname · skeleton_hostname · userinfo", "is_ip · is_idn · display_url",
                                                    "+ canonicalize(url) → CanonicalURL"])
    verdict = cls(1, 1, "module", "verdict_engine", ["+ decide(...) → Verdict", "+ collect_signals(...)",
                                                     "+ detect_sensitive_fields(html)", "Verdict: verdict · rule · reasons"], RED)
    fetcher = cls(2, 1, "module", "page_fetcher", ["+ async fetch_page(url) → FetchResult", "SSRF guard on every redirect",
                                                   "TLS errors → W1 signal"])
    bert = cls(0, 2, "singleton", "SemanticEngine", ["- _model: BertForSequenceClassification", "+ warm_up()",
                                                     "+ async predict(text) → P(phishing)", "results cached by SemanticResultCache"], GREEN)
    mule = cls(1, 2, "singleton", "MuleScanner", ["+ async scan_and_verify(text, db)", "extract_accounts(text)",
                                                  "normalise_account(raw)", "queries repository"], GREEN)
    yolo = cls(2, 2, "Module 2", "VisualLogoDetector", ["- _model: YOLO (lazy)", "+ detect(screenshot)",
                                                       "evaluate_logo_domain(url, logos)"], PURPLE)
    brand = cls(0, 3, "module", "brand_profiler + core.brands", ["BRANDS: 49 brands, 110 domains",
                                                                 "+ profile_brand_impersonation(url, text)"])
    heur = cls(1, 3, "module", "heuristic_engine", ["+ analyze_url_heuristics(url)", "raw IP · '@' · IDN · TLD",
                                                    "subdomains · port · free hosting"])
    qr = cls(2, 3, "module", "qr_payload", ["+ decode_qr_image(image)", "+ classify_payload(text)",
                                            "+ extract_duitnow_accounts(text)"])
    repo = cls(0, 4, "module", "repository", ["+ check_mule_accounts(list, db)", "+ log_scan(entry, db)",
                                              "+ review_mule_report(id, ok, db)"], YELLOW)
    security = cls(1, 4, "module", "security", ["+ verify_api_key(credentials)", "+ verify_dashboard_access(request)",
                                                "_SESSIONS: dict[str, float]"], YELLOW)
    cache = cls(2, 4, "class", "SemanticResultCache", ["- ttl_seconds = 600", "+ hash_key(text)", "+ get / set"], YELLOW)
    d.edge(request, pipeline, "input")
    d.edge(pipeline, response, "returns")
    d.text(20, 770, 830, 44, "analysis_pipeline (red) calls every module in rows 2–4 and writes scan_log through "
                             "repository · «pydantic» = contract validated at the API edge · «Module 2» = partner's "
                             "component · green = models loaded once at start-up · yellow = storage and security",
           size=10, align="left")
    d.save()


activity()
sequence()
class_diagram()
