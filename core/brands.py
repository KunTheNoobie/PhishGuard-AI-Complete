"""
PhishGuard-AI — Protected Brand Registry.
==========================================

One table of every organisation PhishGuard protects against impersonation:
all licensed Malaysian banks and digital banks, the main Malaysian e-wallets,
frequently spoofed Malaysian government, parcel and e-commerce services, and
major global banks and payment brands.

Every other module derives its data from this table:

* ``core.config.TRUSTED_DOMAINS``   — official domains (whitelist).
* ``services.brand_profiler``       — brand-in-hostname, look-alike and
                                      text-mention evidence.
* ``services.visual_detector``      — authorised domains for each logo class.

Fields
------
``domains``      Registrable domains the organisation owns.  Subdomains match.
``host_strings`` Distinctive strings that betray the brand when found
                 *anywhere* in a foreign hostname (``maybank2u-login.top``).
``host_tokens``  Short brand tokens that only count as a whole hostname label
                 or hyphen-separated token (``cimb`` in ``cimb-verify.com``),
                 because as substrings they occur in unrelated words.
``lookalikes``   Canonical strings (>= 6 characters) a typosquatter imitates.
``keywords``     Phrases that name the brand in page text.
``category``     Used for reporting and the dashboard.

Official domains were checked against each organisation's own website.
"""

from __future__ import annotations

from typing import Any, Final

BRANDS: Final[dict[str, dict[str, Any]]] = {
    # ── Malaysian commercial and Islamic banks ───────────────────────────────
    "Maybank": {
        "category": "Malaysian bank",
        "domains": ["maybank2u.com.my", "maybank.com.my", "maybank.com", "maybank2e.com"],
        "host_strings": ["maybank", "malayanbanking"],
        "host_tokens": [],
        "lookalikes": ["maybank2u", "maybank"],
        "keywords": ["maybank", "maybank2u", "malayan banking"],
    },
    "CIMB Bank": {
        "category": "Malaysian bank",
        "domains": ["cimbclicks.com.my", "cimb.com.my", "cimb.com", "cimbbank.com.my"],
        "host_strings": ["cimbclicks", "cimbbank", "cimb-clicks"],
        "host_tokens": ["cimb"],
        "lookalikes": ["cimbclicks"],
        "keywords": ["cimb", "cimb clicks", "cimb octo"],
    },
    "Public Bank": {
        "category": "Malaysian bank",
        "domains": ["pbebank.com", "publicbank.com.my"],
        "host_strings": ["pbebank", "publicbank", "public-bank"],
        "host_tokens": ["pbe", "pbb"],
        "lookalikes": ["pbebank", "publicbank"],
        "keywords": ["public bank", "pbe bank", "pbengage"],
    },
    "RHB Bank": {
        "category": "Malaysian bank",
        "domains": ["rhbgroup.com", "rhb.com.my"],
        "host_strings": ["rhbgroup", "rhbbank", "rhbonline"],
        "host_tokens": ["rhb"],
        "lookalikes": ["rhbgroup"],
        "keywords": ["rhb bank", "rhb online banking", "rhb"],
    },
    "Hong Leong Bank": {
        "category": "Malaysian bank",
        "domains": ["hlb.com.my", "hongleongconnect.my"],
        "host_strings": ["hongleong", "hong-leong", "hlbconnect"],
        "host_tokens": ["hlb", "hlbb"],
        "lookalikes": ["hongleong", "hongleongconnect"],
        "keywords": ["hong leong", "hong leong connect", "hlb connect"],
    },
    "AmBank": {
        "category": "Malaysian bank",
        "domains": ["ambank.com.my", "ambankgroup.com", "amonline.com.my"],
        "host_strings": ["ambank", "amonline"],
        "host_tokens": [],
        "lookalikes": ["ambank", "amonline"],
        "keywords": ["ambank", "amonline"],
    },
    "Bank Islam": {
        "category": "Malaysian bank",
        "domains": ["bankislam.com", "bankislam.com.my", "bankislam.biz"],
        "host_strings": ["bankislam", "bank-islam"],
        "host_tokens": ["bimb"],
        "lookalikes": ["bankislam"],
        "keywords": ["bank islam", "go by bank islam"],
    },
    "Bank Rakyat": {
        "category": "Malaysian bank",
        "domains": ["bankrakyat.com.my", "irakyat.com.my"],
        "host_strings": ["bankrakyat", "bank-rakyat", "irakyat"],
        "host_tokens": [],
        "lookalikes": ["bankrakyat", "irakyat"],
        "keywords": ["bank rakyat", "irakyat"],
    },
    "BSN": {
        "category": "Malaysian bank",
        "domains": ["bsn.com.my", "mybsn.com.my"],
        "host_strings": ["mybsn", "simpanannasional"],
        "host_tokens": ["bsn"],
        "lookalikes": [],
        "keywords": ["bank simpanan nasional", "mybsn"],
    },
    "Alliance Bank": {
        "category": "Malaysian bank",
        "domains": ["alliancebank.com.my", "allianceonline.com.my"],
        "host_strings": ["alliancebank", "allianceonline"],
        "host_tokens": [],
        "lookalikes": ["alliancebank", "allianceonline"],
        "keywords": ["alliance bank", "allianceonline"],
    },
    "Affin Bank": {
        "category": "Malaysian bank",
        "domains": ["affinbank.com.my", "affinalways.com", "affinonline.com"],
        "host_strings": ["affinbank", "affinalways", "affinonline"],
        "host_tokens": ["affin"],
        "lookalikes": ["affinbank", "affinalways"],
        "keywords": ["affin bank", "affinalways", "affinonline"],
    },
    "UOB Malaysia": {
        "category": "Malaysian bank",
        "domains": ["uob.com.my", "uob.com", "uob.com.sg", "uobgroup.com"],
        "host_strings": ["uobgroup", "uobbank"],
        "host_tokens": ["uob"],
        "lookalikes": ["uobgroup"],
        "keywords": ["uob malaysia", "uob personal internet banking", "uob tmrw"],
    },
    "OCBC Malaysia": {
        "category": "Malaysian bank",
        "domains": ["ocbc.com.my", "ocbc.com", "ocbc.com.sg"],
        "host_strings": ["ocbcbank"],
        "host_tokens": ["ocbc"],
        "lookalikes": [],
        "keywords": ["ocbc", "ocbc online banking"],
    },
    "HSBC Malaysia": {
        "category": "Malaysian bank",
        "domains": ["hsbc.com.my", "hsbc.com", "hsbc.co.uk", "hsbcnet.com"],
        "host_strings": ["hsbc"],
        "host_tokens": [],
        "lookalikes": [],
        "keywords": ["hsbc", "hsbcnet"],
    },
    "Standard Chartered Malaysia": {
        "category": "Malaysian bank",
        "domains": ["sc.com", "standardchartered.com", "standardchartered.com.my"],
        "host_strings": ["standardchartered", "standard-chartered"],
        "host_tokens": [],
        "lookalikes": ["standardchartered"],
        "keywords": ["standard chartered"],
    },
    "Citibank Malaysia": {
        "category": "Malaysian bank",
        "domains": ["citibank.com.my", "citibank.com", "citi.com"],
        "host_strings": ["citibank"],
        "host_tokens": ["citi"],
        "lookalikes": ["citibank"],
        "keywords": ["citibank", "citi online"],
    },
    "Agrobank": {
        "category": "Malaysian bank",
        "domains": ["agrobank.com.my"],
        "host_strings": ["agrobank"],
        "host_tokens": [],
        "lookalikes": ["agrobank"],
        "keywords": ["agrobank", "bank pertanian"],
    },
    "Bank Muamalat": {
        "category": "Malaysian bank",
        "domains": ["muamalat.com.my", "i-muamalat.com.my"],
        "host_strings": ["muamalat"],
        "host_tokens": [],
        "lookalikes": ["muamalat"],
        "keywords": ["bank muamalat", "i-muamalat"],
    },
    "MBSB Bank": {
        "category": "Malaysian bank",
        "domains": ["mbsbbank.com"],
        "host_strings": ["mbsbbank"],
        "host_tokens": ["mbsb"],
        "lookalikes": ["mbsbbank"],
        "keywords": ["mbsb bank"],
    },
    # ── Malaysian digital banks ─────────────────────────────────────────────
    "GXBank": {
        "category": "Malaysian digital bank",
        "domains": ["gxbank.my"],
        "host_strings": ["gxbank"],
        "host_tokens": [],
        "lookalikes": [],
        "keywords": ["gxbank", "gx bank"],
    },
    "AEON Bank": {
        "category": "Malaysian digital bank",
        "domains": ["aeonbank.com.my"],
        "host_strings": ["aeonbank"],
        "host_tokens": [],
        "lookalikes": ["aeonbank"],
        "keywords": ["aeon bank"],
    },
    "Boost Bank": {
        "category": "Malaysian digital bank",
        "domains": ["myboostbank.co", "myboost.com.my"],
        "host_strings": ["boostbank", "myboost"],
        "host_tokens": [],
        "lookalikes": ["boostbank"],
        "keywords": ["boost bank", "boost e-wallet", "boost ewallet"],
    },
    "KAF Digital Bank": {
        "category": "Malaysian digital bank",
        "domains": ["kafdigital.com.my", "kafdigitalbank.com.my", "onzbanking.com"],
        "host_strings": ["kafdigital", "onzbanking"],
        "host_tokens": [],
        "lookalikes": ["kafdigital"],
        "keywords": ["kaf digital bank", "onz banking"],
    },
    # ── Malaysian payments and e-wallets ────────────────────────────────────
    "Touch 'n Go eWallet": {
        "category": "Malaysian e-wallet",
        "domains": ["touchngo.com.my", "tngdigital.com.my"],
        "host_strings": ["touchngo", "touch-n-go", "tngdigital", "tngewallet"],
        "host_tokens": ["tng"],
        "lookalikes": ["touchngo"],
        "keywords": ["touch 'n go", "touch n go", "tng ewallet", "tng e-wallet"],
    },
    "DuitNow / PayNet": {
        "category": "Malaysian payments",
        "domains": ["duitnow.my", "paynet.my"],
        "host_strings": ["duitnow", "paynet"],
        "host_tokens": [],
        "lookalikes": ["duitnow"],
        "keywords": ["duitnow", "paynet"],
    },
    "GrabPay": {
        "category": "Malaysian e-wallet",
        "domains": ["grab.com"],
        "host_strings": ["grabpay", "grab-pay"],
        "host_tokens": [],
        "lookalikes": ["grabpay"],
        "keywords": ["grabpay", "grab pay"],
    },
    "ShopeePay / Shopee": {
        "category": "E-commerce",
        "domains": ["shopee.com.my", "shopee.sg", "shopeepay.com.my"],
        "host_strings": ["shopee"],
        "host_tokens": [],
        "lookalikes": ["shopeepay"],
        "keywords": ["shopeepay", "shopee"],
    },
    "Lazada": {
        "category": "E-commerce",
        "domains": ["lazada.com.my", "lazada.sg"],
        "host_strings": ["lazada"],
        "host_tokens": [],
        "lookalikes": ["lazada"],
        "keywords": ["lazada"],
    },
    # ── Malaysian government and utilities ──────────────────────────────────
    "LHDN": {
        "category": "Government",
        "domains": ["hasil.gov.my"],
        "host_strings": [],
        "host_tokens": ["lhdn"],
        "lookalikes": [],
        "keywords": ["lhdn", "lembaga hasil dalam negeri"],
    },
    "KWSP / EPF": {
        "category": "Government",
        "domains": ["kwsp.gov.my"],
        "host_strings": ["kwsp"],
        "host_tokens": [],
        "lookalikes": [],
        "keywords": ["kwsp", "i-akaun"],
    },
    "PDRM": {
        "category": "Government",
        "domains": ["rmp.gov.my"],
        "host_strings": [],
        "host_tokens": ["pdrm"],
        "lookalikes": [],
        "keywords": ["pdrm", "polis diraja malaysia"],
    },
    "JPJ": {
        "category": "Government",
        "domains": ["jpj.gov.my"],
        "host_strings": [],
        "host_tokens": ["jpj"],
        "lookalikes": [],
        "keywords": ["jpj", "jabatan pengangkutan jalan"],
    },
    "Bank Negara Malaysia": {
        "category": "Government",
        "domains": ["bnm.gov.my"],
        "host_strings": ["banknegara", "bank-negara"],
        "host_tokens": ["bnm"],
        "lookalikes": ["banknegara"],
        "keywords": ["bank negara malaysia"],
    },
    "TNB": {
        "category": "Utility",
        "domains": ["tnb.com.my", "mytnb.com.my"],
        "host_strings": ["mytnb"],
        "host_tokens": ["tnb"],
        "lookalikes": [],
        "keywords": ["tenaga nasional", "mytnb"],
    },
    # ── Parcel and courier services ─────────────────────────────────────────
    "Pos Malaysia": {
        "category": "Parcel / courier",
        "domains": ["pos.com.my"],
        "host_strings": ["posmalaysia", "pos-malaysia", "poslaju"],
        "host_tokens": [],
        "lookalikes": ["poslaju"],
        "keywords": ["pos malaysia", "poslaju", "pos laju"],
    },
    "J&T Express": {
        "category": "Parcel / courier",
        "domains": ["jtexpress.my"],
        "host_strings": ["jtexpress", "jnt-express"],
        "host_tokens": [],
        "lookalikes": ["jtexpress"],
        "keywords": ["j&t express"],
    },
    "DHL / FedEx / UPS": {
        "category": "Parcel / courier",
        "domains": ["dhl.com", "dhl.com.my", "fedex.com", "ups.com"],
        "host_strings": ["fedex"],
        "host_tokens": ["dhl"],
        "lookalikes": [],
        "keywords": ["dhl express", "fedex", "ups parcel"],
    },
    # ── Global banks ────────────────────────────────────────────────────────
    "Chase": {
        "category": "Global bank",
        "domains": ["chase.com", "jpmorganchase.com"],
        "host_strings": ["chasebank", "chaseonline"],
        "host_tokens": ["chase"],
        "lookalikes": ["chasebank"],
        "keywords": ["chase bank", "chase online"],
    },
    "Bank of America": {
        "category": "Global bank",
        "domains": ["bankofamerica.com", "bofa.com"],
        "host_strings": ["bankofamerica"],
        "host_tokens": ["bofa"],
        "lookalikes": ["bankofamerica"],
        "keywords": ["bank of america"],
    },
    "Wells Fargo": {
        "category": "Global bank",
        "domains": ["wellsfargo.com"],
        "host_strings": ["wellsfargo", "wells-fargo"],
        "host_tokens": [],
        "lookalikes": ["wellsfargo"],
        "keywords": ["wells fargo"],
    },
    "Barclays": {
        "category": "Global bank",
        "domains": ["barclays.co.uk", "barclays.com"],
        "host_strings": ["barclays"],
        "host_tokens": [],
        "lookalikes": ["barclays"],
        "keywords": ["barclays"],
    },
    "DBS / POSB": {
        "category": "Global bank",
        "domains": ["dbs.com", "dbs.com.sg", "posb.com.sg"],
        "host_strings": ["dbsbank", "digibank"],
        "host_tokens": ["dbs", "posb"],
        "lookalikes": [],
        "keywords": ["dbs bank", "dbs digibank", "posb"],
    },
    "PayPal": {
        "category": "Global payments",
        "domains": ["paypal.com", "paypal.me"],
        "host_strings": ["paypal"],
        "host_tokens": [],
        "lookalikes": ["paypal"],
        "keywords": ["paypal"],
    },
    # ── Global platforms most often used as phishing lures ──────────────────
    "Microsoft": {
        "category": "Global platform",
        "domains": ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"],
        "host_strings": ["microsoft", "office365", "microsoftonline"],
        "host_tokens": [],
        "lookalikes": ["microsoft"],
        "keywords": ["microsoft 365", "office 365", "outlook web access"],
    },
    "Google": {
        "category": "Global platform",
        "domains": ["google.com", "google.com.my", "gmail.com"],
        "host_strings": [],
        "host_tokens": [],
        "lookalikes": [],
        "keywords": ["google account", "gmail"],
    },
    "Apple": {
        "category": "Global platform",
        "domains": ["apple.com", "icloud.com"],
        "host_strings": ["apple-id", "appleid", "icloud"],
        "host_tokens": [],
        "lookalikes": [],
        "keywords": ["apple id", "icloud"],
    },
    "Netflix": {
        "category": "Global platform",
        "domains": ["netflix.com"],
        "host_strings": ["netflix"],
        "host_tokens": [],
        "lookalikes": ["netflix"],
        "keywords": ["netflix"],
    },
    "Meta / WhatsApp": {
        "category": "Global platform",
        "domains": ["facebook.com", "whatsapp.com", "instagram.com", "meta.com"],
        "host_strings": ["whatsapp"],
        "host_tokens": [],
        "lookalikes": ["whatsapp", "facebook"],
        "keywords": ["whatsapp web", "facebook security"],
    },
    "Crypto exchanges": {
        "category": "Global payments",
        "domains": ["binance.com", "coinbase.com", "metamask.io"],
        "host_strings": ["binance", "coinbase", "metamask"],
        "host_tokens": [],
        "lookalikes": ["binance", "coinbase", "metamask"],
        "keywords": ["binance", "coinbase", "metamask", "seed phrase"],
    },
}


def official_domains() -> frozenset[str]:
    """Every official domain of every protected brand."""
    return frozenset(d for info in BRANDS.values() for d in info["domains"])


def brand_for_domain(hostname: str) -> str | None:
    """Return the brand that owns ``hostname`` (exact or subdomain match)."""
    host = (hostname or "").lower().strip(".")
    for name, info in BRANDS.items():
        if any(host == d or host.endswith("." + d) for d in info["domains"]):
            return name
    return None
