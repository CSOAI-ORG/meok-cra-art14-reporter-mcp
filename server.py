#!/usr/bin/env python3
"""
MEOK CRA Article 14 Reporter MCP
=================================

By MEOK AI Labs · https://meok.ai · MIT
<!-- mcp-name: io.github.CSOAI-ORG/meok-cra-art14-reporter-mcp -->

WHAT THIS DOES
--------------
EU Cyber Resilience Act (CRA, Regulation 2024/2847) Article 14 requires
manufacturers of products with digital elements to notify ENISA AND the
national CSIRT when an **actively exploited vulnerability** is discovered.

Effective: **11 September 2026**.

The clock is brutal:
  - **24 hours** — early warning to ENISA + national CSIRT
  - **72 hours** — incident notification with mitigation
  - **14 days** — final report after the vulnerability is resolved
  - PLUS — severe-incident report (Article 14(1)(b)) on any product compromise

This MCP classifies vulnerabilities under Article 14, generates the ENISA
+ national-CSIRT payloads, tracks the three clocks, and HMAC-signs the
chain for audit.

Companion to:
- `cra-compliance-mcp` (Annex I classifier + SBOM + conformity)
- `agent-incident-relay-mcp` (5-clock broadcaster — Art 14 cross-walks)
- `sbom-cyclonedx-mcp` (SBOM for the affected product)

PRICE: £499/mo Governance Substrate · £29/mo Starter · MIT self-host free.
"""

from __future__ import annotations
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
from mcp.server.fastmcp import FastMCP


mcp = FastMCP("meok-cra-art14-reporter")
_HMAC_SECRET = os.environ.get("MEOK_HMAC_SECRET", "")
_VULNS: dict[str, dict] = {}

EFFECTIVE_DATE = "2026-09-11"

CRA_CLOCKS = [
    {"label": "Early warning to ENISA + national CSIRT", "hours": 24, "ref": "Article 14(2)(a)"},
    {"label": "Incident notification with mitigation", "hours": 72, "ref": "Article 14(2)(b)"},
    {"label": "Final report after vulnerability resolved", "hours": 14 * 24, "ref": "Article 14(2)(c)"},
]

EU_CSIRT_BY_COUNTRY = {
    "DE": "BSI / CERT-Bund (csirt@bund.de)",
    "FR": "ANSSI / CERT-FR (cert-fr.cossi@ssi.gouv.fr)",
    "NL": "NCSC-NL (cert@ncsc.nl)",
    "IE": "NCSC-IE (incident@ncsc.gov.ie)",
    "IT": "CSIRT Italia (csirt@cert.gov.it)",
    "ES": "INCIBE-CERT (incidencias@incibe-cert.es)",
    "PL": "NASK CSIRT (cert@cert.pl)",
    "SE": "CERT-SE (cert@cert.se)",
    "BE": "CERT.be (cert@cert.be)",
    "AT": "GovCERT.AT (team@govcert.gv.at)",
}


def _sign(payload: dict) -> str:
    if not _HMAC_SECRET:
        return "unsigned-no-key-configured"
    return hmac.new(_HMAC_SECRET.encode(), json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ──────────────────────────────────────────────────────────────────────
# Tools
# ──────────────────────────────────────────────────────────────────────

@mcp.tool()
def classify_vulnerability(description: str, cvss_v3: Optional[float] = None, exploited_in_wild: bool = False) -> dict:
    """
    Classify a vulnerability against CRA Article 14 reporting thresholds.

    Args:
        description: Free-text vulnerability description.
        cvss_v3: Optional CVSS 3.x base score.
        exploited_in_wild: Has active exploitation been observed?

    Returns:
        {triggers_art_14, severity, mandatory_actions, ...}
    """
    d = description.lower()
    triggers = exploited_in_wild  # Article 14 specifically targets actively-exploited
    severity = "informational"
    if cvss_v3 is not None:
        if cvss_v3 >= 9.0:
            severity = "critical"
        elif cvss_v3 >= 7.0:
            severity = "high"
        elif cvss_v3 >= 4.0:
            severity = "medium"
        else:
            severity = "low"
    # Heuristic exploit-language detection
    if not exploited_in_wild:
        if any(k in d for k in ["actively exploited", "in the wild", "0-day", "zero day", "ransomware leverages", "mass exploitation"]):
            triggers = True

    actions = []
    if triggers:
        actions = [
            "Within 24h: early warning to ENISA + national CSIRT (Article 14(2)(a))",
            "Within 72h: incident notification with mitigation (Article 14(2)(b))",
            "Within 14d after fix: final report (Article 14(2)(c))",
            "Article 11: notify affected users of mitigation steps",
        ]
    return {
        "triggers_art_14": triggers,
        "severity": severity,
        "cvss_v3": cvss_v3,
        "mandatory_actions": actions,
        "next_step": "Call open_vulnerability_case() to start the 3-clock tracker." if triggers else "Not actively exploited - no Article 14 obligation, but voluntary disclosure encouraged.",
    }


@mcp.tool()
def open_vulnerability_case(
    cve_id: str,
    product_name: str,
    description: str,
    cvss_v3: float,
    discovery_ts: Optional[str] = None,
    manufacturer: str = "unspecified",
    member_state: str = "NL",
) -> dict:
    """
    Open a CRA Article 14 case and start the three clocks.

    Args:
        cve_id: CVE identifier (or temporary ID if not yet assigned).
        product_name: Affected product name.
        description: Vulnerability description.
        cvss_v3: CVSS 3.x base score.
        discovery_ts: ISO timestamp of discovery. Defaults to now.
        manufacturer: Manufacturer legal name.
        member_state: ISO 3166-1 alpha-2 (DE, FR, NL, etc.) for national CSIRT mapping.

    Returns:
        {case_id, clocks: [...], national_csirt_contact, ...}
    """
    discovery = discovery_ts or _ts()
    discovery_dt = datetime.fromisoformat(discovery.replace("Z", "+00:00"))
    case_id = f"CRA14_{cve_id.replace('-', '')}_{int(time.time())}"
    clocks = [
        {
            "ref": c["ref"],
            "label": c["label"],
            "deadline_iso": (discovery_dt + timedelta(hours=c["hours"])).isoformat(),
            "hours_from_discovery": c["hours"],
            "status": "open",
        }
        for c in CRA_CLOCKS
    ]
    case = {
        "case_id": case_id,
        "cve_id": cve_id,
        "product_name": product_name,
        "description": description,
        "cvss_v3": cvss_v3,
        "manufacturer": manufacturer,
        "member_state": member_state,
        "discovery_ts": discovery,
        "clocks": clocks,
        "national_csirt": EU_CSIRT_BY_COUNTRY.get(member_state, "ENISA: cra-art14@enisa.europa.eu"),
        "created_at": _ts(),
        "status": "active",
    }
    _VULNS[case_id] = case
    return {
        "case_id": case_id,
        "clocks": clocks,
        "national_csirt_contact": case["national_csirt"],
        "enisa_contact": "cra-art14@enisa.europa.eu",
        "next_step": "Call generate_enisa_payload() within 24 hours of discovery.",
    }


@mcp.tool()
def generate_enisa_payload(case_id: str, mitigation_steps: Optional[list[str]] = None) -> dict:
    """
    Generate the ENISA + national-CSIRT submission payload.

    Args:
        case_id: From open_vulnerability_case().
        mitigation_steps: Optional list of mitigations applied / planned.

    Returns:
        {payload, enisa_email, national_csirt_email}
    """
    if case_id not in _VULNS:
        return {"error": f"Unknown case_id: {case_id}"}
    c = _VULNS[case_id]
    payload = {
        "spec": "CRA_REG_2024_2847_ART_14",
        "case_id": case_id,
        "cve_id": c["cve_id"],
        "manufacturer": c["manufacturer"],
        "product_name": c["product_name"],
        "description": c["description"],
        "cvss_v3": c["cvss_v3"],
        "discovery_ts": c["discovery_ts"],
        "mitigation_steps": mitigation_steps or [],
        "submission_ts": _ts(),
        "member_state": c["member_state"],
    }
    payload["signature"] = _sign(payload)
    return {
        "payload": payload,
        "enisa_email": "cra-art14@enisa.europa.eu",
        "national_csirt": c["national_csirt"],
        "submission_hint": (
            "Submit to ENISA via the single reporting platform (single notification will be "
            "forwarded automatically per Article 14(4)). National CSIRT receives a copy."
        ),
    }


@mcp.tool()
def check_clock_status(case_id: str) -> dict:
    """How many hours remain on each clock for this case?"""
    if case_id not in _VULNS:
        return {"error": f"Unknown case_id: {case_id}"}
    c = _VULNS[case_id]
    now = datetime.now(timezone.utc)
    out = []
    missed = []
    for clk in c["clocks"]:
        deadline = datetime.fromisoformat(clk["deadline_iso"].replace("Z", "+00:00"))
        remaining_h = (deadline - now).total_seconds() / 3600
        rec = {**clk, "hours_remaining": round(remaining_h, 2)}
        out.append(rec)
        if remaining_h < 0 and clk["status"] == "open":
            missed.append(rec)
    return {
        "case_id": case_id,
        "now": _ts(),
        "clocks": out,
        "missed_clocks": missed,
        "all_clear": len(missed) == 0,
    }


@mcp.tool()
def list_national_csirts() -> dict:
    """Return the EU national CSIRT contact map."""
    return {
        "csirts": EU_CSIRT_BY_COUNTRY,
        "count": len(EU_CSIRT_BY_COUNTRY),
        "enisa_central": "cra-art14@enisa.europa.eu",
        "spec_url": "https://eur-lex.europa.eu/eli/reg/2024/2847/oj",
    }


@mcp.tool()
def check_cra_status() -> dict:
    """Days remaining until 11 Sept 2026 CRA Article 14 effective date."""
    today = datetime.now(timezone.utc).date()
    eff = datetime.fromisoformat(EFFECTIVE_DATE).date()
    return {
        "today": today.isoformat(),
        "effective_date": EFFECTIVE_DATE,
        "days_until_effective": (eff - today).days,
        "is_in_force": today >= eff,
    }


@mcp.tool()
def sign_chain(case_id: str) -> dict:
    """HMAC-sign the full Article 14 case for audit."""
    if case_id not in _VULNS:
        return {"error": f"Unknown case_id: {case_id}"}
    c = _VULNS[case_id]
    sealed = {**c, "sealed_at": _ts()}
    sig = _sign(sealed)
    c["signature"] = sig
    c["sealed_at"] = sealed["sealed_at"]
    return {
        "signed": _HMAC_SECRET != "",
        "signature": sig,
        "sealed_at": sealed["sealed_at"],
    }


if __name__ == "__main__":
    mcp.run()


# ── MEOK monetization layer (Stripe upgrade · PAYG · pricing) ──────────
# Free tier is zero-config. Upgrade to Pro (unlimited) or pay-as-you-go per call.
import os as _meok_os
MEOK_STRIPE_UPGRADE = "https://buy.stripe.com/00wfZjcgAeUW4c5cyQ8k90K"  # Pro (unlimited)
MEOK_PAYG_KEY = _meok_os.environ.get("MEOK_PAYG_KEY", "")  # set to enable PAYG (x402 / ~GBP0.05 per call)
MEOK_PRICING = "https://meok.ai/pricing"


def meok_upsell(tier: str = "free") -> dict:
    """Monetization options for free-tier callers: Pro upgrade, PAYG, or pricing page."""
    if tier != "free":
        return {}
    return {"upgrade_url": MEOK_STRIPE_UPGRADE,
            "payg_enabled": bool(MEOK_PAYG_KEY),
            "pricing": MEOK_PRICING}
