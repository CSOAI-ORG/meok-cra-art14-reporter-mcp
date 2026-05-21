"""Smoke tests for meok-cra-art14-reporter-mcp."""
import sys, os, inspect, traceback
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import (
    classify_vulnerability,
    open_vulnerability_case,
    generate_enisa_payload,
    check_clock_status,
    list_national_csirts,
    check_cra_status,
    sign_chain,
    EU_CSIRT_BY_COUNTRY,
    _VULNS,
)


def test_classify_actively_exploited_triggers_art_14():
    r = classify_vulnerability("Remote RCE actively exploited in the wild by ransomware groups", cvss_v3=9.8)
    assert r["triggers_art_14"] is True
    assert r["severity"] == "critical"
    assert len(r["mandatory_actions"]) >= 3


def test_classify_explicit_exploited_flag():
    r = classify_vulnerability("Buffer overflow in TLS handshake", cvss_v3=7.5, exploited_in_wild=True)
    assert r["triggers_art_14"] is True


def test_classify_non_exploited_no_trigger():
    r = classify_vulnerability("Theoretical race condition with no observed exploit", cvss_v3=4.0)
    assert r["triggers_art_14"] is False


def test_open_case_returns_three_clocks():
    _VULNS.clear()
    r = open_vulnerability_case("CVE-2026-1234", "Acme IoT v1.2", "RCE in MQTT", 9.5, manufacturer="Acme", member_state="DE")
    assert r["case_id"].startswith("CRA14_CVE20261234_")
    assert len(r["clocks"]) == 3
    assert "BSI" in r["national_csirt_contact"]


def test_generate_enisa_payload():
    _VULNS.clear()
    case = open_vulnerability_case("CVE-X", "P", "D", 9.0, member_state="NL")
    p = generate_enisa_payload(case["case_id"], mitigation_steps=["Patch v1.3 released"])
    assert p["payload"]["cve_id"] == "CVE-X"
    assert "signature" in p["payload"]
    assert "NCSC-NL" in p["national_csirt"]


def test_generate_enisa_payload_unknown_case():
    r = generate_enisa_payload("nope")
    assert "error" in r


def test_check_clock_status_returns_remaining():
    _VULNS.clear()
    case = open_vulnerability_case("CVE-Y", "P", "D", 9.0)
    s = check_clock_status(case["case_id"])
    assert len(s["clocks"]) == 3
    # 24h clock should still be positive
    assert s["clocks"][0]["hours_remaining"] > 20


def test_check_clock_status_unknown():
    r = check_clock_status("nope")
    assert "error" in r


def test_list_national_csirts():
    r = list_national_csirts()
    assert "DE" in r["csirts"]
    assert "NL" in r["csirts"]
    assert r["count"] >= 10


def test_check_cra_status():
    r = check_cra_status()
    assert "days_until_effective" in r
    assert r["effective_date"] == "2026-09-11"


def test_sign_chain():
    _VULNS.clear()
    case = open_vulnerability_case("CVE-Z", "P", "D", 9.0)
    r = sign_chain(case["case_id"])
    assert "signature" in r


if __name__ == "__main__":
    g = dict(globals())
    fns = [v for k, v in g.items() if k.startswith("test_") and inspect.isfunction(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); print(f"OK {fn.__name__}"); p += 1
        except Exception as e:
            print(f"X  {fn.__name__}: {type(e).__name__}: {e}"); traceback.print_exc(); f += 1
    print(f"\n{p} passed, {f} failed")
