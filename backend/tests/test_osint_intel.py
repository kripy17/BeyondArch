from fastapi.testclient import TestClient
from app.main import app
from app.services.osint_enricher import (
    classify_indicator,
    compute_threat_score,
    generate_passive_dns,
    generate_whois_profile,
    generate_ssl_certificate,
    build_diamond_model,
    generate_stix_bundle,
    enrich_osint_indicator,
)

client = TestClient(app)


def test_classify_indicators():
    assert classify_indicator("185.220.101.4") == "ipv4"
    assert classify_indicator("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "ipv6"
    assert classify_indicator("defense-update.org") == "domain"
    assert classify_indicator("https://phish.target.com/login") == "url"
    assert classify_indicator("cve-2024-3400") == "cve"
    assert classify_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"
    assert classify_indicator("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert classify_indicator("analyst@example.com") == "email"


def test_compute_threat_score_known_threats():
    apt28_ip = compute_threat_score("185.220.101.4", "ipv4")
    assert apt28_ip["score"] >= 90
    assert apt28_ip["threat_actor"] == "APT28"
    assert apt28_ip["verdict"] == "malicious"
    assert apt28_ip["is_known_threat"] is True

    solarwinds_c2 = compute_threat_score("avsvmcloud.com", "domain")
    assert solarwinds_c2["score"] >= 95
    assert solarwinds_c2["threat_actor"] == "APT29"

    cve_result = compute_threat_score("cve-2024-3400", "cve")
    assert cve_result["score"] == 100
    assert cve_result["verdict"] == "weaponized"


def test_passive_dns_and_whois_generation():
    dns_records = generate_passive_dns("avsvmcloud.com")
    assert len(dns_records) >= 2
    record_types = {r["record_type"] for r in dns_records}
    assert "A" in record_types
    assert "MX" in record_types

    whois = generate_whois_profile("defense-update.org")
    assert whois["domain"] == "defense-update.org"
    assert whois["privacy_protected"] is True
    assert len(whois["nameservers"]) > 0


def test_ssl_certificate_metadata():
    cert = generate_ssl_certificate("avsvmcloud.com")
    assert cert["subject_cn"] == "avsvmcloud.com"
    assert "ja3_hash" in cert
    assert "ja4_fingerprint" in cert
    assert len(cert["san_list"]) > 1


def test_diamond_model_structure():
    score_info = {"score": 94, "confidence": "high", "threat_actor": "APT28"}
    diamond = build_diamond_model("185.220.101.4", "ipv4", score_info)
    assert "adversary" in diamond
    assert "capability" in diamond
    assert "infrastructure" in diamond
    assert "victim" in diamond
    assert diamond["adversary"]["actor"] == "APT28"
    assert diamond["adversary"]["origin"] == "Russia"
    assert "Defense" in diamond["victim"]["targeted_sectors"]


def test_stix_bundle_validity():
    score_info = {"score": 92, "confidence": "high", "threat_actor": "APT28"}
    bundle = generate_stix_bundle("185.220.101.4", "ipv4", score_info)
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert len(bundle["objects"]) == 3

    types = {obj["type"] for obj in bundle["objects"]}
    assert "indicator" in types
    assert "threat-actor" in types
    assert "relationship" in types

    indicator_obj = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert "185.220.101.4" in indicator_obj["pattern"]


def test_recon_intel_enrich_api():
    response = client.post("/api/recon-intel/enrich", json={"indicator": "185.220.101.4"})
    assert response.status_code == 200
    data = response.json()
    assert data["indicator"] == "185.220.101.4"
    assert data["indicator_type"] == "ipv4"
    assert data["score_info"]["threat_actor"] == "APT28"
    assert data["diamond_model"]["adversary"]["actor"] == "APT28"
    assert data["stix_bundle"]["type"] == "bundle"
