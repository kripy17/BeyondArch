"""Tests for advanced PCAP analysis, Zeek protocol models, DNS tunneling,
credentials harvesting, and Suricata IDS rule generation."""

import base64
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, wrpcap

from app.services.network_traffic import (
    _detect_file_payload,
    _evaluate_dns_query,
    _extract_credentials,
    _generate_suricata_rules,
    analyze_pcap,
)


def test_dns_tunneling_detection():
    normal = _evaluate_dns_query("api.github.com")
    assert not normal["is_tunneling"]
    assert normal["entropy"] < 3.8

    # High entropy base64 exfiltration subdomain
    exfil = _evaluate_dns_query("aW5maWx0cmF0aW9uLXNlY3JldC1kYXRhLTAwMTI5.tunnel.c2domain.net")
    assert exfil["is_tunneling"]
    assert exfil["entropy"] > 3.8


def test_credentials_harvesting_http_basic():
    auth_header = "Basic " + base64.b64encode(b"admin:SuperSecretP@ss123").decode()
    payload = f"GET /admin HTTP/1.1\r\nHost: target.corp\r\nAuthorization: {auth_header}\r\n\r\n".encode()

    creds = _extract_credentials(payload, "10.0.0.5", "10.0.0.1", "tcp", "80")
    assert len(creds) == 1
    assert creds[0]["protocol"] == "HTTP Basic"
    assert creds[0]["username"] == "admin"
    assert "SuperSecretP@ss123" not in creds[0]["password_masked"]
    assert creds[0]["password_masked"].startswith("S")


def test_credentials_harvesting_ftp():
    user_payload = b"USER backup_svc\r\n"
    pass_payload = b"PASS Summer2026!\r\n"

    creds1 = _extract_credentials(user_payload, "10.0.0.5", "10.0.0.1", "tcp", "21")
    assert len(creds1) == 1
    assert creds1[0]["username"] == "backup_svc"

    creds2 = _extract_credentials(pass_payload, "10.0.0.5", "10.0.0.1", "tcp", "21")
    assert len(creds2) == 1
    assert "Summer2026!" not in creds2[0]["password_masked"]


def test_file_payload_detection():
    pe_payload = b"MZ" + b"\x90" * 100
    res = _detect_file_payload(pe_payload, "10.0.0.1", "10.0.0.5")
    assert res is not None
    assert "Windows PE Executable" in res["type_desc"]
    assert len(res["sha256"]) == 64

    zip_payload = b"PK\x03\x04" + b"\x00" * 100
    res_zip = _detect_file_payload(zip_payload, "10.0.0.1", "10.0.0.5")
    assert res_zip is not None
    assert "ZIP Archive" in res_zip["type_desc"]


def test_suricata_rules_generation():
    findings = []
    repeated_pairs = [{"src": "10.0.0.5", "dst": "45.33.32.156", "packets": 80}]
    suspicious_domains = ["c2beacon.darkops.io"]
    http_requests = [{"user_agent": "curl/7.88.1", "suspicious_ua": True}]

    rules = _generate_suricata_rules(findings, repeated_pairs, suspicious_domains, http_requests)
    assert len(rules) >= 3
    assert any("45.33.32.156" in r for r in rules)
    assert any("c2beacon.darkops.io" in r for r in rules)
    assert any("curl/7.88.1" in r for r in rules)


def test_full_pcap_analysis_zeek_integration(tmp_path):
    packets = [
        # Normal DNS
        IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="portal.corp")),
        # Tunneling DNS
        IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=53001, dport=53) / DNS(rd=1, qd=DNSQR(qname="aW5maWx0cmF0aW9uLXNlY3JldC1kYXRhLTAwMTI5.tunnel.c2domain.net")),
        # HTTP with credentials
        IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=51000, dport=80, flags="PA") / Raw(
            load=b"GET /login HTTP/1.1\r\nHost: example.com\r\nUser-Agent: python-requests/2.31.0\r\nAuthorization: Basic YWRtaW46c2VjcmV0MTIz\r\n\r\n"
        ),
    ]

    pcap_file = tmp_path / "test_zeek.pcap"
    wrpcap(str(pcap_file), packets)

    data = pcap_file.read_bytes()
    result = analyze_pcap("test_zeek.pcap", data)

    assert result["status"] == "parsed"
    assert result["summary"]["packets"] == 3
    assert "zeek_conn" in result
    assert len(result["zeek_conn"]) >= 2
    assert "zeek_dns" in result
    assert len(result["zeek_dns"]) == 2
    assert any(d["is_tunneling"] for d in result["zeek_dns"])
    assert "credentials" in result
    assert len(result["credentials"]) == 1
    assert result["credentials"][0]["username"] == "admin"
    assert "suricata_rules" in result
    assert len(result["suricata_rules"]) >= 1
