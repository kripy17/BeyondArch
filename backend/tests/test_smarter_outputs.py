"""Tests for smarter-output leftovers: batch enrichment, timestamp accuracy,
TLS SNI extraction, and beacon detection."""

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from scapy.all import IP, TCP, wrpcap

from app.main import app
from app.services.mini_siem import parse_timestamp
from app.services.network_traffic import _tls_sni, analyze_pcap

client = TestClient(app)


class TestBatchEnrich:
    def test_mixed_batch_auto_detects_types(self):
        payload = {
            "indicators": [
                {"value": "44d88612fea8a8f36de82e1278abb02f"},
                {"value": "8.8.8.8"},
                {"value": "example.com"},
            ]
        }
        r = client.post("/api/reputation/enrich-batch", json=payload)
        assert r.status_code == 200
        data = r.json()
        results = data["results"]
        assert len(results) == 3
        assert results[0]["type"] == "hash"
        assert results[1]["type"] == "ip"
        assert results[2]["type"] == "domain"
        summary = data["summary"]
        assert summary["requested"] == 3
        assert summary["processed"] == 3
        assert summary["skipped_count"] == 0
        assert isinstance(summary["verdict_counts"], dict)
        assert "note" in summary

    def test_batch_rejects_over_cap(self):
        r = client.post(
            "/api/reputation/enrich-batch",
            json={"indicators": [{"value": f"host{i}.example.com"} for i in range(26)]},
        )
        assert r.status_code == 422

    def test_explicit_type_override(self):
        r = client.post(
            "/api/reputation/enrich-batch",
            json={"indicators": [{"value": "evil.com", "indicator_type": "domain"}]},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["results"][0]["type"] == "domain"
        assert data["results"][0]["normalized"] == "evil.com"


class TestParseTimestamp:
    def test_naive_iso_is_treated_as_utc_not_local(self):
        result = parse_timestamp("2026-01-15T10:30:00")
        assert result.endswith("Z")
        # Hour must survive: naive input means UTC, never re-based onto local tz.
        assert "T10:30" in result

    def test_aware_iso_converts_to_utc(self):
        result = parse_timestamp("2026-01-15T10:30:00+02:00")
        assert result.startswith("2026-01-15T08:30")

    def test_naive_space_format_keeps_parsed_year(self):
        # Regression: old code clobbered the parsed year with the current year.
        result = parse_timestamp("2023-05-01 10:00:00")
        assert result.startswith("2023-05-01T10:00")

    def test_syslog_future_date_gets_previous_year(self):
        now = datetime.now(timezone.utc)
        candidate = datetime(now.year, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        expected_year = now.year if (candidate - now) <= timedelta(days=1) else now.year - 1
        result = parse_timestamp("Dec 31 23:59:59")
        assert result.startswith(f"{expected_year}-12-31T23:59:59")

    def test_fallback_returns_original_value(self):
        assert parse_timestamp("garbage-time") == "garbage-time"


class TestTlsSni:
    def _client_hello(self, host: str) -> bytes:
        return b"\x16\x03\x01\x00\x40\x08\x09\x00\x00" + len(host).to_bytes(2, "big") + host.encode()

    def test_extracts_sni_from_client_hello_bytes(self):
        assert _tls_sni(self._client_hello("Example.COM")) == "example.com"

    def test_non_handshake_record_is_ignored(self):
        assert _tls_sni(b"\x17\x03\x03" + b"\x00" * 20) == ""

    def test_junk_without_marker_is_ignored(self):
        assert _tls_sni(b"\x16\x03\x01" + b"no-sni-marker-here") == ""


class TestBeaconDetection:
    def test_repeated_flow_is_flagged(self, tmp_path):
        packets = [
            IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=40000 + i, dport=443, flags="S")
            for i in range(55)
        ]
        tmp = tmp_path / "beacon-test.pcap"
        wrpcap(str(tmp), packets)
        data = tmp.read_bytes()

        result = analyze_pcap("beacon-test.pcap", data)

        assert result["status"] == "parsed"
        titles = {finding.get("title", "") for finding in result.get("findings", [])}
        flagged = (
            bool(result.get("beaconing_candidates"))
            or "Repeated destination flow" in titles
            or "Potential beaconing candidate" in titles
        )
        assert flagged


class TestPcapHashExtraction:
    def test_hashes_extracted_from_http_payload(self, tmp_path):
        from scapy.all import Raw

        md5 = "44d88612fea8a8f36de82e1278abb02f"
        sha256 = "a" * 64
        body = f'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nsample {md5} and {sha256}'.encode()
        packets = [
            IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=50000, dport=80, flags="PA") / Raw(load=body)
        ]
        tmp = tmp_path / "hashes.pcap"
        wrpcap(str(tmp), packets)

        result = analyze_pcap("hashes.pcap", tmp.read_bytes())

        assert result["status"] == "parsed"
        hashes = result["iocs"]["hashes"]
        assert md5 in hashes
        assert sha256 in hashes

    def test_junk_payload_yields_no_hashes(self, tmp_path):
        from scapy.all import Raw

        body = b"HTTP/1.1 200 OK\r\n\r\nno digests here, just words 12345"
        packets = [
            IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=50001, dport=80, flags="PA") / Raw(load=body)
        ]
        tmp = tmp_path / "junk.pcap"
        wrpcap(str(tmp), packets)

        result = analyze_pcap("junk.pcap", tmp.read_bytes())

        assert result["iocs"]["hashes"] == []
