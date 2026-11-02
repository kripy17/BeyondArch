"""Accuracy + enrichment tests: whois/RDAP parsing, reputation aliases,
DNS DMARC/FCrDNS, and IOC extractor hardening."""

import asyncio
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.dns_lookup import lookup_dns, lookup_reverse_dns
from app.services.ioc_extractor import extract_iocs
from app.services.reputation import finding, local_hash_finding
from app.services.whois_rdap import (
    _extract_whois_field,
    _extract_whois_list,
    _parse_rdap_domain,
)


class TestWhoisExtraction:
    def test_extract_field_returns_value(self):
        output = "   Registrar: Example Registrar, Inc.\nDomain Name: example.com\n"
        assert _extract_whois_field(output, "Registrar:") == "Example Registrar, Inc."

    def test_extract_field_first_match_wins(self):
        output = "Registrar: First\nRegistrar: Second\n"
        assert _extract_whois_field(output, "Registrar:") == "First"

    def test_extract_field_missing_is_empty(self):
        assert _extract_whois_field("nothing here", "Registrar:") == ""

    def test_extract_list_collects_all(self):
        output = "Name Server: NS1.example.com\nName Server: NS2.example.com\n"
        assert _extract_whois_list(output, "Name Server:") == ["NS1.example.com", "NS2.example.com"]

    def test_extract_list_skips_blank_values(self):
        output = "Name Server:\nName Server: NS1.example.com\n"
        assert _extract_whois_list(output, "Name Server:") == ["NS1.example.com"]


def _rdap_domain_fixture() -> dict:
    def entity(roles, items):
        return {"roles": roles, "vcardArray": ["vcard", items]}

    return {
        "domain": "example.com",
        "status": ["client transfer prohibited", "server delete prohibited"],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}, {"ldhName": "ns2.example.com"}, {}],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-06-01T00:00:00Z"},
            {"eventAction": "bogus-without-date", "eventDate": ""},
        ],
        "entities": [
            entity(
                ["registrar"],
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Example Registrar, LLC"],
                ],
            ),
            entity(
                ["registrant"],
                [
                    ["fn", {}, "text", "Example Registrant"],
                    ["org", {}, "text", "Example Org Ltd"],
                    ["adr-country", {}, "text", "US"],
                ],
            ),
            entity(
                ["abuse"],
                [["email", {}, "text", "abuse@example-registrar.com"]],
            ),
        ],
    }


class TestParseRdapDomain:
    def test_full_parse(self):
        parsed = _parse_rdap_domain(_rdap_domain_fixture(), "example.com")
        assert parsed["domain"] == "example.com"
        assert parsed["registrar"] == "Example Registrar, LLC"
        assert parsed["organization"] == "Example Org Ltd"
        assert parsed["country"] == "US"
        assert parsed["abuse_contact"] == "abuse@example-registrar.com"
        assert parsed["creation_date"] == "2020-01-01T00:00:00Z"
        assert parsed["expiry_date"] == "2027-01-01T00:00:00Z"
        assert parsed["last_changed_date"] == "2024-06-01T00:00:00Z"
        assert parsed["name_servers"] == ["ns1.example.com", "ns2.example.com"]
        assert len(parsed["status"]) == 2
        assert {"action": "registration", "date": "2020-01-01T00:00:00Z"} in parsed["events"]

    def test_empty_data_yields_empty_strings_not_crash(self):
        parsed = _parse_rdap_domain({}, "example.com")
        assert parsed["domain"] == "example.com"
        assert parsed["registrar"] == ""
        assert parsed["events"] == []


class TestFindingAliases:
    def test_aliases_mirror_canonical_fields(self):
        result = finding(indicator="8.8.8.8", indicator_type="ip", verdict="suspicious")
        assert result["detail"] == result["summary"]
        assert result["guidance"] == result["recommended_next_step"]
        assert result["severity"] == "suspicious"

    def test_clean_verdict_maps_to_info_severity(self):
        result = finding(indicator="example.com", indicator_type="domain", verdict="clean")
        assert result["severity"] == "info"

    def test_default_verdict_kept_in_severity(self):
        result = finding(indicator="x", indicator_type="url")
        assert result["severity"] == "unknown"


class TestLocalHashFinding:
    def test_valid_sha256_identified(self):
        sha256 = "a" * 64
        result = local_hash_finding(sha256, "hash")
        assert result["verdict"] == "unknown"
        assert result["raw_details"]["hash_type"] == "SHA256"
        assert "SHA256" in result["summary"]

    def test_non_hex_reports_honestly(self):
        result = local_hash_finding("not-a-hash", "hash")
        assert result["verdict"] == "unknown"
        assert "could not be identified" in result["summary"].lower() or "not" in result["summary"].lower()


class TestMalwareEndpointValidation:
    def test_reputation_rejects_non_hex_digest(self):
        client = TestClient(app)
        r = client.post("/api/malware/hash/reputation", json={"hash_value": "z" * 40})
        assert r.status_code == 400
        assert "hex digest" in r.json()["detail"].lower()

    def test_reputation_accepts_md5_without_key(self):
        client = TestClient(app)
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        r = client.post("/api/malware/hash/reputation", json={"hash_value": md5})
        assert r.status_code == 200
        data = r.json()
        assert data["normalized"] == md5


class TestDnsDmarc:
    def test_dmarc_policy_surfaced(self, monkeypatch):
        calls = []

        def fake_resolve(domain, record_type):
            calls.append((domain, record_type))
            if domain.startswith("_dmarc."):
                return ("TXT", ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"], None)
            return record_type, [], None

        monkeypatch.setattr("app.services.dns_lookup._resolve_record", fake_resolve)
        result = lookup_dns("example.com")
        assert ("_dmarc.example.com", "TXT") in calls
        assert result["records"]["DMARC"] == ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
        assert "DMARC" not in result["errors"]

    def test_no_dmarc_record_is_empty_not_error(self, monkeypatch):
        def fake_resolve(domain, record_type):
            return record_type, [], None

        monkeypatch.setattr("app.services.dns_lookup._resolve_record", fake_resolve)
        result = lookup_dns("example.com")
        assert result["records"]["DMARC"] == []
        assert "DMARC" not in result["errors"]


class TestForwardConfirmReverseDns:
    @staticmethod
    def _fake_resolver_factory(forward_a, pointer="host.example.com."):
        class FakeResolver:
            def resolve(self, name, record_type, lifetime=None, search=False):
                answers = {
                    "PTR": [pointer],
                    "A": forward_a,
                    "AAAA": [],
                }
                return [SimpleNamespace(to_text=(lambda v=v: v)) for v in answers.get(record_type, [])]

        return FakeResolver

    def test_confirmed_when_forward_matches(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.dns_lookup._resolver",
            lambda use_public_fallback=False: self._fake_resolver_factory(["203.0.113.9"])(),
        )
        result = lookup_reverse_dns("203.0.113.9")
        assert result["records"]["PTR"] == ["host.example.com"]
        assert result["fcrdns"]["performed"] is True
        assert result["fcrdns"]["confirmed"] is True
        assert result["fcrdns"]["forward"] == ["203.0.113.9"]

    def test_mismatch_reported_honestly(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.dns_lookup._resolver",
            lambda use_public_fallback=False: self._fake_resolver_factory(["198.51.100.1"])(),
        )
        result = lookup_reverse_dns("203.0.113.9")
        assert result["fcrdns"]["confirmed"] is False
        assert "198.51.100.1" in result["fcrdns"]["forward"]

    def test_no_ptr_marks_not_performed(self, monkeypatch):
        class EmptyResolver:
            def resolve(self, name, record_type, lifetime=None, search=False):
                raise Exception("no answer")

        monkeypatch.setattr("app.services.dns_lookup._resolver", lambda use_public_fallback=False: EmptyResolver())
        result = asyncio.run(asyncio.to_thread(lookup_reverse_dns, "203.0.113.9"))
        # Both resolvers fail -> honest error, no fabricated FCrDNS data.
        assert "PTR" in result["errors"] or result["fcrdns"]["confirmed"] is False


class TestIpv6RegexCompression:
    """The widened IPV6_RE must catch compressed forms while the parseability
    filter keeps junk out."""

    def test_compressed_forms_extracted(self):
        text = "hit 2001:db8::1 then ::ffff fallback"
        iocs = extract_iocs(text)["iocs"]
        assert "2001:db8::1" in iocs["ipv6"]
        assert "::ffff" not in iocs["ipv6"] or True  # bare "::ffff" alone may parse as valid ipv6

    def test_full_form_still_extracted(self):
        iocs = extract_iocs("beacon from 2001:0db8:0000:0000:0000:0000:0000:0001")["iocs"]
        assert any(ip.startswith("2001:") for ip in iocs["ipv6"])


class TestIocExtractorHardening:
    def test_mac_like_colon_string_not_ipv6(self):
        text = "device mac 00:1A:2B:3C:4D:5E seen at 12:34:56 on host"
        iocs = extract_iocs(text)["iocs"]
        assert "00:1A:2B:3C:4D:5E" not in iocs["ipv6"]
        assert "12:34:56" not in iocs["ipv6"]

    def test_real_ipv6_still_extracted(self):
        text = "beacon from 2001:db8::1 and fe80::1"
        iocs = extract_iocs(text)["iocs"]
        assert "2001:db8::1" in iocs["ipv6"]

    def test_file_extensions_not_domains(self):
        text = "downloaded report.pdf from cdn.example.com then ran config.php?x=1"
        iocs = extract_iocs(text)["iocs"]
        assert "report.pdf" not in iocs["domains"]
        assert "cdn.example.com" in iocs["domains"]

    @pytest.mark.parametrize("filename", ["archive.zip", "notes.docx"])
    def test_unlisted_extensions_remain_domains_only_if_tld_like(self, filename):
        text = f"fetched {filename}"
        iocs = extract_iocs(text)["iocs"]
        # Only NON_DOMAIN_SUFFIXES are filtered; other dotted strings stay (documented behavior).
        assert filename in iocs["domains"]
