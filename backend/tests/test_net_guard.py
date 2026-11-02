"""Tests for the shared outbound-request guard and its endpoint wiring."""

import socket

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import http_probe, net_guard, osint_tools, web_exposure
from app.services.net_guard import OutboundBlockedError, assert_public_host, blocked_reason, host_of

client = TestClient(app)


def _fake_resolver(records):
    """Return a getaddrinfo replacement yielding the given IPs for any host."""

    def resolver(host, port=None, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in records]

    return resolver


class TestHostOf:
    def test_url_yields_hostname(self):
        assert host_of("https://example.com/path?q=1") == "example.com"

    def test_raw_host(self):
        assert host_of("example.com") == "example.com"

    def test_trailing_dot_stripped(self):
        assert host_of("example.com.") == "example.com"

    def test_non_http_scheme_rejected(self):
        assert host_of("ftp://example.com") is None
        assert host_of("file:///etc/passwd") is None

    def test_path_or_userinfo_in_raw_host_rejected(self):
        assert host_of("example.com/path") is None
        assert host_of("user@example.com") is None

    def test_bare_ipv6_literal(self):
        assert host_of("::1") == "::1"
        assert host_of("2001:db8::1") == "2001:db8::1"

    def test_empty_and_junk(self):
        assert host_of("") is None
        assert host_of("   ") is None
        assert host_of("not:a//host:") is None


class TestIpLiteralBlocks:
    @pytest.mark.parametrize(
        ("target", "fragment"),
        [
            ("127.0.0.1", "loopback"),
            ("::1", "loopback"),
            ("10.1.2.3", "private/internal"),
            ("192.168.1.1", "private/internal"),
            ("172.16.0.9", "private/internal"),
            ("169.254.169.254", "cloud metadata"),
            ("224.0.0.1", "reserved/multicast"),
            ("0.0.0.0", "private/internal"),
        ],
    )
    def test_blocked_ranges(self, target, fragment):
        reason = blocked_reason(target)
        assert reason is not None
        assert fragment in reason

    def test_public_ip_allowed(self):
        assert blocked_reason("8.8.8.8") is None

    def test_single_label_hostname_rejected(self):
        reason = blocked_reason("localhost")
        assert "single-label" in reason

    def test_allow_private_bypasses_ranges_not_metadata_parse(self):
        assert blocked_reason("10.1.2.3", allow_private=True) is None
        assert blocked_reason("169.254.169.254", allow_private=True) is None
        assert blocked_reason("127.0.0.1", allow_private=True) is None
        assert blocked_reason("not a clean host", allow_private=True) is not None


class TestDnsResolutionPath:
    def test_resolves_to_private_is_blocked(self, monkeypatch):
        monkeypatch.setattr(net_guard.socket, "getaddrinfo", _fake_resolver(["192.168.0.7"]))
        reason = blocked_reason("internal.example.com")
        assert reason is not None
        assert "192.168.0.7" in reason
        assert "private" in reason

    def test_resolves_to_public_passes(self, monkeypatch):
        monkeypatch.setattr(net_guard.socket, "getaddrinfo", _fake_resolver(["93.184.216.34"]))
        assert blocked_reason("example.com") is None

    def test_dns_failure_is_honest_not_leaky(self, monkeypatch):
        def boom(host, port=None, *args, **kwargs):
            raise socket.gaierror(8, "nodename nor servname provided")

        monkeypatch.setattr(net_guard.socket, "getaddrinfo", boom)
        reason = blocked_reason("nonexistent.example.com")
        assert reason == "DNS resolution failed (gaierror)"
        assert "nodename" not in reason

    def test_mixed_records_blocked_if_any_private(self, monkeypatch):
        monkeypatch.setattr(
            net_guard.socket,
            "getaddrinfo",
            _fake_resolver(["93.184.216.34", "10.0.0.5"]),
        )
        assert "10.0.0.5" in blocked_reason("dual.example.com")


class TestAssertPublicHost:
    def test_returns_cleaned_hostname(self):
        assert assert_public_host("https://example.com/x") == "example.com"

    def test_raises_with_reason_and_host(self):
        with pytest.raises(OutboundBlockedError) as exc_info:
            assert_public_host("http://127.0.0.1:8000/")
        assert "loopback" in exc_info.value.reason
        assert exc_info.value.host == "127.0.0.1"


class TestServiceWiring:
    def test_probe_http_blocks_loopback_without_dns(self):
        result = http_probe.probe_http("http://127.0.0.1/", mode="head_only")
        assert result["blocked"] is True
        assert "outbound guard" in result["error"]
        assert "loopback" in result["blocked_reason"]

    def test_web_exposure_refuses_private_target_as_value_error(self):
        with pytest.raises(ValueError) as exc_info:
            web_exposure.run_web_exposure_review("10.9.9.9", confirm_permission=True)
        assert "private/internal" in str(exc_info.value)

    def test_local_osint_tool_requires_confirm(self):
        result = osint_tools.run_local_osint_tool(tool_id="dig", domain="example.com")
        assert result["success"] is False
        assert "Confirm authorization" in result["error"]

    def test_maigret_rejects_flag_injection(self):
        from app.services.maigret_service import run_maigret_search

        result = run_maigret_search("--proxy=http://evil.example")
        assert "cannot start with '-'" in result["error"]


class TestEndpointGates:
    def test_passive_requires_confirm(self):
        r = client.post("/api/recon/passive", json={"target": "example.com"})
        assert r.status_code == 400
        assert "Confirm authorization" in r.json()["detail"]

    def test_social_links_requires_confirm(self):
        r = client.post("/api/osint/social-links", json={"website": "https://example.com"})
        assert r.status_code == 400
        assert "Confirm authorization" in r.json()["detail"]

    def test_maigret_requires_confirm(self):
        r = client.post("/api/osint/maigret", json={"username": "someuser"})
        assert r.status_code == 400
        assert "maigret" in r.json()["detail"].lower()

    def test_web_exposure_blocks_private_target(self):
        r = client.post(
            "/api/recon/web-exposure",
            json={"target": "10.9.9.9", "confirm_permission": True},
        )
        assert r.status_code == 400
        assert "private" in r.json()["detail"]

    def test_nmap_stream_still_gated(self):
        r = client.post("/api/network/nmap/stream", json={"target": "example.com"})
        assert r.status_code == 400


class TestCorsPolicy:
    def test_default_origins_no_wildcard(self):
        from app.main import _allow_wildcard

        assert _allow_wildcard is False
