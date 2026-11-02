"""Post-connect peer-IP validation for Safe Fetch (DNS rebinding mitigation)."""

from types import SimpleNamespace

import pytest

from app.services import safe_url_analyzer


class TestPeerIpBlocked:
    @pytest.mark.parametrize(
        ("peer", "expected"),
        [
            ("127.0.0.1", "loopback"),
            ("::1", "loopback"),
            ("10.0.0.5", "private/internal"),
            ("192.168.1.1", "private/internal"),
            ("169.254.169.254", "link-local (cloud metadata range)"),
            ("224.0.0.1", "non-routable"),
            # Python classifies 0.0.0.0 as private too (same as net_guard tests).
            ("0.0.0.0", "private/internal"),
        ],
    )
    def test_blocked_ranges(self, peer, expected):
        assert safe_url_analyzer._peer_ip_blocked(peer) == expected

    @pytest.mark.parametrize("peer", ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"])
    def test_public_passes(self, peer):
        assert safe_url_analyzer._peer_ip_blocked(peer) is None

    def test_none_and_junk(self):
        assert safe_url_analyzer._peer_ip_blocked(None) is None
        assert safe_url_analyzer._peer_ip_blocked("not-an-ip") == "unparseable peer address"


class TestPeerIpOf:
    def test_reads_peername_from_network_stream(self):
        stream = SimpleNamespace(get_extra_info=lambda key: ("10.0.0.5", 443))
        response = SimpleNamespace(extensions={"network_stream": stream})
        assert safe_url_analyzer._peer_ip_of(response) == "10.0.0.5"

    def test_missing_extension_returns_none(self):
        response = SimpleNamespace(extensions={})
        assert safe_url_analyzer._peer_ip_of(response) is None

    def test_broken_stream_returns_none(self):
        class Boom:
            def get_extra_info(self, key):
                raise RuntimeError("no socket here")

        response = SimpleNamespace(extensions={"network_stream": Boom()})
        assert safe_url_analyzer._peer_ip_of(response) is None


class _FakeStream:
    def __init__(self, peer):
        self._peer = peer

    def get_extra_info(self, key):
        return self._peer


class _FakeResponse:
    def __init__(self, peer=None):
        self.status_code = 200
        self.headers = {"content-type": "application/json"}
        self.is_redirect = False
        self.extensions = {"network_stream": _FakeStream(peer)} if peer else {}


class _FakeClient:
    def __init__(self, peer):
        self._peer = peer

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def close(self):
        pass

    def request(self, *args, **kwargs):
        return _FakeResponse(self._peer)


def _fake_resolution(monkeypatch):
    monkeypatch.setattr(
        safe_url_analyzer,
        "_resolve_public_addresses",
        lambda host, allow_private_targets=False: (True, ["93.184.216.34"], None),
    )


class TestSafeFetchRebindingGuard:
    def test_private_peer_aborts_fetch(self, monkeypatch):
        _fake_resolution(monkeypatch)
        monkeypatch.setattr(safe_url_analyzer.httpx, "Client", lambda *a, **k: _FakeClient(("10.0.0.5", 443)))

        result = safe_url_analyzer.safe_analyze_url("http://rebind.example.com", allow_live_fetch=True)

        live = result["live_result"]
        assert "DNS rebinding" in (live["blocked_reason"] or "")
        assert "10.0.0.5" in live["blocked_reason"]
        assert live["redirect_chain"] and "refused" in live["redirect_chain"][0]["notes"]

    def test_metadata_peer_aborts_fetch(self, monkeypatch):
        _fake_resolution(monkeypatch)
        monkeypatch.setattr(
            safe_url_analyzer.httpx,
            "Client",
            lambda *a, **k: _FakeClient(("169.254.169.254", 80)),
        )

        result = safe_url_analyzer.safe_analyze_url("http://rebind.example.com", allow_live_fetch=True)

        assert "link-local" in (result["live_result"]["blocked_reason"] or "")

    def test_public_peer_proceeds_normally(self, monkeypatch):
        _fake_resolution(monkeypatch)
        monkeypatch.setattr(safe_url_analyzer.httpx, "Client", lambda *a, **k: _FakeClient(None))

        result = safe_url_analyzer.safe_analyze_url("http://fine.example.com", allow_live_fetch=True)

        live = result["live_result"]
        assert live["blocked_reason"] is None
        assert live["status_code"] == 200
        assert live["redirect_chain"][0]["status_code"] == 200

    def test_unavailable_peer_skips_check(self, monkeypatch):
        _fake_resolution(monkeypatch)
        monkeypatch.setattr(safe_url_analyzer.httpx, "Client", lambda *a, **k: _FakeClient(None))
        # Response without extensions must not break the fetch loop.
        result = safe_url_analyzer.safe_analyze_url("http://opaque.example.com", allow_live_fetch=True)
        assert result["live_result"]["blocked_reason"] is None


class TestConnectionPinning:
    """The pinning backend must connect only to guard-validated addresses."""

    def _backend_with_fake_inner(self, allowed):
        from app.services.safe_url_analyzer import _PinningNetworkBackend

        backend = _PinningNetworkBackend(allowed)
        calls = []

        class FakeInner:
            def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
                calls.append((host, port))
                return object()

        backend._inner = FakeInner()
        return backend, calls

    def test_connects_to_validated_ip_not_hostname(self):
        backend, calls = self._backend_with_fake_inner({"example.com": ["93.184.216.34"]})
        stream = backend.connect_tcp("example.com", 443)
        assert stream is not None
        assert calls == [("93.184.216.34", 443)]

    def test_unvalidated_host_is_refused(self):
        from app.services.safe_url_analyzer import _PinningNetworkBackend

        backend = _PinningNetworkBackend({})
        try:
            backend.connect_tcp("rebound.example.net", 80)
        except OSError as exc:
            assert "not validated" in str(exc)
        else:
            raise AssertionError("unvalidated host was allowed to connect")

    def test_all_addresses_tried_before_giving_up(self):
        backend, calls = self._backend_with_fake_inner(
            {"example.com": ["192.0.2.10", "192.0.2.11"]}
        )

        class FlakyInner:
            def __init__(self):
                self.n = 0

            def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
                self.n += 1
                if host == "192.0.2.10":
                    raise OSError("first address unreachable")
                return object()

        flaky = FlakyInner()
        backend._inner = flaky
        assert backend.connect_tcp("example.com", 443) is not None
        assert flaky.n == 2


class TestPinnedTransportEndToEnd:
    def test_loopback_fetch_succeeds_through_pinned_transport(self):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            from app.services.safe_url_analyzer import safe_analyze_url

            result = safe_analyze_url(
                f"http://127.0.0.1:{port}/",
                allow_live_fetch=True,
                allow_private_targets=True,
                timeout_seconds=5,
            )
        finally:
            server.shutdown()
            thread.join(timeout=2)

        live = result.get("live_result", {})
        assert live.get("blocked_reason") in (None, ""), live
        statuses = [hop.get("status_code") for hop in live.get("redirect_chain", [])]
        assert 200 in statuses
