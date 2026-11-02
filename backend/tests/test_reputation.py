import asyncio

import httpx

from app.services import reputation
from app.services.reputation import enrich_indicator_reputation, vt_verdict_from_stats

HASH = "d41d8cd98f00b204e9800998ecf8427e"


def patch_vt(monkeypatch, handler):
    real_client = httpx.AsyncClient

    def factory(**kwargs):
        kwargs.pop("transport", None)
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(reputation.httpx, "AsyncClient", factory)


class TestVtVerdictFromStats:
    def test_malicious_majority(self):
        assert vt_verdict_from_stats({"malicious": 5, "suspicious": 1, "undetected": 40, "harmless": 10}) == ("malicious", "high")

    def test_single_malicious_is_medium(self):
        assert vt_verdict_from_stats({"malicious": 1, "undetected": 60}) == ("malicious", "medium")

    def test_suspicious_only(self):
        assert vt_verdict_from_stats({"suspicious": 2, "undetected": 30}) == ("suspicious", "medium")

    def test_clean_with_coverage(self):
        assert vt_verdict_from_stats({"harmless": 55, "undetected": 10}) == ("clean", "high")

    def test_empty_stats(self):
        assert vt_verdict_from_stats({}) == ("clean", "low")


class TestExternalHashReputation:
    def test_no_key_means_local_only(self, monkeypatch):
        monkeypatch.delenv("BEYONDLABS_VT_API_KEY", raising=False)
        result = asyncio.run(enrich_indicator_reputation(HASH, "hash"))
        sources = [f["source"] for f in result["findings"]]
        assert sources == ["BeyondLabs hash classifier"]
        assert "does not query external reputation providers" in result["summary"]["note"]

    def test_key_with_malicious_hash(self, monkeypatch):
        monkeypatch.setenv("BEYONDLABS_VT_API_KEY", "test-key")

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == f"/api/v3/files/{HASH}"
            assert request.headers["x-apikey"] == "test-key"
            return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "suspicious": 0, "undetected": 50, "harmless": 3}}}})

        patch_vt(monkeypatch, handler)
        result = asyncio.run(enrich_indicator_reputation(HASH, "hash"))
        assert len(result["findings"]) == 2
        external = result["findings"][-1]
        assert external["source"] == "VirusTotal"
        assert external["verdict"] == "malicious"
        assert external["confidence"] == "high"
        assert external["trust_type"] == "external_provider"
        assert "opt-in external provider lookup" in result["summary"]["note"]

    def test_key_with_unknown_hash_404(self, monkeypatch):
        monkeypatch.setenv("BEYONDLABS_VT_API_KEY", "test-key")
        patch_vt(monkeypatch, lambda request: httpx.Response(404, json={"error": {"code": "NotFoundError"}}))
        result = asyncio.run(enrich_indicator_reputation(HASH, "hash"))
        external = result["findings"][-1]
        assert external["source"] == "VirusTotal"
        assert external["verdict"] == "unknown"
        assert "unknown to the provider's corpus" in external["summary"]

    def test_network_failure_stays_honest(self, monkeypatch):
        monkeypatch.setenv("BEYONDLABS_VT_API_KEY", "test-key")

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom")

        patch_vt(monkeypatch, handler)
        result = asyncio.run(enrich_indicator_reputation(HASH, "hash"))
        external = result["findings"][-1]
        assert external["verdict"] == "unknown"
        assert "failed" in external["summary"]
        assert "treat as not-checked" in external["limitations"]

    def test_non_hash_types_ignore_the_key(self, monkeypatch):
        monkeypatch.setenv("BEYONDLABS_VT_API_KEY", "test-key")

        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("no external call expected for non-hash indicators")

        patch_vt(monkeypatch, handler)
        result = asyncio.run(enrich_indicator_reputation("evil.com", "domain"))
        assert all(f["source"].startswith("BeyondLabs") for f in result["findings"])
