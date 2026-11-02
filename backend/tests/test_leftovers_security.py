"""Regression tests for the leftover security pass.

Covers:
- nmap custom output-file flags are rejected (arbitrary file write closure)
- optional BEYONDLABS_REQUIRE_AUTH bearer gate (unset = open, set = enforced)
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


class TestNmapCustomOutputFlags:
    def test_output_file_flag_rejected(self):
        r = client.post(
            "/api/recon/nmap-custom",
            json={
                "command": "nmap -oX /tmp/scan-results.json -sn 8.8.8.8",
                "confirm_permission": True,
            },
        )
        assert r.status_code == 200
        data = r.json()
        scan = data.get("scan", data)
        assert scan.get("success") is False
        assert "-oX" in scan.get("error", "")

    def test_stylesheet_flag_rejected(self):
        r = client.post(
            "/api/recon/nmap-custom",
            json={
                "command": "nmap --stylesheet /tmp/x.xsl -sn 8.8.8.8",
                "confirm_permission": True,
            },
        )
        assert r.status_code == 200
        scan = r.json().get("scan", r.json())
        assert scan.get("success") is False
        assert "--stylesheet" in scan.get("error", "")

    def test_clean_command_still_accepted_shape(self):
        r = client.post(
            "/api/recon/nmap-custom",
            json={"command": "nmap -sn 8.8.8.8", "confirm_permission": True},
        )
        assert r.status_code == 200
        scan = r.json().get("scan", r.json())
        # Either nmap ran or the environment lacks the binary — both honest.
        assert isinstance(scan, dict)
        assert "error" not in scan or "blocked" not in str(scan.get("error", "")).lower()


class TestOptionalBearerAuth:
    def _post_protected(self, **headers):
        return client.post(
            "/api/utils/base64",
            json={"text": "hello", "action": "encode"},
            headers=headers or {},
        )

    def test_open_when_unset(self, monkeypatch):
        monkeypatch.delenv("BEYONDLABS_REQUIRE_AUTH", raising=False)
        assert self._post_protected().status_code == 200

    def test_health_stays_public_when_gated(self, monkeypatch):
        monkeypatch.setenv("BEYONDLABS_REQUIRE_AUTH", "testtoken")
        assert client.get("/health").status_code == 200

    def test_401_without_header_when_gated(self, monkeypatch):
        monkeypatch.setenv("BEYONDLABS_REQUIRE_AUTH", "testtoken")
        assert self._post_protected().status_code == 401

    def test_401_with_wrong_token(self, monkeypatch):
        monkeypatch.setenv("BEYONDLABS_REQUIRE_AUTH", "testtoken")
        r = self._post_protected(Authorization="Bearer wrong-token")
        assert r.status_code == 401
        assert "bearer token" in r.json()["detail"].lower()

    def test_200_with_correct_bearer(self, monkeypatch):
        monkeypatch.setenv("BEYONDLABS_REQUIRE_AUTH", "testtoken")
        r = self._post_protected(Authorization="Bearer testtoken")
        assert r.status_code == 200
