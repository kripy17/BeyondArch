"""HTTP-level regression tests for the RCE-hardening work.

Covers the two former unauthenticated-RCE paths (/api/network/nmap/stream
shell-string execution, /api/hackingtool/run any-installed-binary fallback),
the confirm/private-target gates, and the recon_intel guaranteed-500 fix.
"""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.nmap_runner import ALLOWED_SCAN_MODES, build_nmap_argv

client = TestClient(app)

PUBLIC_IP = "8.8.8.8"  # literal IP so tests never touch DNS


# ---------------------------------------------------------------------------
# /api/network/nmap/stream
# ---------------------------------------------------------------------------


def test_nmap_stream_requires_confirm_permission():
    response = client.post(
        "/api/network/nmap/stream",
        json={"target": PUBLIC_IP, "mode": "quick_tcp"},
    )
    assert response.status_code == 400
    assert "confirm" in response.json()["detail"].lower()


def test_nmap_stream_rejects_private_target_without_allow_private():
    response = client.post(
        "/api/network/nmap/stream",
        json={"target": "127.0.0.1", "mode": "quick_tcp", "confirm_permission": True},
    )
    assert response.status_code == 400
    assert "private" in response.json()["detail"].lower()


def test_nmap_stream_rejects_unknown_mode_with_allowlist():
    response = client.post(
        "/api/network/nmap/stream",
        json={
            "target": PUBLIC_IP,
            "mode": 'custom; touch /tmp/pwned',
            "confirm_permission": True,
            "allow_private": True,
        },
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "invalid scan mode" in detail["error"].lower()
    assert sorted(detail["allowed_modes"]) == sorted(ALLOWED_SCAN_MODES.keys())


# ---------------------------------------------------------------------------
# nmap_runner.build_nmap_argv (unit)
# ---------------------------------------------------------------------------


def test_build_nmap_argv_returns_token_list():
    mode = sorted(ALLOWED_SCAN_MODES.keys())[0]
    argv = build_nmap_argv("scanme.nmap.org", mode)
    assert isinstance(argv, list)
    assert argv[0] == "nmap"
    assert argv[-1] == "scanme.nmap.org"
    # every element is a plain token — no shell metacharacter strings
    for token in argv:
        assert ";" not in token and "|" not in token and "`" not in token


def test_build_nmap_argv_refuses_nonallowlisted_mode():
    with pytest.raises(ValueError):
        build_nmap_argv(PUBLIC_IP, "-oN /tmp/evil")


# ---------------------------------------------------------------------------
# /api/hackingtool/run
# ---------------------------------------------------------------------------


def test_hackingtool_run_requires_confirm_authorization():
    response = client.post(
        "/api/hackingtool/run",
        json={"category_id": "information_gathering", "tool_id": "nmap", "target": PUBLIC_IP},
    )
    assert response.status_code == 400
    assert "confirm" in response.json()["detail"].lower()


def _fake_ht_dir(monkeypatch):
    """Point the service at a truthy dir sentinel without needing hackingtool."""
    monkeypatch.setattr("app.services.hackingtool_service.HACKINGTOOL_DIR", "/opt/hackingtool")
    monkeypatch.setattr("app.services.hackingtool_service._tool_map_cache", None)


def test_hackingtool_run_refuses_unmapped_tool_ids(monkeypatch):
    """bash/curl-style ids outside the tool map are no longer resolved by `which` fallback."""
    called = {"run": False}

    def _fail(*a, **k):
        called["run"] = True
        raise AssertionError("subprocess.run must not be reached")

    _fake_ht_dir(monkeypatch)
    monkeypatch.setattr("app.services.hackingtool_service._check_tool", lambda b: True)
    monkeypatch.setattr("app.services.hackingtool_service.subprocess.run", _fail)

    response = client.post(
        "/api/hackingtool/run",
        json={
            "category_id": "information_gathering",
            "tool_id": "totally-not-a-tool",
            "args": "-c id",
            "confirm_authorization": True,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert "unknown tool" in payload.get("error", "").lower()
    assert called["run"] is False


def test_hackingtool_run_mapped_tool_uses_exact_argv(monkeypatch):
    captured = {}

    def fake_run(cmd_parts, **kwargs):
        captured["cmd_parts"] = list(cmd_parts)
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    _fake_ht_dir(monkeypatch)
    monkeypatch.setattr("app.services.hackingtool_service._check_tool", lambda b: True)
    monkeypatch.setattr("app.services.hackingtool_service.subprocess.run", fake_run)

    response = client.post(
        "/api/hackingtool/run",
        json={
            "category_id": "network_utilities",
            "tool_id": "dig",
            "target": "example.com",
            "args": "+short",
            "confirm_authorization": True,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed"
    # argv list, not a shell string; binary comes from the tool map
    assert captured["cmd_parts"] == ["dig", "example.com", "+short"]


def test_hackingtool_run_caps_argument_count(monkeypatch):
    captured = {}

    def fake_run(cmd_parts, **kwargs):
        captured["cmd_parts"] = list(cmd_parts)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    _fake_ht_dir(monkeypatch)
    monkeypatch.setattr("app.services.hackingtool_service._check_tool", lambda b: True)
    monkeypatch.setattr("app.services.hackingtool_service.subprocess.run", fake_run)

    response = client.post(
        "/api/hackingtool/run",
        json={
            "category_id": "information_gathering",
            "tool_id": "nmap",
            "args": " ".join(["-v"] * 100),
            "confirm_authorization": True,
        },
    )
    assert response.status_code == 200
    # [binary] + capped args (no target here) — never more than MAX_TOOL_ARGS + 1
    assert len(captured["cmd_parts"]) <= 33


# ---------------------------------------------------------------------------
# /api/recon-intel/plan (was a guaranteed 500)
# ---------------------------------------------------------------------------


def test_recon_intel_plan_returns_plan_for_ip_target():
    response = client.post("/api/recon-intel/plan", json={"target": PUBLIC_IP})
    assert response.status_code == 200
    payload = response.json()
    assert payload["target"]["hostname"] == PUBLIC_IP
    assert isinstance(payload["local_observations"], list) and payload["local_observations"]
