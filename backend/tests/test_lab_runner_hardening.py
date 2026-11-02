"""Latent-hardening tests for the unrouted lab tool_runner stack.

The stack is not mounted on any router today; these tests pin the safety
properties we want intact before it ever becomes reachable: filesystem
allowlisting for wordlist/hash inputs and the shared outbound guard on
crawler/secret-finder fetches.
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.tool_runner import runner
from app.services.tool_runner.tools import local_labs


@pytest.fixture()
def lab_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    allowed = tmp_path / "wordlists"
    allowed.mkdir()
    monkeypatch.setattr(runner, "LAB_FILES_DIR", allowed.resolve())
    return allowed


class TestLabFileAllowlist:
    def test_wordlist_inside_dir_resolves(self, lab_dir: Path):
        target = lab_dir / "dirs.txt"
        target.write_text("/admin\n/api\n")
        assert runner._lab_file_path(str(target)) == str(target)

    def test_path_outside_dir_refused(self, tmp_path: Path):
        outside = tmp_path / "elsewhere" / "secret-list.txt"
        outside.parent.mkdir(parents=True)
        outside.write_text("x\n")
        assert runner._lab_file_path(str(outside)) is None

    def test_missing_file_inside_dir_refused(self, lab_dir: Path):
        assert runner._lab_file_path(str(lab_dir / "does-not-exist.txt")) is None

    def test_traversal_escape_refused(self, lab_dir: Path, tmp_path: Path):
        sneaky = lab_dir / ".." / "escape.txt"
        sneaky.parent.chmod(0o755)
        (tmp_path / "escape.txt").write_text("x\n")
        assert runner._lab_file_path(str(sneaky)) is None


class TestJohnAuditCommand:
    def test_hash_file_outside_dir_rejected(self, tmp_path: Path):
        outside = tmp_path / "hashes.txt"
        outside.write_text("hash:data\n")
        request = SimpleNamespace(target="", profile="default", inputs={"hash_file_path": str(outside)})
        command, error = runner.build_command("john-audit", request)
        assert command is None and "allowlisted" in (error or "")

    def test_hash_file_inside_dir_builds_john_argv(self, lab_dir: Path):
        hash_file = lab_dir / "ntlm.txt"
        hash_file.write_text("31d6cfe0d16ae931b73c59d7e0c089c0::\n")
        request = SimpleNamespace(target="", profile="default", inputs={"hash_file_path": str(hash_file)})
        command, error = runner.build_command("john-audit", request)
        assert command == ["john", "--show", str(hash_file)] and error is None


class TestOutboundGuardOnCrawlTools:
    def test_crawler_skips_loopback_target(self):
        result = local_labs.run_web_crawler("127.0.0.1", {}, timeout=5)
        pages = result["parsed_summary"]["pages"]
        assert pages, "expected at least one page record"
        first = pages[0]
        assert first["status"] == "skipped"
        assert "Outbound guard" in first.get("reason", "")

    def test_secretfinder_blocks_loopback_url(self):
        result = local_labs.run_secretfinder("127.0.0.1", {}, timeout=5)
        summary = result.get("parsed_summary") or {}
        assert "Outbound guard" in summary.get("error", "")

    def test_fetch_error_is_sanitized(self, monkeypatch: pytest.MonkeyPatch):
        def boom(url, timeout):
            raise RuntimeError("internal detail: /etc/shadow line 3")

        monkeypatch.setattr(local_labs, "_fetch_page", boom)
        pages = local_labs.run_web_crawler("example.com", {"max_pages": 1}, timeout=5)["parsed_summary"]["pages"]
        assert pages
        assert pages[0]["reason"] == "RuntimeError while fetching."
