from fastapi.testclient import TestClient
from app.main import app
from app.services.cyber_utils import (
    calculate_entropy,
    xor_brute_force,
    sniff_magic_bytes,
    powershell_encoded_command,
    defang_indicators,
    refang_indicators,
)

client = TestClient(app)


def test_calculate_entropy_text_and_random():
    # Low entropy for repetitive text
    rep_res = calculate_entropy("AAAAAAAAAA")
    assert rep_res["entropy"] == 0.0
    assert rep_res["classification"] == "low"

    # Normal text
    text_res = calculate_entropy("The quick brown fox jumps over the lazy dog.")
    assert 3.5 <= text_res["entropy"] <= 5.0
    assert text_res["classification"] == "normal"

    # High entropy (pseudorandom / encrypted bytes)
    high_res = calculate_entropy(bytes(range(256)))
    assert high_res["entropy"] >= 7.9
    assert high_res["is_suspicious"] is True


def test_xor_brute_force_with_known_needle():
    # Plaintext "powershell -enc test" XORed with key 0x5A
    plaintext = "powershell.exe -ExecutionPolicy Bypass"
    key = 0x5A
    ciphertext_bytes = bytes(ord(c) ^ key for c in plaintext)
    hex_cipher = ciphertext_bytes.hex()

    results = xor_brute_force(hex_cipher, top_k=5, known_plaintext="powershell")
    assert len(results) > 0
    top_match = results[0]
    assert top_match["key"] == key
    assert top_match["has_needle"] is True
    assert "powershell.exe" in top_match["preview"]


def test_sniff_magic_bytes_signatures():
    # PE Header
    pe_res = sniff_magic_bytes("4d5a90000300000004000000ffff0000")
    assert pe_res["detected"] is True
    assert "PE" in pe_res["description"]

    # GZIP Header
    gzip_res = sniff_magic_bytes("1f8b0800000000000003")
    assert gzip_res["detected"] is True
    assert "GZIP" in gzip_res["description"]

    # ZIP Header
    zip_res = sniff_magic_bytes("504b0304140000000800")
    assert zip_res["detected"] is True
    assert "ZIP" in zip_res["description"]

    # PowerShell Base64
    ps_res = sniff_magic_bytes("cwBhAG0AcABsAGUA")
    assert ps_res["detected"] is True
    assert "PowerShell" in ps_res["description"]


def test_powershell_utf16le_codec():
    cmd = "Write-Host 'Infiltrated!'"
    enc = powershell_encoded_command(cmd, action="encode")
    assert enc["valid"] is True
    b64_val = enc["output"]

    dec = powershell_encoded_command(b64_val, action="decode")
    assert dec["valid"] is True
    assert dec["output"] == cmd


def test_defang_and_refang_indicators():
    raw = "Alert: https://evil-c2.ru/beacon from 185.220.101.5 and admin@badactor.org"
    defanged = defang_indicators(raw)["output"]
    assert "hxxps://" in defanged
    assert "evil-c2[.]ru" in defanged
    assert "185[.]220[.]101[.]5" in defanged
    assert "admin[@]badactor[.]org" in defanged

    refanged = refang_indicators(defanged)["output"]
    assert "https://" in refanged
    assert "evil-c2.ru" in refanged
    assert "185.220.101.5" in refanged
    assert "admin@badactor.org" in refanged



def test_utils_router_endpoints():
    # Entropy endpoint
    r = client.post("/api/utils/entropy", json={"text": "Suspicious payload testing"})
    assert r.status_code == 200
    assert "entropy" in r.json()

    # XOR endpoint
    r = client.post("/api/utils/xor-bruteforce", json={"ciphertext": "4142434445", "top_k": 3})
    assert r.status_code == 200
    assert len(r.json()["results"]) == 3

    # Magic bytes endpoint
    r = client.post("/api/utils/magic-bytes", json={"data": "4d5a9000"})
    assert r.status_code == 200
    assert r.json()["detected"] is True
