import base64
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import parse_qs, quote, unquote, urlparse


def base64_encode(text: str) -> dict:
    encoded = base64.b64encode(text.encode("utf-8")).decode("utf-8")
    return {
        "input": text,
        "output": encoded,
    }


def base64_decode(text: str) -> dict:
    try:
        decoded = base64.b64decode(text.strip(), validate=True).decode("utf-8", errors="replace")
        return {
            "valid": True,
            "input": text,
            "output": decoded,
        }
    except Exception as e:
        return {
            "valid": False,
            "input": text,
            "error": type(e).__name__,
        }


def url_encode(text: str) -> dict:
    return {
        "input": text,
        "output": quote(text, safe=""),
    }


def url_decode(text: str) -> dict:
    return {
        "input": text,
        "output": unquote(text),
    }


def parse_url(url: str) -> dict:
    parsed = urlparse(url if "://" in url else f"http://{url}")

    return {
        "original": url,
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "query_params": parse_qs(parsed.query),
        "fragment": parsed.fragment,
    }


def decode_base64url(value: str):
    padding = "=" * (-len(value) % 4)
    decoded = base64.urlsafe_b64decode(value + padding)

    try:
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return decoded.decode("utf-8", errors="replace")


def unix_to_iso(value):
    try:
        timestamp = int(value)
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


def decode_jwt(token: str) -> dict:
    parts = token.strip().split(".")

    if len(parts) != 3:
        return {
            "valid_format": False,
            "error": "JWT must contain header, payload, and signature parts.",
        }

    header_raw, payload_raw, signature = parts

    try:
        header = decode_base64url(header_raw)
        payload = decode_base64url(payload_raw)

        readable_claims = {}

        if isinstance(payload, dict):
            for key in ["iat", "nbf", "exp"]:
                if key in payload:
                    readable_claims[key] = unix_to_iso(payload[key])

        return {
            "valid_format": True,
            "header": header,
            "payload": payload,
            "signature_present": bool(signature),
            "readable_claims": readable_claims,
            "warning": "This only decodes the JWT. It does not verify the signature or trustworthiness.",
        }

    except Exception as e:
        return {
            "valid_format": False,
            "error": f"JWT decode failed ({type(e).__name__}).",
        }


def convert_timestamp(value: str) -> dict:
    cleaned = value.strip()

    # Unix timestamp to ISO
    if cleaned.isdigit():
        timestamp = int(cleaned)

        # Handle milliseconds
        if timestamp > 9999999999:
            timestamp = timestamp / 1000

        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)

        return {
            "input": value,
            "detected_type": "unix",
            "utc": dt.isoformat(),
            "unix_seconds": int(timestamp),
        }

    # ISO/date string to Unix
    try:
        normalized = cleaned.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return {
            "input": value,
            "detected_type": "datetime",
            "utc": dt.astimezone(timezone.utc).isoformat(),
            "unix_seconds": int(dt.timestamp()),
        }

    except Exception as e:
        return {
            "input": value,
            "detected_type": "unknown",
            "error": f"Timestamp conversion failed ({type(e).__name__}).",
        }


def calculate_entropy(data: str | bytes) -> dict:
    if isinstance(data, str):
        raw_bytes = data.encode("utf-8", errors="replace")
    else:
        raw_bytes = bytes(data)

    if not raw_bytes:
        return {
            "entropy": 0.0,
            "byte_length": 0,
            "classification": "empty",
            "is_suspicious": False,
            "top_frequencies": [],
        }

    length = len(raw_bytes)
    counts = Counter(raw_bytes)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    entropy = round(entropy, 4)

    if entropy < 3.2:
        classification = "low"
        description = "Sparse / Repetitive Text"
    elif entropy < 5.2:
        classification = "normal"
        description = "Standard Plaintext / Structured Code"
    elif entropy < 7.1:
        classification = "high"
        description = "Compressed / Obfuscated Data"
    else:
        classification = "very_high"
        description = "Encrypted / Packed Binary Payload"

    top_freqs = [
        {"byte": b, "hex": f"0x{b:02x}", "char": chr(b) if 32 <= b <= 126 else ".", "count": cnt, "percent": round((cnt / length) * 100, 2)}
        for b, cnt in counts.most_common(5)
    ]

    return {
        "entropy": entropy,
        "byte_length": length,
        "classification": classification,
        "description": description,
        "is_suspicious": entropy >= 7.0,
        "top_frequencies": top_freqs,
    }


def xor_brute_force(ciphertext: str, top_k: int = 5, known_plaintext: str = None) -> list[dict]:
    cleaned = ciphertext.strip()
    # Try parsing hex first
    raw_bytes: bytes
    if re.fullmatch(r"([0-9a-fA-F]{2}[\s,:]*)+", cleaned):
        try:
            hex_clean = re.sub(r"[\s,:]+", "", cleaned)
            raw_bytes = bytes.fromhex(hex_clean)
        except Exception:
            raw_bytes = cleaned.encode("latin1", errors="replace")
    else:
        raw_bytes = cleaned.encode("latin1", errors="replace")

    if not raw_bytes:
        return []

    # Frequency table for English letters (order of popularity)
    english_freq = set("etaoinshrdlcumwfgypbvkjxqzETAOINSHRDLCUMWFGYPBVKJXQZ 0123456789\r\n\t")
    needle_lower = known_plaintext.strip().lower() if known_plaintext else None

    candidates = []
    total_len = len(raw_bytes)

    for key in range(256):
        xored = bytes(b ^ key for b in raw_bytes)
        printable_count = sum(1 for b in xored if 32 <= b <= 126 or b in (9, 10, 13))
        ascii_ratio = printable_count / total_len

        # Score by printable ratio and English characters
        eng_count = sum(1 for b in xored if chr(b) in english_freq)
        score = (ascii_ratio * 0.6) + ((eng_count / total_len) * 0.4)

        decoded_text = xored.decode("latin1", errors="replace")
        has_needle = False
        if needle_lower and needle_lower in decoded_text.lower():
            has_needle = True
            score += 10.0  # Dominant match bonus

        candidates.append({
            "key": key,
            "key_hex": f"0x{key:02x}",
            "score": round(score, 4),
            "ascii_ratio": round(ascii_ratio * 100, 1),
            "has_needle": has_needle,
            "preview": decoded_text[:200],
        })

    candidates.sort(key=lambda c: (c["has_needle"], c["score"]), reverse=True)
    return candidates[:top_k]


def sniff_magic_bytes(data: str | bytes) -> dict:
    if isinstance(data, str):
        cleaned = data.strip()
        # Check if hex representation
        if re.fullmatch(r"([0-9a-fA-F]{2}[\s,:]*)+", cleaned) and len(cleaned) >= 4:
            try:
                raw = bytes.fromhex(re.sub(r"[\s,:]+", "", cleaned)[:64])
            except Exception:
                raw = cleaned.encode("latin1", errors="replace")[:32]
        else:
            raw = cleaned.encode("latin1", errors="replace")[:32]
    else:
        raw = bytes(data)[:32]

    hex_prefix = raw.hex().lower()

    signatures = [
        ("4d5a", "Windows PE Executable (EXE/DLL/SYS)", "Extract Strings / PE Headers"),
        ("7f454c46", "Linux ELF Executable / Shared Object", "Extract Strings / Parse ELF"),
        ("1f8b", "GZIP Compressed Stream", "Gunzip Decompress"),
        ("504b0304", "ZIP Archive / Office OpenXML / JAR", "Unzip Archive"),
        ("504b0506", "Empty ZIP Archive", "Unzip Archive"),
        ("25504446", "PDF Document", "Extract PDF Streams / Obfuscated JS"),
        ("7b5c727466", "Rich Text Format (RTF)", "RTF Exploit Deobfuscation"),
        ("d4c3b2a1", "PCAP Capture (Little Endian)", "Inspect Network Frames"),
        ("a1b2c3d4", "PCAP Capture (Big Endian)", "Inspect Network Frames"),
        ("0a0d0d0a", "PCAPNG Capture", "Inspect Network Frames"),
        ("377abcaf271c", "7-Zip Compressed Archive", "Unpack 7-Zip"),
        ("ffd8ffe0", "JPEG Image", "View Image / EXIF Metadata"),
        ("ffd8ffe1", "JPEG Image (EXIF)", "View Image / EXIF Metadata"),
        ("89504e47", "PNG Image", "View Image / LSB Steganography"),
        ("cafebabe", "Java Class / Mach-O Fat Binary", "Decompile / Disassemble"),
    ]

    for sig_hex, desc, rec in signatures:
        if hex_prefix.startswith(sig_hex):
            return {
                "detected": True,
                "magic_hex": sig_hex,
                "description": desc,
                "recommendation": rec,
            }

    # Text-based signatures
    if isinstance(data, str):
        s = data.strip()
        if s.startswith("eyJh") or s.startswith("eyJhb"):
            return {
                "detected": True,
                "magic_hex": "ey...",
                "description": "JSON Web Token (JWT)",
                "recommendation": "Dissect JWT Claims",
            }
        if re.match(r"^(?:cwBh|SQBu|JAB|aQBl|VwBy)", s):
            return {
                "detected": True,
                "magic_hex": "powershell_b64",
                "description": "PowerShell UTF-16LE Base64 (-EncodedCommand)",
                "recommendation": "Decode PowerShell -EncodedCommand",
            }

    return {
        "detected": False,
        "magic_hex": hex_prefix[:8] if hex_prefix else "",
        "description": "Unknown Binary or Plaintext",
        "recommendation": "Analyze with Entropy / IOC Extractor",
    }


def powershell_encoded_command(text: str, action: str = "decode") -> dict:
    cleaned = text.strip()
    if action == "decode":
        try:
            # Handle potential whitespace or url-safe variations
            b64_clean = cleaned.replace("-", "+").replace("_", "/")
            b64_clean = b64_clean + "=" * (-len(b64_clean) % 4)
            raw = base64.b64decode(b64_clean)
            decoded = raw.decode("utf-16le", errors="replace").lstrip("\ufeff")
            return {
                "valid": True,
                "action": "decode",
                "input": text,
                "output": decoded,
            }
        except Exception as e:
            return {
                "valid": False,
                "action": "decode",
                "input": text,
                "error": f"PowerShell decode failed: {type(e).__name__}",
            }
    else:
        try:
            utf16_bytes = cleaned.encode("utf-16le")
            encoded = base64.b64encode(utf16_bytes).decode("ascii")
            return {
                "valid": True,
                "action": "encode",
                "input": text,
                "output": encoded,
            }
        except Exception as e:
            return {
                "valid": False,
                "action": "encode",
                "input": text,
                "error": f"PowerShell encode failed: {type(e).__name__}",
            }


def defang_indicators(text: str) -> dict:
    # Defang http/https
    out = text.replace("https://", "hxxps://").replace("http://", "hxxp://")
    # Defang email addresses first
    out = re.sub(r"([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-.]+)", r"\1[@]\2", out)
    # Defang IP addresses (replace dots with [.])
    out = re.sub(r"(\b\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}\b)", r"\1[.]\2[.]\3[.]\4", out)
    # Defang domain extensions (e.g. .com -> [.][a-z]+)
    out = re.sub(r"([a-zA-Z0-9_-]+)\.(com|org|net|io|ru|cn|xyz|top|info|biz|me|online|live)\b", r"\1[.]\2", out, flags=re.IGNORECASE)
    return {
        "input": text,
        "output": out,
    }



def refang_indicators(text: str) -> dict:
    out = text.replace("hxxps://", "https://").replace("hxxp://", "http://")
    out = out.replace("[.]", ".").replace("[:]", ":").replace("[@]", "@")
    return {
        "input": text,
        "output": out,
    }

