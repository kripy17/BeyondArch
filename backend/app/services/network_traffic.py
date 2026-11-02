import base64
import hashlib
import ipaddress
import math
from collections import Counter, defaultdict

from app.utils import HASH_RE

MAX_HASH_PAYLOAD_BYTES = 4096
MAX_HASH_IOCS = 50

SUSPICIOUS_USER_AGENTS = [
    "curl", "powershell", "python-requests", "go-http-client",
    "sqlmap", "nikto", "mimikatz", "certutil", "wget", "nmap",
    "cobaltstrike", "meterpreter"
]


def _hash_candidates(payload: bytes) -> list[str]:
    if not payload:
        return []
    text = payload[:MAX_HASH_PAYLOAD_BYTES].decode("utf-8", errors="ignore")
    return HASH_RE.findall(text)


def _load_scapy():
    try:
        from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, IPv6, Raw, rdpcap  # type: ignore

        return {
            "DNS": DNS,
            "DNSQR": DNSQR,
            "DNSRR": DNSRR,
            "IP": IP,
            "IPv6": IPv6,
            "TCP": TCP,
            "UDP": UDP,
            "Raw": Raw,
            "rdpcap": rdpcap,
        }
    except Exception:
        return None


def _safe_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except Exception:
        return value


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for count in Counter(data).values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def _evaluate_dns_query(query: str) -> dict:
    clean_query = query.strip(".").lower()
    labels = clean_query.split(".")
    subdomain = ".".join(labels[:-2]) if len(labels) > 2 else clean_query
    entropy = _shannon_entropy(subdomain)
    is_tunneling = False
    reasons = []

    if len(clean_query) > 50:
        is_tunneling = True
        reasons.append(f"Domain length {len(clean_query)} > 50")
    if entropy > 3.8 and len(subdomain) > 15:
        is_tunneling = True
        reasons.append(f"High subdomain entropy {entropy} > 3.8")
    if len(labels) >= 5:
        is_tunneling = True
        reasons.append(f"Excessive subdomain depth ({len(labels)} labels)")

    return {
        "query": clean_query,
        "entropy": entropy,
        "is_tunneling": is_tunneling,
        "reasons": reasons,
    }


def _http_request(payload: bytes) -> dict | None:
    if not payload:
        return None

    try:
        text = payload[:2048].decode("utf-8", errors="ignore")
    except Exception:
        return None

    first = text.splitlines()[0] if text.splitlines() else ""
    if not first.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")):
        return None

    headers = {}
    for line in text.splitlines()[1:]:
        if not line.strip():
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    parts = first.split(" ")
    ua = headers.get("user-agent", "")
    ua_lower = ua.lower()
    suspicious_ua = any(s in ua_lower for s in SUSPICIOUS_USER_AGENTS) or (parts[0] == "POST" and not ua)

    return {
        "method": parts[0] if parts else "unknown",
        "path": parts[1] if len(parts) > 1 else "",
        "host": headers.get("host", ""),
        "user_agent": ua,
        "suspicious_ua": suspicious_ua,
    }


def _extract_credentials(payload: bytes, src: str, dst: str, proto: str, dport: str) -> list[dict]:
    creds = []
    try:
        text = payload[:4096].decode("utf-8", errors="ignore")
    except Exception:
        return []

    # 1. HTTP Basic Auth
    for line in text.splitlines():
        if line.lower().startswith("authorization: basic "):
            b64_part = line.split(" ", 2)[-1].strip()
            try:
                decoded = base64.b64decode(b64_part).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    user, pwd = decoded.split(":", 1)
                    masked = pwd[:1] + "*" * max(1, len(pwd) - 2) + pwd[-1:] if len(pwd) > 2 else "***"
                    creds.append({
                        "protocol": "HTTP Basic",
                        "src": src,
                        "dst": dst,
                        "username": user,
                        "password_masked": masked,
                        "raw": line.strip(),
                    })
            except Exception:
                pass

    # 2. FTP
    if dport in ("21", "2121"):
        for line in text.splitlines():
            if line.upper().startswith("USER "):
                user = line[5:].strip()
                creds.append({
                    "protocol": "FTP",
                    "src": src,
                    "dst": dst,
                    "username": user,
                    "password_masked": "[Pending PASS]",
                    "raw": line.strip(),
                })
            elif line.upper().startswith("PASS "):
                pwd = line[5:].strip()
                masked = pwd[:1] + "*" * max(1, len(pwd) - 2) + pwd[-1:] if len(pwd) > 2 else "***"
                creds.append({
                    "protocol": "FTP",
                    "src": src,
                    "dst": dst,
                    "username": "[Observed in stream]",
                    "password_masked": masked,
                    "raw": "PASS [MASKED]",
                })

    return creds


def _detect_file_payload(payload: bytes, src: str, dst: str) -> dict | None:
    if len(payload) < 64:
        return None

    if payload.startswith(b"MZ"):
        return {
            "filename": "payload_pe.exe",
            "mime_type": "application/x-dosexec",
            "type_desc": "Windows PE Executable / DLL",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
            "src": src,
            "dst": dst,
        }
    if payload.startswith(b"PK\x03\x04"):
        return {
            "filename": "archive.zip",
            "mime_type": "application/zip",
            "type_desc": "ZIP Archive or OOXML Document",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
            "src": src,
            "dst": dst,
        }
    if payload.startswith(b"%PDF"):
        return {
            "filename": "document.pdf",
            "mime_type": "application/pdf",
            "type_desc": "PDF Document",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
            "src": src,
            "dst": dst,
        }
    if payload.startswith(b"#!/bin/") or b"powershell" in payload[:100].lower():
        return {
            "filename": "script_payload.sh",
            "mime_type": "text/x-shellscript",
            "type_desc": "Shell / PowerShell Script",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
            "src": src,
            "dst": dst,
        }
    return None


def _tls_sni(payload: bytes) -> str:
    marker = b"\x00\x00"
    if len(payload) < 10 or payload[0] != 0x16:
        return ""

    # Lightweight best-effort SNI extraction
    for offset in range(0, min(len(payload) - 8, 512)):
        if payload[offset:offset + 2] != marker:
            continue
        length = int.from_bytes(payload[offset + 2:offset + 4], "big")
        candidate = payload[offset + 4:offset + 4 + length]
        if 3 <= length <= 253 and b"." in candidate:
            try:
                name = candidate.decode("ascii")
            except Exception:
                continue
            if all(char.isalnum() or char in ".-" for char in name):
                return name.lower().strip(".")
    return ""


def _extract_tls_info(payload: bytes, src: str, dst: str) -> dict | None:
    if len(payload) < 5 or payload[0] != 0x16:
        return None

    # TLS Record version
    rec_ver_major = payload[1]
    rec_ver_minor = payload[2]
    ver_map = {
        (3, 0): "SSL 3.0",
        (3, 1): "TLS 1.0",
        (3, 2): "TLS 1.1",
        (3, 3): "TLS 1.2",
        (3, 4): "TLS 1.3",
    }
    version = ver_map.get((rec_ver_major, rec_ver_minor), f"{rec_ver_major}.{rec_ver_minor}")
    is_deprecated = (rec_ver_major, rec_ver_minor) in [(3, 0), (3, 1), (3, 2)]

    sni = _tls_sni(payload)

    # Simulated JA3 fingerprint from TLS header attributes
    ja3_raw = f"{rec_ver_major}.{rec_ver_minor}-{len(payload)}-{payload[:16].hex()}"
    ja3 = hashlib.md5(ja3_raw.encode()).hexdigest()

    return {
        "src": src,
        "dst": dst,
        "server_name": sni or "—",
        "version": version,
        "is_deprecated": is_deprecated,
        "ja3": ja3,
    }


def _infer_service(dport: str, proto: str) -> str:
    port_map = {
        "80": "http",
        "8080": "http",
        "8000": "http",
        "443": "ssl",
        "8443": "ssl",
        "53": "dns",
        "22": "ssh",
        "21": "ftp",
        "23": "telnet",
        "25": "smtp",
        "110": "pop3",
        "143": "imap",
        "445": "smb",
        "139": "netbios",
        "3389": "rdp",
    }
    return port_map.get(dport, proto)


def _generate_suricata_rules(findings: list[dict], repeated_pairs: list[dict], suspicious_domains: list[str], http_requests: list[dict]) -> list[str]:
    rules = []
    sid = 2026101

    for pair in repeated_pairs[:3]:
        rules.append(
            f'alert tcp any any -> {pair["dst"]} any (msg:"BeyondLabs PCAP - Outbound Beaconing Pattern to {pair["dst"]}"; flow:established,to_server; threshold:type both, track by_src, count 20, seconds 60; classtype:trojan-activity; sid:{sid}; rev:1;)'
        )
        sid += 1

    for domain in suspicious_domains[:3]:
        rules.append(
            f'alert dns any any -> any 53 (msg:"BeyondLabs PCAP - DNS Tunneling Query to {domain}"; dns.query; content:"{domain[:25]}"; nocase; classtype:bad-unknown; sid:{sid}; rev:1;)'
        )
        sid += 1

    for req in http_requests[:3]:
        if req.get("suspicious_ua"):
            rules.append(
                f'alert http any any -> any any (msg:"BeyondLabs PCAP - Suspicious User-Agent ({req.get("user_agent", "unknown")})"; http.user_agent; content:"{req.get("user_agent", "")}"; classtype:suspicious-traffic; sid:{sid}; rev:1;)'
            )
            sid += 1

    return rules


def analyze_pcap(filename: str, data: bytes) -> dict:
    scapy = _load_scapy()
    sha256 = hashlib.sha256(data).hexdigest()

    if not scapy:
        return {
            "status": "dependency_missing",
            "filename": filename,
            "sha256": sha256,
            "summary": {
                "packets": 0,
                "dns_queries": 0,
                "http_requests": 0,
                "tls_sni": 0,
                "findings": 1,
            },
            "findings": [
                {
                    "severity": "info",
                    "title": "PCAP parser dependency missing",
                    "detail": "Install scapy in the backend virtual environment to enable PCAP parsing.",
                    "recommendation": "Run pip install -r requirements.txt after scapy is added.",
                }
            ],
            "iocs": {"ips": [], "domains": [], "urls": [], "hashes": []},
            "limitations": ["No packets were parsed because scapy is not installed."],
        }

    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        tmp.write(data)
        tmp.flush()
        packets = scapy["rdpcap"](tmp.name)

    ip_counter = Counter()
    flows = Counter()
    dns_queries = []
    zeek_dns = []
    http_requests = []
    zeek_ssl = []
    tls_names = []
    hash_hits: list[str] = []
    findings = []
    credentials = []
    extracted_files = []

    # Connection tracking state
    conn_tracker: dict[tuple, dict] = {}

    for packet in packets:
        src = dst = ""
        pkt_time = float(getattr(packet, "time", 0.0))
        pkt_len = len(packet)

        if packet.haslayer(scapy["IP"]):
            src = _safe_ip(packet[scapy["IP"]].src)
            dst = _safe_ip(packet[scapy["IP"]].dst)
        elif packet.haslayer(scapy["IPv6"]):
            src = _safe_ip(packet[scapy["IPv6"]].src)
            dst = _safe_ip(packet[scapy["IPv6"]].dst)

        if src:
            ip_counter[src] += 1
        if dst:
            ip_counter[dst] += 1

        sport = ""
        dport = ""
        proto = ""
        tcp_flags = ""

        if packet.haslayer(scapy["TCP"]):
            proto = "tcp"
            tcp_layer = packet[scapy["TCP"]]
            sport = str(tcp_layer.sport)
            dport = str(tcp_layer.dport)
            tcp_flags = str(tcp_layer.flags)
        elif packet.haslayer(scapy["UDP"]):
            proto = "udp"
            udp_layer = packet[scapy["UDP"]]
            sport = str(udp_layer.sport)
            dport = str(udp_layer.dport)

        if src and dst and proto:
            flow_key = (src, sport, dst, dport, proto)
            flows[(src, dst, proto, dport)] += 1

            if flow_key not in conn_tracker:
                conn_tracker[flow_key] = {
                    "uid": f"C{hashlib.md5(f'{src}:{sport}->{dst}:{dport}:{pkt_time}'.encode()).hexdigest()[:10]}",
                    "ts": pkt_time,
                    "last_ts": pkt_time,
                    "orig_h": src,
                    "orig_p": sport,
                    "resp_h": dst,
                    "resp_p": dport,
                    "proto": proto,
                    "service": _infer_service(dport, proto),
                    "orig_bytes": pkt_len,
                    "resp_bytes": 0,
                    "packets": 1,
                    "conn_state": "S0" if proto == "tcp" else "SF",
                }
            else:
                c = conn_tracker[flow_key]
                c["last_ts"] = pkt_time
                c["orig_bytes"] += pkt_len
                c["packets"] += 1
                if "S" in tcp_flags and "A" in tcp_flags:
                    c["conn_state"] = "SF"
                elif "R" in tcp_flags:
                    c["conn_state"] = "REJ"

        # DNS Inspection
        if packet.haslayer(scapy["DNS"]) and packet.haslayer(scapy["DNSQR"]):
            query = packet[scapy["DNSQR"]].qname
            qtype = packet[scapy["DNSQR"]].qtype
            if isinstance(query, bytes):
                query = query.decode("utf-8", errors="ignore")
            query = str(query).strip(".").lower()

            if query:
                dns_queries.append(query)
                eval_res = _evaluate_dns_query(query)
                qtype_map = {1: "A", 28: "AAAA", 16: "TXT", 5: "CNAME", 15: "MX", 12: "PTR"}
                qtype_name = qtype_map.get(qtype, str(qtype))

                zeek_dns.append({
                    "ts": pkt_time,
                    "query": query,
                    "qtype": qtype_name,
                    "rcode": "NOERROR",
                    "answers": [],
                    "entropy": eval_res["entropy"],
                    "is_tunneling": eval_res["is_tunneling"],
                    "reasons": eval_res["reasons"],
                })

        # Payload Inspection
        if packet.haslayer(scapy["Raw"]):
            payload = bytes(packet[scapy["Raw"]].load)

            # HTTP
            request = _http_request(payload)
            if request:
                http_requests.append({
                    "src": src,
                    "dst": dst,
                    **request,
                })
                if request.get("suspicious_ua"):
                    findings.append({
                        "severity": "high",
                        "title": f"Suspicious User-Agent ({request['user_agent']})",
                        "detail": f"Automated or reconnaissance tool User-Agent detected requesting {request['host']}{request['path']}.",
                        "recommendation": "Block malicious tool agent string and investigate endpoint activity.",
                    })

            # TLS SNI & Version
            tls_info = _extract_tls_info(payload, src, dst)
            if tls_info:
                zeek_ssl.append(tls_info)
                if tls_info["server_name"] and tls_info["server_name"] != "—":
                    tls_names.append(tls_info["server_name"])
                if tls_info["is_deprecated"]:
                    findings.append({
                        "severity": "medium",
                        "title": f"Deprecated TLS Protocol In Use ({tls_info['version']})",
                        "detail": f"Traffic between {src} and {dst} uses {tls_info['version']} which lacks modern cipher security.",
                        "recommendation": "Upgrade client/server configuration to TLS 1.2 or TLS 1.3.",
                    })

            # Credentials
            creds = _extract_credentials(payload, src, dst, proto, dport)
            if creds:
                credentials.extend(creds)
                for cred in creds:
                    findings.append({
                        "severity": "critical",
                        "title": f"Plaintext {cred['protocol']} Credentials Transmitted",
                        "detail": f"Account '{cred['username']}' transmitted cleartext password over network from {src} to {dst}.",
                        "recommendation": "Enforce TLS/HTTPS immediately and rotate exposed credentials.",
                    })

            # File payloads
            extracted = _detect_file_payload(payload, src, dst)
            if extracted:
                extracted_files.append(extracted)
                findings.append({
                    "severity": "high" if "Executable" in extracted["type_desc"] else "medium",
                    "title": f"Unencrypted {extracted['type_desc']} Transfer Detected",
                    "detail": f"{extracted['filename']} ({extracted['size_bytes']} bytes, SHA-256: {extracted['sha256'][:16]}...) transferred from {src} to {dst}.",
                    "recommendation": "Extract file payload for static and dynamic malware sandbox analysis.",
                })

            hash_hits.extend(_hash_candidates(payload))

    # Compile Zeek Conn Records
    zeek_conn = []
    for c in list(conn_tracker.values())[:100]:
        dur = round(max(0.0, c["last_ts"] - c["ts"]), 3)
        zeek_conn.append({
            "uid": c["uid"],
            "ts": c["ts"],
            "duration": dur,
            "orig_h": c["orig_h"],
            "orig_p": c["orig_p"],
            "resp_h": c["resp_h"],
            "resp_p": c["resp_p"],
            "proto": c["proto"],
            "service": c["service"],
            "orig_bytes": c["orig_bytes"],
            "resp_bytes": c["resp_bytes"],
            "conn_state": c["conn_state"],
            "packets": c["packets"],
        })

    flow_totals = defaultdict(int)
    for (src, dst, proto, dport), count in flows.items():
        flow_totals[(src, dst)] += count
        if count >= 20 and dport in {"80", "443", "53"}:
            findings.append({
                "severity": "medium",
                "title": "Repeated destination flow",
                "detail": f"{src} contacted {dst}:{dport}/{proto} {count} times.",
                "recommendation": "Review timing, destination reputation, and process context for beaconing behavior.",
            })

    repeated_pairs = [
        {"src": src, "dst": dst, "packets": count}
        for (src, dst), count in flow_totals.items()
        if count >= 50
    ]

    if repeated_pairs:
        findings.append({
            "severity": "medium",
            "title": "Potential beaconing candidate",
            "detail": f"{len(repeated_pairs)} source/destination pairs have repeated packet patterns.",
            "recommendation": "Check interval regularity and correlate with DNS, HTTP, and endpoint telemetry.",
        })

    # Flag DNS Tunneling findings
    tunneling_dns = [d for d in zeek_dns if d["is_tunneling"]]
    if tunneling_dns:
        findings.append({
            "severity": "high",
            "title": "Potential DNS Tunneling / Exfiltration Detected",
            "detail": f"{len(tunneling_dns)} suspicious DNS queries with high Shannon entropy or excessive label length.",
            "recommendation": "Inspect query payload contents and block suspect authoritative nameserver domains.",
        })

    domains = sorted(set(dns_queries + tls_names + [item["host"] for item in http_requests if item.get("host")]))
    urls = sorted(set(
        f"http://{item['host']}{item['path']}"
        for item in http_requests
        if item.get("host") and item.get("path")
    ))

    suricata_rules = _generate_suricata_rules(
        findings,
        repeated_pairs,
        [d["query"] for d in tunneling_dns],
        http_requests,
    )

    return {
        "status": "parsed",
        "filename": filename,
        "sha256": sha256,
        "summary": {
            "packets": len(packets),
            "unique_ips": len(ip_counter),
            "dns_queries": len(dns_queries),
            "http_requests": len(http_requests),
            "tls_sni": len(tls_names),
            "findings": len(findings),
            "credentials_found": len(credentials),
            "files_extracted": len(extracted_files),
        },
        "top_ips": [{"ip": ip, "packets": count} for ip, count in ip_counter.most_common(20)],
        "dns_queries": sorted(set(dns_queries))[:100],
        "http_requests": http_requests[:100],
        "tls_server_names": sorted(set(tls_names))[:100],
        "beaconing_candidates": repeated_pairs[:50],
        "findings": findings,
        "zeek_conn": zeek_conn,
        "zeek_dns": zeek_dns[:100],
        "zeek_http": http_requests[:100],
        "zeek_ssl": zeek_ssl[:100],
        "credentials": credentials[:50],
        "extracted_files": extracted_files[:50],
        "suricata_rules": suricata_rules,
        "iocs": {
            "ips": [item[0] for item in ip_counter.most_common(50)],
            "domains": domains[:100],
            "urls": urls[:100],
            "hashes": sorted(set(hash_hits + [f["sha256"] for f in extracted_files]))[:MAX_HASH_IOCS],
        },
        "limitations": [
            "Beaconing detection is heuristic and based on repeated packet patterns only.",
            "Encrypted payload content is not decrypted.",
            "Hash indicators are best-effort hex matches and extracted file checksums from unencrypted payloads only.",
            "PCAPs are parsed locally by the backend and are not uploaded to third-party services.",
        ],
    }
