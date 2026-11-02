# Architectural References: Network Traffic Analysis & PCAP Forensics

This reference document compiles open-source architectural patterns, protocol models, and telemetry schemas harvested from industry standard network security tools: **Wireshark/TShark**, **Zeek (Bro)**, **Suricata IDS**, **NetworkMiner**, and **Arkime (Moloch)**.

---

## 1. Zeek Protocol Log Models (`conn`, `dns`, `http`, `ssl`, `files`)

Zeek transforms raw packets into high-fidelity behavioral log streams:

### A. Connection Log (`conn.log`)
- `ts`: Epoch timestamp of first packet
- `uid`: Unique connection identifier (e.g. `C1abc23xyz`)
- `id.orig_h` / `id.orig_p`: Source IP and Port
- `id.resp_h` / `id.resp_p`: Destination IP and Port
- `proto`: Transport protocol (`tcp`, `udp`, `icmp`)
- `service`: Detected application protocol (`dns`, `http`, `ssl`, `ssh`, `smb`)
- `duration`: Session duration in seconds
- `orig_bytes` / `resp_bytes`: Payload bytes sent by originator vs responder
- `conn_state`: State history flags:
  - `S0`: Connection attempt seen, no reply (port scan / SYN flood / blocked)
  - `S1`: Connection established, not terminated
  - `SF`: Normal SYN-ACK-FIN establishment and termination
  - `REJ`: Connection attempt rejected (RST received)
  - `RSTO`: Connection established, originator aborted with RST
  - `RSTR`: Responder aborted with RST
  - `SHR`: Responder sent SYN-ACK, originator aborted
- `history`: Sequence of flags (e.g., `ShADadfF` for normal SYN, SYN-ACK, ACK, Data, FIN)

### B. DNS Log (`dns.log`)
- `query`: Queried domain name
- `qtype_name`: Query type (`A`, `AAAA`, `TXT`, `CNAME`, `MX`, `PTR`, `SRV`)
- `rcode_name`: Response code (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`)
- `answers`: Resolved IP addresses or aliases
- `TTLs`: Time-to-live values (short TTLs like <60s often indicate fast-flux or C2)

### C. HTTP Log (`http.log`)
- `method`: `GET`, `POST`, `PUT`, `DELETE`, `CONNECT`
- `host`: Target domain / IP
- `uri`: Requested path and query string
- `user_agent`: Client User-Agent string (critical for malware beacon detection)
- `status_code`: 200, 302, 403, 404, 500
- `request_body_len` / `response_body_len`: Size in bytes
- `mime_type`: Content-Type (e.g. `application/x-dosexec` for PE binary delivery)

### D. SSL/TLS Log (`ssl.log`)
- `version`: TLS 1.2, TLS 1.3
- `cipher`: Negotiated cipher suite
- `server_name`: SNI (Server Name Indication)
- `ja3` / `ja3s`: Client and Server TLS handshake fingerprints (MD5 of SSLVersion, Ciphers, Extensions, EllipticCurves, PointFormats)
- `subject` / `issuer`: X.509 Certificate details (self-signed, Let's Encrypt, or suspicious issuers)

---

## 2. Wireshark / TShark Display Filter Syntax

Analyst-standard display filters for rapid triage:
- HTTP Suspicious Requests: `http.request.method == "POST" && !(http.response.code in {200, 204})`
- DNS Tunneling / High Entropy: `dns.flags.response == 0 && frame.len > 120`
- TLS Without SNI or Untrusted: `tls.handshake.type == 1 && !tls.handshake.extension.type == 0`
- Port Scan / Half-Open: `tcp.flags.syn == 1 && tcp.flags.ack == 0`
- Reverse Shell / C2 Flow: `tcp.port in {4444, 1337, 8443, 9001} && ip.dst != 10.0.0.0/8`

---

## 3. Suricata IDS Detection Rule Generation

Standard Suricata v5+ rule syntax for observed network anomalies:
```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET [80,8080,443] (
  msg:"BeyondLabs PCAP Detection - Suspicious HTTP Beaconing";
  flow:established,to_server;
  content:"POST"; http_method;
  content:"/api/v1/beacon"; http_uri;
  classtype:trojan-activity;
  sid:20260901; rev:1;
)
```

---

## 4. NetworkMiner & Arkime Extraction Capabilities

- **Credential Harvester**: Cleartext credentials in HTTP Basic Auth, FTP, Telnet, POP3, IMAP, SMTP, LDAP.
- **Transferred Files / Payloads**: Extracted executable binaries (`MZ` / `0x4D5A`), scripts, images, and documents with hashes.
- **Host Profiling**: Operating system heuristic detection based on TTL (Windows ~128, Linux/macOS ~64) and TCP Window Size.
- **TCP Stream Viewer**: Bi-directional dialogue reconstruction (Client in blue, Server in red) with Hex/ASCII inspection.
