# Threat Intelligence, OSINT & Adversary Profiling Reference

## 1. Domain Overview & Enterprise Problem Statement
In tier-1 SOC operations, incident responders and threat hunters face severe context switching when analyzing alerts. An analyst encountering a suspicious IP (`185.220.101.4`) or domain (`defense-update.org`) typically opens 15–20 browser tabs:
- **VirusTotal / AlienVault OTX / AbuseIPDB**: Multi-engine community verdicts and threat pulses.
- **Maltego / SpiderFoot / MISP**: Graphing infrastructure pivots, co-hosted domains, parent C2 infrastructure.
- **Censys / Shodan / crt.sh**: Passive TLS certificates, open ports, JA3/JA4 fingerprints.
- **MITRE ATT&CK Navigator**: Mapping observed tactics, techniques, and procedures (TTPs) against known threat actors.
- **Mandiant / CrowdStrike Dossiers**: Understanding adversary motivation, attribution, Diamond Model vertices, and active campaigns.

BeyondLabs integrates these workflows into a single cohesive workstation across two interconnected hubs:
- `/intel` (**OSINT & Threat Intel Hub**): Fast multi-indicator resolution, passive infrastructure dissection, relationship graph exploration, and community threat pulses.
- `/threat-actors` (**Threat Actor Dossiers**): Comprehensive adversary profiling with Diamond Model intrusion analysis, interactive MITRE ATT&CK Navigator heatmap, chronological campaign timelines, weaponized CVE arsenals, and exportable STIX 2.1 intelligence bundles.

---

## 2. Industry Benchmark Patterns & Standards

### A. Link Analysis & Infrastructure Pivoting (Maltego / MISP Galaxy)
- **Entities & Transforms**: Every observable belongs to a typed category:
  - `threat-actor` (e.g. APT28, APT29, Lazarus Group, Volt Typhoon, Scattered Spider)
  - `malware` (e.g. Cobalt Strike, PlugX, X-Agent, ShadowPad, Mimikatz)
  - `vulnerability` (CVE-2024-3400, CVE-2024-21413, CVE-2023-38408)
  - `domain` / `hostname`
  - `ipv4` / `ipv6`
  - `file-hash` (MD5, SHA1, SHA256)
  - `tls-fingerprint` (JA3, JA4)
- **Bidirectional Relationship Graph**: Visualizing multi-hop pivot paths:
  - `Actor -> uses-tool -> Malware`
  - `Actor -> targets-cve -> Vulnerability`
  - `Actor -> operates-infra -> IP/Domain`
  - `Malware -> communicates-with -> C2 IP`
  - `Domain -> resolves-to -> IP`
  - `Domain -> shares-cert -> Co-hosted Domains`

### B. The Diamond Model of Intrusion Analysis (Mandiant / Caltagirone et al.)
- **Adversary**: Intent, motivation (Espionage, Financial, Sabotage), attribution confidence, state apparatus (FSB, GRU, SVR, MSS, RGB).
- **Capability**: Arsenal of tools, backdoors, custom implants, exploit kits, living-off-the-land techniques.
- **Infrastructure**: Command-and-control servers, fast-flux DNS, bulletproof hosting, proxy chains, staging domains.
- **Victim**: Targeted verticals (Defense, Energy, Healthcare, Telecom, Crypto), geography, victim persona.

### C. MITRE ATT&CK Navigator Matrix
- Full Enterprise ATT&CK matrix representation:
  - 14 Enterprise Tactics (Reconnaissance to Impact).
  - Techniques mapped to threat actors with frequency / confidence heatmaps.
  - Quick-filtering by tactic, search by technique ID (`T1566`, `T1059`), and 1-click pivot to detection engineering (`/detection`).

### D. STIX 2.1 & OpenCTI Interoperability
- Seamless export of intelligence into standard STIX 2.1 JSON:
  - `identity` (Threat Actor / Campaign)
  - `indicator` (Observable with pattern)
  - `attack-pattern` (MITRE ATT&CK Technique)
  - `relationship` (`uses`, `targets`, `indicates`, `attributed-to`)
- 1-click copy, markdown dossier export, case attachment, and Locker stashing.
