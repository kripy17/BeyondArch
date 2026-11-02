# BeyondLabs URL Forensics & Email Phishing Workstation Architecture

This document synthesizes core design principles, forensic patterns, and feature architectures from industry-standard investigative platforms: **urlscan.io**, **Cisco Talos**, **VirusTotal**, **PhishTool**, **Sublime Security**, **Inky**, and **SpamAssassin**.

---

## 1. URL & Web Forensics Engine (`/url`)

### Reference Inspirations:
- **urlscan.io**: Deep URL anatomy breakdown, redirect chains, ASN/network context, domain reputation, and screenshot-less landing page telemetry.
- **Cisco Talos / VirusTotal**: Punycode / IDN homograph detection, lexical entropy (DGA / token randomization), open redirect detection, IP-in-URL obfuscation.

### Core Capabilities Required:
1. **URL Anatomy Dissection**:
   - Scheme / Protocol (`https`, `http`, `ftp`, `data`, `javascript`)
   - Embedded Credentials (`user:pass@host`) — high-risk credential leakage or phishing cloaking
   - Hostname breakdown: Subdomains, Apex/Registrable Domain, Public Suffix (TLD)
   - Port analysis: Standard (`80`, `443`) vs non-standard (`8080`, `8443`, `8888`, `4444`, `1337`)
   - Path, Query Parameters, and URL Fragment
   - Shannon Lexical Entropy calculation for hostname and path (detecting DGAs or encrypted tokens)
2. **Homograph & Punycode Deobfuscation**:
   - RFC 3492 Punycode decoding (`xn--pple-43d.com` -> `apple.com` with Cyrillic 'а')
   - Confusable / Lookalike character scanner (Cyrillic, Greek, accented Latin homoglyphs)
3. **Obfuscation & Evasion Detection**:
   - Hex / Octal / DWORD IP encoding (`http://0x7f000001`, `http://2130706433`, `http://0177.0.0.1`)
   - Double-slash evasion (`https://trusted.com@evil.com/`)
   - Open Redirect abuse patterns (`?redirect=`, `?url=`, `?next=`, `?dest=`, `?link=`)
4. **Interactive Redirect Chain Simulator**:
   - Step-by-step visual hop sequence:
     - Hop 1: Shortener / Tracking link (e.g. `bit.ly/3xK9pQz`) [301 Moved]
     - Hop 2: Intermediate traffic distributor / TDS [302 Found]
     - Hop 3: Final credential harvester / payload landing page [200 OK]
   - Shows status codes, destination IPs, and evasion flags per hop.
5. **Brand Impersonation & Phishing Kit Heuristics**:
   - Keyword & brand signature matching: Microsoft 365, Google Workspace, PayPal, DocuSign, Apple, Netflix, DHL, Bank of America, Chase, Wells Fargo, etc.
   - 1-Click analyst actions:
     - **Defang / Refang**
     - **To CyberChef** (decode encoded query params or base64 redirects)
     - **Look up on Intel** (`/intel?q=<domain/ip>`)
     - **Add to Case / Locker**

---

## 2. Email Phishing & Header Triage Workstation (`/phishing`)

### Reference Inspirations:
- **PhishTool**: RFC 822/5322 header dissection, hop-by-hop Received route timeline, SPF/DKIM/DMARC alignment matrix, raw email preview.
- **Sublime Security & Inky**: Display-name spoofing detection, cousin domain analysis, text-vs-href link discrepancy detection, urgency & credential theft scoring.

### Core Capabilities Required:
1. **RFC 5322 Envelope & Sender Identity Triage**:
   - `From:` Display Name and Email Address
   - `Reply-To:` destination check (flags mismatch against From domain)
   - `Return-Path:` envelope sender alignment
   - `Message-ID:` syntax and domain validation
   - Sender Brand Spoofing / Cousin Domain heuristic (e.g. `paypa1.com`, `rnicrosoft.com`)
2. **Email Authentication Alignment Matrix**:
   - **SPF**: Result (`pass`, `softfail`, `fail`, `neutral`, `none`), sending IP, and envelope domain.
   - **DKIM**: Result (`pass`, `fail`, `none`), signing domain (`d=`), and selector (`s=`).
   - **DMARC**: Policy (`none`, `quarantine`, `reject`), alignment status (SPF alignment + DKIM alignment).
   - Visual summary card indicating whether email passes domain DMARC validation.
3. **MTA Received Path Route Timeline**:
   - Parses all `Received:` headers chronologically from client origin to final mailbox server.
   - Extracts hop IP, reverse DNS name, timestamp, and transit delay.
   - Flags untrusted internal relays, suspicious foreign transit MTAs, or anomalous delivery delays (> 1 hour).
4. **Hyperlink Discrepancy Matrix**:
   - Extracts all URLs from HTML and plain text bodies.
   - Side-by-side comparison:
     - **Anchor Text Shown to User** (e.g. `https://login.microsoft.com/auth`)
     - **Actual Target URL Href** (e.g. `http://185.220.101.161/ms-login`)
   - Highlights deceptive mismatch in bright red warning with 1-click **Triage URL** button.
5. **Lure & Social Engineering Scorer**:
   - Urgency indicators (imminent deadline, legal action, account lockout)
   - Financial lures (payroll update, wire transfer, invoice overdue)
   - Credential harvesting triggers (password reset, 2FA verification, verify identity)
6. **Unified Forensic Action Bar**:
   - **1-Click Triage in URL Analysis**
   - **1-Click Stash IOCs to Locker**
   - **1-Click Pivot to CyberChef**
   - **Export Forensic Phishing Report (Markdown / JSON)**
