# Feature: URL analysis knowledge expansion

Recovery item 3 — in-progress roadmap (docs/ROADMAP.md → Recovery Items → URL mitigation analysis).

## Objective

Deepen the Safe URL analyzer's offline, evidence-aware output: canonical URL normalization,
punycode/IDN decoding, an expanded WHOIS-profile table, certificate/TLS placeholders, host-style
and ASN rows, related-domain (incl. homoglyph) candidates, extracted observables from path/query,
related graph entities, and an explicit Passive DNS placeholder. No live lookups — everything is
locally derivable fact or an explicit "requires opt-in live enrichment" placeholder.

## Dependencies

- `lib/ioc-patterns` (`TRACKING_PARAMS`, `defang` — unused, pre-existing)
- Graph spine types (`Artifact/Evidence/...`) via `types/url.ts` re-exports
- Workspace-state resume (analyzer result recomputes from saved artifact)

## Files touched

- `frontend/src/types/url.ts` (new `UrlKnowledge`, `UrlObservable`, `UrlKnowledgeRow`; `knowledge` on `UrlAnalysisResult`)
- `frontend/src/data/analyzers/url.ts` (punycode decode/encode, `lookalikeCandidates`, `ipv4Class`, `extractObservables`, `buildUrlKnowledge`)
- `frontend/src/routes/url.tsx` (7 knowledge panels; md/json export includes `knowledge` section)

## Design notes

- Knowledge is a single `knowledge` block on the analysis result, rendered by the page but owned by
  the analyzer — md/json export and future graph ingestion stay shape-identical to the UI.
- WHOIS/cert/ASN/PDNS rows are either locally derived facts (`derived: true`, "derived · offline"
  meta) or explicit placeholders; never synthesized live data.
- Related domains marked `verified` only when derived structurally (registrable, decoded IDN form);
  homoglyph candidates and `www.` alias are always `verified: false` + warning tone.
- Punycode: dependency-free RFC 3492 decoder + encoder, judged against `node:punycode` reference
  vectors (14 valid decode vectors incl. no-delimiter cases + 8 encode round-trips — all match).
  Basic-copy loop does not advance the decode index; no-delimiter ⇒ `basicLen = 0`; case-insensitive
  letters 0–25, digits 26–35.
- Homoglyph candidates derive from the decoded IDN label (e.g. `xn--pple-43d` → `аpple` → `apple`)
  and are re-encoded to punycode when non-ASCII. Cyrillic→Latin map included (а/е/о/р/с/х/у/і).
- Numeric host: ASN block classifies RFC 1918/5735/3927/6598/5771; registrable = host itself.

## Verification

`npm run build`, `npm run lint` (104 warnings, 0 errors — all pre-existing).

## Driver updates

- Punycode sample (`xn--pple-43d.com/auth`): canonical form kept, IDN row shows `аpple.com`,
  3 homoglyph candidates incl. `apple.com` (Cyrillic а → ASCII a).
- Typed `HTTPS://Evil-Host.RU:443/path/../token?mkt=123&utm_source=x&fbid=z#frag`: canonical strips
  default port, lowercases host, normalizes `..`/empty path, removes `utm_source`, drops fragment;
  change list rendered.
- IP sample `192.168.1.25:8080`: ASN block shows "private — RFC 1918 (192.168.0.0/16)"; path/query
  extraction found `admin@evil.com` (email) + 32-hex hash (MD5); Related Domains show host with no
  bogus label-split registrable.
- JSON export contains `knowledge` (canonicalization, whois(+unavailable), certificate(+unavailable),
  asn, related_domains, observables, related_entities, passive_dns).
- R1 regression: analyze → refresh → Resume restores artifact and re-renders all 7 knowledge panels.

## Dogfood scenarios

1. Load Punycode sample → confirm decoded IDN + `apple.com` homoglyph candidate.
2. Paste canonical-heavy URL → confirm change list (port/tracking/fragment).
3. Paste IP + email/hash in query → ASN class + observables with copy + locker.
4. Export JSON → `knowledge` block present and structurally consistent with the page.
5. Reload mid-session → Resume → panels recompute from artifact.

## Acceptance criteria

- Canonical URL shown with explicit change list; no silent mutation claims.
- Punycode decode/encode correct vs node reference; homoglyph candidates labelled unverified.
- Observables extractable and lockable; related entities feed the graph spine shape.
- Placeholders say "unknown — requires opt-in live enrichment", never fake data.
- md/json export includes the knowledge section; R1 resume still works.

## Open items / status

- **Frozen (2026-08-05):** driver-verified (punycode IDN decode + homoglyph `apple.com`, canonical
  change-list, RFC1918 ASN class, observable extraction, JSON export knowledge block, R1 resume),
  build ✓ lint 0 errors, tracking doc written, memory entity created.
- Deferred (out of scope, offline): live WHOIS/registrar, certificate fetch/validation, ASN
  attribution, passive DNS history, redirect-hop observation — all marked opt-in enrichable in UI.