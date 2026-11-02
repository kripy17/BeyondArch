# Feature: File analysis depth expansion

Recovery item 4 — in-progress roadmap (docs/ROADMAP.md → Improve existing analyzers → File Analyzer).

## Objective

Deepen the File analyzer's offline, evidence-aware output: real cryptographic hashes
(MD5/SHA1/SHA256), strings extraction with classification, best-effort PE header inspection,
string-derived import/API evidence, archive/container detection with ZIP entry listing, Office
OOXML metadata + macro detection, an illustrative YARA-style rule preview, and hash relationship
analysis (embedded vs own hashes). Everything is locally derivable from the text projection or an
explicit "requires byte-level upload (opt-in)" placeholder. No fabricated binary-parsed values.

## Dependencies

- `lib/ioc-patterns` (`entropy`, `scanSecrets`)
- Graph spine types (`Artifact/Evidence/IOC/Finding`) via `types/security` + `types/analysis`
- Workspace-state resume (analyzer result recomputes from saved artifact)
- Web Crypto `crypto.subtle` (SHA-1/SHA-256) — available in modern browsers and node ≥ 20

## Files touched

- `frontend/src/data/analyzers/file.ts` — rewritten: `md5Hex` (hand-rolled RFC 1321), `shaHex`
  (subtle digest), `extractStrings`, `peInspect`, `importEvidence`, `archiveInspect`,
  `officeInspect`, `yaraPreview`, `hashRelations`; `analyzeFile` now async
- `frontend/src/routes/file.tsx` — async analysis effect (debounced, cancellation-safe), 7 new
  depth panels, `genMarkdownExport` + `exportMd` wiring

## Design notes

- **Real hashes over fabricated:** the previous analyzer returned FNV-style fake digests; the
  rewrite computes genuine MD5/SHA1/SHA256 (MD5 hand-rolled to keep hashing synchronous, SHA via
  subtle — hence async `analyzeFile`). Validated 8/8 vs `node:crypto` on empty/short/long/unicode/
  binary-embedded vectors.
- **Text-projection honesty:** PE header, imports, archive entries, and Office fields are derived
  from the pasted text (which is how the route receives content). Every section carries a note that
  binary-accurate results need byte-level upload (opt-in). Non-ASCII header bytes yield `unknown`.
- **Strings:** ASCII runs ≥ 4 chars, classified email/url/ipv4/hex/base64/file-ref/path/api/string;
  24 samples + per-category counts.
- **PE inspection:** `PE\0\0` signature scan in first 4 KB; machine/subsystem/entrypoint read with
  bounds-checked byte reads; unknown values when non-ASCII.
- **Imports/API:** DLL references (`\w+\.(dll|ocx|sys)`) plus a suspicious-API list
  (CreateRemoteThread, WriteProcessMemory, VirtualAllocEx, WinHttp*, ShellExecute*, IsDebuggerPresent,
  GetAsyncKeyState, URLDownloadToFile, WinExec, …) with A/W/Ex suffix-tolerant call-pattern scan.
- **Archive:** ZIP local-header walk (name-length bounds-checked, ≤ 40 entries) plus RAR/GZIP/7z/
  PE/PDF magic detection.
- **Office:** OOXML `[Content_Types].xml` presence + `core.xml` property extraction; macro via
  `vbaProject.bin` / `word/vba` etc.
- **YARA preview:** 12 illustrative offline rules (has_pe_header, powershell_encoded,
  powershell_download_cradle, base64_blob, suspicious_api, bitcoin_address, private_key, many_urls,
  many_ips, suspicious_masquerade, office_macro, encoded_script). Labelled "not YARA — port to a
  real rule before operational use".
- **Hash relationships:** embedded 32/40/64-hex candidates from content, with own hashes excluded
  from the embedded list; self-reference flag when an embedded hash equals the computed hash.
- Sample `invoice_2024_05_15.pdf.exe` extended with a realistic PE header (i386 / Windows GUI /
  entry 0x40) so the PE panel is exercised by the driver.

## Verification

`npm run build` ✓, `npm run lint` (98 warnings, 0 errors — all pre-existing; file.ts/file.tsx
clean). Hash correctness vs `node:crypto` in `/tmp/opencode/md5_check.mjs` (9/9) and
`/tmp/opencode/file_check.mjs` (8/8 SHA+MD5, analyzer output shape).

## Driver updates

- suspicious_exe sample: all panels render — File Metadata, Raw Hash Inventory, Hash Relationships,
  Strings, PE Header (i386, Windows GUI, entry 0x40), Imports & API Calls, Archive/Container
  (PE/EXE), YARA-style Preview (has_pe_header + private_key matched); MD5/SHA1/SHA256 rows are
  valid-length hex.
- document.js sample: strings panel, powershell_encoded + base64_blob YARA matches.
- docx (OOXML + vbaProject.bin) sample: Office Metadata shows creator/title/lastModifiedBy/revision/
  created + macros PRESENT; office_macro YARA match; archive kind ZIP with entry list.
- Markdown export contains PE/i386, YARA/private_key, MD5/SHA256, strings total, limitations
  note; downloaded `.md` verified via blob capture.
- Reload → Resume banner → restore re-renders all depth panels from stored analysis (workspace
  analysis contains strings/pe/imports/archive/office/yara/hashRelations keys).

## Dogfood scenarios

1. Load suspicious_exe → verify hashes, PE header values, YARA hits (has_pe_header/private_key).
2. Paste document.js → strings + powershell_encoded/base64_blob rules.
3. Paste OOXML docx → Office metadata + macro warning + archive entries.
4. Export Markdown/JSON → sections present, limitations explicit.
5. Reload mid-session → Resume → panels recompute from artifact.

## Acceptance criteria

- MD5/SHA1/SHA256 match node:crypto output; hashes computed over the content as analyzed.
- Depth panels render for their matching sample; non-matching samples show honest "none/not
  detected" states with notes.
- No fabricated binary values: unknown header bytes are `unknown`, archive/PE/imports are
  string-derived and labelled as such.
- YARA preview is explicitly non-authoritative.
- md export added (was json-only); R1 resume still works.

## Open items / status

- In progress (2026-08-05): analyzer + route + export implemented; build/lint clean; hashes
  validated vs node:crypto; driver checks for PE sample, js sample, docx sample, md export, and
  resume all pass.
- Deferred (out of scope, offline): byte-level upload path, real import-table parsing, real YARA
  engine, Office legacy OLE (doc/xls/ppt) metadata, archive entry CRC validation.
