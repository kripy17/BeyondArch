# Feature: Lightweight workspace state (recovery)

Recovery item 2 — frozen roadmap (docs/ROADMAP.md → Recovery Items → File persistence).

## Objective

Recover the analyst's immediate working context after refresh / accidental tab close:
current artifact, most recent completed analysis, per analyzer. Not a history system,
not a database, not autosave of transient UI. Expires after 24h or explicit Start Fresh.

## Dependencies

- `lib/storage.ts` (storageGet/storageSet wrapper)
- `AnalyzerShell` (resumeBanner slot) and the parser's custom layout

## Files touched

- `frontend/src/lib/workspace-state.ts` (new — save/load/clear/expired, key `ba.workspace.v1`, TTL 24h)
- `frontend/src/lib/use-workspace-state.ts` (new — hook: pending/accept/save/clear + useDebouncedWorkspaceSave)
- `frontend/src/components/ResumeBanner.tsx` (new — "Previous analysis found" + [Resume] [Start Fresh], relative time)
- `frontend/src/components/soc/AnalyzerShell.tsx` (resumeBanner slot after header)
- `frontend/src/routes/url.tsx` (save on run, resume restores artifact + reruns)
- `frontend/src/routes/file.tsx` (save artifact on run, artifact+analysis on result; resume restores fileName from analysis)
- `frontend/src/routes/phishing.tsx` (save artifact on run, analysis=apiResult on success; resume restores input + apiResult + runs)
- `frontend/src/routes/parser.tsx` (debounced artifact save + save on deep scan; resume restores input)
- `frontend/src/routes/logs.tsx` (mirror of file)

## Write sites

- `workspace-state.ts` — single namespace object `ba.workspace.v1` → `{ [ws]: { artifact, analysis?, updatedAt } }`; one record per workspace (no duplicate keys).
- Page run/result boundaries (no keystroke autosave except parser's 1.2s debounce, required because parser is a live page with no run button — artifact only, never analysis).
- Page clear buttons and Start Fresh both call `clear()`.

## Read sites

- `useWorkspaceState` on mount (`workspace.load`); `pending` drives the banner. Resume never silently overwrites — explicit [Resume] / [Start Fresh].

## Verification

- `npm run build`, `npm run lint` green.
- Driver suite R1–R6 (below).

## Driver updates

- Playwright scenarios: R1 url analyze→refresh→resume→restored; R2 Start Fresh clears storage; R3 expired (inject old timestamp) → nothing restored; R4 file filename+hash+results restored; R5 parser large input restored exactly; R6 incomplete analysis → artifact only, no fake results.

## Dogfood scenarios

1. Analyze a URL, refresh, Resume → input restored and analysis recomputed.
2. Start Fresh → refresh → no banner; storage key empty for that workspace.
3. Paste big log into parser, wait ~1.5s, refresh, Resume → exact text back.
4. File analysis with results → refresh → Resume restores filename + results, not just the textarea.
5. Phishing with backend offline (analysis incomplete) → refresh → banner offers artifact only; results area shows nothing until re-run.

## Acceptance criteria

- One storage implementation, one schema, one namespace key; no duplicated persistence code in pages.
- No database, no background autosave loop (parser debounce is the sole exception, documented above).
- Resume is explicit; nothing silently overwrites the page.
- Expiration via timestamp comparison (24h) and Start Fresh.
- R1–R6 pass; build + lint green.

## Freeze notes

- **Done (2026-08-04):** util, hook, banner, AnalyzerShell slot, five pages wired; build ✓ lint 0 errors.
- **Frozen (2026-08-05):** driver suite R1–R6 all PASS — R1 url analyze→refresh→Resume restores input + recomputes findings; R2 Start Fresh clears storage (banner gone, input empty); R3 expired timestamp (25h) → no banner, nothing restored; R4 file Resume restores filename + hash inventory + score + workflow actions; R5 parser 52,659 chars restored byte-exact; R6 phishing API-fail → artifact only (no analysis), Resume restores input, no fabricated results.
- url/phishing/parser store artifact (results recompute deterministically from artifact); file/logs store the result object too (fileName lives in `FileAnalysisResult`).
- Parser's debounce is the only timer-based write; justified by R5 (live page, no run button).
- Deferred: Share verb can now reuse the same saved state later; settings "Resume last workspace" remains separate nav behavior.
