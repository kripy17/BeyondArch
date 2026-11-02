# Feature: Shared WorkflowActions primitive

Recovery item 1 — frozen roadmap (docs/ROADMAP.md → Recovery Items → Shared WorkflowActions primitive).

## Objective

One shared action bar primitive for the common workflow verbs —
`Pivot to Intel | Create Investigation | Export | Copy | Share | Detection | Report` —
used by every page that currently implements action bars independently.

## Dependencies

- `lib/copy.ts` (`copyText`)
- `components/soc` barrel (`soc/index.ts`)
- AnalyzerShell (consumes the primitive for all analyzer pages)

## Files touched

- `frontend/src/components/soc/WorkflowActions.tsx` (new — the primitive)
- `frontend/src/components/soc/AnalyzerShell.tsx` (renders the primitive; drops ExportPanel + SendToRow)
- `frontend/src/components/soc/index.ts` (barrel export)
- `frontend/src/components/forms/ExportPanel.tsx` (deleted — dead after migration)
- `frontend/src/components/forms/index.ts` (deleted — empty barrel)
- `frontend/src/routes/url.tsx` (extraActions: copy refanged URL)
- `docs/features/workflow-actions.md` (this file)

## Write sites

- `WorkflowActions.tsx` — renders actions; copy/share flip to a transient "copied" state.
- `AnalyzerShell.tsx` — composes actions from existing props (`exportMd`, `exportJson`, `onCreateInvestigation`, `sendToTargets`) plus new `extraActions` prop.
- `url.tsx` — passes a copy action for the refanged URL.

## Read sites

- All pages using AnalyzerShell: url, file, phishing, parser, logs (action bar rendered automatically from props).
- No page reads the primitive directly yet; `case.tsx` still uses `SendToRow` (Phase 1 case redesign will migrate it).

## Verification

- `npm run build` passes.
- `npm run lint` passes.
- Analyzer pages render the workflow bar only when at least one action is present (no empty bar on parser/url without results).
- Copy action flips to checkmark and copies the exact value (navigator.clipboard).
- Pivot actions keep their existing href + onClick behavior (artifact handoff still fires).

## Driver updates

- Playwright: run URL analysis, confirm workflow bar appears with pivot targets, investigation, exports; click Copy and verify clipboard value + visual feedback.

## Dogfood scenarios

1. Phishing sample → bar shows pivot targets, Create Investigation, export md/json; handoff still opens the target page.
2. File sample → same bar; Detection pivot still sends the artifact hash.
3. URL page → copy action copies the refanged URL, not the defanged input.
4. Parser page → no bar when nothing parsed (honest UI, no empty chrome).

## Acceptance criteria

- Single `WorkflowActions` primitive; no analyzer page builds its own action bar.
- Bar renders `pivot → investigation → export-md → export-json → extra` order.
- Zero behavior regression in pivot handoffs (sendArtifact/locker side effects preserved).
- `ExportPanel` fully removed; no dangling imports.
- Consistent styling with the existing run bar (border-divider-strong, bg-card/70, mono, ba-text-2xs).

## Freeze notes

- **Done (2026-08-04):** primitive built, AnalyzerShell migrated, `ExportPanel` removed, url.tsx copy action added. Verified in browser: URL page (bar with pivots + Investigation + Markdown + JSON + Copy; copy = refanged URL `https://evil.example.com/payload.exe`, flips to "copied" 1.2s), phishing (pivot anchors navigate + fire `sendArtifact`), parser (no bar when no actions — honest UI). Build ✓, lint 0 errors.
- **Bug found during verification:** pivot with `onClick` rendered as `<button>` dropping navigation; fixed to `<a href onClick>` (SendToRow semantics preserved).
- Left for Phase 1: migrating `case.tsx` (SendToRow → WorkflowActions), Share verb (requires file persistence so a shared link carries state), Detection/Report verbs (require lifecycle model — Phase 2).
