import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { pushTimelineEvent } from "@/lib/timeline";
import { useRecentInputs } from "@/lib/use-recent-inputs";
import { useWorkspaceState } from "@/lib/use-workspace-state";
import { ResumeBanner } from "@/components/ResumeBanner";
import { PageShell } from "@/components/PageShell";
import { AnalyzerShell } from "@/components/soc";
import type { AnalyzerState } from "@/components/soc";
import { IntakeCard, SectionBar, Panel, Chip, IocInventory } from "@/components/soc";
import { KeyFields, Empty, EvidenceCard, ResultBanner, PhishingVerdictSkeleton, DataTable, type Column } from "@/components/output";
import { PreviewBadge } from "@/components/PreviewBadge";
import { takePendingArtifact, sendArtifact } from "@/lib/handoff";
import { analyzeFullEmail, safeAnalyzeUrl } from "@/api/backend";
import { toast } from "sonner";
import { refang, defang } from "@/lib/ioc-patterns";
import { useLocker, type LockerItem } from "@/lib/locker";
import { Mail, ShieldAlert, ShieldCheck, Link2, Database, CheckCircle2, XCircle, MinusCircle, AlertTriangle, FileText, Hash, Crosshair, Key, FlaskConical, Activity, Languages, BadgeCheck, ListChecks, Workflow } from "lucide-react";
import { ExplainThisButton } from "@/components/ExplainThis";
import { EntitySection } from "@/components/entity";
import {
  SAMPLES, SENDER_TLDS, RX,
  extractBody, extractHeaders, htmlToText,
  genMarkdown, genJsonExport, type AuthState,
} from "@/data/phishing";
import { analyzePhishing } from "@/lib/emailArtifact";
import { buildLocalHistory } from "@/lib/correlation/history";
import { rememberCorrelation } from "@/lib/correlation";
import { createCaseFromAnalysis } from "@/data/case-factory";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { parseEmailForensics } from "@/lib/phishing/email-header-parser";
import { EmailAuthMatrix } from "@/components/phishing/EmailAuthMatrix";
import { MtaRouteTimeline } from "@/components/phishing/MtaRouteTimeline";
import { LinkDiscrepancyGrid } from "@/components/phishing/LinkDiscrepancyGrid";
import { PhishingContainmentConsole } from "@/components/phishing/PhishingContainmentConsole";

export const Route = createFileRoute("/phishing")({ component: PhishingPage });

function AuthTile({ name, state }: { name: string; state: AuthState }) {
  const cfg =
    state === "pass" ? { Icon: CheckCircle2, cls: "border-success/50 bg-success/10 text-success", label: "PASS" } :
    state === "fail" ? { Icon: XCircle, cls: "border-destructive/50 bg-destructive/10 text-destructive", label: "FAIL" } :
    state === "softfail" ? { Icon: AlertTriangle, cls: "border-warning/50 bg-warning/10 text-warning", label: "SOFTFAIL" } :
                       { Icon: MinusCircle, cls: "border-border bg-surface-1 text-muted-foreground", label: "\u2014" };
  const { Icon, cls, label } = cfg;
  return (
    <div className={"flex items-center justify-between gap-2 rounded-md border px-3 py-2 " + cls}>
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4" />
        <span className="text-mono ba-text-sm">{name}</span>
      </div>
      <span className="text-mono ba-text-sm font-semibold tabular-nums">{label}</span>
    </div>
  );
}

function EmptyPreview() {
  const cards: [import("lucide-react").LucideIcon, string, string][] = [
    [Mail, "Sender Identity", "From, Reply-To, Return-Path, display-name mismatches"],
    [Key, "Header Authentication", "SPF, DKIM, DMARC, Received path, auth results"],
    [Link2, "Extracted URLs", "Visible text, actual href, defanged targets"],
    [AlertTriangle, "Lure Signals", "Urgency, credential request, brand impersonation"],
    [FileText, "Case Findings", "Report-ready summary, limitations, next steps"],
  ];
  return (
    <Panel title="Awaiting Analysis" icon={FlaskConical} meta="expected output structure" priority="secondary">
      <div className="grid gap-3 grid-cols-2 sm:grid-cols-3">
        {cards.map(([Icon, title, text]) => (
          <div key={title} className="rounded-md border border-dashed border-divider-strong bg-surface-1 p-3">
            <div className="flex items-center gap-1.5 text-mono ba-text-2xs font-semibold text-fg-dim">
              <Icon className="h-3.5 w-3.5 text-primary/70" />
              {title}
            </div>
            <p className="mt-1 ba-text-2xs text-muted-foreground">{text}</p>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function ScoreGauge({ score, maxScore, label }: { score: number; maxScore: number; label: string }) {
  const pct = maxScore > 0 ? Math.min(100, Math.round((score / maxScore) * 100)) : 0;
  const tone = pct >= 60 ? "destructive" : pct >= 30 ? "warning" : "success";
  const color = tone === "destructive" ? "bg-destructive" : tone === "warning" ? "bg-warning" : "bg-success";
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-2 rounded-full bg-surface-2 overflow-hidden">
        <div className={"h-full transition-all " + color} style={{ width: `${pct}%` }} />
      </div>
      <span className={"text-mono ba-text-sm font-semibold tabular-nums " + (tone === "destructive" ? "text-destructive" : tone === "warning" ? "text-warning" : "text-success")}>{score}/{maxScore}</span>
      <span className="text-mono ba-text-3xs text-muted-foreground">{label}</span>
    </div>
  );
}

function PhishingPage() {
  const pendingRef = useRef(takePendingArtifact());
  const [input, setInput] = useState(() => {
    const p = pendingRef.current;
    return p?.kind === "email" || p?.kind === "raw" || p?.kind === "ioc" ? (p.value ?? "") : "";
  });
  const [loading, setLoading] = useState<string | null>(null);
  const [notice, setNotice] = useState<string>("");
  const [runs, setRuns] = useState(() => pendingRef.current ? 1 : 0);
  const [apiResult, setApiResult] = useState<Record<string, any> | null>(null);
  const navigate = useNavigate();
  const locker = useLocker();
  const [iocDefanged, setIocDefanged] = useState(true);
  const { items: recentItems, push: pushRecent, clear: clearRecent } = useRecentInputs("phishing");
  const { pending, accept, save, clear: wsClear } = useWorkspaceState("phishing");
  const has = input.trim().length > 0;

  useEffect(() => {
    if (pendingRef.current && input) {
      setNotice(`Loaded ${pendingRef.current.kind} from ${pendingRef.current.source}`);
      pendingRef.current = null;
    }
  }, [input]);

  useEffect(() => {
    if (input.trim()) pushRecent(input);
  }, [runs, input, pushRecent]);

  const flashNotice = (msg: string) => {
    setNotice(msg);
    setTimeout(() => setNotice(""), 3000);
  };

  const data = useMemo(() => {
    return analyzePhishing(input, apiResult, { history: buildLocalHistory() });
  }, [input, apiResult]);

  const emailForensics = useMemo(() => {
    if (!input.trim()) return null;
    try {
      const headers = extractHeaders(input);
      const body = extractBody(input);
      return parseEmailForensics(headers, body);
    } catch {
      return null;
    }
  }, [input]);

  useEffect(() => {
    if (data?.correlation?.length) rememberCorrelation(data.correlation, { source: "phishing" });
  }, [data]);

  const pushedPhishRef = useRef("");
  useEffect(() => {
    if (data?.verdict && pushedPhishRef.current !== data.verdict.label + runs) {
      pushedPhishRef.current = data.verdict.label + runs;
      pushTimelineEvent({ source: "phishing", verb: "analyzed", detail: `Phishing analysis: ${data.verdict.label} risk`, result: `${data.findings.length} findings` });
    }
  }, [data, runs]);

  const handoff = (kind: string, value: string, to: string) => {
    sendArtifact({ kind, value, source: "/phishing" });
    navigate({ to });
  };

  const state: AnalyzerState = loading ? "parsing" : !has ? "idle" : !data ? "idle" : "ready";

  const run = async () => {
    if (loading || !has) return;
    save({ artifact: input });
    setRuns((r) => r + 1);
    setLoading("analysing");
    setNotice("");
    try {
      const body = extractBody(input);
      const headers = extractHeaders(input);
      const response = await analyzeFullEmail(headers, body, true);
      setApiResult(response);
      save({ artifact: input, analysis: response });
    } catch (e: any) {
      setApiResult(null);
      toast.error(e?.message || "Analysis failed", { description: e?.suggestion });
    }
    try {
      const refanged = refang(input);
      const urls = Array.from(new Set(refanged.match(RX.URL) ?? [])).slice(0, 3);
      if (urls.length > 0) {
        await Promise.all(urls.map((url) =>
          safeAnalyzeUrl({
            url,
            allow_live_fetch: true,
            max_redirects: 3,
            timeout_seconds: 6,
            allow_private_targets: false,
          }).catch(() => null)
        ));
      }
      flashNotice("Analysis complete");
      toast.success("Phishing analysis complete");
    } catch (e: any) {
      flashNotice("Analysis completed (partial)");
      toast.error(e?.message || "Analysis completed with errors", { description: e?.suggestion });
    } finally {
      setLoading(null);
    }
  };

  const clear = useCallback(() => { setInput(""); setRuns(0); setNotice(""); setApiResult(null); wsClear(); }, [wsClear]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") clear();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [clear]);

  return (
    <ErrorBoundary name="PhishingPage">
    <PageShell
      eyebrow="triage / phishing"
      title="Phishing Triage"
      description="Static-only inspection of email envelope, auth results, body, and embedded indicators. No links followed."
      crumbs={[{ label: "Triage" }, { label: "Phishing" }]}
      jumps={[{ label: "URL Analysis", to: "/url" }, { label: "Detection", to: "/detection" }]}
    >
      <AnalyzerShell
        icon={Mail}
        title="Phishing Triage"
        purpose="Static analysis of email envelope, authentication and body lures."
        state={state}
        canRun={has && !loading}
        onRun={run}
        onClear={clear}
        resumeBanner={pending && (
          <ResumeBanner
            artifact={pending.artifact}
            updatedAt={pending.updatedAt}
            onResume={() => {
              const s = accept();
              if (s) {
                setInput(s.artifact);
                setApiResult(s.analysis ? (s.analysis as Record<string, unknown>) : null);
                setRuns(1);
              }
            }}
            onStartFresh={clear}
          />
        )}
        intake={
          <>
            <SectionBar id="IN" label="Intake · raw email source" meta="paste full source incl. headers" />
            <IntakeCard
              icon={Mail}
              title="Email Source"
              value={input}
              onChange={setInput}
              onPaste={(t) => { setInput(t); setRuns((r) => r + 1); }}
              samples={[
                { key: "lure", label: "Credential lure", hint: "spf/dkim/dmarc fail" },
                { key: "bec", label: "BEC wire request", hint: "lookalike domain, attachment" },
                { key: "invoice", label: "Invoice / portal", hint: "all auth pass, attachment" },
                { key: "html", label: "HTML form phish", hint: "form, password field, secrets" },
                { key: "suspicious_invoice", label: "Suspicious invoice", hint: "overdue payment lure" },
                { key: "account_alert", label: "Account alert", hint: "security alert + spoofed sender" },
              ]}
              onLoadSample={(key) => {
                const s = SAMPLES[key as keyof typeof SAMPLES] ?? SAMPLES.lure;
                setInput(s);
                setRuns((r) => r + 1);
              }}
              onFile={(txt) => { setInput(txt); setRuns((r) => r + 1); }}
              fileAccept=".eml,.txt,.msg,.log"
              run={{ label: "analyse", icon: ShieldAlert, onClick: run, disabled: !has || !!loading }}
              onClear={clear}
              rows={10}
              placeholder="Paste raw email source including headers — or drop a .eml file."
              notice={notice || undefined}
            />
            {recentItems.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 rounded border border-subtle bg-surface-1 px-2.5 py-1.5">
                <span className="text-mono ba-text-3xs text-muted-foreground">recent</span>
                {recentItems.slice(0, 8).map((item, i) => (
                  <button key={i} onClick={() => { setInput(item); setRuns((r) => r + 1); pushRecent(item); }}
                    className="max-w-[160px] truncate rounded border border-subtle bg-surface-0 px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:border-primary/40 hover:text-primary"
                    title={item}
                  >{item.slice(0, 40)}{item.length > 40 ? "…" : ""}</button>
                ))}
                {recentItems.length > 8 && <span className="text-mono ba-text-3xs text-muted-foreground">+{recentItems.length - 8} more</span>}
                <button onClick={() => clearRecent()} className="ml-auto text-mono ba-text-3xs text-muted-foreground hover:text-destructive">clear</button>
              </div>
            )}
          </>
        }
        resultBanner={data ? (
          <div className="pointer-events-none select-none">
            <ResultBanner
              sticky
              tone={data.verdict.tone === "destructive" ? "destructive" : data.verdict.tone === "warning" ? "warning" : "default"}
              badge={data.verdict.tone === "destructive" ? "likely phishing" : data.verdict.tone === "warning" ? "suspicious" : "inconclusive"}
              caseId={`BA-PH-${String(data.displayFindings.length).padStart(2, "0")}`}
              title={data.verdict.label}
              subtitle="Authentication snapshot computed from the message's Authentication-Results header."
              reasons={data.displayFindings.slice(0, 3).map((f) => f.title)}
              metrics={[
                { label: "Findings", value: data.displayFindings.length, tone: data.displayFindings.length > 0 ? "warning" : "success" },
                { label: "SPF",   value: data.auth.spf.toUpperCase(),   tone: data.auth.spf === "fail" ? "destructive" : data.auth.spf === "softfail" ? "warning" : data.auth.spf === "pass" ? "success" : "default" },
                { label: "DKIM",  value: data.auth.dkim.toUpperCase(),  tone: data.auth.dkim === "fail" ? "destructive" : data.auth.dkim === "softfail" ? "warning" : data.auth.dkim === "pass" ? "success" : "default" },
                { label: "DMARC", value: data.auth.dmarc.toUpperCase(), tone: data.auth.dmarc === "fail" ? "destructive" : data.auth.dmarc === "softfail" ? "warning" : data.auth.dmarc === "pass" ? "success" : "default" },
              ]}
            />
          </div>
        ) : undefined}
        exportMd={data ? () => {
          const md = genMarkdown(input, data, data.iocsByCategory);
          const blob = new Blob([md], { type: "text/markdown" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = `phishing-report-${Date.now()}.md`; a.click();
          URL.revokeObjectURL(url);
        } : undefined}
        exportJson={data ? () => {
          const json = genJsonExport(data, data.iocsByCategory);
          const blob = new Blob([json], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = `phishing-report-${Date.now()}.json`; a.click();
          URL.revokeObjectURL(url);
        } : undefined}
        onCreateInvestigation={data ? () => {
          const { investigation } = createCaseFromAnalysis(data);
          toast.success(`Investigation created: ${investigation.case.title}`);
          navigate({ to: "/case" });
        } : undefined}
        sendToTargets={data ? [
          { label: "Safe URL Analyzer", to: "/url", icon: Link2, onClick: () => sendArtifact({ kind: "url", value: data.urlAnalysis[0]?.value ?? input, source: "/phishing" }) },
          { label: "Malware & File", to: "/file", icon: FileText, onClick: () => sendArtifact({ kind: "email", value: input, source: "/phishing" }) },
          { label: "Detection & MITRE", to: "/detection", icon: ShieldAlert, onClick: () => sendArtifact({ kind: "raw", value: input, source: "/phishing" }) },
          { label: "Logs & Alerts", to: "/logs", icon: Database, onClick: () => sendArtifact({ kind: "raw", value: input, source: "/phishing" }) },
        ] : undefined}
      >
        {loading ? <PhishingVerdictSkeleton /> : data ? <>
              <PhishingContainmentConsole
                data={data}
                rawInput={input}
                emailForensics={emailForensics}
              />

              {emailForensics && (
                <div className="space-y-4 mb-4">
                  <EmailAuthMatrix
                    auth={emailForensics.auth}
                    fromDomain={emailForensics.domains.fromDomain}
                  />

                  {emailForensics.linkDiscrepancies.length > 0 && (
                    <LinkDiscrepancyGrid
                      discrepancies={emailForensics.linkDiscrepancies}
                      onTriageUrl={(target) => navigate({ to: `/url?url=${encodeURIComponent(target)}` })}
                    />
                  )}

                  {emailForensics.mtaHops.length > 0 && (
                    <MtaRouteTimeline mtaHops={emailForensics.mtaHops} />
                  )}
                </div>
              )}

              <Panel title="Authentication detail" icon={ShieldCheck} meta="SPF · DKIM · DMARC" actions={<PreviewBadge />}>
                <div className="grid gap-2 grid-cols-3">
                  <AuthTile name="SPF" state={data.auth.spf} />
                  <AuthTile name="DKIM" state={data.auth.dkim} />
                  <AuthTile name="DMARC" state={data.auth.dmarc} />
                </div>
              </Panel>

              <Panel title="Auth Chain" icon={ShieldCheck} meta="SPF · DKIM · DMARC chain-of-trust"
                actions={<ExplainThisButton kind="email" input={input} />}
              >
                <div className="flex items-center gap-2">
                  <Chip tone={data.auth.spf === "pass" ? "success" : data.auth.spf === "fail" ? "destructive" : data.auth.spf === "softfail" ? "warning" : "default"}>SPF: {data.auth.spf.toUpperCase()}</Chip>
                  <Chip tone={data.auth.dkim === "pass" ? "success" : data.auth.dkim === "fail" ? "destructive" : data.auth.dkim === "softfail" ? "warning" : "default"}>DKIM: {data.auth.dkim.toUpperCase()}</Chip>
                  <Chip tone={data.auth.dmarc === "pass" ? "success" : data.auth.dmarc === "fail" ? "destructive" : data.auth.dmarc === "softfail" ? "warning" : "default"}>DMARC: {data.auth.dmarc.toUpperCase()}</Chip>
                </div>
                {(() => {
                  const ar = data.authResults;
                  const conflicts = (["spf", "dkim", "dmarc"] as const).filter((f) => ar.conflict[f]);
                  if (ar.headerCount <= 1 && conflicts.length === 0) return null;
                  return (
                    <p className={"mt-2 text-mono ba-text-2xs " + (conflicts.length > 0 ? "text-warning" : "text-muted-foreground/70")}>
                      {ar.headerCount} Authentication-Results header{ar.headerCount === 1 ? "" : "s"} parsed — verdicts shown from the topmost (last evaluating) hop.
                      {conflicts.length > 0 && ` Conflicting verdicts across headers: ${conflicts.map((c) => c.toUpperCase()).join(", ")} — review raw headers below before trusting the snapshot.`}
                    </p>
                  );
                })()}
              </Panel>

              <Panel title="Sender Identity" icon={ShieldCheck}>
                <KeyFields items={[
                  { label: "From", value: data.fromLine || "\u2014" },
                  { label: "Reply-To", value: data.replyLine || "\u2014", tone: data.replyMismatch ? "warning" : "default" },
                  { label: "Return-Path", value: data.pathLine || "\u2014" },
                  { label: "Subject", value: (input.match(/Subject:\s*(.+)/i)?.[1] ?? "\u2014").trim() },
                  { label: "Sender TLD", value: data.fromDomain ? `.${data.fromDomain.split(".").pop()}` : "\u2014", tone: data.fromDomain && SENDER_TLDS.has(data.fromDomain.split(".").pop() || "") ? "warning" : "default" },
                  { label: "Authentication", value: data.auth.spf === "fail" || data.auth.dmarc === "fail" ? "FAIL" : data.auth.spf === "softfail" || data.auth.dmarc === "softfail" || data.auth.dkim === "softfail" ? "SOFTFAIL" : "pass", tone: data.auth.spf === "fail" || data.auth.dmarc === "fail" ? "destructive" : data.auth.spf === "softfail" || data.auth.dmarc === "softfail" || data.auth.dkim === "softfail" ? "warning" : "success" },
                   ...(data.hasAttachment.hasAttachments ? [{ label: "Attachment", value: data.hasAttachment.detail.join("; "), tone: "warning" as const }] : []),
                 ]} />
                {data.attachmentFiles.length > 0 && (
                  <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-border/40 pt-2">
                    <span className="text-mono ba-text-2xs text-muted-foreground">attachment →</span>
                    {data.attachmentFiles.map((f) => (
                      <button
                        key={f}
                        onClick={() => { sendArtifact({ kind: "file", value: f, source: "/phishing" }); navigate({ to: "/file" }); }}
                        className="inline-flex items-center gap-1 rounded border border-border/60 bg-surface-0 px-2 py-0.5 font-mono ba-text-2xs hover:border-primary/50 hover:text-foreground"
                      >
                        <FileText className="h-3 w-3" />{f} → File Analyzer
                      </button>
                    ))}
                    <span className="text-mono ba-text-2xs text-muted-foreground/70">filename only — attachment content is not carried over</span>
                  </div>
                )}
              </Panel>

              {/* Body content */}
              {data.body && (
                <Panel title="Email Body" icon={FileText} meta={data.hasHtmlForm ? "contains HTML" : "plain text"}>
                  {data.hasHtmlForm ? (
                    <pre className="max-h-[280px] overflow-auto rounded border border-subtle bg-surface-0 p-2.5 text-mono ba-text-sm leading-relaxed text-fg-dim whitespace-pre-wrap">{data.body}</pre>
                  ) : (
                    <pre className="max-h-[200px] overflow-auto rounded border border-subtle bg-surface-0 p-2.5 text-mono ba-text-sm leading-relaxed text-fg-dim whitespace-pre-wrap">{data.body}</pre>
                  )}
                  {data.hasHtmlForm && (
                    <details className="mt-1">
                      <summary className="cursor-pointer text-mono ba-text-2xs text-muted-foreground hover:text-foreground">plain text extract ({htmlToText(data.body).length} chars)</summary>
                      <pre className="mt-1 max-h-[160px] overflow-auto rounded border border-divider-soft bg-surface-0 p-2 text-mono ba-text-sm text-fg-dim whitespace-pre-wrap">{htmlToText(data.body)}</pre>
                    </details>
                  )}
                </Panel>
              )}

              {/* Delivery path */}
              {(() => {
                const hops = Array.from(input.matchAll(/Received:\s*from\s+(\S+)\s*(?:\(([^)]+)\))?(?:\s+by\s+(\S+))?(?:\s+with\s+(\S+))?/gi)).map((m) => ({
                  from: m[1],
                  ip: m[2] ?? "",
                  by: m[3] ?? "",
                  protocol: m[4] ?? "",
                }));
                const classifyHop = (host: string): { label: string; tone: "primary" | "info" | "warning" | "destructive" } => {
                  const h = host.toLowerCase();
                  if (h.includes("mx") || h.includes("mail")) return { label: "MX", tone: "info" };
                  if (h.includes("edge")) return { label: "edge", tone: "warning" };
                  if (h.includes("gateway") || h.includes("gw")) return { label: "gateway", tone: "destructive" };
                  return { label: "relay", tone: "primary" };
                };
                const protoTone = (p: string): "primary" | "info" | "warning" | "success" | "destructive" => {
                  const v = p.toLowerCase();
                  if (v === "esmtpsa") return "warning";
                  if (v === "esmtps") return "info";
                  if (v === "esmtp") return "primary";
                  return "primary";
                };
                return (
                  <Panel title="Delivery Path" meta={`${hops.length} hop${hops.length === 1 ? "" : "s"}`} priority="secondary" collapsible storageKey="ba.panel.phish.delivery" defaultCollapsed>
                    {hops.length === 0 ? (
                      <p className="text-mono ba-text-sm text-muted-foreground">No Received: hops found.</p>
                    ) : (
                      <ol className="relative space-y-0">
                        {hops.map((h, i) => {
                          const cls = classifyHop(h.from);
                          return (
                            <li key={i}>
                              <div className="relative flex items-start gap-3 pb-1">
                                {i < hops.length - 1 && (
                                  <span className="absolute left-[7px] top-4 bottom-0 w-px bg-divider-strong" aria-hidden />
                                )}
                                <div className="relative flex flex-col items-center pt-0.5">
                                  <span className="grid h-3 w-3 shrink-0 place-items-center rounded-full bg-primary ring-2 ring-background" />
                                </div>
                                <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5 py-0.5">
                                  <Chip tone="primary">hop {hops.length - i}</Chip>
                                  <code className="text-mono ba-text-sm text-foreground">{h.from}</code>
                                  {h.ip && <span className="text-mono ba-text-2xs text-muted-foreground">({h.ip})</span>}
                                  {h.protocol && <Chip tone={protoTone(h.protocol)}>{h.protocol}</Chip>}
                                  <Chip tone={cls.tone}>{cls.label}</Chip>
                                </div>
                              </div>
                              {i < hops.length - 1 && (
                                <div className="flex items-center gap-2 pl-[7px] pb-1">
                                  <span className="text-mono ba-text-2xs text-muted-foreground">↓</span>
                                  <span className="h-px flex-1 bg-divider-soft" />
                                </div>
                              )}
                            </li>
                          );
                        })}
                      </ol>
                    )}
                  </Panel>
                );
              })()}

              {/* URL analysis */}
              {data.urlAnalysis.length > 0 && (
                <Panel title="URL Deep Analysis" icon={Link2} meta={`${data.urlAnalysis.length} URL${data.urlAnalysis.length === 1 ? "" : "s"}`} priority="secondary">
                  <div className="space-y-2">
                    {data.urlAnalysis.map((u: any, i: number) => (
                      <div key={i} className="flex flex-wrap items-center gap-2 rounded border border-subtle bg-surface-1 px-3 py-2">
                        <code className="min-w-0 flex-1 truncate text-mono ba-text-sm text-foreground">{defang(u.value)}</code>
                        <div className="flex flex-wrap items-center gap-1">
                          {u.badges.length === 0 && <Chip tone="default">no url flags</Chip>}
                          {u.badges.map((b: any, j: number) => (
                            <Chip key={j} tone={b.tone}>{b.label}</Chip>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}

              {/* Language */}
              {data.language && (
                <Panel title="Language" icon={Languages} meta="script detection" priority="secondary">
                  <div className="flex flex-wrap items-center gap-2">
                    <Chip tone={data.language.script === "latin" ? "success" : "warning"}>{data.language.label}</Chip>
                    {data.language.script !== "latin" && <Chip tone="warning">non-Latin script — localise analysis</Chip>}
                  </div>
                  {data.language.samples.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {data.language.samples.map((s, i) => (
                        <code key={i} className="rounded border border-subtle bg-surface-1 px-2 py-0.5 text-mono ba-text-sm text-fg-dim">{s}</code>
                      ))}
                    </div>
                  )}
                </Panel>
              )}

              {/* Brand impersonation */}
              {(data.brandClaims ?? []).length > 0 && (
                <Panel title="Brand Impersonation" icon={BadgeCheck} meta={`${(data.brandClaims ?? []).length} claim${(data.brandClaims ?? []).length === 1 ? "" : "s"}`} priority="secondary" collapsible storageKey="ba.panel.phish.brand" defaultCollapsed>
                  <div className="space-y-2">
                    {(data.brandClaims ?? []).map((c, i) => (
                      <div key={i} className={`flex flex-wrap items-center gap-2 rounded border px-3 py-2 ${c.typosquat ? "border-destructive/40 bg-destructive/10" : "border-subtle bg-surface-1"}`}>
                        <Chip tone={c.typosquat ? "destructive" : "info"}>{c.brand}</Chip>
                        <span className="text-mono ba-text-sm text-fg-dim">{c.claim}</span>
                        {c.typosquat && <Chip tone="destructive">typosquat</Chip>}
                      </div>
                    ))}
                  </div>
                </Panel>
              )}

              {/* Recommendations */}
              {(data.recommendations ?? []).length > 0 && (
                <Panel title="Recommendations" icon={ListChecks} meta={`${(data.recommendations ?? []).length} action${(data.recommendations ?? []).length === 1 ? "" : "s"}`} priority="secondary">
                  <ol className="space-y-1.5">
                    {(data.recommendations ?? []).map((r, i) => (
                      <li key={i} className="flex items-start gap-2.5 rounded border border-subtle bg-surface-1 px-3 py-2">
                        <span className={`mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded ${r.sev === "destructive" ? "bg-destructive/15 text-destructive" : r.sev === "warning" ? "bg-warning/15 text-warning" : "bg-info/15 text-info"}`}>
                          <span className="text-mono ba-text-2xs font-bold">{i + 1}</span>
                        </span>
                        <div className="min-w-0">
                          <div className="text-mono ba-text-sm text-fg-dim">{r.text}</div>
                        </div>
                        <Chip tone="info">{r.source}</Chip>
                      </li>
                    ))}
                  </ol>
                </Panel>
              )}

              {/* Secrets in body */}
              {data.secrets.length > 0 && (
                <Panel title="Secrets Detected in Body" icon={Key} meta={`${data.secrets.length} potential exposure`} priority="secondary">
                  <div className="space-y-1.5">
                    {data.secrets.map((s: any, i: number) => (
                      <div key={i} className="flex items-center justify-between gap-2 rounded border border-destructive/30 bg-destructive/5 px-2.5 py-1.5">
                        <span className="text-mono ba-text-2xs text-destructive">{s.type}</span>
                        <code className="text-mono ba-text-sm text-fg-dim">{s.value}</code>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}

              {/* IOC inventory */}
              {data.iocsByCategory && (
                <>
                  <label className="inline-flex items-center gap-2 cursor-pointer mb-2">
                    <input
                      type="checkbox"
                      checked={iocDefanged}
                      onChange={(e) => setIocDefanged(e.target.checked)}
                      className="sr-only"
                    />
                    <span className={`relative inline-block h-5 w-9 rounded-full transition-colors duration-150 ${iocDefanged ? "bg-primary" : "bg-muted-foreground/30"}`}>
                      <span className={`absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-background transition-transform ${iocDefanged ? "translate-x-4" : "translate-x-0"}`} />
                    </span>
                    <span className="text-mono ba-text-2xs text-muted-foreground">{iocDefanged ? "defanged" : "refanged"}</span>
                  </label>
                  <SectionBar id="IO" label="IOC inventory" meta="urls · domains · ips · hashes · emails · cve · attack" priority="secondary" />
                  <div className="flex flex-wrap gap-1.5 mb-2">
                    {(Object.entries(data.iocsByCategory) as [string, string[]][]).filter(([, v]) => v.length > 0).map(([k, v]) => (
                      <button
                        key={k}
                        onClick={() => { const t = k === "urls" ? "url" : k === "ips" ? "ipv4" : k === "hashes" ? "sha256" : k === "domains" ? "domain" : k === "emails" ? "email" : k === "cve" ? "cve" : k === "attack" ? "mitre-attack" : "unknown"; v.forEach((item: string) => locker.add({ value: item, type: t as LockerItem["type"], source: "/phishing", note: "" })); flashNotice(`Added ${v.length} ${k} to locker`); }}
                        className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-1 text-mono ba-text-3xs text-muted-foreground hover:bg-card/70 hover:text-foreground transition-colors duration-150"
                      >
                        + {k} ({v.length})
                      </button>
                    ))}
                  </div>
                  <IocInventory
                    onSendTo={(kind, value) => {
                      const k = kind.toLowerCase();
                      const map: Record<string, string> = { urls: "/url", domains: "/intel", ips: "/intel", hashes: "/attachment", emails: "/intel", cve: "/detection", attack: "/detection" };
                      if (map[k] === "/intel") { navigate({ to: "/intel", search: { q: value } }); return; }
                      handoff(k, value, map[k] ?? "/case");
                    }}
                    groups={[
                      { kind: "urls", items: (data.iocsByCategory.urls ?? []).map(iocDefanged ? defang : refang), tone: "destructive" },
                      { kind: "domains", items: (data.iocsByCategory.domains ?? []).map(iocDefanged ? defang : refang), tone: "warning" },
                      { kind: "ips", items: (data.iocsByCategory.ips ?? []).map(iocDefanged ? defang : refang), tone: "info" },
                      { kind: "hashes", items: (data.iocsByCategory.hashes ?? []).map(iocDefanged ? defang : refang), tone: "primary" },
                      { kind: "emails", items: (data.iocsByCategory.emails ?? []).map(iocDefanged ? defang : refang), tone: "success" },
                      ...((data.iocsByCategory.cve ?? []).length ? [{ kind: "cve" as const, items: (data.iocsByCategory.cve ?? []).map(iocDefanged ? defang : refang), tone: "destructive" as const }] : []),
                      ...((data.iocsByCategory.attack ?? []).length ? [{ kind: "attack" as const, items: (data.iocsByCategory.attack ?? []).map(iocDefanged ? defang : refang), tone: "destructive" as const }] : []),
                    ]}
                  />
                </>
              )}

              {/* MITRE */}
              {data.mitre.length > 0 && (
                <Panel title="MITRE ATT&CK Mapping" icon={Crosshair} meta={`${data.mitre.length} technique${data.mitre.length === 1 ? "" : "s"}`} priority="secondary" collapsible storageKey="ba.panel.phish.mitre" defaultCollapsed>
                  <div className="grid gap-2 grid-cols-3">
                    {data.mitre.map((m: any, i: number) => (
                      <div key={i} className="flex items-center gap-2.5 rounded border border-subtle bg-surface-1 px-3 py-2">
                        <span className="grid h-7 w-7 place-items-center rounded border border-destructive/40 bg-destructive/10">
                          <Crosshair className="h-3.5 w-3.5 text-destructive" />
                        </span>
                        <div>
                          <div className="text-mono ba-text-2xs font-semibold text-destructive">{m.id}</div>
                          <div className="text-mono ba-text-sm text-fg-dim">{m.name}</div>
                        </div>
                        <Chip tone="info">{m.source}</Chip>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}

              {/* Scoring breakdown table */}
              <SectionBar id="TA" label="Technical · scoring breakdown" meta={`score computed from ${data.breakdown.filter((b: any) => b.weight > 0).length} signal(s)`} priority="raw" />
              <Panel icon={Activity} title="Signal weights" meta="how the risk score was assembled" priority="secondary">
                {(() => { const totalScore = data.breakdown.reduce((a: number, b: any) => a + (b.state === "pass" ? 0 : b.weight), 0); const maxScore = data.breakdown.reduce((a: number, b: any) => a + b.weight, 0); return <ScoreGauge score={totalScore} maxScore={maxScore} label="risk score" />; })()}
                {(() => {
                  const totalWt = (arr: any[]) => arr.reduce((a: number, x: any) => a + (x.state === "pass" ? 0 : x.weight), 0);
                  const breakdown = data.breakdown;
                  const total = totalWt(breakdown);
                  const columns: Column<any>[] = [
                    { key: "signal", label: "Signal", sortable: true, sortValue: (b: any) => String(b.signal), render: (b: any) => <span className="font-medium text-foreground">{b.signal}</span> },
                    {
                      key: "state", label: "State", render: (b: any) => {
                        const tone = b.state === "fail" ? "destructive" : b.state === "softfail" ? "warning" : "default";
                        return <Chip tone={tone as "destructive" | "warning" | "default"}>{b.state}</Chip>;
                      },
                    },
                    { key: "contribution", label: "Contribution", align: "right", sortable: true, sortValue: (b: any) => (b.state === "pass" ? 0 : b.weight), render: (b: any) => <span className="text-foreground">+{b.state === "pass" ? 0 : b.weight}</span> },
                    {
                      key: "share", label: "Share", render: (b: any) => {
                        const wt = b.state === "pass" ? 0 : b.weight;
                        const pct = total > 0 ? Math.round((wt / total) * 100) : 0;
                        const tone = b.state === "fail" ? "destructive" : b.state === "softfail" ? "warning" : "default";
                        return (
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 w-24 overflow-hidden rounded bg-surface-0">
                              <div className={"h-full " + (wt === 0 ? "bg-muted-foreground/30" : tone === "destructive" ? "bg-destructive/70" : tone === "warning" ? "bg-warning/70" : "bg-primary/70")} style={{ width: `${pct}%` }} />
                            </div>
                            <span className="text-muted-foreground">{pct}%</span>
                          </div>
                        );
                      },
                    },
                  ];
                  return (
                    <div className="mt-3">
                      <DataTable columns={columns} rows={breakdown} />
                    </div>
                  );
                })()}
              </Panel>

              {/* Evidence cards */}
              <SectionBar id="EV" label="Evidence cards" meta="reason · limitation · action" />
              <div className="grid gap-3 grid-cols-2">
                {data.displayFindings.length === 0 ? <Empty title="No suspicious patterns triggered" hint="Phishing Triage scans email headers and body for SPF/DKIM/DMARC failures, suspicious sender addresses, deceptive links, and urgency language. Try pasting a full email source (headers + body)." /> : data.displayFindings.map((f, i: number) => (
                  <EvidenceCard key={i} severity={f.severity} title={f.title} reason={f.reason} action={f.action} limitation="Heuristic — confirm against gateway logs and user report." />
                ))}
              </div>



              {/* Raw panels */}
              <div className="grid gap-3 grid-cols-2">
                <Panel icon={ShieldCheck} title="Authentication-Results · raw" meta="parsed verbatim" priority="raw" collapsible storageKey="ba.panel.phish.authraw" defaultCollapsed>
                  <pre className="overflow-x-auto rounded border border-subtle bg-surface-0 p-2.5 text-mono ba-text-sm text-fg-dim whitespace-pre-wrap">
                    {(input.match(/Authentication-Results:[^\n]*(?:\n\s+[^\n]+)*/gi) ?? ["— none found —"]).join("\n\n")}
                  </pre>
                </Panel>
                <Panel icon={Hash} title="Message identifiers" meta="for de-duplication & search" priority="secondary" collapsible storageKey="ba.panel.phish.msgid" defaultCollapsed>
                  <KeyFields items={[
                    { label: "Message-ID",     value: (input.match(/Message-ID:\s*<([^>]+)>/i)?.[1] ?? "—") },
                    { label: "X-Mailer",       value: (input.match(/X-Mailer:\s*(.+)/i)?.[1]?.trim() ?? "—") },
                    { label: "Date",           value: (input.match(/^Date:\s*(.+)$/im)?.[1]?.trim() ?? "—") },
                    { label: "MIME-Version",   value: (input.match(/MIME-Version:\s*(.+)/i)?.[1]?.trim() ?? "—") },
                    { label: "Content-Type",   value: (input.match(/Content-Type:\s*([^;\n]+)/i)?.[1]?.trim() ?? "—") },
                  ]} />
                </Panel>
              </div>

              <Panel icon={FileText} title="Raw headers" meta="everything before the first blank line" priority="raw" actions={<PreviewBadge label="verbatim" />} collapsible storageKey="ba.panel.phish.rawheaders" defaultCollapsed>
                <pre className="max-h-[320px] overflow-auto rounded border border-subtle bg-surface-0 p-2.5 text-mono ba-text-2xs leading-relaxed text-fg-dim whitespace-pre-wrap">
                  {extractHeaders(input) || "— empty —"}
                </pre>
              </Panel>

              {/* Engine sections */}
              {data.opportunities.length > 0 && (
                <EntitySection title="Detection Coverage" icon={Crosshair} meta={`${data.opportunities.length} technique${data.opportunities.length === 1 ? "" : "s"} · engine`}>
                  <div className="space-y-2">
                    {data.opportunities.map((o) => (
                      <div key={o.id} className="rounded-md border border-subtle bg-surface-1 px-3 py-2.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-mono ba-text-2xs font-semibold text-destructive">{o.technique}</span>
                          <Chip tone={o.coverage === "detected" ? "success" : o.coverage === "gap" ? "warning" : "info"}>{o.coverage}</Chip>
                          <Chip tone="primary">{o.priority}</Chip>
                        </div>
                        <p className="mt-1 ba-text-2xs leading-relaxed text-muted-foreground">{o.behavior}</p>
                        {o.existingRule && <p className="mt-1 text-mono ba-text-3xs text-fg-dim">existing rule · {o.existingRule}</p>}
                        {o.suggestedHunt && <p className="mt-1 text-mono ba-text-3xs text-fg-dim">hunt · {o.suggestedHunt}</p>}
                      </div>
                    ))}
                  </div>
                </EntitySection>
              )}

              <EntitySection title="Analysis Quality" icon={Activity} meta={`coverage ${Math.round((data.quality.coverage.score ?? 0) * 100)}%`}>
                <div className="grid gap-2 grid-cols-2">
                  <div className="rounded-md border border-subtle bg-surface-1 px-3 py-2.5">
                    <div className="text-mono ba-text-2xs text-muted-foreground">coverage score</div>
                    <div className="mt-1 text-mono ba-text-xl font-semibold text-foreground">{Math.round((data.quality.coverage.score ?? 0) * 100)}%</div>
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {data.quality.coverage.gaps.length === 0 ? (
                        <Chip tone="success">all evidence categories covered</Chip>
                      ) : (
                        data.quality.coverage.gaps.map((g) => <Chip key={g} tone="info">{g}</Chip>)
                      )}
                    </div>
                  </div>
                  <div className="rounded-md border border-subtle bg-surface-1 px-3 py-2.5">
                    <div className="text-mono ba-text-2xs text-muted-foreground">recommended next step</div>
                    <p className="mt-1 ba-text-sm text-foreground">{data.quality.recommendedNextStep}</p>
                    {data.quality.weakSignals.length > 0 && (
                      <p className="mt-1.5 text-mono ba-text-3xs text-muted-foreground">weak signals · {data.quality.weakSignals.join(", ")}</p>
                    )}
                  </div>
                </div>
              </EntitySection>

              <EntitySection title="Correlation" icon={Workflow} meta={`${data.correlation.length} matches · local history`}>
                {data.correlation.length === 0 ? (
                  <p className="text-mono ba-text-sm text-muted-foreground">
                    No prior-case, detection, or intel-corpus matches in the local case/detection/entity corpus. Findings above are unaffected.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {data.correlation.map((m) => (
                      <div key={`${m.dimension}-${m.value}`} className="rounded-md border border-subtle bg-surface-1 px-3 py-2.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <Chip tone="info">{m.dimension}</Chip>
                          <span className="text-mono ba-text-sm text-foreground">{m.value}</span>
                          <Chip tone="primary">{Math.round(m.confidence * 100)}%</Chip>
                        </div>
                        <p className="mt-1 text-mono ba-text-3xs text-muted-foreground">{m.label} · {m.matches.map((x) => x.label).join(", ")}</p>
                      </div>
                    ))}
                  </div>
                )}
                {data.correlationRelationships.length > 0 && (
                  <p className="mt-2 text-mono ba-text-3xs text-muted-foreground">{data.correlationRelationships.length} graph relationship(s) queued with origin=correlation for analyst review.</p>
                )}
              </EntitySection>

          </>
        : has ? <Empty icon={ShieldAlert} title="Press analyse or paste to run" hint="Paste the full email source above to compute the risk verdict." /> : <EmptyPreview />}
      </AnalyzerShell>
    </PageShell>
    </ErrorBoundary>
  );
}


