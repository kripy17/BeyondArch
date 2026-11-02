import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { Printer, Database, ArrowLeft, ShieldAlert, CheckCircle, Clock, FileText, Activity, AlertTriangle, Globe, Link2, Fingerprint, HelpCircle, Copy, Download, History, Save, GitCompare, GitBranch, ShieldCheck, BookOpen, Columns2 } from "lucide-react";
import { useLocker } from "@/lib/locker";
import { notify } from "@/lib/notify";
import { copyText } from "@/lib/copy";
import { snapshotFrom, loadReportHistory, saveReportVersion, attachVersionEvent, deltaBetween, diffSavedVersions, sameInputs, type ReportVersion } from "@/lib/report-history";
import { loadSchedules, addSchedule, removeSchedule, schedulesForCase, CADENCES, type Cadence, type Schedule } from "@/lib/report-schedule";

import { PageShell } from "@/components/PageShell";
import { Chip, SendToRow } from "@/components/soc";
import { EntityHeader, EntitySection, KnowledgeBar, ActionDock, FindingCard, HeaderAction } from "@/components/entity";
import type { Case } from "@/data/case";
import { loadCases, saveCases, KIND_COLOR } from "@/data/case";
import { getUnifiedFindings, getUnifiedIOCs } from "@/components/investigation";
import { explainObject as explainObjectFn, explainableRefs } from "@/lib/explain";
import { loadHypotheses } from "@/data/notebook";
import { buildReportMarkdown, mitreRows, technicalSummary, REPORT_TYPES, reportSectionsFor, execSummaryRows, hypothesisRows, correlationRows, decisionRows, CORRELATION_DIMENSION_LABEL, type ReportType } from "@/lib/report";
import { buildExportBundle, htmlShell } from "@/lib/export-bundle";
import { downloadTextFile } from "@/lib/download";
import { ReportWorkbench } from "@/components/report/ReportWorkbench";

const REPORT_VIEW_KEY = "ba.report.view.v1";

function loadReportView(): "composed" | "workbench" {
  try {
    return localStorage.getItem(REPORT_VIEW_KEY) === "workbench" ? "workbench" : "composed";
  } catch {
    return "composed";
  }
}

export const Route = createFileRoute("/report/$caseId")({ component: ReportPage });

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function daysSince(iso: string): number {
  return Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
}

const IOC_ICON: Record<string, typeof Globe> = {
  ipv4: Globe, ipv6: Globe, domain: Globe, url: Link2,
  md5: Fingerprint, sha1: Fingerprint, sha256: Fingerprint,
  email: Globe, cve: AlertTriangle, ja3: Fingerprint, ua: HelpCircle,
};

function ReportPage() {
  const { caseId } = Route.useParams();
  const navigate = useNavigate();
  const locker = useLocker();
  const [reportCase, setReportCase] = useState<Case | null>(null);
  const [reportType, setReportType] = useState<ReportType>("technical");
  const [viewMode, setViewMode] = useState<"composed" | "workbench">(loadReportView);
  const [copiedMd, setCopiedMd] = useState(false);
  const [versions, setVersions] = useState<ReportVersion[]>([]);
  const [versionFlash, setVersionFlash] = useState<string | null>(null);
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [schedCadence, setSchedCadence] = useState<Cadence>("daily");
  const [schedType, setSchedType] = useState<ReportType>("technical");

  useEffect(() => {
    const all = loadCases();
    setReportCase(all.find((c) => c.id === caseId) ?? null);
  }, [caseId]);

  useEffect(() => {
    setVersions(loadReportHistory(caseId));
    setSchedules(schedulesForCase(loadSchedules(), caseId));
  }, [caseId]);

  useEffect(() => {
    const onFocus = () => {
      setVersions(loadReportHistory(caseId));
      setSchedules(schedulesForCase(loadSchedules(), caseId));
    };
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [caseId]);

  if (!reportCase) {
    return (
      <PageShell title="Report" eyebrow="investigation / report" description="Case report" crumbs={[{ label: "Report" }]}>
        <div className="flex flex-col items-center justify-center py-20 text-center">
          <AlertTriangle className="mb-4 h-8 w-8 text-destructive" />
          <h2 className="mb-2 font-mono text-lg font-bold text-foreground">Case not found</h2>
          <p className="mb-6 font-mono text-sm text-muted-foreground">The case <code className="rounded bg-card px-1 py-0.5">{caseId}</code> does not exist or has been deleted.</p>
          <button onClick={() => navigate({ to: "/case" })} className="inline-flex items-center gap-1 rounded border border-border px-3 py-1.5 font-mono text-xs text-foreground hover:border-primary/50 hover:text-primary">
            <ArrowLeft className="h-3.5 w-3.5" /> Back to cases
          </button>
        </div>
      </PageShell>
    );
  }

  const c = reportCase;
  const entries = c.entries ?? [];
  const findingsCount = c.findings?.length ?? entries.filter(e => e.kind === "evidence").length;
  const iocsCount = c.iocs?.length ?? entries.filter(e => e.kind === "ioc").length;
  const eventsCount = c.events?.length ?? 0;
  const age = daysSince(c.createdAt);
  const allIocs = getUnifiedIOCs(c);
  const allFindings = getUnifiedFindings(c);
  const recaps = explainableRefs(c).map((ref) => ({ ...explainObjectFn(c, ref) }));
  const mitre = mitreRows(c);
  const corrRows = correlationRows(c.id);
  const decRows = decisionRows(c);
  const summaryLines = technicalSummary(c);
  const summaryRows = execSummaryRows(c);
  const hyps = hypothesisRows(loadHypotheses(), c.id);
  const sections = reportSectionsFor(reportType);
  const has = (s: (typeof sections)[number]) => sections.includes(s);
  const reportTypeMeta = REPORT_TYPES.find((t) => t.id === reportType)!;
  const reportMd = buildReportMarkdown(c, reportType, hyps);
  const setReportView = (mode: "composed" | "workbench") => {
    setViewMode(mode);
    try {
      localStorage.setItem(REPORT_VIEW_KEY, mode);
    } catch {
      /* noop */
    }
  };
  const currentSnap = snapshotFrom({
    caseId: c.id,
    reportType,
    findings: allFindings,
    iocs: allIocs,
    hypotheses: hyps,
    techniques: mitre.map((r) => r.technique),
    eventCount: eventsCount,
  });
  const latest = versions[0] ?? null;
  const deltas = latest ? deltaBetween(latest, currentSnap) : [];

  const saveVersion = () => {
    try {
      saveReportVersion(currentSnap);
      const all = loadCases();
      saveCases(all.map((c2) => (c2.id === c.id ? attachVersionEvent(c2, currentSnap) : c2)));
      setVersions(loadReportHistory(c.id));
      setVersionFlash("saved");
      notify.success(`Report version saved (${reportTypeMeta.label})`);
      setTimeout(() => setVersionFlash(null), 1200);
    } catch {
      /* noop */
    }
  };

  const exportBundle = () => {
    try {
      const { blob } = buildExportBundle({ case: c, reportType, hypotheses: hyps });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `beyondcase-${c.id}-${reportType}.zip`;
      a.click();
      URL.revokeObjectURL(a.href);
      notify.success("Export bundle downloaded — includes case JSON, markdown + HTML report, raw artifacts, and a fingerprinted manifest");
    } catch (e) {
      notify.error(`Bundle export failed: ${e instanceof Error ? e.message : "unknown error"}`);
    }
  };

  const copyReportMd = () => {
    try {
      copyText(reportMd);
      setCopiedMd(true);
      notify.success(`Copied ${reportTypeMeta.label} report as markdown`);
      setTimeout(() => setCopiedMd(false), 1200);
    } catch {
      /* noop */
    }
  };

  const downloadReportMd = () => {
    try {
      downloadTextFile(`report-${c.id}-${reportType}.md`, reportMd, "text/markdown");
      notify.success(`Downloaded ${reportTypeMeta.label} report (.md)`);
    } catch {
      notify.error("Failed to download markdown report");
    }
  };

  const downloadReportHtml = () => {
    try {
      const html = htmlShell(`${c.title} — ${reportTypeMeta.label} Report`, reportMd);
      downloadTextFile(`report-${c.id}-${reportType}.html`, html, "text/html");
      notify.success(`Downloaded standalone ${reportTypeMeta.label} report (.html)`);
    } catch {
      notify.error("Failed to download HTML report");
    }
  };

  const createSchedule = () => {
    addSchedule({ caseId: c.id, cadence: schedCadence, reportType: schedType });
    setSchedules(schedulesForCase(loadSchedules(), c.id));
    notify.success(`Scheduled ${CADENCES.find((x) => x.id === schedCadence)?.label} ${REPORT_TYPES.find((x) => x.id === schedType)?.label} report`);
  };

  const deleteSchedule = (id: string) => {
    removeSchedule(id);
    setSchedules(schedulesForCase(loadSchedules(), c.id));
  };

  return (
    <>
      <style>{printCss}</style>
      <PageShell title={`Report: ${c.title}`} eyebrow="investigation / report" description="Publication view" crumbs={[{ label: "Report" }]}>
        <EntityHeader
          variant="case"
          title={c.title}
          tags={c.tags}
          onBack={() => navigate({ to: "/case" })}
          actions={
            <>
              <HeaderAction
                onClick={copyReportMd}
                className="no-print"
                icon={<Copy className="h-3 w-3" />}
                title="Copy report as markdown"
              >
                {copiedMd ? "copied" : "copy md"}
              </HeaderAction>
              <HeaderAction
                onClick={downloadReportMd}
                className="no-print"
                icon={<Download className="h-3 w-3" />}
                title="Download report as Markdown file"
              >
                .md
              </HeaderAction>
              <HeaderAction
                onClick={downloadReportHtml}
                className="no-print"
                icon={<Download className="h-3 w-3" />}
                title="Download standalone executive report as HTML (offline styled)"
              >
                .html
              </HeaderAction>
              <HeaderAction
                onClick={exportBundle}
                className="no-print"
                icon={<Download className="h-3 w-3" />}
                title="Download full case investigation bundle (.zip)"
              >
                .zip bundle
              </HeaderAction>
              <HeaderAction
                onClick={() => window.print()}
                className="no-print"
                icon={<Printer className="h-3 w-3" />}
                title="Print / Save as PDF with corporate letterhead"
              >
                print / pdf
              </HeaderAction>
            </>
          }
        >
          <div className="mt-2 flex flex-wrap items-center gap-3 font-mono ba-text-2xs text-muted-foreground">
            <Chip tone={c.state === "active" ? "warning" : "default"}>{c.state}</Chip>
            <span>Created: {formatDate(c.createdAt)}</span>
            <span>ID: {c.id}</span>
            <span>Age: {age} day{age !== 1 ? "s" : ""}</span>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <span className="font-mono ba-text-2xs text-muted-foreground">report type:</span>
            {REPORT_TYPES.map((t) => {
              const active = t.id === reportType;
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setReportType(t.id)}
                  title={t.audience}
                  className={`rounded border px-2 py-0.5 font-mono ba-text-2xs transition-colors duration-150 ${active ? "border-primary/40 bg-primary/15 text-foreground" : "border-subtle bg-background/30 text-muted-foreground hover:border-primary/30 hover:text-foreground"}`}
                >
                  {t.label}
                </button>
              );
            })}
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <span className="font-mono ba-text-2xs text-muted-foreground">view:</span>
            <button
              type="button"
              onClick={() => setReportView("composed")}
              aria-pressed={viewMode === "composed"}
              className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 font-mono ba-text-2xs transition-colors duration-150 ${viewMode === "composed" ? "border-primary/40 bg-primary/15 text-foreground" : "border-subtle bg-background/30 text-muted-foreground hover:border-primary/30 hover:text-foreground"}`}
            >
              <FileText className="h-3 w-3" /> composed
            </button>
            <button
              type="button"
              onClick={() => setReportView("workbench")}
              aria-pressed={viewMode === "workbench"}
              className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 font-mono ba-text-2xs transition-colors duration-150 ${viewMode === "workbench" ? "border-primary/40 bg-primary/15 text-foreground" : "border-subtle bg-background/30 text-muted-foreground hover:border-primary/30 hover:text-foreground"}`}
            >
              <Columns2 className="h-3 w-3" /> workbench
            </button>
          </div>
        </EntityHeader>

        <div className="print-banner hidden print:block">
          <div className="flex items-center justify-between font-mono ba-text-3xs text-muted-foreground">
            <span>BEYONDLABS CASE REPORT</span>
            <span>{formatDate(new Date().toISOString())}</span>
          </div>
          <h1 className="mt-2 font-mono text-2xl font-bold text-foreground">{c.title}</h1>
          <div className="mt-2 font-mono ba-text-2xs text-muted-foreground">
            Type: <span className="text-foreground">{reportTypeMeta.label}</span> — {reportTypeMeta.audience}
          </div>
          <div className="font-mono ba-text-2xs text-muted-foreground">
            Case <span className="text-foreground">{c.id}</span> · {c.state} · tags {c.tags.length ? c.tags.join(", ") : "—"}
          </div>
          <div className="mt-1 border-t border-border pt-1 font-mono ba-text-3xs text-muted-foreground">
            Sections: {sections.join(" · ")}
          </div>
        </div>

        <div className="no-print">
          <KnowledgeBar
            entity={{ title: c.title, type: "vulnerability", observables: allIocs } as any}
            relationshipCount={c.events?.length ?? 0}
            activeCase={c}
            observables={allIocs.length}
            mitre={c.findings?.filter(f => f.technique).length ?? 0}
          />
        </div>

        {viewMode === "workbench" ? (
          <div className="no-print mb-4">
            <ReportWorkbench md={reportMd} title={c.title} typeLabel={reportTypeMeta.label} />
          </div>
        ) : (
        <div className="mb-4 space-y-4">
        {has("summary") && (
            <EntitySection title="Executive Summary" icon={FileText}>
              <table className="w-full text-left font-mono ba-text-xs">
                <thead>
                  <tr className="border-b border-border ba-text-3xs text-muted-foreground">
                    <th scope="col" className="pb-2 pr-4">Kind</th>
                    <th scope="col" className="pb-2 pr-4">Count</th>
                    <th scope="col" className="pb-2">% of total</th>
                  </tr>
                </thead>
                <tbody>
                  {summaryRows.map(row => {
                    const color = row.kind === "Findings" ? "var(--color-primary)" : row.kind === "IOCs" ? "var(--color-destructive)" : "var(--color-muted-foreground)";
                    return (
                      <tr key={row.kind} className="border-b border-subtle">
                        <td className="py-1.5 pr-4">
                          <span className="inline-flex items-center rounded border border-current/30 bg-current/10 px-1.5 py-0.5 ba-text-3xs" style={{ color, borderColor: `${color}30`, background: `${color}15` }}>
                            {row.kind}
                          </span>
                        </td>
                        <td className="py-1.5 pr-4 font-semibold text-foreground">{row.count}</td>
                        <td className="py-1.5 text-muted-foreground">{row.pct}%</td>
                      </tr>
                    );
                  })}
                  <tr className="border-t-2 border-border font-semibold">
                    <td className="py-1.5 pr-4">Total</td>
                    <td className="py-1.5 pr-4">{findingsCount + iocsCount + eventsCount}</td>
                    <td className="py-1.5">100%</td>
                  </tr>
                </tbody>
              </table>
            </EntitySection>
          )}

          {has("technical") && (
            <EntitySection title="Technical Summary" icon={Fingerprint} meta={`${summaryLines.length} statements`}>
              <ul className="space-y-1.5 font-mono ba-text-xs text-foreground">
                {summaryLines.map((l, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="text-muted-foreground">—</span>
                    <span>{l}</span>
                  </li>
                ))}
              </ul>
            </EntitySection>
          )}

          {has("ioc") && allIocs.length > 0 && (
            <EntitySection title="IOC Summary" icon={Activity} meta={`${allIocs.length} indicators`}>
              <table className="w-full text-left font-mono ba-text-xs">
                <thead>
                  <tr className="border-b border-border ba-text-3xs text-muted-foreground">
                    <th scope="col" className="pb-2 pr-4">Type</th>
                    <th scope="col" className="pb-2 pr-4">Value</th>
                    <th scope="col" className="pb-2">Source</th>
                  </tr>
                </thead>
                <tbody>
                  {allIocs.map((ioc, idx) => {
                    const Icon = IOC_ICON[ioc.type] ?? AlertTriangle;
                    return (
                      <tr key={idx} className="border-b border-subtle">
                        <td className="py-1.5 pr-4">
                          <span className="inline-flex items-center gap-1 font-medium text-foreground">
                            <Icon className="h-3.5 w-3.5 text-muted-foreground" /> {ioc.type}
                          </span>
                        </td>
                        <td className="py-1.5 pr-4">
                          <code className="rounded bg-surface-2 px-1 py-0.5 font-mono ba-text-2xs break-all">{ioc.value}</code>
                        </td>
                        <td className="py-1.5">
                          <div className="flex items-center gap-2 font-mono ba-text-2xs text-muted-foreground">
                            <span>{ioc.source || "manual"}</span>
                            <button onClick={() => { locker.add({ value: ioc.value, type: ioc.type, source: "/report" }); notify.success("Added to locker"); }} className="rounded p-1 text-muted-foreground transition-colors duration-150 hover:text-foreground" title="Add to locker">
                              <Database className="h-3 w-3" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </EntitySection>
          )}

          {has("mitre") && (
            <EntitySection title="MITRE Coverage" icon={HelpCircle} meta={`${mitre.length} technique(s)`}>
              {mitre.length === 0 ? (
                <p className="py-2 text-mono ba-text-xs text-muted-foreground">No MITRE techniques mapped — findings carry no technique attribution.</p>
              ) : (
                <table className="w-full text-left font-mono ba-text-xs">
                  <thead>
                    <tr className="border-b border-border ba-text-3xs text-muted-foreground">
                      <th className="pb-2 pr-4">Technique</th>
                      <th className="pb-2 pr-4">Findings</th>
                      <th className="pb-2">Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mitre.map((row) => (
                      <tr key={row.technique} className="border-b border-subtle">
                        <td className="py-1.5 pr-4">
                          <code className="rounded bg-surface-2 px-1 py-0.5 font-mono ba-text-2xs">{row.technique}</code>
                        </td>
                        <td className="py-1.5 pr-4 text-muted-foreground">{row.findings.join(", ")}</td>
                        <td className="py-1.5 font-semibold text-foreground">{row.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </EntitySection>
          )}

          {has("timeline") && (
            <EntitySection title="Timeline" icon={Clock} meta={`${c.events?.length ?? c.entries.length} entries`}>
            <div className="relative pl-6">
              <div className="absolute left-[7px] top-0 bottom-0 w-[2px] bg-border" />
              {(c.events && c.events.length > 0 ? (
                [...c.events].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime()).map((ev, i, arr) => {
                  const prev = i > 0 ? arr[i - 1] : null;
                  const prevDate = prev ? new Date(prev.ts).toDateString() : null;
                  const currDate = new Date(ev.ts).toDateString();
                  const showDate = currDate !== prevDate;
                  return (
                    <TimelineEntry key={ev.id} showDate={showDate} ts={ev.ts} color={ev.kind.startsWith("ioc") ? "var(--color-destructive)" : ev.importance === "critical" ? "var(--color-destructive)" : "var(--color-primary)"}>
                      <div className="flex items-center gap-2 mb-0.5">
                        <Chip tone="default">{ev.category}</Chip>
                        <span className="font-mono ba-text-2xs text-muted-foreground">{formatDate(ev.ts)}</span>
                      </div>
                      <div className="font-mono ba-text-xs text-foreground"><strong>{ev.title}</strong>{ev.detail ? ` — ${ev.detail}` : ""}</div>
                    </TimelineEntry>
                  );
                })
              ) : c.entries.length > 0 ? (
                [...c.entries].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime()).map((e, i, sorted) => {
                  const prev = i > 0 ? sorted[i - 1] : null;
                  const prevDate = prev ? new Date(prev.ts).toDateString() : null;
                  const currDate = new Date(e.ts).toDateString();
                  const showDate = currDate !== prevDate;
                  return (
                    <TimelineEntry key={e.id} showDate={showDate} ts={e.ts} color={KIND_COLOR[e.kind] ?? "var(--color-muted-foreground)"}>
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="inline-flex items-center rounded border px-1.5 py-px font-mono ba-text-3xs" style={{ color: KIND_COLOR[e.kind] ?? "var(--color-muted-foreground)", borderColor: `${KIND_COLOR[e.kind] ?? "var(--color-muted-foreground)"}40`, background: `${KIND_COLOR[e.kind] ?? "var(--color-muted-foreground)"}15` }}>
                          {e.kind}
                        </span>
                        <span className="font-mono ba-text-2xs text-muted-foreground">{formatDate(e.ts)}</span>
                      </div>
                      <div className="font-mono ba-text-xs text-foreground">{e.body}</div>
                    </TimelineEntry>
                  );
                })
              ) : (
                <div className="py-8 text-center font-mono ba-text-2xs italic text-muted-foreground">No entries recorded.</div>
              ))}
            </div>
          </EntitySection>
          )}

          {has("findings") && allFindings.length > 0 && (
            <EntitySection title="Findings" icon={CheckCircle} meta={`${allFindings.length} items`}>
              <div className="space-y-2">
                {allFindings.map((f, idx) => (
                  <FindingCard key={f.id ?? idx} finding={f} relatedIocs={f.iocs ?? allIocs.filter(ioc => ioc.source === f.source)} />
                ))}
              </div>
            </EntitySection>
          )}

          {has("hypotheses") && (
            <EntitySection title="Analyst Hypotheses" icon={Activity} meta={`${hyps.length} in notebook`}>
              {hyps.length === 0 ? (
                <p className="py-2 text-mono ba-text-xs text-muted-foreground">No hypotheses in the analyst notebook for this case.</p>
              ) : (
                <div className="space-y-2">
                  {hyps.map((h) => (
                    <details key={h.id} className="group rounded border border-subtle bg-background/30 px-3 py-2">
                      <summary className="flex cursor-pointer items-center justify-between gap-2">
                        <span className="min-w-0 flex-1 truncate font-mono ba-text-xs text-foreground">{h.hypothesis}</span>
                        <span className="inline-flex items-center gap-2">
                          <Chip tone={h.status === "supported" ? "success" : h.status === "refuted" ? "destructive" : "warning"}>{h.status}</Chip>
                          <span className="font-mono ba-text-2xs text-muted-foreground">{h.confidence}</span>
                        </span>
                      </summary>
                      <dl className="mt-2 space-y-1.5 border-t border-subtle pt-2 font-mono ba-text-xs">
                        <div className="grid grid-cols-[100px_1fr] gap-2">
                          <dt className="text-muted-foreground">supporting</dt>
                          <dd className="text-foreground">{h.supporting.length ? h.supporting.join(", ") : "—"}</dd>
                        </div>
                        <div className="grid grid-cols-[100px_1fr] gap-2">
                          <dt className="text-muted-foreground">contradicting</dt>
                          <dd className="text-foreground">{h.contradicting.length ? h.contradicting.join(", ") : "—"}</dd>
                        </div>
                        {h.decision && (
                          <div className="grid grid-cols-[100px_1fr] gap-2">
                            <dt className="text-muted-foreground">decision</dt>
                            <dd className="text-foreground">{h.decision}</dd>
                          </div>
                        )}
                        {h.nextStep && (
                          <div className="grid grid-cols-[100px_1fr] gap-2">
                            <dt className="text-muted-foreground">next step</dt>
                            <dd className="text-foreground">{h.nextStep}</dd>
                          </div>
                        )}
                      </dl>
                    </details>
                  ))}
                </div>
              )}
            </EntitySection>
          )}

          {/* Explain everything (Phase 3) — every object answers why / how / source / confidence / relationships */}
          {has("provenance") && (
            <EntitySection title="Provenance recap" icon={Link2} meta={`${recaps.length} objects`}>
            {recaps.length === 0 ? (
              <p className="py-2 text-mono ba-text-sm text-muted-foreground">No findings or observables to recap — analyse an artifact first.</p>
            ) : (
              <div className="space-y-2">
                {recaps.map((ex) => (
                  <details key={ex.kind + ex.id} className="group rounded border border-subtle bg-background/30 px-3 py-2">
                    <summary className="flex cursor-pointer items-center justify-between gap-2">
                      <span className="min-w-0 flex-1 truncate text-mono ba-text-sm text-foreground">
                        <Chip tone={ex.kind === "ioc" ? "warning" : ex.kind === "finding" ? "destructive" : "default"}>{ex.kind}</Chip>{" "}
                        {ex.label}
                      </span>
                      <span className="text-mono ba-text-2xs text-muted-foreground">
                        {ex.confidence != null ? `confidence ${Math.round(ex.confidence * 100)}%` : "no confidence"}
                      </span>
                    </summary>
                    <dl className="mt-2 space-y-1.5 border-t border-subtle pt-2 font-mono ba-text-xs">
                      <div className="grid grid-cols-[90px_1fr] gap-2">
                        <dt className="text-muted-foreground">why</dt>
                        <dd className="text-foreground">{ex.why}</dd>
                      </div>
                      <div className="grid grid-cols-[90px_1fr] gap-2">
                        <dt className="text-muted-foreground">source</dt>
                        <dd className="text-foreground">{ex.source.length ? ex.source.join(", ") : "—"}</dd>
                      </div>
                      <div className="grid grid-cols-[90px_1fr] gap-2">
                        <dt className="text-muted-foreground">how</dt>
                        <dd className="text-foreground">
                          {ex.how.length ? ex.how.join(" · ") : "no provenance edges found"}
                        </dd>
                      </div>
                      <div className="grid grid-cols-[90px_1fr] gap-2">
                        <dt className="text-muted-foreground">relationships</dt>
                        <dd className="text-foreground">
                          {ex.relationships.length
                            ? ex.relationships.map((r) => `${r.relation} ${r.from.kind}→${r.to.kind} (${r.source})`).join(", ")
                            : "—"}
                        </dd>
                      </div>
                    </dl>
                  </details>
                ))}
              </div>
            )}
            </EntitySection>
          )}

          {has("correlation") && (
            <EntitySection title="Correlation Matches" icon={GitCompare} meta={`${corrRows.length} on record for this case`}>
              {corrRows.length === 0 ? (
                <p className="py-2 font-mono ba-text-xs text-muted-foreground">
                  No correlation matches on record for this case.
                </p>
              ) : (
                <ul className="space-y-2">
                  {corrRows.map((r) => (
                    <li key={r.id} className="rounded border border-subtle bg-background/30 px-3 py-2 font-mono ba-text-xs">
                      <div className="flex items-center justify-between gap-2">
                        <span className="min-w-0 flex-1 truncate text-foreground">{r.value}</span>
                        <Chip tone={r.status === "confirmed" ? "success" : r.status === "dismissed" ? "default" : "warning"}>{r.status}</Chip>
                      </div>
                      <div className="mt-1 text-muted-foreground">
                        {CORRELATION_DIMENSION_LABEL[r.dimension] ?? r.dimension} · {r.label} · {Math.round(r.confidence * 100)}% · seen {r.seen}×
                      </div>
                      <div className="mt-0.5 text-muted-foreground/60">sources: {r.sources.join(", ")}</div>
                    </li>
                  ))}
                </ul>
              )}
            </EntitySection>
          )}

          {has("decisions") && (
            <EntitySection title="Analyst Decisions" icon={GitBranch} meta={`${decRows.length} recorded`}>
              {decRows.length === 0 ? (
                <p className="py-2 font-mono ba-text-xs text-muted-foreground">
                  No analyst decisions recorded in this case.
                </p>
              ) : (
                <ul className="space-y-2">
                  {decRows.map((r) => (
                    <li key={r.id} className="rounded border border-subtle bg-background/30 px-3 py-2 font-mono ba-text-xs">
                      <div className="flex items-center justify-between gap-2">
                        <span className="min-w-0 flex-1 truncate text-foreground">{r.verdict}</span>
                        <span className="shrink-0 text-muted-foreground/60">{formatDate(r.ts)}</span>
                      </div>
                      <div className="mt-1 text-muted-foreground">{r.body}</div>
                    </li>
                  ))}
                </ul>
              )}
            </EntitySection>
          )}

          {has("recommendations") && (
            <EntitySection title="Detection Recommendations" icon={ShieldCheck} meta="critical + high findings">
              <ul className="space-y-1.5 font-mono ba-text-xs text-foreground">
                {allFindings.filter((f) => f.severity === "critical" || f.severity === "high").length === 0 && (
                  <li className="py-1 text-muted-foreground">No critical or high findings to route — confirm coverage before closing.</li>
                )}
                {allFindings.filter((f) => f.severity === "critical" || f.severity === "high").map((f) => (
                  <li key={f.id} className="flex gap-2">
                    <span className="text-warning">—</span>
                    <span><Chip tone={f.severity === "critical" ? "destructive" : "warning"}>{f.severity}</Chip> <strong>{f.title}</strong>{f.technique ? ` (${f.technique})` : ""} — investigate against the recorded evidence.</span>
                  </li>
                ))}
                <li className="flex gap-2 text-muted-foreground"><span>—</span><span>Preserve the timeline and evidence before remediation; route MITRE-mapped findings to the detection workspace.</span></li>
              </ul>
            </EntitySection>
          )}

          {has("appendix") && (
            <EntitySection title="Appendix" icon={BookOpen} meta={`${allIocs.length} ioc(s) · ${allFindings.length} finding(s) · ${entries.length} entr${entries.length === 1 ? "y" : "ies"}`}>
              <p className="mb-2 font-mono ba-text-xs text-muted-foreground">Raw case record on file — counts and first-line bodies for verification.</p>
              {entries.length === 0 ? (
                <p className="py-1 font-mono ba-text-xs text-muted-foreground">No case entries recorded.</p>
              ) : (
                <ul className="space-y-1.5 font-mono ba-text-xs">
                  {entries.slice(0, 20).map((e) => (
                    <li key={e.id} className="flex gap-2">
                      <span className="shrink-0 text-muted-foreground/60">{formatDate(e.ts)}</span>
                      <span className="shrink-0 uppercase text-fg-dim" style={{ width: "5rem" }}>{e.kind}</span>
                      <span className="min-w-0 flex-1 truncate text-foreground">{e.body.split("\n")[0]}</span>
                    </li>
                  ))}
                </ul>
              )}
            </EntitySection>
          )}
        </div>
        )}

        <EntitySection title="Report versions" icon={History} meta={`${versions.length} saved`} className="no-print">
          <div className="mb-3 flex items-center gap-2">
            <button
              onClick={saveVersion}
              className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-1 font-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"
            >
              <Save className="h-3 w-3" /> save current version
            </button>
            <button
              onClick={exportBundle}
              title="Zip with case.beyondcase.json + report.md + report.html + raw artifacts + fingerprinted MANIFEST"
              className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 font-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:text-foreground"
            >
              <Download className="h-3 w-3" /> export bundle
            </button>
            {versionFlash === "saved" && <span className="font-mono ba-text-2xs text-success">saved</span>}
          </div>
          {versions.length === 0 ? (
            <p className="py-1 font-mono ba-text-xs text-muted-foreground">
              No versions saved yet — save a snapshot to track what changes between reports.
            </p>
          ) : (
            <div className="space-y-3">
              <div>
                <div className="mb-1.5 font-mono ba-text-2xs text-muted-foreground">
                  What changed since the version saved <span className="text-foreground">{formatDate(latest!.generatedAt)}</span>
                </div>
                {deltas.length === 0 ? (
                  <p className="font-mono ba-text-xs text-muted-foreground">No changes since the last saved version.</p>
                ) : (
                  <ul className="space-y-1 font-mono ba-text-xs">
                    {deltas.map((d, i) => (
                      <li key={i} className="flex gap-2">
                        <Chip tone={d.kind === "finding-new" || d.kind === "finding-severity" ? "destructive" : d.kind === "ioc-new" ? "warning" : "success"}>{d.label}</Chip>
                        <span className="text-foreground">{d.detail}</span>
                      </li>
                    ))}
                  </ul>
                )}
                {versions.length >= 2 && (
                  <DiffSaved versions={versions} />
                )}
              </div>
              <table className="w-full text-left font-mono ba-text-xs">
                <thead>
                  <tr className="border-b border-border ba-text-3xs text-muted-foreground">
                    <th scope="col" className="pb-2 pr-4">Saved</th>
                    <th scope="col" className="pb-2 pr-4">Type</th>
                    <th scope="col" className="pb-2 pr-4">Source</th>
                    <th scope="col" className="pb-2 pr-4">Findings</th>
                    <th scope="col" className="pb-2 pr-4">IOCs</th>
                    <th scope="col" className="pb-2">Events</th>
                  </tr>
                </thead>
                <tbody>
                  {versions.map((v) => (
                    <tr key={v.id} className="border-b border-subtle">
                      <td className="py-1.5 pr-4 text-muted-foreground">{formatDate(v.generatedAt)}</td>
                      <td className="py-1.5 pr-4"><Chip tone="default">{v.reportType}</Chip></td>
                      <td className="py-1.5 pr-4">
                        {v.source === "scheduled" ? (
                          <Chip tone="info">scheduled{v.scheduledFor !== v.generatedAt ? " late" : ""}</Chip>
                        ) : (
                          <Chip tone="default">manual</Chip>
                        )}
                      </td>
                      <td className="py-1.5 pr-4 text-foreground">{v.summary.findings}</td>
                      <td className="py-1.5 pr-4 text-foreground">{v.summary.iocs}</td>
                      <td className="py-1.5 text-foreground">{v.summary.events}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="mt-5 border-t border-subtle pt-4">
            <div className="mb-2 font-mono ba-text-2xs text-muted-foreground">
              Scheduled exports — generate a report version automatically while this workspace is open (missed runs are caught up once on next open, flagged as late)
            </div>
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <select
                value={schedCadence}
                onChange={(e) => setSchedCadence(e.target.value as Cadence)}
                aria-label="Schedule cadence"
                className="rounded border border-border bg-surface-2 px-2 py-1 font-mono ba-text-2xs text-foreground outline-none focus:border-primary/50"
              >
                {CADENCES.map((x) => (
                  <option key={x.id} value={x.id}>{x.label}</option>
                ))}
              </select>
              <select
                value={schedType}
                onChange={(e) => setSchedType(e.target.value as ReportType)}
                aria-label="Schedule report type"
                className="rounded border border-border bg-surface-2 px-2 py-1 font-mono ba-text-2xs text-foreground outline-none focus:border-primary/50"
              >
                {REPORT_TYPES.map((x) => (
                  <option key={x.id} value={x.id}>{x.label}</option>
                ))}
              </select>
              <button
                onClick={createSchedule}
                className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-1 font-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"
              >
                <Clock className="h-3 w-3" /> add schedule
              </button>
            </div>
            {schedules.length === 0 ? (
              <p className="font-mono ba-text-xs text-muted-foreground">No schedules — nothing will be generated automatically.</p>
            ) : (
              <ul className="space-y-2">
                {schedules.map((s) => {
                  const late = s.missedRuns > 0;
                  return (
                    <li key={s.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded border border-subtle bg-background/30 px-3 py-2 font-mono ba-text-xs">
                      <Chip tone={late ? "warning" : "default"}>{CADENCES.find((x) => x.id === s.cadence)?.label}</Chip>
                      <Chip tone="default">{REPORT_TYPES.find((x) => x.id === s.reportType)?.label}</Chip>
                      <span className="text-muted-foreground">
                        next <span className="text-foreground">{formatDate(s.nextRunAt)}</span>
                      </span>
                      <span className="text-muted-foreground">
                        last {s.generatedAt ? <span className="text-foreground">{formatDate(s.generatedAt)}</span> : <span className="text-fg-dim">—</span>}
                      </span>
                      {late && (
                        <Chip tone="warning">{s.missedRuns > 1 ? `${s.missedRuns} missed runs` : "1 missed run"}</Chip>
                      )}
                      <button
                        onClick={() => deleteSchedule(s.id)}
                        aria-label={`Delete ${s.cadence} schedule`}
                        className="ml-auto rounded border border-border px-2 py-0.5 text-muted-foreground transition-colors duration-150 hover:border-destructive/50 hover:text-destructive"
                      >
                        delete
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </EntitySection>

        <div className="no-print">
        <ActionDock
          activeCase={c}
          findingCreated={false}
          iocsAttached={false}
          observableCount={0}
          onCreateFinding={() => {}}
          onAttachIocs={() => {}}
          onAddToLocker={() => {}}
          onExport={() => {}}
        />
        </div>

        <div className="mt-6 border-t border-border pt-4 text-center font-mono ba-text-2xs text-muted-foreground">
          Generated by BeyondLabs Case Report · {new Date().toISOString()}
        </div>

        <div className="no-print">
        <SendToRow targets={[
          { label: "Case", to: "/case", icon: ShieldAlert },
          { label: "Detection", to: "/detection", icon: ShieldAlert },
        ]} />
        </div>
      </PageShell>
    </>
  );
}

function DiffSaved({ versions }: { versions: ReportVersion[] }) {
  const [aId, setAId] = useState<string>(versions[1]?.id ?? "");
  const [bId, setBId] = useState<string>(versions[0]?.id ?? "");
  const a = versions.find((v) => v.id === aId) ?? versions[1];
  const b = versions.find((v) => v.id === bId) ?? versions[0];
  if (!a || !b || a.id === b.id) {
    return (
      <div className="mt-3 border-t border-subtle pt-2">
        <div className="mb-1.5 font-mono ba-text-2xs text-muted-foreground">diff two saved versions</div>
        <p className="font-mono ba-text-xs text-muted-foreground">Pick two different saved versions to diff them.</p>
        <DiffPickers versions={versions} aId={a?.id ?? ""} bId={b?.id ?? ""} setAId={setAId} setBId={setBId} />
      </div>
    );
  }
  const { older, newer, deltas } = diffSavedVersions(a, b);
  return (
    <div className="mt-3 border-t border-subtle pt-2">
      <div className="mb-1.5 font-mono ba-text-2xs text-muted-foreground">
        diff · <span className="text-foreground">{formatDate(older.generatedAt)}</span> → <span className="text-foreground">{formatDate(newer.generatedAt)}</span>
        {sameInputs(older, newer) && <span className="ml-2 text-success">(identical input hash)</span>}
        {!sameInputs(older, newer) && !!older.repro && !!newer.repro && (
          <span className="ml-2" title={`fnv1a-64 of the snapshot inputs — ${older.repro.inputHash} vs ${newer.repro.inputHash}`}>
            inputs differ
          </span>
        )}
      </div>
      <DiffPickers versions={versions} aId={a.id} bId={b.id} setAId={setAId} setBId={setBId} />
      {deltas.length === 0 ? (
        <p className="font-mono ba-text-xs text-muted-foreground">
          No tracked differences between these two versions{!sameInputs(older, newer) && !!older.repro ? " — but their input hashes differ, so the underlying data moved in ways this diff does not track." : "."}
        </p>
      ) : (
        <ul className="space-y-1 font-mono ba-text-xs">
          {deltas.map((d, i) => (
            <li key={i} className="flex gap-2">
              <Chip tone={d.kind === "finding-new" || d.kind === "finding-severity" ? "destructive" : d.kind === "ioc-new" ? "warning" : "success"}>{d.label}</Chip>
              <span className="text-foreground">{d.detail}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function DiffPickers({ versions, aId, bId, setAId, setBId }: { versions: ReportVersion[]; aId: string; bId: string; setAId: (id: string) => void; setBId: (id: string) => void }) {
  const opts = versions.map((v) => (
    <option key={v.id} value={v.id}>{formatDate(v.generatedAt)} · {v.reportType}</option>
  ));
  return (
    <div className="mb-2 flex flex-wrap items-center gap-1.5">
      <select aria-label="diff base version" value={aId} onChange={(e) => setAId(e.target.value)} className="h-6 rounded border border-divider-strong bg-surface-1 px-1.5 font-mono ba-text-2xs text-foreground outline-none focus:border-primary/50">{opts}</select>
      <span className="font-mono ba-text-2xs text-muted-foreground">→</span>
      <select aria-label="diff compare version" value={bId} onChange={(e) => setBId(e.target.value)} className="h-6 rounded border border-divider-strong bg-surface-1 px-1.5 font-mono ba-text-2xs text-foreground outline-none focus:border-primary/50">{opts}</select>
    </div>
  );
}

function TimelineEntry({ showDate, ts, color, children }: { showDate: boolean; ts: string; color: string; children: React.ReactNode }) {
  return (
    <div className="relative pb-1">
      {showDate && (
        <div className="relative z-10 ml-3 mb-1 mt-2 font-mono ba-text-2xs font-semibold text-muted-foreground">
          <span className="bg-background pr-2">{new Date(ts).toLocaleDateString(undefined, { weekday: "short", year: "numeric", month: "short", day: "numeric" })}</span>
        </div>
      )}
      <div className="flex gap-3 py-1">
        <div className="mt-1 h-3 w-3 shrink-0 rounded-full border-2 border-background z-10" style={{ background: color }} />
        <div className="min-w-0 flex-1">{children}</div>
      </div>
    </div>
  );
}

const printCss = `
  @media print {
    @page { margin: 16mm 14mm; size: A4; }
    *, *:before, *:after {
      -webkit-print-color-adjust: exact !important;
      print-color-adjust: exact !important;
    }
    body {
      font-size: 9.5pt !important;
      line-height: 1.45 !important;
      background: #ffffff !important;
      color: #0f172a !important;
    }
    .no-print, nav, aside, [data-sidebar], button, .elevation-raised, [aria-label*="navigation"] {
      display: none !important;
    }
    .print-banner {
      display: block !important;
      border: 2px solid #0284c7 !important;
      border-left: 8px solid #0284c7 !important;
      background: #f0f9ff !important;
      padding: 18px 22px !important;
      margin-bottom: 24px !important;
      border-radius: 4px !important;
      page-break-after: avoid !important;
    }
    .print-banner * {
      color: #0f172a !important;
    }
    section, .group\\/section {
      border: 1px solid #cbd5e1 !important;
      background: #ffffff !important;
      margin-bottom: 16px !important;
      border-radius: 4px !important;
      page-break-inside: avoid !important;
      break-inside: avoid !important;
    }
    header {
      background: #f8fafc !important;
      border-bottom: 1px solid #cbd5e1 !important;
      page-break-after: avoid !important;
    }
    table, tr, td, th {
      page-break-inside: avoid !important;
      break-inside: avoid !important;
      border-color: #cbd5e1 !important;
    }
    th {
      background: #f1f5f9 !important;
      color: #0f172a !important;
      font-weight: 700 !important;
    }
    td {
      color: #334155 !important;
    }
    code, pre {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
      background: #f8fafc !important;
      border: 1px solid #e2e8f0 !important;
      color: #0f172a !important;
    }
    .timeline-marker {
      background: #0284c7 !important;
    }
    .report-table-wrapper {
      overflow: visible !important;
    }
    h1, h2, h3, h4 {
      color: #0f172a !important;
      page-break-after: avoid !important;
    }
  }
`;
