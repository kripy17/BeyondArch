import React, { useState, useMemo } from "react";
import {
  X,
  Copy,
  Download,
  Check,
  Briefcase,
  Clock,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  FileText,
  Activity,
  UserCheck,
  Send,
  Layers,
} from "lucide-react";
import { type Case } from "@/data/case";
import { type TimelineEvent } from "@/lib/timeline";
import {
  type ShiftWindow,
  buildShiftBriefing,
  generateShiftBriefingMarkdown,
  recordShiftHandoverToTimeline,
} from "@/lib/shift-handover";
import { downloadTextFile } from "@/lib/download";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface ShiftHandoverBriefingModalProps {
  open: boolean;
  onClose: () => void;
  cases: Case[];
  timelineEvents?: TimelineEvent[];
}

export function ShiftHandoverBriefingModal({
  open,
  onClose,
  cases,
  timelineEvents = [],
}: ShiftHandoverBriefingModalProps) {
  const [shiftWindow, setShiftWindow] = useState<ShiftWindow>("current_8h");
  const [outgoingLead, setOutgoingLead] = useState("SecOps Watch Lead (Shift A)");
  const [incomingLead, setIncomingLead] = useState("Incoming Watch Officer (Shift B)");
  const [shiftNotes, setShiftNotes] = useState(
    "All active P1/P2 items briefed. Perimeter firewall drop rules active for C2 IP 51.15.0.100. Host WS-SEC-092 remains isolated awaiting forensic memory dump verification."
  );
  const [activeTab, setActiveTab] = useState<"dashboard" | "markdown">("dashboard");
  const [copied, setCopied] = useState(false);
  const [recordedToTimeline, setRecordedToTimeline] = useState(false);

  const briefing = useMemo(() => {
    return buildShiftBriefing({
      cases,
      timelineEvents,
      shiftWindow,
      outgoingLead,
      incomingLead,
      shiftNotes,
    });
  }, [cases, timelineEvents, shiftWindow, outgoingLead, incomingLead, shiftNotes]);

  const markdownContent = useMemo(() => {
    return generateShiftBriefingMarkdown(briefing);
  }, [briefing]);

  if (!open) return null;

  const handleCopyMarkdown = () => {
    navigator.clipboard.writeText(markdownContent);
    setCopied(true);
    toast.success("Shift Handover briefing copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadMarkdown = () => {
    const filename = `soc-shift-handover-${new Date().toISOString().slice(0, 10)}.md`;
    downloadTextFile(filename, markdownContent, "text/markdown");
    toast.success(`Downloaded ${filename}`);
  };

  const handleRecordToTimeline = () => {
    recordShiftHandoverToTimeline(briefing);
    setRecordedToTimeline(true);
    toast.success("Shift Handover officially recorded to Master Attack Timeline");
  };

  const { metrics, p1Blockers, inFlightCases, infrastructure } = briefing;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-3 sm:p-4 backdrop-blur-sm overflow-y-auto"
      id="shift-handover-modal"
    >
      <div className="relative w-full max-w-4xl max-h-[92vh] flex flex-col rounded-2xl border border-border/80 bg-card shadow-2xl overflow-hidden min-w-0">
        {/* Header Strip */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/80 px-6 py-4 bg-muted/20 min-w-0">
          <div className="flex items-center gap-3 min-w-0">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-amber-500/40 bg-amber-500/10 text-amber-400">
              <Briefcase className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-base font-bold tracking-tight text-foreground truncate">
                  SOC Shift Handover & Incident Briefing
                </h2>
                <span
                  className={cn(
                    "text-[10px] font-mono px-2 py-0.5 rounded-full font-bold uppercase tracking-wider border",
                    metrics.defconColor === "destructive"
                      ? "bg-destructive/15 text-destructive border-destructive/40 animate-pulse"
                      : metrics.defconColor === "warning"
                      ? "bg-amber-500/15 text-amber-400 border-amber-500/40"
                      : "bg-emerald-500/15 text-emerald-400 border-emerald-500/40"
                  )}
                >
                  {metrics.defconLevel}
                </span>
              </div>
              <p className="text-xs text-muted-foreground truncate">
                Operational Watch Handover Protocol (SOC-OP-04) · Auto-aggregated metrics & case triage
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {/* Tab switch */}
            <div className="inline-flex rounded-lg border border-border bg-muted/40 p-1 text-xs">
              <button
                type="button"
                onClick={() => setActiveTab("dashboard")}
                className={cn(
                  "px-3 py-1 rounded-md font-medium transition-all",
                  activeTab === "dashboard"
                    ? "bg-card text-foreground shadow-sm border border-border"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                Dashboard
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("markdown")}
                className={cn(
                  "px-3 py-1 rounded-md font-medium transition-all",
                  activeTab === "markdown"
                    ? "bg-card text-foreground shadow-sm border border-border"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                Markdown SITREP
              </button>
            </div>

            <button
              type="button"
              onClick={onClose}
              className="rounded-lg p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
              title="Close modal"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Scrollable Content Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5 min-w-0 max-w-full">
          {/* Shift Configuration Controls */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-3.5 rounded-xl border border-border/70 bg-card/60">
            <div>
              <label className="block text-[11px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                Shift Window
              </label>
              <select
                value={shiftWindow}
                onChange={(e) => setShiftWindow(e.target.value as ShiftWindow)}
                className="w-full rounded-lg border border-border bg-card px-3 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              >
                <option value="current_8h">Current Shift (Last 8h)</option>
                <option value="past_12h">Extended Shift (Last 12h)</option>
                <option value="past_24h">Full Day (Last 24h)</option>
                <option value="all_active">All Active Backlog</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                Outgoing Watch Lead
              </label>
              <input
                type="text"
                value={outgoingLead}
                onChange={(e) => setOutgoingLead(e.target.value)}
                className="w-full rounded-lg border border-border bg-card px-3 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                Incoming Watch Officer
              </label>
              <input
                type="text"
                value={incomingLead}
                onChange={(e) => setIncomingLead(e.target.value)}
                className="w-full rounded-lg border border-border bg-card px-3 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
          </div>

          {activeTab === "dashboard" ? (
            <>
              {/* 4 Core SOC KPI Metric Cards */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <div className="rounded-xl border border-border/80 bg-card p-3.5 space-y-1">
                  <div className="flex items-center justify-between text-muted-foreground">
                    <span className="text-[11px] font-semibold uppercase tracking-wider">MTTA (Ack)</span>
                    <Clock className="h-4 w-4 text-primary" />
                  </div>
                  <div className="text-2xl font-bold tracking-tight text-foreground font-mono">
                    {metrics.mttaFormatted}
                  </div>
                  <div className="text-[10px] text-muted-foreground flex items-center gap-1">
                    <span className="text-emerald-400 font-semibold">SLA &lt;10m</span> · Mean Ack Time
                  </div>
                </div>

                <div className="rounded-xl border border-border/80 bg-card p-3.5 space-y-1">
                  <div className="flex items-center justify-between text-muted-foreground">
                    <span className="text-[11px] font-semibold uppercase tracking-wider">MTTD (Dwell)</span>
                    <Flame className="h-4 w-4 text-amber-400" />
                  </div>
                  <div className="text-2xl font-bold tracking-tight text-amber-400 font-mono">
                    {metrics.mttdFormatted}
                  </div>
                  <div className="text-[10px] text-muted-foreground flex items-center gap-1">
                    <span className="text-amber-400 font-semibold">SLA &lt;30m</span> · Intrusion Detection
                  </div>
                </div>

                <div className="rounded-xl border border-border/80 bg-card p-3.5 space-y-1">
                  <div className="flex items-center justify-between text-muted-foreground">
                    <span className="text-[11px] font-semibold uppercase tracking-wider">MTTR (Contain)</span>
                    <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  </div>
                  <div className="text-2xl font-bold tracking-tight text-foreground font-mono">
                    {metrics.mttrFormatted}
                  </div>
                  <div className="text-[10px] text-muted-foreground flex items-center gap-1">
                    <span className="text-emerald-400 font-semibold">SLA &lt;60m</span> · Response Velocity
                  </div>
                </div>

                <div className="rounded-xl border border-border/80 bg-card p-3.5 space-y-1">
                  <div className="flex items-center justify-between text-muted-foreground">
                    <span className="text-[11px] font-semibold uppercase tracking-wider">Shift Incidents</span>
                    <Layers className="h-4 w-4 text-primary" />
                  </div>
                  <div className="text-2xl font-bold tracking-tight text-foreground font-mono">
                    {metrics.activeIncidents}
                    <span className="text-xs font-normal text-muted-foreground ml-1">
                      active / {metrics.totalIncidents}
                    </span>
                  </div>
                  <div className="text-[10px] text-muted-foreground">
                    {metrics.criticalIncidents} Critical · {metrics.isolatedEndpointsCount} Contained
                  </div>
                </div>
              </div>

              {/* Shift Notes & Handover Mandate */}
              <div className="space-y-1.5">
                <label className="block text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">
                  Operational Watch Notes & Priority Handover Instructions
                </label>
                <textarea
                  rows={2}
                  value={shiftNotes}
                  onChange={(e) => setShiftNotes(e.target.value)}
                  placeholder="Enter specific watch turnover notes, pending containment verifications, or leadership directives..."
                  className="w-full rounded-xl border border-border bg-card p-3 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono resize-y"
                />
              </div>

              {/* Critical P1/P2 Case Handover Matrix */}
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-destructive" />
                    <span className="text-xs font-bold uppercase tracking-wider text-foreground">
                      Critical Incident Handover Matrix ({p1Blockers.length})
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-destructive/15 text-destructive border border-destructive/30 font-semibold">
                      WATCH CONTINUITY
                    </span>
                  </div>
                  <span className="text-[11px] text-muted-foreground">
                    Mandatory review for incoming shift
                  </span>
                </div>

                {p1Blockers.length === 0 ? (
                  <div className="p-4 rounded-xl border border-border/70 bg-card text-center text-xs text-muted-foreground">
                    No active Critical or High severity incidents in queue for this shift.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {p1Blockers.map((c) => (
                      <div
                        key={c.id}
                        className="p-3.5 rounded-xl border border-destructive/30 bg-destructive/[0.04] space-y-2 transition-colors hover:border-destructive/50"
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap min-w-0">
                            <span className="text-xs font-mono font-bold text-foreground">{c.id}</span>
                            <span className="text-xs font-semibold text-foreground truncate max-w-xs sm:max-w-md">
                              {c.title}
                            </span>
                            <span className="text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-destructive/20 text-destructive border border-destructive/40">
                              {c.severity}
                            </span>
                            <span
                              className={cn(
                                "text-[10px] font-mono px-2 py-0.5 rounded border",
                                c.isContained
                                  ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                                  : "bg-destructive/20 text-destructive border-destructive/40 animate-pulse"
                              )}
                            >
                              {c.isContained ? "CONTAINED" : "UNCONTAINED"}
                            </span>
                          </div>
                          <span className="text-[11px] font-mono text-muted-foreground shrink-0">
                            Duration: {c.durationFormatted}
                          </span>
                        </div>

                        <div className="text-xs text-muted-foreground bg-card/60 p-2.5 rounded-lg border border-border/50">
                          <span className="font-semibold text-foreground">Key Finding: </span>
                          {c.keyFinding}
                        </div>

                        <div className="text-xs text-amber-400 bg-amber-500/10 p-2.5 rounded-lg border border-amber-500/30">
                          <span className="font-bold uppercase tracking-wider text-amber-300">
                            Incoming Shift Mandate:{" "}
                          </span>
                          {c.nextSteps}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Hostile Infrastructure Watchlist */}
              {infrastructure.length > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold uppercase tracking-wider text-foreground flex items-center gap-2">
                      <Activity className="h-4 w-4 text-primary" />
                      Hostile Threat Infrastructure &amp; C2 Watchlist ({infrastructure.length})
                    </span>
                    <span className="text-[11px] text-muted-foreground">
                      Synchronized across cases
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {infrastructure.map((inf) => (
                      <div
                        key={`${inf.type}-${inf.value}`}
                        className="p-2.5 rounded-lg border border-border/60 bg-card flex flex-col justify-between"
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 rounded bg-muted text-muted-foreground">
                            {inf.type}
                          </span>
                          <span className="text-[10px] font-mono text-muted-foreground">
                            Case {inf.caseId}
                          </span>
                        </div>
                        <div className="font-mono text-xs font-semibold text-foreground truncate select-all">
                          {inf.value}
                        </div>
                        <div className="text-[10px] text-muted-foreground truncate mt-1">
                          {inf.context}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            /* Markdown SITREP Raw View */
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>Standard DFIR / SOC-OP-04 Formatted Output</span>
                <span>{markdownContent.split("\n").length} lines · {markdownContent.length} characters</span>
              </div>
              <pre className="p-4 rounded-xl border border-border/80 bg-surface-0 font-mono text-xs text-foreground/90 overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-[500px]">
                {markdownContent}
              </pre>
            </div>
          )}
        </div>

        {/* Action Footer */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-t border-border/80 px-6 py-4 bg-muted/20 min-w-0">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <UserCheck className="h-4 w-4 text-emerald-400 shrink-0" />
            <span className="truncate">
              Digital Sign-off: {outgoingLead} $\rightarrow$ {incomingLead}
            </span>
          </div>

          <div className="flex items-center gap-2 flex-wrap shrink-0">
            <button
              type="button"
              onClick={handleCopyMarkdown}
              id="btn-copy-shift-briefing"
              className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-card px-3 py-2 text-xs font-medium text-foreground hover:bg-muted transition-colors"
              title="Copy markdown to clipboard"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5 text-muted-foreground" />}
              <span>{copied ? "Copied" : "Copy SITREP"}</span>
            </button>

            <button
              type="button"
              onClick={handleDownloadMarkdown}
              id="btn-download-shift-briefing"
              className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-card px-3 py-2 text-xs font-medium text-foreground hover:bg-muted transition-colors"
              title="Download markdown briefing file"
            >
              <Download className="h-3.5 w-3.5 text-muted-foreground" />
              <span>Download .md</span>
            </button>

            <button
              type="button"
              onClick={handleRecordToTimeline}
              disabled={recordedToTimeline}
              id="btn-record-shift-timeline"
              className={cn(
                "inline-flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-xs font-semibold shadow-sm transition-colors",
                recordedToTimeline
                  ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 cursor-default"
                  : "bg-primary text-primary-foreground hover:bg-primary/90"
              )}
              title="Push official handover milestone to Master Attack Timeline"
            >
              {recordedToTimeline ? (
                <>
                  <Check className="h-3.5 w-3.5" />
                  <span>Logged in Timeline</span>
                </>
              ) : (
                <>
                  <Send className="h-3.5 w-3.5" />
                  <span>Audit to Timeline</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
