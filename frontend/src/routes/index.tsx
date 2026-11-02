import { createFileRoute, Link } from "@tanstack/react-router";
import { PageShell } from "@/components/PageShell";
import { EntitySection, EntityHeader, headerActionClass } from "@/components/entity";
import { Empty } from "@/components/output";
import { Chip } from "@/components/soc";
import { CaseLoadSection } from "@/components/dashboard/CaseLoadSection";
import { OmniTriageDock } from "@/components/dashboard/OmniTriageDock";
import { ActiveCaseSentinel } from "@/components/dashboard/ActiveCaseSentinel";
import { SecurityChronicle } from "@/components/dashboard/SecurityChronicle";
import { ShiftHandoverModal } from "@/components/dashboard/ShiftHandoverModal";
import { getTimelineEvents } from "@/lib/timeline";
import { useRecentInputs } from "@/lib/use-recent-inputs";
import { listActive, type WorkspaceId } from "@/lib/workspace-state";
import { loadAlertLedger } from "@/lib/alerts/ingest";
import { loadPinnedCaseIds, loadPins } from "@/lib/pins";
import { loadCases, useActiveCase, type Case } from "@/data/case";
import { loadRules, type SavedRule } from "@/data/detection";
import { getEntityById } from "@/data/intel";
import { loadHunts, type SavedHunt } from "@/data/siem";
import { addScratchNote, deleteScratchNote, loadScratchNotes, type ScratchNote } from "@/lib/scratchpad";
import { usePrefs } from "@/lib/prefs";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import {
  evaluateThreatPosture,
  generateShiftHandoverReport,
  exportDeckTelemetryJson,
} from "@/lib/command-deck";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  ArrowRight, Activity, Zap, Mail, Link2, FileWarning, Network, FileText,
  Bell, Pin, PinOff, Terminal, Target, Search, Globe, Clock, Wand2,
  Scan, StickyNote, ShieldCheck, FlaskConical, Crosshair, Database, History,
  Play, Download, Radio, ShieldAlert, FolderPlus, Copy, Check, Share2, Eye,
  type LucideIcon,
} from "lucide-react";
import { useCallback, useMemo, useState } from "react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Incident Command Deck — BeyondLabs" },
      { name: "description", content: "Tier-1 DFIR / SOC analyst workbench and command deck." },
    ],
  }),
  component: Dashboard,
});

type StationLink = { label: string; to: string; icon: LucideIcon; hint: string };

const INTAKE_STATIONS: StationLink[] = [
  { label: "Email / Phishing", to: "/phishing", icon: Mail, hint: "headers · spf/dkim · eml" },
  { label: "URL Reputation", to: "/url", icon: Link2, hint: "vt · urlscan · screenshot" },
  { label: "File & Hash", to: "/file", icon: FileWarning, hint: "pe · entropy · hashes" },
  { label: "PCAP Network", to: "/pcap", icon: Network, hint: "zeek flows · beacons" },
  { label: "Log Forensics", to: "/logs", icon: FileText, hint: "suricata · evtx · syslog" },
  { label: "Universal Intake", to: "/intake", icon: Terminal, hint: "multi-source dropper" },
];

const FORENSIC_STATIONS: StationLink[] = [
  { label: "Smart Parser", to: "/parser", icon: Zap, hint: "universal ioc extraction" },
  { label: "CyberChef Engine", to: "/chef", icon: Wand2, hint: "decode · de-obfuscate" },
  { label: "Regex Lab", to: "/regex-playground", icon: Search, hint: "pattern craft & test" },
  { label: "Diff Workbench", to: "/diff", icon: Scan, hint: "payload version compare" },
  { label: "Chrono-Timeline", to: "/timeline", icon: History, hint: "incident sequence chart" },
];

const DETECTION_STATIONS: StationLink[] = [
  { label: "Rule Editor", to: "/detection", icon: ShieldCheck, hint: "yara · sigma · suricata" },
  { label: "Sigma Sandbox", to: "/sigma-tester", icon: FlaskConical, hint: "live rules testing" },
  { label: "MITRE ATT&CK", to: "/mitre", icon: Crosshair, hint: "tactic & technique matrix" },
  { label: "SIEM Hunter", to: "/siem", icon: Activity, hint: "elastic/splunk query engine" },
  { label: "Threat Intel", to: "/intel", icon: Eye, hint: "apt dossiers & indicators" },
];

const COMMAND_STATIONS: StationLink[] = [
  { label: "Case Notebook", to: "/case", icon: Database, hint: "incident evidence ledger" },
  { label: "Case Desk", to: "/investigation", icon: Share2, hint: "investigation command center" },
  { label: "IOC Locker", to: "/case", icon: ShieldAlert, hint: "active observables vault" },
  { label: "Alert Ingest", to: "/triage", icon: Bell, hint: "enterprise alert queues" },
];

function Dashboard() {
  const { prefs } = usePrefs();
  const ds = prefs.dashboardSections;
  const { activeCase, addEntry } = useActiveCase();

  const [handoverOpen, setHandoverOpen] = useState(false);

  // Load telemetry sources
  const cases = useMemo(() => loadCases(), []);
  const events = useMemo(() => getTimelineEvents(), []);
  const alertsRecord = useMemo(() => loadAlertLedger(), []);
  const alerts = useMemo(
    () =>
      Object.values(alertsRecord).sort((a, b) => b.ingestedAt.localeCompare(a.ingestedAt)),
    [alertsRecord]
  );

  const parserRecents = useRecentInputs("parser");
  const active = useMemo(() => listActive(), []);

  // Compute SOC Threat Posture & Readiness
  const readiness = useMemo(() => evaluateThreatPosture(cases, alerts, events), [cases, alerts, events]);

  const handoverReport = useMemo(
    () => generateShiftHandoverReport(readiness, activeCase, alerts, events),
    [readiness, activeCase, alerts, events]
  );

  const handleExportTelemetry = () => {
    try {
      const jsonStr = exportDeckTelemetryJson(readiness, activeCase, cases, alerts);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      const dateStr = new Date().toISOString().slice(0, 10);
      link.href = url;
      link.download = `beyondlabs-soc-telemetry-${dateStr}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      toast.success("Exported SOC Telemetry Snapshot (JSON)");
    } catch {
      toast.error("Failed to export telemetry JSON");
    }
  };

  // Pinned items
  const pinnedCases = useMemo(() => {
    const ids = loadPinnedCaseIds();
    if (!ids.length) return [];
    const byId = new Map(cases.map((c) => [c.id, c]));
    return ids.map((id) => byId.get(id)).filter((c): c is NonNullable<typeof c> => Boolean(c));
  }, [cases]);

  const pinnedRules = useMemo(() => {
    const ids = loadPins("detection");
    if (!ids.length) return [] as SavedRule[];
    const byId = new Map(loadRules().map((r) => [r.id, r]));
    return ids.map((id) => byId.get(id)).filter((r): r is SavedRule => Boolean(r));
  }, []);

  const pinnedEntities = useMemo(() => {
    const ids = loadPins("entity");
    if (!ids.length) return [];
    return ids.map((id) => getEntityById(id)).filter((e): e is NonNullable<typeof e> => Boolean(e));
  }, []);

  const pinnedHunts = useMemo(() => loadHunts().filter((h) => h.pinned), []);

  const defconTone =
    readiness.defconLevel === 1
      ? "border-destructive/80 bg-destructive/15 text-destructive"
      : readiness.defconLevel === 2
      ? "border-warning/80 bg-warning/15 text-warning"
      : readiness.defconLevel === 3
      ? "border-yellow-500/70 bg-yellow-500/10 text-yellow-400"
      : readiness.defconLevel === 4
      ? "border-blue-500/50 bg-blue-500/10 text-blue-400"
      : "border-success/60 bg-success/10 text-success";

  const defconLabel =
    readiness.defconLevel === 1
      ? "DEFCON 1 · CRITICAL THREAT"
      : readiness.defconLevel === 2
      ? "DEFCON 2 · HIGH THREAT"
      : readiness.defconLevel === 3
      ? "DEFCON 3 · ELEVATED POSTURE"
      : readiness.defconLevel === 4
      ? "DEFCON 4 · GUARDED POSTURE"
      : "DEFCON 5 · NORMAL OPERATIONS";

  return (
    <ErrorBoundary name="Dashboard">
      <PageShell
        eyebrow="// soc · operations"
        title="Incident Command Deck"
        description="Tier-1 DFIR workbench — real-time threat posture, active sentinel, and rapid forensic launchpad."
      >
        {/* Top SOC Readiness & Operational Health Actions */}
        <EntityHeader
          variant="case"
          actions={
            <div className="flex flex-wrap items-center gap-1.5">
              <button
                onClick={() => setHandoverOpen(true)}
                className={cn(headerActionClass, "border-primary/50 bg-primary/10 text-primary hover:bg-primary/20")}
                title="Open Shift Handover Report Generator"
              >
                <FileText className="h-3 w-3" />
                <span>Shift Handover</span>
              </button>
              <button
                onClick={handleExportTelemetry}
                className={headerActionClass}
                title="Export complete telemetry state as JSON"
              >
                <Download className="h-3 w-3" />
                <span className="hidden sm:inline">Export JSON</span>
              </button>
              <Link to="/settings" className={headerActionClass} title="Workbench Preferences">
                <Globe className="h-3 w-3" />
                <span className="hidden sm:inline">Settings</span>
              </Link>
            </div>
          }
        >
          <div className="hidden sm:flex flex-wrap items-center gap-2 font-mono ba-text-3xs text-muted-foreground">
            <span className="inline-flex items-center gap-1 text-primary">
              <ShieldCheck className="h-3 w-3" />
              <span>tier-1 soc console</span>
            </span>
            <span>·</span>
            <span>offline-safe local vault</span>
          </div>
        </EntityHeader>

        {/* Full-width SOC Threat Posture & 5-KPI Ribbon */}
        {ds.commandStrip && (
          <div className="space-y-2">
            {/* DEFCON Threat Bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-subtle bg-surface-1 px-3 py-2">
              <div className="flex items-center gap-2 min-w-0">
                <span className={cn("inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono ba-text-2xs font-bold uppercase shrink-0", defconTone)}>
                  <Radio className="h-3 w-3 animate-pulse" />
                  <span>{defconLabel}</span>
                </span>
                <span className="font-mono ba-text-3xs text-muted-foreground truncate">
                  Score: <strong className="text-foreground">{readiness.threatScore}/100</strong>
                </span>
              </div>

              <div className="flex items-center gap-3 font-mono ba-text-3xs text-muted-foreground">
                <span className="inline-flex items-center gap-1">
                  <ShieldCheck className="h-3.5 w-3.5 text-success" />
                  <span className="text-foreground font-medium">Local-First</span>
                </span>
                <span className="hidden sm:inline text-muted-foreground/60">·</span>
                <span className="hidden sm:inline">
                  Timeline: <strong className="text-foreground">{readiness.timelineEventsCount}</strong> events
                </span>
              </div>
            </div>

            {/* 5-KPI Posture Ribbon */}
            <div className="grid gap-2 grid-cols-2 sm:grid-cols-3 lg:grid-cols-5">
              {[
                {
                  label: "Active Incidents",
                  value: `${readiness.activeCasesCount} active`,
                  sub: `${readiness.totalCasesCount} total`,
                  icon: ShieldAlert,
                  tone: readiness.activeCasesCount > 0 ? "text-warning" : "text-muted-foreground",
                },
                {
                  label: "Critical / High IOCs",
                  value: `${readiness.criticalIocsCount + readiness.highIocsCount} flagged`,
                  sub: `${readiness.totalIocsCount} total`,
                  icon: Target,
                  tone: readiness.criticalIocsCount > 0 ? "text-destructive" : "text-primary",
                },
                {
                  label: "Ingested Alerts",
                  value: `${readiness.unhandledAlertsCount} queued`,
                  sub: "Ledger pipeline",
                  icon: Bell,
                  tone: readiness.unhandledAlertsCount > 0 ? "text-yellow-400" : "text-muted-foreground",
                },
                {
                  label: "MITRE ATT&CK",
                  value: `${readiness.mitreTechniquesCount} techniques`,
                  sub: "Active coverage",
                  icon: Crosshair,
                  tone: "text-primary",
                },
                {
                  label: "Recoverable State",
                  value: `${active.length} workspace${active.length === 1 ? "" : "s"}`,
                  sub: "Persistent cache",
                  icon: Database,
                  tone: "text-emerald-400",
                },
              ].map((s) => (
                <div
                  key={s.label}
                  className="flex flex-col rounded border border-subtle bg-surface-1 px-3 py-2 min-w-0"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono ba-text-3xs text-muted-foreground uppercase">{s.label}</span>
                    <s.icon className={cn("h-3.5 w-3.5 shrink-0", s.tone)} />
                  </div>
                  <div className="mt-1 font-mono ba-text-sm font-semibold text-foreground truncate">
                    {s.value}
                  </div>
                  <div className="font-mono ba-text-3xs text-muted-foreground truncate">{s.sub}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Universal Fast-Triage Dock */}
        <OmniTriageDock />

        {/* Active Incident Command Sentinel */}
        {ds.continueRow && <ActiveCaseSentinel cases={cases} />}

        {/* Forensic Operations Launchpad (Grouped 4-Station Matrix) */}
        {ds.workflowRibbon && (
          <EntitySection title="Forensic Operations Launchpad" icon={Zap} headingLevel="h2">
            <div className="grid gap-3 grid-cols-1 md:grid-cols-2 lg:grid-cols-4">
              {/* Column 1: Intake & Triage */}
              <div className="rounded-md border border-subtle bg-surface-1/60 p-2.5 space-y-1.5">
                <div className="flex items-center gap-1.5 pb-1 border-b border-subtle font-mono ba-text-3xs text-primary uppercase tracking-wider font-semibold">
                  <Zap className="h-3 w-3" />
                  <span>1. Ingestion & Triage</span>
                </div>
                {INTAKE_STATIONS.map((l) => (
                  <StationRow key={l.label} {...l} />
                ))}
              </div>

              {/* Column 2: Deep Forensics */}
              <div className="rounded-md border border-subtle bg-surface-1/60 p-2.5 space-y-1.5">
                <div className="flex items-center gap-1.5 pb-1 border-b border-subtle font-mono ba-text-3xs text-yellow-400 uppercase tracking-wider font-semibold">
                  <Wand2 className="h-3 w-3" />
                  <span>2. Deep Forensics</span>
                </div>
                {FORENSIC_STATIONS.map((l) => (
                  <StationRow key={l.label} {...l} />
                ))}
              </div>

              {/* Column 3: Detection Engineering */}
              <div className="rounded-md border border-subtle bg-surface-1/60 p-2.5 space-y-1.5">
                <div className="flex items-center gap-1.5 pb-1 border-b border-subtle font-mono ba-text-3xs text-purple-400 uppercase tracking-wider font-semibold">
                  <ShieldCheck className="h-3 w-3" />
                  <span>3. Detection & Hunting</span>
                </div>
                {DETECTION_STATIONS.map((l) => (
                  <StationRow key={l.label} {...l} />
                ))}
              </div>

              {/* Column 4: Command & Evidence */}
              <div className="rounded-md border border-subtle bg-surface-1/60 p-2.5 space-y-1.5">
                <div className="flex items-center gap-1.5 pb-1 border-b border-subtle font-mono ba-text-3xs text-emerald-400 uppercase tracking-wider font-semibold">
                  <Database className="h-3 w-3" />
                  <span>4. Command & Evidence</span>
                </div>
                {COMMAND_STATIONS.map((l) => (
                  <StationRow key={l.label} {...l} />
                ))}
              </div>
            </div>
          </EntitySection>
        )}

        {/* Case Load & Threat Posture */}
        {ds.metrics && <CaseLoadSection />}

        {/* Security Chronicle Real-time Event Stream */}
        {ds.tracks && (
          <SecurityChronicle
            timelineEvents={events}
            alerts={alerts}
            cases={cases}
          />
        )}

        {/* Pinned Investigations & Personal Workspace */}
        {ds.pinned && (
          <div className="grid gap-4 grid-cols-1 md:grid-cols-2">
            {/* Left: Pinned Cases */}
            <EntitySection title="Pinned Investigations" icon={Pin} headingLevel="h2">
              {pinnedCases.length > 0 ? (
                <div className="space-y-1.5">
                  {pinnedCases.map((c) => (
                    <Link
                      key={c.id}
                      to="/case"
                      className="flex items-center justify-between gap-2 rounded border border-border/60 bg-surface-0/60 px-2.5 py-1.5 transition-colors duration-150 hover:border-primary/40"
                    >
                      <div className="min-w-0">
                        <div className="truncate font-mono ba-text-sm text-foreground">{c.title}</div>
                        <div className="text-mono ba-text-2xs text-muted-foreground">
                          {c.entries.length} entries · opened {new Date(c.createdAt).toLocaleDateString()}
                        </div>
                      </div>
                      <Chip tone={c.state === "active" ? "warning" : "default"}>{c.state}</Chip>
                    </Link>
                  ))}
                </div>
              ) : (
                <Empty compact icon={Pin} title="No pinned cases" hint="Pin an incident from the case notebook to monitor it here.">
                  <EmptyCta to="/case" label="open case notebook" />
                </Empty>
              )}
            </EntitySection>

            {/* Right: Pinned Detections, Entities & Hunts */}
            <EntitySection title="Pinned Artifacts & Rules" icon={ShieldCheck} headingLevel="h2">
              {pinnedRules.length === 0 && pinnedEntities.length === 0 && pinnedHunts.length === 0 ? (
                <Empty compact icon={Pin} title="Nothing pinned yet" hint="Pin detections, threat actors, or SIEM hunts to keep them here." />
              ) : (
                <div className="space-y-1.5 max-h-60 overflow-y-auto">
                  {pinnedRules.map((r) => (
                    <Link
                      key={r.id}
                      to="/detection"
                      className="flex items-center justify-between gap-2 rounded border border-border/60 bg-surface-0/60 px-2.5 py-1.5 transition-colors hover:border-primary/40"
                    >
                      <div className="min-w-0">
                        <div className="truncate font-mono ba-text-xs text-foreground">{r.name}</div>
                        <div className="font-mono ba-text-3xs text-muted-foreground">Rule · {r.format}</div>
                      </div>
                      <Pin className="h-3 w-3 shrink-0 text-primary/60" />
                    </Link>
                  ))}
                  {pinnedEntities.map((e) => (
                    <Link
                      key={e.id}
                      to="/intel"
                      search={{ q: e.title }}
                      className="flex items-center justify-between gap-2 rounded border border-border/60 bg-surface-0/60 px-2.5 py-1.5 transition-colors hover:border-primary/40"
                    >
                      <div className="min-w-0">
                        <div className="truncate font-mono ba-text-xs text-foreground">{e.title}</div>
                        <div className="font-mono ba-text-3xs text-muted-foreground">{e.type} · Intel</div>
                      </div>
                      <Pin className="h-3 w-3 shrink-0 text-primary/60" />
                    </Link>
                  ))}
                  {pinnedHunts.map((h: SavedHunt) => (
                    <Link
                      key={h.id}
                      to="/siem"
                      className="flex items-center justify-between gap-2 rounded border border-border/60 bg-surface-0/60 px-2.5 py-1.5 transition-colors hover:border-primary/40"
                    >
                      <div className="min-w-0">
                        <div className="truncate font-mono ba-text-xs text-foreground">{h.name}</div>
                        <div className="font-mono ba-text-3xs text-muted-foreground">SIEM Hunt</div>
                      </div>
                      <Pin className="h-3 w-3 shrink-0 fill-current text-primary" />
                    </Link>
                  ))}
                </div>
              )}
            </EntitySection>
          </div>
        )}

        {/* Scratch Notes Panel */}
        {ds.footer && <ScratchNotesPanel />}

        {/* Recent Parser Inputs */}
        {ds.workspaces && (
          <EntitySection title="Recent Parser Inputs" icon={Clock} headingLevel="h2">
            {parserRecents.items.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {parserRecents.items.slice(0, 12).map((item, i) => (
                  <Link
                    key={i}
                    to="/parser"
                    className="max-w-[200px] truncate rounded border border-subtle bg-surface-0 px-2 py-1 font-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-primary"
                    title={item}
                  >
                    {item.length > 35 ? item.slice(0, 35) + "…" : item}
                  </Link>
                ))}
                {parserRecents.items.length > 12 && (
                  <span className="self-center font-mono ba-text-3xs text-muted-foreground">
                    +{parserRecents.items.length - 12} more
                  </span>
                )}
              </div>
            ) : (
              <Empty compact icon={Clock} title="No recent parses" hint="Paste an IOC or log into the parser to begin.">
                <EmptyCta to="/parser" label="open parser" />
              </Empty>
            )}
          </EntitySection>
        )}

        {/* Shift Handover Modal */}
        <ShiftHandoverModal
          open={handoverOpen}
          onClose={() => setHandoverOpen(false)}
          reportMarkdown={handoverReport}
        />
      </PageShell>
    </ErrorBoundary>
  );
}

function EmptyCta({ to, label }: { to: string; label: string }) {
  return (
    <Link
      to={to}
      className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2.5 py-1 font-mono ba-text-3xs text-primary transition-colors duration-150 hover:bg-primary/20"
    >
      {label} <ArrowRight className="h-3 w-3" />
    </Link>
  );
}

function StationRow({ label, to, icon: Icon, hint }: StationLink) {
  return (
    <Link
      to={to}
      className="group flex items-center justify-between gap-2 rounded border border-subtle bg-surface-0 px-2.5 py-1.5 transition-all duration-150 hover:-translate-y-px hover:border-primary/40 hover:shadow-xs"
    >
      <div className="flex items-center gap-2 min-w-0 flex-1">
        <span className="grid h-6 w-6 shrink-0 place-items-center rounded border border-subtle bg-surface-1 transition-colors group-hover:border-primary/40">
          <Icon className="h-3 w-3 text-primary/80" />
        </span>
        <div className="min-w-0 flex-1">
          <span className="block truncate font-mono ba-text-2xs font-medium text-foreground group-hover:text-primary transition-colors">
            {label}
          </span>
          <span className="block truncate font-mono ba-text-3xs text-muted-foreground">
            {hint}
          </span>
        </div>
      </div>
      <ArrowRight className="h-3 w-3 shrink-0 text-muted-foreground opacity-0 transition-all group-hover:translate-x-0.5 group-hover:opacity-100" />
    </Link>
  );
}

function ScratchNotesPanel() {
  const [notes, setNotes] = useState<ScratchNote[]>(() => loadScratchNotes());
  const [draft, setDraft] = useState("");
  const { addEntry, activeCase } = useActiveCase();
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const add = useCallback(() => {
    if (!draft.trim()) return;
    setNotes(addScratchNote(draft));
    setDraft("");
  }, [draft]);

  const handleCopyNote = async (text: string, id: string) => {
    const ok = await copyText(text);
    if (ok) {
      setCopiedId(id);
      toast.success("Copied note to clipboard");
      setTimeout(() => setCopiedId(null), 1500);
    }
  };

  const handlePromoteToCase = (text: string) => {
    if (!activeCase) {
      toast.error("No active investigation selected");
      return;
    }
    addEntry(text, "note", "Analyst Scratchpad");
    toast.success(`Attached note to case: ${activeCase.title}`);
  };

  return (
    <EntitySection title="Analyst Scratchpad" icon={StickyNote} headingLevel="h2">
      <div className="flex items-center gap-1.5">
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") add();
          }}
          placeholder="quick note — hashes, leads, reminders, hypotheses…"
          aria-label="New scratch note"
          className="min-w-0 flex-1 rounded border border-border bg-surface-0 px-3 py-1.5 font-mono ba-text-xs text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/50"
        />
        <button
          onClick={add}
          className="rounded border border-primary/50 bg-primary/10 px-3 py-1.5 font-mono ba-text-2xs font-semibold text-primary transition-colors hover:bg-primary/20"
        >
          save note
        </button>
      </div>

      {notes.length > 0 ? (
        <div className="mt-2.5 max-h-64 space-y-1.5 overflow-y-auto pr-1">
          {notes.map((n) => (
            <div
              key={n.id}
              className="flex items-start justify-between gap-2 rounded border border-border/60 bg-surface-0/60 p-2.5"
            >
              <div className="min-w-0 flex-1">
                <p className="whitespace-pre-wrap break-words font-mono ba-text-xs text-foreground leading-relaxed">
                  {n.text}
                </p>
                <div className="mt-1 flex items-center gap-2 font-mono ba-text-3xs text-muted-foreground">
                  <span>{new Date(n.ts).toLocaleString()}</span>
                  {activeCase && (
                    <button
                      onClick={() => handlePromoteToCase(n.text)}
                      className="inline-flex items-center gap-1 text-primary hover:underline"
                      title="Attach note as entry in current active case"
                    >
                      <FolderPlus className="h-2.5 w-2.5" />
                      <span>attach to case</span>
                    </button>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-1 shrink-0">
                <button
                  onClick={() => handleCopyNote(n.text, n.id)}
                  aria-label="Copy note"
                  title="Copy note"
                  className="rounded border border-subtle p-1 text-muted-foreground hover:bg-surface-2 hover:text-foreground"
                >
                  {copiedId === n.id ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                </button>
                <button
                  onClick={() => setNotes(deleteScratchNote(n.id))}
                  aria-label="Delete note"
                  title="Delete note"
                  className="rounded border border-subtle p-1 text-muted-foreground transition-colors hover:border-destructive/50 hover:text-destructive"
                >
                  <PinOff className="h-3 w-3" />
                </button>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="py-2.5 text-center font-mono ba-text-2xs text-muted-foreground">
          Nothing jotted yet — notes stay local to this machine.
        </div>
      )}
    </EntitySection>
  );
}
