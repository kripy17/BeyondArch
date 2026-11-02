import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { analyzeSiemText } from "@/api/backend";
import { PageShell } from "@/components/PageShell";
import { IntakeCard, SectionBar, SendToRow, Chip, IocInventory } from "@/components/soc";
import { EntityHeader, EntitySection, HeaderAction } from "@/components/entity";
import { StatusBar, ResultBanner, Empty, EvidenceCard, DataTable } from "@/components/output";
import { useOutputFilter, OutputFilterBar, OutputFilter } from "@/components/soc/OutputFilter";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from "@/components/ui/resizable";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts";
import {
  Database, ArrowRight, Zap, ShieldAlert, Activity,
  Download, Clock, X, ListFilter, FileText, Crosshair, Bug, Loader2,
  Hash, ChevronDown, ChevronRight, Search, Pin, Save, Trash2, Target, Star,
  Upload, BarChart3, Terminal, Copy, Check, Lock, Server,
  BookMarked, Sparkles,
} from "lucide-react";
import { sendToCase } from "@/lib/handoff";
import { useLocker } from "@/lib/locker";
import { notify } from "@/lib/notify";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { copyText } from "@/lib/copy";
import { getSearchLog } from "@/lib/search-engine";
import { loadRules, ruleTechniques } from "@/data/detection";
import { loadCases } from "@/data/case";
import { loadAlertLedger } from "@/lib/alerts/ingest";
import {
  type SiemEvent, type Range, type FilterChip,
  SEV_TONE, SAMPLE_TEXTS, backendToEvent, RANGE_MIN,
  LOCALSTORE_CHIPS, LOCALSTORE_KEYWORD, LOCALSTORE_RANGE,
  loadPersist, savePersist, readInitialPrefill, parsePastedEvents,
  FIELDS, toCsv, download, genMarkdownReport, TACTIC_MAP,
  HUNT_PRESETS, loadSiemFavorites, toggleSiemFavorite,
  detectionsToFindings, buildMetricsNarrative, sendArtifactClick,
  loadHunts, saveHunts, huntAgeLabel, huntIsStale, type SavedHunt,
  exportHuntsBundle, importHuntsBundle,
} from "@/data/siem";
import { SplunkSearchBar } from "@/components/siem/SplunkSearchBar";
import { FieldFacetSidebar } from "@/components/siem/FieldFacetSidebar";
import { KillChainTimeline } from "@/components/siem/KillChainTimeline";
import { FieldStatsModal } from "@/components/siem/FieldStatsModal";
import { DecodedPayloadPopover } from "@/components/siem/DecodedPayloadPopover";
import { HuntingPlaybookArsenalModal } from "@/components/siem/HuntingPlaybookArsenalModal";
import { computeBeaconJitter } from "@/lib/siem/beacon-jitter";
import { computeFieldFacets } from "@/lib/siem/field-facets";
import { reconstructKillChain, classifyEventPhase, type KillChainPhaseId } from "@/lib/siem/killchain-reconstruction";
import { parseQuery } from "@/lib/siem/query-translator";


export const Route = createFileRoute("/siem")({ component: SiemPage });

const RX_HASH = /\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b/i;
const RX_IPV4 = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/;
const RX_DOMAIN = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/i;

/** SIEM 2.0 IOC highlighting via terminal ANSI palette — IP red | Hash magenta | Domain blue. */
function iocColorClass(value: string): string | undefined {
  const v = (value || "").trim();
  if (!v) return undefined;
  if (RX_IPV4.test(v) || /\b(?:(?:[0-9a-f]{1,4}):){2,}[0-9a-f]{1,4}\b/i.test(v)) return "text-[var(--ansi-red)]";
  if (RX_HASH.test(v)) return "text-[var(--ansi-magenta)]";
  if (RX_DOMAIN.test(v)) return "text-[var(--ansi-blue)]";
  return undefined;
}

function SiemPage() {
  const navigate = useNavigate();
  const [drilldownTechnique, setDrilldownTechnique] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [recentQueries, setRecentQueries] = useState<{ q: string; ts: number }[]>([]);
  const [favoriteQueries, setFavoriteQueries] = useState<string[]>(() => loadSiemFavorites());
  const [pasted, setPasted] = useState(() => readInitialPrefill() || SAMPLE_TEXTS.beacon);
  const [range, setRange] = useState<Range>(() => loadPersist<Range>(LOCALSTORE_RANGE, "all"));
  const [chips, setChips] = useState<FilterChip[]>(() => loadPersist<FilterChip[]>(LOCALSTORE_CHIPS, []));
  const [apiEvents, setApiEvents] = useState<SiemEvent[]>([]);
  const [apiDetections, setApiDetections] = useState<any[]>([]);
  const [apiMetrics, setApiMetrics] = useState<Record<string, unknown> | null>(null);
  const [apiIocs, setApiIocs] = useState<{ ips?: string[]; urls?: string[]; emails?: string[]; domains?: string[] } | null>(null);
  const { filterText, setFilterText, showFilter, setShowFilter } = useOutputFilter();
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState("");
  const [siemError, setSiemError] = useState<string | null>(null);
  const [modal, setModal] = useState<{ title: string; subtitle?: string; data: unknown } | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [hunts, setHunts] = useState<SavedHunt[]>(() => loadHunts());
  const [savingHunt, setSavingHunt] = useState(false);
  const [huntName, setHuntName] = useState("");
  const [showNarrative, setShowNarrative] = useState(false);
  const [huntsOpen, setHuntsOpen] = useState(false);
  const [huntingArsenalOpen, setHuntingArsenalOpen] = useState(false);
  const [timelineTab, setTimelineTab] = useState<"incident" | "event">("incident");
  const [selectedPhase, setSelectedPhase] = useState<KillChainPhaseId | null>(null);
  const [statsField, setStatsField] = useState<string | null>(null);
  const [timeSliceFilter, setTimeSliceFilter] = useState<number | null>(null);
  const locker = useLocker();
  const noticeTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const queryRef = useRef<HTMLInputElement>(null);

  const flash = (msg: string) => {
    setNotice(msg);
    clearTimeout(noticeTimer.current);
    noticeTimer.current = setTimeout(() => setNotice(""), 4000);
  };

  const ingest = useCallback(async (text: string) => {
    if (!text.trim()) return;
    setSiemError(null);
    setLoading(true);
    try {
      const result: any = await analyzeSiemText(text);
      const events = (result.events || []).map(backendToEvent);
      setApiEvents(events);
      setApiDetections(result.detections || []);
      setApiMetrics(result.metrics || null);
      setApiIocs(result.extracted_iocs || null);
      flash(`Ingested ${events.length} events, ${(result.detections || []).length} detections`);
    } catch {
      setSiemError("Backend unavailable — parsed locally");
      setApiEvents(parsePastedEvents(text, 0));
      setApiDetections([]);
      setApiMetrics(null);
      setApiIocs(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (pasted) { flash("Loaded pending artifact from handoff — auto-ingesting"); ingest(pasted); }
  }, [pasted, ingest]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") { setExpanded(null); } };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);

  useEffect(() => { savePersist(LOCALSTORE_RANGE, range); }, [range]);
  useEffect(() => { savePersist(LOCALSTORE_CHIPS, chips); }, [chips]);
  useEffect(() => { savePersist(LOCALSTORE_KEYWORD, q); }, [q]);

  useEffect(() => { setRecentQueries(getSearchLog().slice(-5).reverse()); }, []);

  const toggleFavorite = useCallback((q: string) => {
    toggleSiemFavorite(q);
    setFavoriteQueries(loadSiemFavorites());
  }, []);

  useEffect(() => { saveHunts(hunts); }, [hunts]);

  const commitHunt = (name: string) => {
    const trimmed = name.trim();
    if (!trimmed || !pasted.trim()) return;
    const hunt: SavedHunt = {
      id: `hunt-${Date.now().toString(36)}`,
      name: trimmed.slice(0, 60),
      text: pasted,
      q,
      chips,
      range,
      pinned: false,
      updatedAt: Date.now(),
    };
    setHunts((prev) => [hunt, ...prev]);
    setSavingHunt(false);
    setHuntName("");
    flash(`Saved hunt "${trimmed}"`);
  };

  const applyHunt = (h: SavedHunt) => {
    setPasted(h.text);
    setQ(h.q);
    setChips(h.chips);
    setRange(h.range);
    ingest(h.text);
    if (h.id.startsWith("hunt-")) {
      setHunts((prev) => prev.map((x) => (x.id === h.id ? { ...x, lastRunAt: Date.now() } : x)));
    }
    flash(`Loaded hunt "${h.name}"`);
  };

  const togglePinHunt = (id: string) => {
    setHunts((prev) => prev.map((h) => (h.id === id ? { ...h, pinned: !h.pinned, updatedAt: Date.now() } : h)));
  };

  const deleteHunt = (id: string) => {
    setHunts((prev) => prev.filter((h) => h.id !== id));
  };

  const activeEvents = apiEvents;

  const maxMin = useMemo(() => activeEvents.reduce((m, e) => Math.max(m, e.min), 0), [activeEvents]);

  const filtered = useMemo(() => {
    const rangeMin = RANGE_MIN[range];
    const { terms, fieldFilters } = parseQuery(q);

    return activeEvents.filter((e) => {
      if (Number.isFinite(rangeMin) && maxMin - e.min > rangeMin) return false;
      if (timeSliceFilter !== null && e.min !== timeSliceFilter) return false;
      for (const c of chips) {
        const eventVal = String(e[c.field as keyof SiemEvent] ?? "").toLowerCase();
        const chipVal = c.value.toLowerCase();
        if (c.field === "sig") {
          if (!eventVal.includes(chipVal)) return false;
        } else {
          if (eventVal !== chipVal) return false;
        }
      }
      if (selectedPhase && classifyEventPhase(e) !== selectedPhase) {
        return false;
      }
      for (const ff of fieldFilters) {
        const val = String(e[ff.field as keyof SiemEvent] ?? "").toLowerCase();
        if (!val.includes(ff.value.toLowerCase())) return false;
      }
      if (terms.length > 0) {
        const haystack = Object.values(e).join(" ").toLowerCase();
        const orSegments = terms.join(" ").split("|").map((s) => s.trim().toLowerCase()).filter(Boolean);
        if (orSegments.length > 1) {
          if (!orSegments.some((term) => haystack.includes(term))) return false;
        } else {
          const matchAll = terms.every((term) => haystack.includes(term.toLowerCase()));
          if (!matchAll) return false;
        }
      }
      return true;
    });
  }, [activeEvents, q, chips, range, maxMin, selectedPhase, timeSliceFilter]);

  const fieldFacets = useMemo(() => computeFieldFacets(filtered), [filtered]);
  const killChain = useMemo(() => reconstructKillChain(filtered), [filtered]);
  const beaconJitterAnalysis = useMemo(() => computeBeaconJitter(activeEvents), [activeEvents]);
  const activeBeacons = useMemo(() => Object.values(beaconJitterAnalysis).filter((b) => b.isBeacon), [beaconJitterAnalysis]);

  const has = filtered.length > 0;


  const findings = useMemo(() => detectionsToFindings(apiDetections), [apiDetections]);

  const mitre = useMemo(() => {
    const set = new Set<string>();
    for (const d of apiDetections) {
      for (const m of d.mitre_candidates || []) set.add(m);
    }
    return Array.from(set);
  }, [apiDetections]);

  const tacticCoverage = useMemo(() => {
    const map = new Map<string, { techniques: Set<string>; count: number }>();
    for (const m of mitre) {
      const [id] = m.split(" ");
      const tactic = TACTIC_MAP[id] ?? "Other";
      if (!map.has(tactic)) map.set(tactic, { techniques: new Set(), count: 0 });
      const entry = map.get(tactic)!;
      entry.techniques.add(id);
      entry.count++;
    }
    return Array.from(map.entries())
      .map(([tactic, data]) => ({ tactic, techniques: Array.from(data.techniques), count: data.count }))
      .sort((a, b) => b.count - a.count);
  }, [mitre]);

  /** SIEM 2.0 MITRE drill-down: technique → detection rules / previous cases / related alerts. */
  const mitreDrilldown = useMemo(() => {
    const rules = loadRules();
    const cases = loadCases();
    const ledger = Object.values(loadAlertLedger());
    const byTechnique = new Map<string, { rules: string[]; cases: string[]; alerts: string[] }>();
    for (const r of rules) {
      for (const tid of ruleTechniques(r)) {
        if (!byTechnique.has(tid)) byTechnique.set(tid, { rules: [], cases: [], alerts: [] });
        byTechnique.get(tid)!.rules.push(r.ruleKey);
      }
    }
    for (const c of cases) {
      for (const f of c.findings ?? []) {
        if (f.technique) {
          if (!byTechnique.has(f.technique)) byTechnique.set(f.technique, { rules: [], cases: [], alerts: [] });
          byTechnique.get(f.technique)!.cases.push(c.title);
        }
      }
    }
    const ruleKeyBySlug = new Map(rules.map((r) => [r.ruleKey, r]));
    for (const a of ledger) {
      if (!a.ruleKey) continue;
      const rule = ruleKeyBySlug.get(a.ruleKey);
      if (!rule) continue;
      for (const tid of ruleTechniques(rule)) {
        if (!byTechnique.has(tid)) byTechnique.set(tid, { rules: [], cases: [], alerts: [] });
        byTechnique.get(tid)!.alerts.push(a.title);
      }
    }
    return byTechnique;
  }, []);

  const iocs = useMemo(() => {
    const groups: { kind: string; items: string[]; tone?: "warning" | "destructive" | "info" | "primary" }[] = [];
    if (apiIocs?.ips?.length) groups.push({ kind: "IPs", items: apiIocs.ips, tone: "warning" });
    if (apiIocs?.urls?.length) groups.push({ kind: "URLs", items: apiIocs.urls, tone: "warning" });
    if (apiIocs?.emails?.length) groups.push({ kind: "Emails", items: apiIocs.emails, tone: "info" });
    if (apiIocs?.domains?.length) groups.push({ kind: "Domains", items: apiIocs.domains, tone: "info" });
    if (!groups.length) {
      const allIps = new Set<string>(), allUsers = new Set<string>(), allSigs = new Set<string>();
      for (const e of filtered) {
        if (e.src && e.src !== "\u2014") allIps.add(e.src);
        if (e.dst && e.dst !== "\u2014") allIps.add(e.dst);
        if (e.user && e.user !== "-") allUsers.add(e.user);
        if (e.sig && e.sig !== "\u2014") allSigs.add(e.sig);
      }
      if (allIps.size) groups.push({ kind: "IPs", items: Array.from(allIps), tone: "warning" });
      if (allUsers.size) groups.push({ kind: "Users", items: Array.from(allUsers), tone: "info" });
      if (allSigs.size) groups.push({ kind: "Signatures", items: Array.from(allSigs) });
    }
    return groups;
  }, [apiIocs, filtered]);

  const histo = useMemo(() => {
    const bins = new Map<number, { min: number; high: number; medium: number; low: number }>();
    const sevKey = (s: string): "high" | "medium" | "low" => s === "critical" ? "high" : s === "high" ? "high" : s === "medium" ? "medium" : "low";
    filtered.forEach((e) => {
      const b = bins.get(e.min) ?? { min: e.min, high: 0, medium: 0, low: 0 };
      b[sevKey(e.sev)]++;
      bins.set(e.min, b);
    });
    return Array.from(bins.values()).sort((a, b) => a.min - b.min);
  }, [filtered]);
  const chartConfig = {
    high: { label: "High", color: "hsl(var(--destructive))" },
    medium: { label: "Medium", color: "hsl(var(--warning))" },
    low: { label: "Low", color: "hsl(var(--success))" },
  } satisfies ChartConfig;

  const chartData = histo.map((b) => ({
    time: `t+${b.min}m`,
    min: b.min,
    high: b.high,
    medium: b.medium,
    low: b.low,
  }));

  /** SIEM 2.0 incident timeline: chronological `HH:MM label` strip. */
  const incidentTimeline = useMemo(() => {
    const tsToClock = (ts: string): string => {
      const m = ts.match(/(\d{1,2}):(\d{2})(?::\d{2})?/);
      return m ? `${m[1].padStart(2, "0")}:${m[2]}` : "";
    };
    const labelFor = (e: SiemEvent): string => {
      const s = e.sig;
      if (/(failed password|login)/i.test(s)) return "Login";
      if (/powershell|encodedcommand/i.test(s)) return "PowerShell";
      if (/service|created|installed/i.test(s)) return "Service created";
      if (/beacon|curl.*outbound|https outbound/i.test(s)) return "Beacon";
      if (/c2|command and control|exfil/i.test(s)) return "C2";
      if (/rdp|net use|psexec|smb/i.test(s)) return "Lateral movement";
      if (/dns/i.test(s)) return "DNS";
      return s.split(" ").slice(0, 3).join(" ") || s;
    };
    return [...filtered]
      .sort((a, b) => a.min - b.min || a.ts.localeCompare(b.ts))
      .slice(0, 12)
      .map((e) => ({
        time: tsToClock(e.ts) || `t+${e.min}m`,
        min: e.min,
        label: labelFor(e),
        sev: e.sev,
      }));
  }, [filtered]);


  const fieldSummary = useMemo(() => {
    return FIELDS.map((f) => {
      const counts = new Map<string, number>();
      filtered.forEach((e) => { const v = String(e[f]); counts.set(v, (counts.get(v) ?? 0) + 1); });
      const top = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5);
      return { field: f, unique: counts.size, top };
    });
  }, [filtered]);

  const addChip = (field: string, value: string) => {
    setChips((prev) => (prev.some((c) => c.field === field && c.value === value) ? prev : [...prev, { field, value }]));
  };
  const removeChip = (i: number) => setChips((prev) => prev.filter((_, j) => j !== i));
  const exportCsv = () => download(`siem-events-${Date.now()}.csv`, toCsv(filtered));
  const exportReport = () => {
    const md = genMarkdownReport(filtered, findings, mitre);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `siem-report-${Date.now()}.md`;
    a.click(); URL.revokeObjectURL(url);
  };

  const highCount = filtered.filter((e) => e.sev === "high").length;
  const fieldTopSrc = fieldSummary.find((f) => f.field === "src")?.top[0]?.[0] ?? "—";

  const logClassify = useMemo(() => {
    const txt = pasted || "";
    const fmt = /sshd/i.test(txt) ? "SSH Auth" : /event_type/.test(txt) ? "Suricata/JSON" : /Event ID: 4688/.test(txt) ? "Windows Security" : /Event ID: [13]/.test(txt) ? "Sysmon" : /DROP|ALLOW/.test(txt) ? "Firewall" : /GET |POST /.test(txt) ? "HTTP/Apache" : /EncodedCommand/.test(txt) ? "PowerShell" : /IOC/i.test(txt) ? "IOC List" : "Generic";
    const ips = [...new Set(txt.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [])];
    const users = [...new Set(txt.match(/(?:user|account|Account Name:)\s*(\S+)/ig) ?? [])];
    const procs = [...new Set(txt.match(/\b(powershell|cmd|sshd|bash|wmic|rundll32|mshta|curl|wget|chrome|update)(?:\.exe)?\b/gi) ?? [])];
    const hashes = [...new Set(txt.match(/\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b/g) ?? [])];
    return { fmt, ips, users, procs, hashes } as const;
  }, [pasted]);
  const { fmt: logFmt, ips: classifyIps, users: classifyUsers, procs: classifyProcs, hashes: classifyHashes } = logClassify;

  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [containmentTab, setContainmentTab] = useState<"firewall" | "identity" | "edr" | "ticket">("firewall");

  const handleCopyScript = (code: string, key: string, label: string) => {
    copyText(code).then(() => {
      setCopiedKey(key);
      flash(`${label} copied to clipboard`);
      setTimeout(() => setCopiedKey(null), 2500);
    }).catch(() => {});
  };

  const containmentData = useMemo(() => {
    const hostileIps = Array.from(new Set([
      ...classifyIps,
      ...(apiIocs?.ips || []),
      ...activeBeacons.map((b) => b.destination),
    ])).filter((ip) => ip && ip !== "—" && !ip.startsWith("127.") && !ip.startsWith("0.0.0.0"));

    const targetedUsers = Array.from(new Set([
      ...classifyUsers,
      ...(apiIocs?.emails || []),
    ])).filter((u) => u && u !== "-");

    const activeTechniques = mitre;

    // 1. Network Perimeter Scripts
    const iptablesCmd = hostileIps.length > 0
      ? `# Linux iptables Emergency Inbound Drop\n` + hostileIps.map((ip) => `iptables -I INPUT -s ${ip} -j DROP\niptables -I FORWARD -s ${ip} -j DROP`).join("\n")
      : "# No external hostile IPs identified in current scope";

    const paloAltoCmd = hostileIps.length > 0
      ? `# Palo Alto PAN-OS Security Rule\n` +
        `set address-group "SIEM_HOSTILE_IOCS" static [ ${hostileIps.map((ip) => `"${ip}"`).join(" ")} ]\n` +
        `set rulebase security rules "AUTO_SOC_DROP_SIEM" to any from any source "SIEM_HOSTILE_IOCS" destination any application any action drop`
      : "# No external hostile IPs identified";

    // 2. Identity Containment
    const identityCmd = targetedUsers.length > 0
      ? `# Microsoft Graph & Active Directory Emergency Session Kill\n` +
        targetedUsers.map((u) => (
          `# Revoke all refresh tokens & active sessions for ${u}\n` +
          `Revoke-MgUserSignOutSession -UserId "${u}"\n` +
          `# Disable Active Directory account (Optional)\n` +
          `Disable-ADAccount -Identity "${u}"`
        )).join("\n\n")
      : "# No compromised identity accounts detected";

    // 3. EDR / Host Isolation
    const edrCmd = `# Microsoft Defender for Endpoint - Automated Device Isolation\n` +
      `$headers = @{ "Authorization" = "Bearer $DEFENDER_TOKEN"; "Content-Type" = "application/json" }\n` +
      `$body = @{ "Comment" = "Host isolation triggered by BeyondArch SIEM automated triage"; "IsolationType" = "Full" } | ConvertTo-Json\n` +
      `# Trigger isolation across impacted asset endpoints:\n` +
      `Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/machines/{MachineId}/isolate" -Method Post -Headers $headers -Body $body`;

    // 4. Incident Response Dossier Draft
    const ticketDraft = `### [P1/CRITICAL] SOC Incident Escalation - Automated SIEM Correlated Threat\n` +
      `**Generated:** ${new Date().toISOString()}\n` +
      `**Correlated Events:** ${filtered.length} visible (${activeEvents.length} ingested)\n` +
      `**Progression Index:** ${killChain.progressionScore}% (${killChain.activePhaseCount}/5 Cyber Kill-Chain Phases Active)\n` +
      `**Threat Narrative:** ${killChain.threatNarrative}\n\n` +
      `#### Hostile Indicators (IOCs):\n` +
      `- Attacker IPs / C2 Endpoints: ${hostileIps.join(", ") || "None"}\n` +
      `- Compromised Accounts / Usernames: ${targetedUsers.join(", ") || "None"}\n` +
      `- MITRE Techniques: ${activeTechniques.join(", ") || "Unmapped"}\n\n` +
      `#### Recommended Containment Actions:\n` +
      `1. Block hostile IP perimeter ingress at firewalls (Palo Alto / AWS WAF / iptables).\n` +
      `2. Force credential resets and invalidate refresh tokens for flagged accounts.\n` +
      `3. Review endpoint process tree execution and isolate compromised workstations.`;

    return { hostileIps, targetedUsers, iptablesCmd, paloAltoCmd, identityCmd, edrCmd, ticketDraft };
  }, [classifyIps, apiIocs, activeBeacons, classifyUsers, mitre, filtered.length, activeEvents.length, killChain]);

  const narrative = useMemo(() => buildMetricsNarrative(apiMetrics, activeEvents, findings), [apiMetrics, activeEvents, findings]);

  const handleSendTo = (page: string) => {
    sendArtifactClick(page, filtered.slice(0, 25).map((r) => JSON.stringify(r)).join("\n"));
    flash(`Sent events to ${page}`);
  };

  /** SIEM 2.0 pivot: event → investigation. Parks a compact evidence entry
   *  in the case notebook handoff and opens the case page, which materializes
   *  a default case when none exists yet and stamps a handoff provenance event. */
  const handlePivot = (e: SiemEvent) => {
    const lines = [
      `**SIEM event** — ${e.sig}`,
      `- _time: ${e.ts}`,
      `- ${e.src} → ${e.dst}`,
      e.user && e.user !== "-" ? `- user: ${e.user}` : null,
      `- severity: ${e.sev}`,
    ];
    sendToCase({ body: lines.filter(Boolean).join("\n"), source: "/siem", kind: "evidence" });
    flash(`Parked event in case notebook — opening case`);
    navigate({ to: "/case" });
  };

  const facetContent = (
    <FieldFacetSidebar
      facets={fieldFacets}
      onAddChip={addChip}
      activeChips={chips}
      onViewStats={(f) => setStatsField(f)}
    />
  );

  const eventsContent = (
    <EntitySection title="Events" icon={Activity} meta={`${filtered.length} rows`}>
      <DataTable
        className="max-h-[600px] w-full"
        rows={filtered}
        emptyMessage="No events match this query"
        emptyHint="Loosen the time range, remove a chip, or clear the search."
        onRowClick={(_e, i) => setExpanded(expanded === i ? null : i)}
        isRowSelected={(_e, i) => expanded === i}
        renderExpanded={(e, i) => (
          <EventExpanded
            event={e}
            onFilter={addChip}
            onSendTo={handleSendTo}
            onPivot={() => handlePivot(e)}
            onShowJson={() => setModal({ title: "Event Detail", subtitle: `${e.ts} | ${e.sig}`, data: e })}
          />
        )}
        columns={[
          {
            key: "exp", label: "", width: "40px",
            render: (_e, i) => (expanded === i ? <ChevronDown className="h-3 w-3 text-fg-dim" /> : <ChevronRight className="h-3 w-3 text-fg-dim" />),
          },
          {
            key: "ts", label: "Time",
            render: (e) => <span className="text-fg-dim tabular-nums">{e.ts}</span>,
          },
          {
            key: "src", label: "Source",
            render: (e) => (
              <button onClick={(ev) => { ev.stopPropagation(); addChip("src", e.src); }} className={"underline decoration-dotted decoration-border underline-offset-2 hover:text-primary hover:decoration-primary " + (iocColorClass(e.src) ?? "text-foreground")}>{e.src}</button>
            ),
          },
          {
            key: "dst", label: "Destination",
            render: (e) => (
              <button onClick={(ev) => { ev.stopPropagation(); addChip("dst", e.dst); }} className={"underline decoration-dotted decoration-border underline-offset-2 hover:text-primary hover:decoration-primary " + (iocColorClass(e.dst) ?? "text-foreground")}>{e.dst}</button>
            ),
          },
          {
            key: "user", label: "User",
            render: (e) => <button onClick={(ev) => { ev.stopPropagation(); addChip("user", e.user); }} className={"underline decoration-dotted decoration-border underline-offset-2 hover:text-primary hover:decoration-primary " + (e.user ? "text-[var(--ansi-green)]" : "text-foreground")}>{e.user}</button>,
          },
          {
            key: "signature", label: "Signature",
            render: (e) => (
              <div className="flex items-center gap-1.5 min-w-0">
                <button onClick={(ev) => { ev.stopPropagation(); addChip("sig", e.sig); }} className="truncate text-left text-fg-dim hover:text-primary">
                  {e.sig}
                </button>
                <DecodedPayloadPopover rawText={e.sig} onPivotToDetection={() => navigate({ to: "/detection" })} />
              </div>
            ),
          },
          {
            key: "sev", label: "Severity",
            render: (e) => <button onClick={(ev) => { ev.stopPropagation(); addChip("sev", e.sev); }}><Chip tone={SEV_TONE[e.sev]}>{e.sev}</Chip></button>,
          },
        ]}
      />
    </EntitySection>
  );

  return (
    <ErrorBoundary name="SIEM">
    <PageShell
      eyebrow="siem / workspace"
      title="SIEM Workspace"
      description="Query, filter, and analyse event streams — auto‑classifies log format, counts entities, and lets you filter by them."
      crumbs={[{ label: "SIEM" }, { label: "Workspace" }]}
      jumps={[{ label: "Detection", to: "/detection" }]}
    >
      <EntityHeader
        variant="case"
        actions={
          <div className="flex items-center gap-1.5">
            <HeaderAction onClick={exportReport} disabled={!has} icon={<Hash className="h-3 w-3" />}>MD</HeaderAction>
            <HeaderAction onClick={exportCsv} disabled={!has} icon={<Download className="h-3 w-3" />}>CSV</HeaderAction>
          </div>
        }
      >
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {filtered.filter((e: any) => e.sev === "high").length > 0 && (
            <span className="inline-flex items-center gap-1 rounded border border-warning/30 bg-warning/10 px-1.5 py-0.5 text-mono ba-text-3xs text-warning">{filtered.filter((e: any) => e.sev === "high").length} high</span>
          )}
          {filtered.filter((e: any) => e.sev === "medium").length > 0 && (
            <span className="inline-flex items-center gap-1 rounded border border-warning/30 bg-warning/10 px-1.5 py-0.5 text-mono ba-text-3xs text-warning">{filtered.filter((e: any) => e.sev === "medium").length} med</span>
          )}
          {filtered.filter((e: any) => e.sev === "low").length > 0 && (
            <span className="inline-flex items-center gap-1 rounded border border-success/30 bg-success/10 px-1.5 py-0.5 text-mono ba-text-3xs text-success">{filtered.filter((e: any) => e.sev === "low").length} low</span>
          )}
          <span className="font-mono ba-text-2xs text-fg-dim">{filtered.length} / {activeEvents.length} events</span>
        </div>
      </EntityHeader>

      <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-subtle bg-surface-0 px-3 py-2.5">
        <button
          onClick={() => { document.getElementById("siem-intake")?.focus(); document.getElementById("siem-intake")?.scrollIntoView({ behavior: "smooth", block: "center" }); }}
          className="inline-flex h-7 items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-3 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"
        >
          <Crosshair className="h-3 w-3" /> start a hunt
        </button>
        <button
          onClick={() => setHuntingArsenalOpen(true)}
          className="inline-flex h-7 items-center gap-1.5 rounded border border-primary/50 bg-primary/20 px-3 text-mono ba-text-2xs font-medium text-primary transition-colors duration-150 hover:bg-primary/30 shadow-sm"
          title="Open Threat Hunting Playbook Arsenal & Sigma Auto-Tuning"
        >
          <BookMarked className="h-3 w-3" /> hunting arsenal
        </button>
        {recentQueries.length > 0 && (
          <>
            <span className="mx-1 hidden h-4 w-px bg-divider sm:block" />
            <span className="hidden text-mono ba-text-2xs text-fg-dim sm:inline">recent queries</span>
            {recentQueries.map((rq) => (
              <span key={`${rq.ts}-${rq.q}`} className="inline-flex max-w-52 items-center gap-0.5 rounded border border-subtle bg-surface-1 pl-2 pr-1 text-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-primary">
                <button
                  onClick={() => setQ(rq.q)}
                  className="inline-flex min-w-0 flex-1 items-center gap-1 truncate text-left"
                  title={`Apply "${rq.q}" to search`}
                >
                  <Search className="h-3 w-3 shrink-0" />
                  <span className="truncate">{rq.q}</span>
                </button>
                <button onClick={() => toggleFavorite(rq.q)} title={favoriteQueries.includes(rq.q) ? "Unfavorite" : "Favorite"} className={"shrink-0 rounded p-0.5 " + (favoriteQueries.includes(rq.q) ? "text-warning" : "text-muted-foreground hover:text-warning")}>
                  <Star className={"h-3 w-3 " + (favoriteQueries.includes(rq.q) ? "fill-warning" : "")} />
                </button>
              </span>
            ))}
          </>
        )}
        {favoriteQueries.length > 0 && (
          <>
            <span className="mx-1 hidden h-4 w-px bg-divider sm:block" />
            <span className="hidden text-mono ba-text-2xs text-fg-dim sm:inline">favorites</span>
            {favoriteQueries.map((fav) => (
              <span key={fav} className="inline-flex max-w-52 items-center gap-0.5 rounded border border-warning/30 bg-warning/5 pl-2 pr-1 text-mono ba-text-2xs text-foreground">
                <button
                  onClick={() => setQ(fav)}
                  className="inline-flex min-w-0 flex-1 items-center gap-1 truncate text-left hover:text-warning"
                  title={`Apply "${fav}" to search`}
                >
                  <Star className="h-3 w-3 shrink-0 fill-warning text-warning" />
                  <span className="truncate">{fav}</span>
                </button>
                <button onClick={() => toggleFavorite(fav)} title="Unfavorite" className="shrink-0 rounded p-0.5 text-muted-foreground hover:text-warning">
                  <X className="h-3 w-3" />
                </button>
              </span>
            ))}
          </>
        )}
        <span className="ml-auto hidden font-mono ba-text-2xs text-fg-dim md:inline">hunts persist locally — pinned hunts float to the front</span>
      </div>

      {/* Hunt library — collapsible: presets + saved hunts behind one toggle */}
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <button
          onClick={() => setHuntsOpen((v) => !v)}
          aria-expanded={huntsOpen}
          className="inline-flex items-center gap-1.5 rounded border border-subtle bg-surface-0 px-2.5 py-1 text-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-primary"
        >
          {huntsOpen ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          hunt library
          <span className="text-fg-dim/70">· {HUNT_PRESETS.length} presets · {hunts.length} saved</span>
        </button>
        <button
          onClick={() => setHuntingArsenalOpen(true)}
          className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-surface-0 px-2.5 py-1 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/10"
        >
          <Sparkles className="h-3 w-3" />
          hunting playbook arsenal
        </button>
      </div>
      {huntsOpen && (
      <>
      {/* Hunt presets — SIEM 2.0: one click loads a named hunt (keyword + chips) */}
      <div className="mb-3 flex flex-wrap items-center gap-1.5 rounded-lg border border-subtle bg-surface-0 px-3 py-2">
        <span className="text-mono ba-text-2xs text-fg-dim">hunt presets</span>
        {HUNT_PRESETS.map((h) => (
          <button
            key={h.id}
            onClick={() => applyHunt(h)}
            title={`Load ${h.name} — keyword + filter chips`}
            className="inline-flex h-6 items-center gap-1 rounded border border-border/70 bg-surface-1 px-2 text-mono ba-text-2xs text-foreground transition-colors duration-150 hover:border-primary/40 hover:text-primary"
          >
            <Target className="h-3 w-3 text-primary/70" /> {h.name}
          </button>
        ))}
      </div>

      {/* Saved hunts — SIEM 2.0: load reapplies query, chips, range, and re-ingests the source text */}
      <div className="mb-3 flex flex-wrap items-center gap-1.5 rounded-lg border border-subtle bg-surface-0 px-3 py-2">
        <span className="text-mono ba-text-2xs text-fg-dim">saved hunts</span>
        <button
          onClick={() => setSavingHunt((v) => !v)}
          disabled={!pasted.trim()}
          className="inline-flex h-6 items-center gap-1 rounded border border-subtle bg-surface-1 px-2 text-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-primary disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Save className="h-3 w-3" /> {savingHunt ? "cancel" : "save view"}
        </button>
        <button
          onClick={() => {
            const bundle = exportHuntsBundle(hunts);
            download(`beyondlabs-hunts-${Date.now()}.json`, bundle);
            flash("Exported hunts bundle");
          }}
          disabled={hunts.length === 0}
          className="inline-flex h-6 items-center gap-1 rounded border border-subtle bg-surface-1 px-2 text-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-primary disabled:cursor-not-allowed disabled:opacity-40"
          title="Export all hunts as JSON bundle"
        >
          <Download className="h-3 w-3" /> export
        </button>
        <label
          className="inline-flex h-6 cursor-pointer items-center gap-1 rounded border border-subtle bg-surface-1 px-2 text-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-primary"
          title="Import hunts from JSON bundle"
        >
          <Upload className="h-3 w-3" /> import
          <input
            type="file"
            accept=".json"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              const reader = new FileReader();
              reader.onload = (ev) => {
                const content = ev.target?.result as string;
                if (content) {
                  const imported = importHuntsBundle(content);
                  if (imported.length > 0) {
                    setHunts((prev) => [...imported, ...prev.filter((p) => !imported.some((i) => i.id === p.id))]);
                    flash(`Imported ${imported.length} saved hunt(s)`);
                  } else {
                    flash("No valid hunts found in JSON file");
                  }
                }
              };
              reader.readAsText(file);
            }}
          />
        </label>

        {savingHunt && (
          <input
            autoFocus
            value={huntName}
            onChange={(e) => setHuntName(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") commitHunt(huntName); if (e.key === "Escape") setSavingHunt(false); }}
            placeholder="hunt name"
            className="h-6 w-40 rounded border border-divider-strong bg-surface-1 px-2 text-mono ba-text-2xs text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/50"
          />
        )}
        {savingHunt && (
          <button
            onClick={() => commitHunt(huntName)}
            disabled={!huntName.trim()}
            className="inline-flex h-6 items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20 disabled:cursor-not-allowed disabled:opacity-40"
          >
            save
          </button>
        )}
        {hunts.length === 0 && !savingHunt && (
          <span className="text-mono ba-text-2xs text-fg-dim/70">none yet — ingest events and save the view</span>
        )}
        {hunts.map((h) => (
          <span key={h.id} className="inline-flex h-6 max-w-full items-center gap-1 rounded border border-subtle bg-surface-1 pl-2 text-mono ba-text-2xs text-fg-dim">
            {h.pinned && <Pin className="h-3 w-3 shrink-0 text-primary" />}
            <button
              onClick={() => applyHunt(h)}
              className="max-w-44 truncate text-foreground hover:text-primary"
              title={`Load ${h.name} — ${h.text.split(/\r?\n/).length} lines`}
            >
              {h.name}
            </button>
            {huntIsStale(h) ? (
              <span
                className="inline-flex shrink-0 items-center gap-1 rounded bg-warning/15 px-1.5 py-0.5 text-warning"
                title="Local reminder: this hunt has not been re-run recently (or ever). Results come from the stored snapshot — re-ingest fresh data before trusting them."
              >
                <span className="h-1.5 w-1.5 rounded-full bg-current" />
                {Number.isFinite(h.lastRunAt) ? `run ${huntAgeLabel(h.lastRunAt as number)}` : "never run"}
              </span>
            ) : (
              <span className="shrink-0 text-fg-dim/70">run {huntAgeLabel(h.lastRunAt as number)}</span>
            )}
            <button onClick={() => togglePinHunt(h.id)} title={h.pinned ? "unpin" : "pin"} className="rounded px-1 py-0.5 text-muted-foreground hover:text-primary">
              <Pin className="h-3 w-3" />
            </button>
            <button onClick={() => deleteHunt(h.id)} title="delete hunt" className="rounded px-1 py-0.5 text-muted-foreground hover:text-destructive">
              <Trash2 className="h-3 w-3" />
            </button>
          </span>
        ))}
      </div>
      </>
      )}

      <SectionBar id="IN" label="Intake · query + paste" meta={`${filtered.length} / ${activeEvents.length} events`} />

      <div className="grid gap-3 grid-cols-1">
        <IntakeCard
          textareaId="siem-intake"
          icon={FileText}
          title="Paste raw events"
          value={pasted}
          onChange={setPasted}
          rows={6}
          placeholder="JSONL alerts, syslog lines, or CSV — mapped to src/dst/user/sig/sev"
          samples={[
            { key: "demo", label: "JSONL demo" },
            { key: "ssh",  label: "SSH brute" },
            { key: "beacon", label: "C2 beacon" },
            { key: "web",  label: "Web attack" },
          ]}
          onLoadSample={(k) => {
            const sample = SAMPLE_TEXTS[k];
            if (sample) { setPasted(sample); ingest(sample); }
          }}
          onFile={(txt) => { setPasted(txt); ingest(txt); }}
          fileAccept=".log,.json,.jsonl,.txt"
          run={{ label: loading ? "ingesting..." : "ingest", icon: loading ? Loader2 : Zap, onClick: () => ingest(pasted), disabled: loading || !pasted.trim() }}
          onClear={() => { setPasted(""); setApiEvents([]); }}
          showCopy={false}
        />
      </div>

      {/* Notice banner */}
      {notice && (
        <div className="flex items-center gap-2 rounded-md border border-primary/30 bg-primary/10 px-3 py-2">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />
          <span className="flex-1 text-mono ba-text-sm text-primary">{notice}</span>
          <button onClick={() => setNotice("")} className="text-primary/60 hover:text-primary" aria-label="dismiss"><X className="h-3 w-3" /></button>
        </div>
      )}

      {siemError && (
        <div className="flex items-center gap-2 rounded border border-destructive/40 bg-destructive/5 p-3 text-mono ba-text-sm text-destructive">
          <span className="flex-1">{siemError}</span>
          <button onClick={() => setSiemError(null)} className="text-destructive/60 hover:text-destructive" aria-label="dismiss"><X className="h-3 w-3" /></button>
        </div>
      )}

      <SplunkSearchBar
        query={q}
        onQueryChange={setQ}
        chips={chips}
        onAddChip={addChip}
        onRemoveChip={removeChip}
        onClearChips={() => setChips([])}
        range={range}
        onRangeChange={setRange}
        onApplyHuntPreset={applyHunt}
        mitreTechniques={mitre}
        totalMatches={filtered.length}
        totalEvents={activeEvents.length}
      />

      <StatusBar stats={[
        { label: "Status",   value: loading ? "Loading..." : has ? "Ready" : "Awaiting input", tone: loading ? "warning" : has ? "success" : "default" },
        { label: "Sources",  value: new Set(filtered.map((e) => e.src)).size },
        { label: "High sev", value: highCount, tone: highCount ? "warning" : "default" },
        { label: "Window",   value: range },
      ]} />

      {/* ── Log Classification (from LogsViewer essence) ── */}
      {has && (
        <div className="mb-4">
          <div className="inline-flex flex-wrap items-center gap-2 rounded-md border border-subtle bg-surface-1 px-3 py-2">
            <span className="text-mono ba-text-2xs text-muted-foreground">format</span>
            <Chip tone="primary">{logFmt}</Chip>
            <span className="mx-2 h-3 w-px bg-border/60" />
            <span className="text-mono ba-text-2xs text-muted-foreground">entities</span>
            <button onClick={() => { classifyIps.forEach((ip) => addChip("src", ip)); }} className="inline-flex items-center gap-1 rounded border border-info/30 bg-info/10 px-1.5 py-0.5 text-mono ba-text-3xs text-info hover:bg-info/20 hover:border-info/50 cursor-pointer transition-colors duration-150" title="Filter all IPs as src">{classifyIps.length} IPs</button>
            {classifyUsers.length > 0 && <button onClick={() => { classifyUsers.forEach((u) => addChip("user", u)); }} className="inline-flex items-center gap-1 rounded border border-warning/30 bg-warning/10 px-1.5 py-0.5 text-mono ba-text-3xs text-warning hover:bg-warning/20 hover:border-warning/50 cursor-pointer transition-colors duration-150" title="Filter all users">{classifyUsers.length} users</button>}
            {classifyProcs.length > 0 && <button onClick={() => { classifyProcs.forEach((p) => addChip("sig", p)); }} className="inline-flex items-center gap-1 rounded border border-accent/30 bg-accent/10 px-1.5 py-0.5 text-mono ba-text-3xs text-accent hover:bg-accent/20 hover:border-accent/50 cursor-pointer transition-colors duration-150" title="Filter all processes">{classifyProcs.length} processes</button>}
            {classifyHashes.length > 0 && <span className="inline-flex items-center gap-1 rounded border border-destructive/30 bg-destructive/10 px-1.5 py-0.5 text-mono ba-text-3xs text-destructive">{classifyHashes.length} hashes</span>}
          </div>
        </div>
      )}

      <SectionBar id="OT" label="Output · events + analysis" meta={`${findings.length} finding(s) · ${mitre.length} mitre`} />

      {showFilter && (
        <OutputFilterBar
          filterText={filterText}
          onChange={setFilterText}
          onClear={() => setFilterText("")}
          onClose={() => { setShowFilter(false); setFilterText(""); }}
        />
      )}

      {/* AnalystOutputCard-style summary */}
        <OutputFilter query={filterText.toLowerCase()}>
        <div className="pointer-events-none select-none">
          <ResultBanner
            badge="SIEM Summary"
            title={`${filtered.length} events · ${findings.length} detection lead(s)`}
            subtitle={activeEvents.length ? `${activeEvents.length} total event(s) · ` + (chips.length ? `filtered: ${chips.map((c) => `${c.field}=${c.value}`).join(" · ")}` : "click cells to pin filters, use range pills to scope") : "Paste logs above and click ingest to begin."}
            reasons={[
              `${activeEvents.length} total event(s), ${filtered.length} visible`,
              fieldTopSrc !== "—" ? `Top source: ${fieldTopSrc}` : "",
              findings.find((f) => f.sev === "destructive") ? `Destructive finding: ${findings.find((f) => f.sev === "destructive")?.title}` : "",
              `${mitre.length} MITRE technique(s) mapped`,
            ].filter(Boolean) as string[]}
            metrics={[
              { label: "Events",   value: filtered.length, tone: "primary" },
              { label: "Top src",  value: fieldTopSrc },
              { label: "Highest",  value: highCount, tone: highCount ? "warning" : "default" },
              { label: "Findings", value: findings.length, tone: findings.some((f) => f.sev === "destructive") ? "destructive" : findings.some((f) => f.sev === "warning") ? "warning" : "default" },
            ]}
          />
        </div>

      {/* SIEM Summary Narrative toggle */}
      {has && (
        <EntitySection title="SIEM Summary Narrative" icon={FileText}>
          <button
            onClick={() => setShowNarrative(!showNarrative)}
            className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"
          >
            {showNarrative ? "Hide" : "Generate"} SIEM Summary
          </button>
          {showNarrative && (
            <div className="mt-3 rounded border border-divider-strong bg-surface-0 p-3">
              <pre className="whitespace-pre-wrap text-mono ba-text-sm leading-relaxed text-foreground">{narrative}</pre>
              <button
                onClick={() => { copyText(narrative); flash("Summary copied"); }}
                className="mt-2 inline-flex items-center gap-1 rounded border border-subtle bg-surface-2 px-2 py-0.5 text-mono ba-text-2xs text-fg-dim hover:text-foreground"
              >Copy Summary</button>
            </div>
          )}
        </EntitySection>
      )}

      {/* Timelines (SIEM 2.0) — incident strip / event histogram tabbed */}
      <EntitySection title="Timelines" icon={Clock} meta={timelineTab === "incident" ? `${incidentTimeline.length} step(s)` : `${histo.length} bucket(s)`}>
        <div className="mb-2 flex flex-wrap items-center gap-1">
          {(["incident", "event"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTimelineTab(t)}
              className={"rounded border px-2.5 py-1 text-mono ba-text-2xs transition-colors duration-150" + (timelineTab === t ? " border-primary/50 bg-primary/10 text-primary" : " border-subtle text-muted-foreground hover:text-foreground")}
            >{t} timeline</button>
          ))}
        </div>
        {timelineTab === "incident" ? (
          incidentTimeline.length === 0 ? (
            <Empty title="No events in range" hint="Widen the time range or remove a filter chip." />
          ) : (
            <div className="flex flex-wrap items-center gap-1.5">
              {incidentTimeline.map((s, i) => (
                <span key={i} className="inline-flex items-center gap-1.5">
                  <button
                    onClick={() => setTimeSliceFilter((prev) => (prev === s.min ? null : s.min))}
                    title={`Filter view to minute t+${s.min}m`}
                    className={"inline-flex items-center gap-1 rounded border px-2 py-1 font-mono ba-text-2xs transition-colors " + (timeSliceFilter === s.min ? "border-primary bg-primary/20 text-primary" : "border-border bg-surface-1 text-foreground hover:border-primary/40")}
                  >
                    <span className="tabular-nums text-primary">{s.time}</span>
                    <span className={s.sev === "high" || s.sev === "critical" ? "text-destructive" : s.sev === "medium" ? "text-warning" : "text-fg-dim"}>{s.label}</span>
                  </button>
                  {i < incidentTimeline.length - 1 && <ArrowRight className="h-3 w-3 text-muted-foreground/50" />}
                </span>
              ))}
            </div>
          )
        ) : (
          histo.length === 0 ? (
            <Empty title="No events in range" hint="Widen the time range or remove a filter chip." />
          ) : (
            <div>
              {timeSliceFilter !== null && (
                <div className="mb-2 flex items-center justify-between rounded border border-primary/40 bg-primary/10 px-3 py-1 text-mono ba-text-2xs text-primary">
                  <span>Zoomed into minute: <strong>t+{timeSliceFilter}m</strong> ({filtered.length} matching events)</span>
                  <button
                    onClick={() => setTimeSliceFilter(null)}
                    className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 hover:bg-primary/20 transition-colors cursor-pointer"
                  >
                    <X className="h-3 w-3" /> Reset Time Zoom
                  </button>
                </div>
              )}
              <ChartContainer config={chartConfig} className="aspect-[4/1] w-full cursor-pointer">
                <BarChart
                  data={chartData}
                  margin={{ top: 4, right: 8, left: -16, bottom: 4 }}
                  onClick={(state) => {
                    const clickedMin = (state as any)?.activePayload?.[0]?.payload?.min;
                    if (typeof clickedMin === "number") {
                      setTimeSliceFilter((prev) => (prev === clickedMin ? null : clickedMin));
                    }
                  }}
                >
                  <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="time" tickLine={false} axisLine={false} fontSize={10} />
                  <YAxis tickLine={false} axisLine={false} fontSize={10} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="high" fill="var(--color-high)" stackId="a" radius={[0, 0, 0, 0]} />
                  <Bar dataKey="medium" fill="var(--color-medium)" stackId="a" radius={[0, 0, 0, 0]} />
                  <Bar dataKey="low" fill="var(--color-low)" stackId="a" radius={[0, 0, 0, 0]} />
                </BarChart>
              </ChartContainer>
            </div>
          )
        )}
      </EntitySection>

      {/* C2 Beaconing Alert Banner */}
      {activeBeacons.length > 0 && (
        <div className="mb-3 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2.5 rounded-lg border border-destructive/40 bg-destructive/10 px-3.5 py-2.5">
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="h-5 w-5 animate-pulse text-destructive shrink-0" />
            <div>
              <span className="font-mono ba-text-xs font-bold text-destructive">
                Deterministic C2 Beaconing Cadence Detected ({activeBeacons.length} target{activeBeacons.length > 1 ? "s" : ""})
              </span>
              <div className="mt-0.5 flex flex-wrap gap-2 text-mono ba-text-2xs text-fg-dim">
                {activeBeacons.map((b) => (
                  <span key={b.destination} className="inline-flex items-center gap-1">
                    <strong className="text-foreground">{b.destination}</strong>: mean interval {b.meanIntervalSec}s, jitter {b.jitterPct}% ({b.confidence} confidence)
                  </span>
                ))}
              </div>
            </div>
          </div>
          <button
            onClick={() => addChip("dst", activeBeacons[0].destination)}
            className="rounded border border-destructive/50 bg-destructive/20 px-2 py-1 font-mono ba-text-2xs text-destructive hover:bg-destructive/30 transition-colors shrink-0 self-end sm:self-center"
          >
            Filter Beacon Target
          </button>
        </div>
      )}

      {/* Cyber Kill-Chain Attack Progression */}
      {has && (
        <KillChainTimeline
          analysis={killChain}
          selectedPhase={selectedPhase}
          onSelectPhase={setSelectedPhase}
        />
      )}

      {/* 1-Click SOC Containment Console */}
      {has && (
        <div className="rounded-lg border border-border bg-surface-1 p-3.5 shadow-sm space-y-3 min-w-0 max-w-full">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-2.5">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-warning shrink-0" />
              <h3 className="font-mono ba-text-xs font-semibold uppercase tracking-wider text-foreground">
                1-Click SOC Response & Containment Console
              </h3>
              <span className="rounded bg-surface-2 px-1.5 py-0.5 text-mono ba-text-3xs text-fg-dim">
                {containmentData.hostileIps.length} Hostile IPs · {containmentData.targetedUsers.length} Targeted Users
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              {(["firewall", "identity", "edr", "ticket"] as const).map(tab => (
                <button
                  key={tab}
                  onClick={() => setContainmentTab(tab)}
                  className={"rounded px-2.5 py-1 text-mono ba-text-2xs font-semibold transition-colors " + (containmentTab === tab ? "border border-primary/50 bg-primary/15 text-primary" : "border border-border bg-surface-0 text-muted-foreground hover:text-foreground")}
                >
                  {tab === "firewall" ? "Firewall Rules" : tab === "identity" ? "Identity Lockout" : tab === "edr" ? "EDR Isolation" : "IR Ticket Draft"}
                </button>
              ))}
            </div>
          </div>

          {/* Tab Body */}
          <div className="space-y-2">
            {containmentTab === "firewall" && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="rounded border border-subtle bg-surface-0 p-2.5">
                  <div className="flex items-center justify-between pb-1 mb-1.5 border-b border-border/40">
                    <span className="text-mono ba-text-3xs font-semibold text-foreground">Linux iptables / UFW Drop</span>
                    <button
                      onClick={() => handleCopyScript(containmentData.iptablesCmd, "iptables", "iptables script")}
                      className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
                    >
                      {copiedKey === "iptables" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                      {copiedKey === "iptables" ? "copied" : "copy"}
                    </button>
                  </div>
                  <pre className="text-mono ba-text-3xs text-muted-foreground p-2 bg-surface-1 rounded overflow-x-auto whitespace-pre max-h-48">
                    {containmentData.iptablesCmd}
                  </pre>
                </div>

                <div className="rounded border border-subtle bg-surface-0 p-2.5">
                  <div className="flex items-center justify-between pb-1 mb-1.5 border-b border-border/40">
                    <span className="text-mono ba-text-3xs font-semibold text-foreground">Palo Alto PAN-OS Rule</span>
                    <button
                      onClick={() => handleCopyScript(containmentData.paloAltoCmd, "palo", "Palo Alto commands")}
                      className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
                    >
                      {copiedKey === "palo" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                      {copiedKey === "palo" ? "copied" : "copy"}
                    </button>
                  </div>
                  <pre className="text-mono ba-text-3xs text-muted-foreground p-2 bg-surface-1 rounded overflow-x-auto whitespace-pre max-h-48">
                    {containmentData.paloAltoCmd}
                  </pre>
                </div>
              </div>
            )}

            {containmentTab === "identity" && (
              <div className="rounded border border-subtle bg-surface-0 p-2.5">
                <div className="flex items-center justify-between pb-1 mb-1.5 border-b border-border/40">
                  <span className="text-mono ba-text-3xs font-semibold text-foreground">PowerShell Entra ID & Active Directory Lockout</span>
                  <button
                    onClick={() => handleCopyScript(containmentData.identityCmd, "id", "Identity lockout script")}
                    className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
                  >
                    {copiedKey === "id" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                    {copiedKey === "id" ? "copied" : "copy"}
                  </button>
                </div>
                <pre className="text-mono ba-text-3xs text-muted-foreground p-2 bg-surface-1 rounded overflow-x-auto whitespace-pre max-h-48">
                  {containmentData.identityCmd}
                </pre>
              </div>
            )}

            {containmentTab === "edr" && (
              <div className="rounded border border-subtle bg-surface-0 p-2.5">
                <div className="flex items-center justify-between pb-1 mb-1.5 border-b border-border/40">
                  <span className="text-mono ba-text-3xs font-semibold text-foreground">Microsoft Defender Endpoint Device Isolation</span>
                  <button
                    onClick={() => handleCopyScript(containmentData.edrCmd, "edr", "Defender isolation script")}
                    className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
                  >
                    {copiedKey === "edr" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                    {copiedKey === "edr" ? "copied" : "copy"}
                  </button>
                </div>
                <pre className="text-mono ba-text-3xs text-muted-foreground p-2 bg-surface-1 rounded overflow-x-auto whitespace-pre max-h-48">
                  {containmentData.edrCmd}
                </pre>
              </div>
            )}

            {containmentTab === "ticket" && (
              <div className="rounded border border-subtle bg-surface-0 p-2.5">
                <div className="flex items-center justify-between pb-1 mb-1.5 border-b border-border/40">
                  <span className="text-mono ba-text-3xs font-semibold text-foreground">Incident Response Ticket Draft (Markdown)</span>
                  <button
                    onClick={() => handleCopyScript(containmentData.ticketDraft, "ticket", "IR Ticket Draft")}
                    className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
                  >
                    {copiedKey === "ticket" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                    {copiedKey === "ticket" ? "copied" : "copy"}
                  </button>
                </div>
                <pre className="text-mono ba-text-3xs text-muted-foreground p-2 bg-surface-1 rounded overflow-x-auto whitespace-pre max-h-48">
                  {containmentData.ticketDraft}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Desktop resizable layout */}
      <div className="hidden md:block">
        <ResizablePanelGroup orientation="horizontal" className="gap-3 min-h-[520px]">
          <ResizablePanel defaultSize={28} minSize={20} maxSize={42}>
            {facetContent}
          </ResizablePanel>

          <ResizableHandle withHandle className="self-stretch" />
          <ResizablePanel defaultSize={72} minSize={50} className="min-w-0">
            {eventsContent}
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>

      {/* Mobile stacked layout */}
      <div className="flex flex-col gap-3 md:hidden min-w-0 max-w-full overflow-hidden">
        {facetContent}
        <div className="min-w-0 max-w-full overflow-x-auto">
          {eventsContent}
        </div>
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="grid gap-3 grid-cols-1 md:grid-cols-2">
          {findings.map((f, i) => (
            <EvidenceCard key={i} severity={f.sev} title={f.title} reason={f.reason} action={f.action} limitation="Correlation based on available event fields — confirm with full packet capture." />
          ))}
        </div>
      )}

      {/* MITRE ATT&CK — grouped by tactic, drill-down per technique */}
      {tacticCoverage.length > 0 && (
        <EntitySection title="MITRE ATT&CK Tactic Coverage" icon={Crosshair} meta={`${tacticCoverage.length} tactic(s) · ${mitre.length} technique(s)`}>
          <div className="grid gap-3 grid-cols-1 sm:grid-cols-2 md:grid-cols-3">
            {tacticCoverage.map((t) => (
              <div key={t.tactic} className="rounded border border-divider-strong bg-surface-1 px-3 py-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-mono ba-text-sm font-semibold text-foreground">{t.tactic}</span>
                  <Chip tone={t.count >= 3 ? "destructive" : t.count >= 2 ? "warning" : "info"}>{t.count}</Chip>
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {t.techniques.map((tid) => (
                    <button
                      key={tid}
                      onClick={() => setDrilldownTechnique(drilldownTechnique === tid ? null : tid)}
                      title={`${tid} — click for rules, cases, alerts`}
                      className={"rounded border px-1.5 py-0.5 text-mono ba-text-2xs transition-colors duration-150 " + (drilldownTechnique === tid ? "border-primary bg-primary/10 text-primary" : "border-subtle bg-surface-0 text-muted-foreground hover:border-primary/40 hover:text-primary")}
                    >
                      {tid}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {drilldownTechnique && (() => {
            const d = mitreDrilldown.get(drilldownTechnique);
            const name = mitre.find((m) => m.startsWith(drilldownTechnique))?.split(" ").slice(1).join(" ") ?? drilldownTechnique;
            return (
              <div className="mt-3 rounded border border-primary/30 bg-primary/[0.04] p-3">
                <div className="mb-2 flex items-center justify-between gap-2">
                  <span className="font-mono ba-text-sm font-semibold text-primary">{drilldownTechnique} · {name}</span>
                  <button onClick={() => setDrilldownTechnique(null)} className="rounded border border-subtle px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-foreground">close</button>
                </div>
                <div className="grid gap-3 md:grid-cols-3">
                  <div>
                    <div className="mb-1 text-mono ba-text-3xs uppercase text-muted-foreground">detection rules</div>
                    {d && d.rules.length > 0 ? (
                      <div className="space-y-1">
                        {d.rules.map((rk) => <button key={rk} onClick={() => navigate({ to: "/detection" })} className="block w-full truncate rounded border border-subtle bg-surface-0 px-2 py-1 text-left font-mono ba-text-2xs text-foreground hover:border-primary/40 hover:text-primary">{rk}</button>)}
                      </div>
                    ) : <div className="text-mono ba-text-2xs text-fg-dim">no saved rule targets {drilldownTechnique}</div>}
                  </div>
                  <div>
                    <div className="mb-1 text-mono ba-text-3xs uppercase text-muted-foreground">previous cases</div>
                    {d && d.cases.length > 0 ? (
                      <div className="space-y-1">
                        {d.cases.slice(0, 6).map((t) => <div key={t} className="truncate rounded border border-subtle bg-surface-0 px-2 py-1 font-mono ba-text-2xs text-fg-dim" title={t}>{t}</div>)}
                      </div>
                    ) : <div className="text-mono ba-text-2xs text-fg-dim">no case findings mapped to {drilldownTechnique}</div>}
                  </div>
                  <div>
                    <div className="mb-1 text-mono ba-text-3xs uppercase text-muted-foreground">related alerts</div>
                    {d && d.alerts.length > 0 ? (
                      <div className="space-y-1">
                        {d.alerts.slice(0, 6).map((t) => <div key={t} className="truncate rounded border border-subtle bg-surface-0 px-2 py-1 font-mono ba-text-2xs text-fg-dim" title={t}>{t}</div>)}
                      </div>
                    ) : <div className="text-mono ba-text-2xs text-fg-dim">no ingested alerts fire rules for {drilldownTechnique}</div>}
                  </div>
                </div>
              </div>
            );
          })()}
        </EntitySection>
      )}

      {/* MITRE flat list (kept for full reference) */}
      {mitre.length > 0 && (
        <EntitySection title="MITRE ATT&CK Techniques" icon={Crosshair} meta={`${mitre.length} technique${mitre.length === 1 ? "" : "s"}`}>
          <div className="flex flex-wrap gap-2">
            {mitre.map((m) => (
              <span key={m} className="inline-flex items-center gap-1.5 rounded border border-divider-strong bg-surface-1 px-2 py-1 text-mono ba-text-sm text-fg-dim">
                <Bug className="h-3 w-3 text-destructive" />
                <span className="font-semibold">{m.split(" ")[0]}</span>
                <span className="text-muted-foreground">:</span>
                <span>{m.split(" ").slice(1).join(" ")}</span>
              </span>
            ))}
          </div>
        </EntitySection>
      )}

      {/* IOC Inventory */}
      {iocs.length > 0 && (
        <EntitySection title="IOC Inventory" icon={Database} meta={`${iocs.reduce((s, g) => s + g.items.length, 0)} indicators`}>
          <IocInventory groups={iocs} onSendTo={() => {}} />
          <div className="mt-2 flex flex-wrap gap-1.5">
            {iocs.map((g) => (
              <button key={g.kind} onClick={() => { const t = g.kind === "URLs" ? "url" : g.kind === "IPs" ? "ipv4" : g.kind === "Emails" ? "email" : g.kind === "Domains" ? "domain" : "unknown"; g.items.forEach((v) => locker.add({ value: v, type: t, source: "/siem" })); notify.success(`Added ${g.items.length} ${g.kind} to locker`); }}
                className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-1 text-mono ba-text-3xs text-muted-foreground hover:bg-card/70 hover:text-foreground"
              >+ {g.kind} ({g.items.length})</button>
            ))}
          </div>
        </EntitySection>
      )}

      </OutputFilter>

      <SendToRow targets={[
        { label: "Detection",      to: "/detection", icon: ShieldAlert },
        { label: "MITRE Coverage", to: "/mitre",     icon: ArrowRight },
        { label: "Case Notebook",  to: "/case",      icon: ArrowRight, onClick: () => sendToCase({ body: JSON.stringify(filtered.slice(0, 20), null, 2), source: "/siem", kind: "evidence" }) },
      ]} />

      {/* Modal */}
      {modal && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 backdrop-blur-sm" onMouseDown={() => setModal(null)}>
          <div className="max-h-[80vh] w-full max-w-2xl overflow-auto rounded-lg border border-subtle bg-card p-5 elevation-floating" onMouseDown={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-mono ba-text-2xs text-primary">Details</div>
                <h2 className="text-mono ba-text-base font-semibold text-foreground">{modal.title}</h2>
                {modal.subtitle && <p className="text-mono ba-text-sm text-muted-foreground">{modal.subtitle}</p>}
              </div>
              <button onClick={() => setModal(null)} className="text-muted-foreground hover:text-foreground" aria-label="Close"><X className="h-4 w-4" /></button>
            </div>
            <pre className="mt-4 overflow-x-auto rounded border border-divider-strong bg-surface-0 p-3 text-mono ba-text-sm leading-relaxed text-foreground">{JSON.stringify(modal.data, null, 2)}</pre>
            <div className="mt-3 flex justify-end gap-2">
                <button onClick={() => { copyText(JSON.stringify(modal.data, null, 2)); flash("JSON copied"); }} className="rounded border border-subtle bg-surface-2 px-2 py-1 text-mono ba-text-2xs text-fg-dim hover:text-foreground">Copy JSON</button>
              <button onClick={() => setModal(null)} className="rounded border border-subtle bg-surface-2 px-2 py-1 text-mono ba-text-2xs text-fg-dim hover:text-foreground">Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Field Statistics Modal */}
      {statsField && (

        <FieldStatsModal
          field={statsField}
          events={activeEvents}
          onClose={() => setStatsField(null)}
          onAddChip={addChip}
          onAppendQuery={(sub) => setQ((prev) => prev + sub)}
        />
      )}

      {/* Threat Hunting Playbook Arsenal & Sigma Auto-Tuning Modal */}
      <HuntingPlaybookArsenalModal
        open={huntingArsenalOpen}
        onClose={() => setHuntingArsenalOpen(false)}
        onLoadQuery={(query) => {
          setQ(query);
          flash("Hunting query loaded into SIEM search bar");
        }}
      />
    </PageShell>

    </ErrorBoundary>
  );
}

/* ── Expanded event detail (Splunk CIM & Elastic ECS equivalent) ── */
function EventExpanded({ event, onFilter, onSendTo, onPivot, onShowJson }: {
  event: SiemEvent;
  onFilter: (field: string, value: string) => void;
  onSendTo: (page: string) => void;
  onPivot: () => void;
  onShowJson: () => void;
}) {
  const navigate = useNavigate();
  const locker = useLocker();

  const handleStashIocs = () => {
    let count = 0;
    if (event.src && event.src !== "—") {
      locker.add({ type: "ipv4", value: event.src, source: "/siem", note: "siem-event" });
      count++;
    }
    if (event.dst && event.dst !== "—") {
      locker.add({ type: "ipv4", value: event.dst, source: "/siem", note: "siem-event" });
      count++;
    }
    notify.success(`Stashed ${count} IOC(s) to Evidence Locker`);
  };

  const handlePivotParser = () => {
    navigate({ to: "/parser" });
  };

  const entries = [
    { field: "ts" as const, label: "_time", ecs: "@timestamp", value: event.ts },
    { field: "src" as const, label: "src_ip", ecs: "source.ip", value: event.src },
    { field: "dst" as const, label: "dest_ip", ecs: "destination.ip", value: event.dst },
    { field: "user" as const, label: "user", ecs: "user.name", value: event.user },
    { field: "sig" as const, label: "signature", ecs: "event.action", value: event.sig },
    { field: "sev" as const, label: "severity", ecs: "event.severity", value: event.sev },
  ];

  return (
    <div className="space-y-3 rounded-md border border-subtle bg-surface-1/60 p-3">
      <div className="flex flex-wrap items-center gap-1.5">
        <button onClick={onPivot} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20 font-medium">
          <ArrowRight className="h-3 w-3" /> Pivot to Case
        </button>
        <button onClick={handlePivotParser} className="inline-flex items-center gap-1 rounded border border-info/40 bg-info/10 px-2 py-0.5 text-mono ba-text-2xs text-info transition-colors duration-150 hover:bg-info/20 font-medium">
          <Database className="h-3 w-3" /> Pivot to Parser
        </button>
        <button onClick={handleStashIocs} className="inline-flex items-center gap-1 rounded border border-warning/40 bg-warning/10 px-2 py-0.5 text-mono ba-text-2xs text-warning transition-colors duration-150 hover:bg-warning/20 font-medium">
          <Database className="h-3 w-3" /> Stash to Locker
        </button>
        <button onClick={onShowJson} className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-2 px-2 py-0.5 text-mono ba-text-2xs text-fg-dim hover:text-foreground transition-colors duration-150">
          JSON
        </button>
        <span className="mx-1 h-3.5 w-px bg-border/60" />
        <button onClick={() => onSendTo("logs")} className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-2 px-2 py-0.5 text-mono ba-text-2xs text-fg-dim hover:text-foreground">
          Forensic Logs
        </button>
        <button onClick={() => onSendTo("detection-mitre")} className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-2 px-2 py-0.5 text-mono ba-text-2xs text-fg-dim hover:text-foreground">
          Detection
        </button>
      </div>

      <div className="grid gap-2 grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
        {entries.map(({ field, label, ecs, value }) => (
          <button
            key={field}
            onClick={() => onFilter(field, value)}
            className="group flex flex-col items-start gap-0.5 rounded border border-subtle bg-surface-0 px-2.5 py-1.5 text-left transition-colors duration-150 hover:border-primary/50 hover:bg-primary/[0.04]"
          >
            <div className="flex w-full items-center justify-between text-mono ba-text-3xs text-fg-dim">
              <span>{label}</span>
              <span className="text-primary/70">{ecs}</span>
            </div>
            <span className="w-full truncate text-mono ba-text-xs text-foreground group-hover:text-primary font-medium">{value}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
