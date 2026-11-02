import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { useMutation } from "@tanstack/react-query";
import { PageShell } from "@/components/PageShell";
import { IntakeCard, SendToRow, SectionBar, Chip, Panel, MetricTile } from "@/components/soc";
import { EntitySection, EntityHeader } from "@/components/entity";
import {
  Zap, Terminal, ArrowRight, Mail, Link2,
  FileWarning, Activity, Globe, Hash, Crosshair, Network, Copy, Check,
  Sparkles, FileText, Workflow, AlertTriangle, ShieldAlert, Key, Download,
  Scan, Loader2, Search, SlidersHorizontal, CheckSquare, Square,
  ExternalLink, ChevronDown, RefreshCw, Layers, ShieldCheck, Database,
  Server, Coins, Cloud, CornerDownRight, X
} from "lucide-react";
import { refang, defang } from "@/lib/ioc-patterns";
import { useLocker, type LockerItem } from "@/lib/locker";
import { copyText } from "@/lib/copy";
import { AttachButton } from "@/components/AttachButton";
import { useRecentInputs } from "@/lib/use-recent-inputs";
import { useWorkspaceState, useDebouncedWorkspaceSave } from "@/lib/use-workspace-state";
import { ResumeBanner } from "@/components/ResumeBanner";
import { analyzeFullEmail } from "@/api/phishing";
import { pushTimelineEvent } from "@/lib/timeline";
import { mapMitre } from "@/api/detection";
import { notify } from "@/lib/notify";
import {
  SAMPLES, KIND_META, OSINT_TOOLS_PER_KIND,
  autoDetectInputType,
} from "@/data/parser";
import { analyzeArtifact } from "@/lib/artifact";
import { buildLocalHistory } from "@/lib/correlation/history";
import { rememberCorrelation } from "@/lib/correlation";
import { severityTone } from "@/lib/severity";
import {
  SEMANTIC_FIELDS, detectLogFields, loadStoredMapping, saveFieldMapping,
  effectiveMapping, extractValue, type SemanticField, type GuessConfidence,
} from "@/lib/log-mapping";
import {
  TIMELINE_FIELDS, detectTimelineFields, effectiveTimelineMapping,
  importCaseTimeline, loadStoredTimelineMapping, saveTimelineMapping,
  timelineRowTexts, type TimelineImportReport,
} from "@/lib/timeline-import";
import { useActiveCase, useCaseList } from "@/data/case";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import {
  detectObfuscation,
  decodePowerShell,
  decodeBase64,
  decodeUrl,
  decodeHex,
  decodeRot13,
  reverseText,
  generateCyberChefUrl,
  type ObfuscationCandidate,
} from "@/lib/deobfuscator";
import {
  extractObservables,
  promoteObservablesToCase,
  exportObservablesCsv,
  exportObservablesJson,
  exportObservablesMarkdown,
  exportObservablesDefangedList,
  type ScoredObservable,
} from "@/lib/parser-engine";

export const Route = createFileRoute("/parser")({ component: ParserPage });

function ParserPage() {
  const [input, setInput] = useState("");
  const [activeTab, setActiveTab] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [defanged, setDefanged] = useState(true);
  const [copiedKey, setCopiedKey] = useState<string>("");
  const [deepScanError, setDeepScanError] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [showOsintMenu, setShowOsintMenu] = useState<string | null>(null);

  const searchInputRef = useRef<HTMLInputElement>(null);
  const { items: recentItems, push: pushRecent, clear: clearRecent } = useRecentInputs("parser");
  const { pending, accept, save, clear } = useWorkspaceState("parser");
  useDebouncedWorkspaceSave("parser", input);
  const locker = useLocker();
  const navigate = useNavigate();

  useEffect(() => {
    if (typeof window !== "undefined") {
      const sp = new URLSearchParams(window.location.search);
      const q = sp.get("q") || sp.get("query") || sp.get("input");
      if (q) {
        setInput(q);
      }
    }
  }, []);

  // Active case context
  const { activeCase } = useActiveCase();
  const cases = useCaseList();
  const [targetCaseId, setTargetCaseId] = useState("");
  const targetCase = targetCaseId || activeCase?.id || "";

  // Auto-detect format & obfuscation
  const inputType = useMemo(() => autoDetectInputType(input), [input]);
  const obfuscations = useMemo<ObfuscationCandidate[]>(() => detectObfuscation(input), [input]);

  // Modern DFIR Scored Observables
  const scoredObservables = useMemo<ScoredObservable[]>(() => {
    return extractObservables(input);
  }, [input]);

  // Legacy artifact analysis engine for correlations, findings, and MITRE mapping
  const result = useMemo(() => {
    const t = input.trim();
    if (!t) return null;
    return analyzeArtifact(t, { source: "parser", history: buildLocalHistory() });
  }, [input]);

  // Log mapping state
  const [mappingVersion, setMappingVersion] = useState(0);
  const fieldGuess = useMemo(() => detectLogFields(input), [input]);
  const storedMapping = useMemo(() => {
    void mappingVersion;
    return fieldGuess ? loadStoredMapping(fieldGuess.source) : null;
  }, [fieldGuess, mappingVersion]);
  const effective = useMemo(
    () => (fieldGuess ? effectiveMapping(fieldGuess, storedMapping) : {}),
    [fieldGuess, storedMapping]
  );
  const isCorrected = (f: SemanticField) =>
    !!fieldGuess && effective[f] !== undefined && fieldGuess.guess[f] !== effective[f];

  // Timeline import state
  const [timelineVersion, setTimelineVersion] = useState(0);
  const timelineGuess = useMemo(() => detectTimelineFields(input), [input]);
  const storedTimelineMapping = useMemo(() => {
    void timelineVersion;
    return timelineGuess ? loadStoredTimelineMapping(timelineGuess.source) : null;
  }, [timelineGuess, timelineVersion]);
  const effTimeline = useMemo(
    () => (timelineGuess ? effectiveTimelineMapping(timelineGuess, storedTimelineMapping) : {}),
    [timelineGuess, storedTimelineMapping]
  );
  const [importReport, setImportReport] = useState<TimelineImportReport | null>(null);

  // Deep scan mutation
  const deepScanMutation = useMutation({
    mutationFn: async ({ inputText, hasEmails }: { inputText: string; hasDomains: boolean; hasIps: boolean; hasEmails: boolean }) => {
      const r: Record<string, unknown> = {};
      const run = async (label: string, fn: () => Promise<unknown>) => {
        try { r[label] = await fn(); } catch { r[label] = { error: "unavailable" }; }
      };
      const promises: Promise<void>[] = [];
      if (hasEmails) {
        const lines = inputText.trim().split("\n");
        const headerEnd = lines.findIndex((l) => l.trim() === "");
        const headers = headerEnd > 0 ? lines.slice(0, headerEnd).join("\n") : inputText.trim();
        const body = headerEnd > 0 ? lines.slice(headerEnd).join("\n") : "";
        promises.push(run("phishing", () => analyzeFullEmail(headers, body, true)));
      }
      promises.push(run("mitre", () => mapMitre(inputText)));
      await Promise.all(promises);
      return r;
    },
    onSuccess: () => { notify.success("Deep scan complete"); },
    onError: (e) => { setDeepScanError(`Deep scan failed: ${(e as Error).message}`); },
  });

  // Track correlations
  useEffect(() => {
    if (result?.correlation?.length) rememberCorrelation(result.correlation, { source: "parser" });
  }, [result]);

  // Timeline push on extract
  const pushedRef = useRef(0);
  useEffect(() => {
    if (scoredObservables.length > 0 && pushedRef.current !== scoredObservables.length) {
      pushedRef.current = scoredObservables.length;
      pushTimelineEvent({
        source: "parser",
        verb: "extracted",
        detail: `Extracted ${scoredObservables.length} observables across ${new Set(scoredObservables.map((o) => o.type)).size} families`,
        result: `${scoredObservables.length} observables`,
      });
    }
  }, [scoredObservables]);

  // Recent inputs debounce
  useEffect(() => {
    if (!input.trim()) return;
    const timer = setTimeout(() => pushRecent(input), 2500);
    return () => clearTimeout(timer);
  }, [input, pushRecent]);

  // Copy helper
  const handleCopy = (k: string, text: string) => {
    try {
      copyText(text);
      setCopiedKey(k);
      notify.success("Copied to clipboard");
      setTimeout(() => setCopiedKey(""), 1200);
    } catch {
      notify.error("Copy failed");
    }
  };

  // Filtered observables
  const filteredObservables = useMemo(() => {
    let list = scoredObservables;
    if (activeTab !== "ALL") {
      list = list.filter((o) => o.type.toUpperCase() === activeTab.toUpperCase());
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      list = list.filter(
        (o) =>
          o.value.toLowerCase().includes(q) ||
          o.defanged.toLowerCase().includes(q) ||
          o.type.toLowerCase().includes(q) ||
          o.tags.some((t) => t.toLowerCase().includes(q))
      );
    }
    return list;
  }, [scoredObservables, activeTab, searchQuery]);

  // Category counts
  const categoryCounts = useMemo(() => {
    const map: Record<string, number> = { ALL: scoredObservables.length };
    for (const o of scoredObservables) {
      const k = o.type.toUpperCase();
      map[k] = (map[k] || 0) + 1;
    }
    return map;
  }, [scoredObservables]);

  // Observable metrics for KPI Ribbon
  const metrics = useMemo(() => {
    const total = scoredObservables.length;
    const criticalHigh = scoredObservables.filter((o) => o.severity === "critical" || o.severity === "high").length;
    const families = new Set(scoredObservables.map((o) => o.type)).size;
    const threatSignals = (result?.secrets.length || 0) + (result?.cmds.length || 0) + (result?.findings.length || 0);
    return { total, criticalHigh, families, threatSignals };
  }, [scoredObservables, result]);

  // Bulk selection toggles
  const toggleSelectAll = () => {
    if (selectedIds.size === filteredObservables.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filteredObservables.map((o) => o.id)));
    }
  };

  const toggleSelectOne = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // 1-Click Promote to Case
  const handlePromoteToCase = (subset?: ScoredObservable[]) => {
    const toPromote = subset ?? (selectedIds.size > 0
      ? scoredObservables.filter((o) => selectedIds.has(o.id))
      : scoredObservables);

    if (!toPromote.length) {
      notify.error("No observables selected to promote");
      return;
    }
    if (!targetCase) {
      notify.error("No target case available. Please select or create a case first.");
      return;
    }

    const { added, skipped } = promoteObservablesToCase(targetCase, toPromote);
    const caseTitle = cases.find((c) => c.id === targetCase)?.title ?? targetCase;

    if (added > 0) {
      notify.success(`Promoted ${added} observable${added === 1 ? "" : "s"} to ${caseTitle}`, {
        description: skipped > 0 ? `${skipped} already existed in case ledger` : undefined,
      });
      setSelectedIds(new Set());
    } else {
      notify.info("Observables already present in active case ledger");
    }
  };

  // De-obfuscation in place
  const applyDeobfuscation = (candidate: ObfuscationCandidate) => {
    setInput(candidate.decoded);
    notify.success(`Applied ${candidate.label}`);
  };

  // Timeline import execution
  const runTimelineImport = () => {
    if (!fieldGuess || !targetCase) return;
    const report = importCaseTimeline(targetCase, input, effTimeline);
    setImportReport(report);
    if (report.imported > 0) {
      notify.success(`Imported ${report.imported} timeline event${report.imported === 1 ? "" : "s"}`, {
        description: report.skipped.length ? `${report.skipped.length} row${report.skipped.length === 1 ? "" : "s"} skipped` : undefined,
      });
    } else {
      notify.error("Nothing imported", { description: report.skipped[0]?.reason });
    }
  };

  const hasIps = (result?.iocs.IPv4.length ?? 0) > 0;
  const hasDomains = (result?.iocs.Domain.length ?? 0) > 0;
  const hasEmails = (result?.iocs.Email.length ?? 0) > 0;
  const canDeepScan = hasIps || hasDomains || hasEmails;

  const handleDeepScan = useCallback(() => {
    if (!result) return;
    save({ artifact: input });
    setDeepScanError(null);
    deepScanMutation.mutate({
      inputText: input.trim(),
      hasDomains,
      hasIps,
      hasEmails,
    });
  }, [result, input, hasDomains, hasIps, hasEmails, deepScanMutation, save]);

  // Multi-format export trigger
  const triggerExport = (format: "csv" | "json" | "markdown" | "defanged") => {
    const list = selectedIds.size > 0
      ? scoredObservables.filter((o) => selectedIds.has(o.id))
      : scoredObservables;

    if (!list.length) {
      notify.error("No observables to export");
      return;
    }

    let content = "";
    let filename = `observables-${Date.now()}`;
    let mimeType = "text/plain";

    if (format === "csv") {
      content = exportObservablesCsv(list);
      filename += ".csv";
      mimeType = "text/csv;charset=utf-8;";
    } else if (format === "json") {
      content = exportObservablesJson(list, { inputChars: input.length, detectedFamily: inputType?.label });
      filename += ".json";
      mimeType = "application/json;charset=utf-8;";
    } else if (format === "markdown") {
      content = exportObservablesMarkdown(list, `Observables Export — ${inputType?.label ?? "Artifact"}`);
      filename += ".md";
      mimeType = "text/markdown;charset=utf-8;";
    } else if (format === "defanged") {
      content = exportObservablesDefangedList(list);
      filename += "-defanged.txt";
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    setShowExportMenu(false);
    notify.success(`Exported ${list.length} observables as ${format.toUpperCase()}`);
  };

  return (
    <ErrorBoundary name="ParserPage">
      <PageShell
        eyebrow="investigation / forensic / Parser"
        title="Universal Log Parser & IOC Station"
        description="Freeform artifact de-obfuscation, deep observable extraction, threat scoring, and case ledger synchronization."
        crumbs={[{ label: "Forensics" }, { label: "Parser" }]}
      >
        <EntityHeader
          variant="case"
          title="Universal Log Parser & IOC Station"
          tags={[inputType?.label ?? "Forensic Intake"]}
        />

        {pending && (
          <ResumeBanner
            artifact={pending.artifact}
            updatedAt={pending.updatedAt}
            onResume={() => {
              const s = accept();
              if (s) setInput(s.artifact);
            }}
            onStartFresh={clear}
          />
        )}

        {/* ── 4-Tile DFIR KPI Ribbon ── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <MetricTile
            label="Total Observables"
            value={String(metrics.total)}
            hint={metrics.total > 0 ? `${metrics.families} distinct types` : "Awaiting artifact"}
            icon={Layers}
            tone={metrics.total > 0 ? "primary" : undefined}
          />
          <MetricTile
            label="High & Critical Risk"
            value={String(metrics.criticalHigh)}
            hint={metrics.criticalHigh > 0 ? "Actionable indicators" : "No high-risk flags"}
            icon={ShieldAlert}
            tone={metrics.criticalHigh > 0 ? "destructive" : undefined}
          />
          <MetricTile
            label="Format Detection"
            value={inputType?.label ?? (input.trim() ? "Unknown Grammar" : "Idle")}
            hint={inputType ? `Confidence: ${inputType.level}` : "Paste any raw artifact"}
            icon={FileText}
            tone={inputType ? "success" : undefined}
          />
          <MetricTile
            label="Adversary Signals"
            value={String(metrics.threatSignals)}
            hint={metrics.threatSignals > 0 ? "Secrets, LOLBins & findings" : "Clean baseline"}
            icon={AlertTriangle}
            tone={metrics.threatSignals > 0 ? "warning" : undefined}
          />
        </div>

        {/* ── Main Dual-Pane Cockpit ── */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">

          {/* ══ LEFT COLUMN: Intake & De-obfuscation Station (5 cols) ══ */}
          <div className="lg:col-span-5 space-y-4 min-w-0">
            <SectionBar
              id="INTAKE"
              label="Intake & De-obfuscation Station"
              meta={`${input.length.toLocaleString()} chars · ${input.split("\n").length} lines`}
              action={
                inputType && (
                  <span className="inline-flex items-center gap-1.5">
                    <Chip tone={inputType.tone}>{inputType.label}</Chip>
                    <Chip tone={inputType.level === "high" ? "success" : inputType.level === "medium" ? "warning" : "default"}>
                      {inputType.level}
                    </Chip>
                  </span>
                )
              }
            />

            {/* ── Log Schema Auto-Detection Banner ── */}
            {fieldGuess && (
              <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs text-foreground">
                <div className="flex items-center gap-2">
                  <Database className="h-4 w-4 text-primary shrink-0" />
                  <span>
                    <strong className="text-primary uppercase font-bold">{fieldGuess.source}</strong> Schema Auto-Detected ({fieldGuess.columns.length} columns recognized)
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-1.5">
                  {Object.entries(fieldGuess.guess).map(([sem, col]) => (
                    <span key={sem} className="rounded bg-surface-2 px-1.5 py-0.5 text-mono ba-text-3xs text-foreground border border-subtle">
                      <span className="text-primary font-bold">{sem}</span>: {col}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* ── Obfuscation Detection Alert Banner ── */}
            {obfuscations.length > 0 && (
              <div className="rounded-lg border border-warning/40 bg-warning/5 p-3 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-warning">
                    <Zap className="h-4 w-4 shrink-0 animate-pulse" />
                    <span className="text-mono ba-text-xs font-semibold">
                      Detected {obfuscations.length} Obfuscated Payload{obfuscations.length > 1 ? "s" : ""}
                    </span>
                  </div>
                  <span className="text-mono ba-text-3xs text-muted-foreground">in-memory decoding</span>
                </div>
                {obfuscations.map((c, idx) => (
                  <div key={idx} className="flex flex-col gap-1.5 rounded border border-warning/25 bg-surface-0/80 p-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-mono ba-text-2xs font-semibold text-foreground">{c.label}</span>
                      <button
                        onClick={() => applyDeobfuscation(c)}
                        className="inline-flex items-center gap-1 rounded border border-warning/50 bg-warning/15 px-2 py-0.5 text-mono ba-text-3xs font-semibold text-warning hover:bg-warning/25 transition-colors"
                      >
                        <Zap className="h-3 w-3" /> De-obfuscate in Place
                      </button>
                    </div>
                    <p className="ba-text-3xs text-muted-foreground">{c.description}</p>
                    <pre className="max-h-16 overflow-x-auto rounded bg-surface-1 p-1.5 text-mono ba-text-3xs text-fg-dim border border-subtle">
                      {c.decoded.slice(0, 160)}{c.decoded.length > 160 ? "…" : ""}
                    </pre>
                  </div>
                ))}
              </div>
            )}

            {/* ── De-obfuscation Quick Toolbar ── */}
            <div className="rounded-md border border-subtle bg-surface-1 px-3 py-2 space-y-1.5">
              <div className="flex items-center justify-between text-mono ba-text-3xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Terminal className="h-3 w-3 text-primary" /> De-obfuscation Helpers
                </span>
                <span>freeform tools</span>
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                <button
                  onClick={() => {
                    const dec = decodeBase64(input.trim());
                    if (dec) { setInput(dec); notify.success("Decoded Base64 (UTF-8)"); }
                    else notify.error("Invalid Base64 payload");
                  }}
                  disabled={!input.trim()}
                  className="rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-3xs text-foreground hover:border-primary/50 hover:bg-primary/5 disabled:opacity-40 transition-colors"
                >
                  Base64 (UTF-8)
                </button>
                <button
                  onClick={() => {
                    const dec = decodePowerShell(input.trim());
                    if (dec) { setInput(dec); notify.success("Decoded PowerShell (UTF-16LE)"); }
                    else notify.error("Could not decode as PowerShell UTF-16LE");
                  }}
                  disabled={!input.trim()}
                  className="rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-3xs text-foreground hover:border-primary/50 hover:bg-primary/5 disabled:opacity-40 transition-colors"
                >
                  PS (UTF-16LE)
                </button>
                <button
                  onClick={() => {
                    const dec = decodeUrl(input.trim());
                    setInput(dec);
                    notify.success("Decoded URL Percent-Encoding");
                  }}
                  disabled={!input.trim()}
                  className="rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-3xs text-foreground hover:border-primary/50 hover:bg-primary/5 disabled:opacity-40 transition-colors"
                >
                  URL Decode
                </button>
                <button
                  onClick={() => {
                    const dec = decodeHex(input.trim());
                    if (dec && dec !== input.trim()) { setInput(dec); notify.success("Decoded Hex String"); }
                    else notify.error("No valid hex byte sequence found");
                  }}
                  disabled={!input.trim()}
                  className="rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-3xs text-foreground hover:border-primary/50 hover:bg-primary/5 disabled:opacity-40 transition-colors"
                >
                  Hex → ASCII
                </button>
                <button
                  onClick={() => {
                    const dec = decodeRot13(input.trim());
                    setInput(dec);
                    notify.success("Applied ROT13");
                  }}
                  disabled={!input.trim()}
                  className="rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-3xs text-foreground hover:border-primary/50 hover:bg-primary/5 disabled:opacity-40 transition-colors"
                >
                  ROT13
                </button>
                <button
                  onClick={() => {
                    const dec = reverseText(input.trim());
                    setInput(dec);
                    notify.success("Reversed Text");
                  }}
                  disabled={!input.trim()}
                  className="rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-3xs text-foreground hover:border-primary/50 hover:bg-primary/5 disabled:opacity-40 transition-colors"
                >
                  Reverse
                </button>
                <a
                  href={generateCyberChefUrl(input.trim())}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="ml-auto inline-flex items-center gap-1 rounded border border-primary/30 bg-primary/10 px-2 py-1 text-mono ba-text-3xs text-primary hover:bg-primary/20 transition-colors"
                >
                  CyberChef <ExternalLink className="h-2.5 w-2.5" />
                </a>
              </div>
            </div>

            {/* ── Raw Intake Card ── */}
            <IntakeCard
              icon={Terminal}
              title="Forensic Intake Buffer"
              value={input}
              onChange={(t) => { setInput(t); deepScanMutation.reset(); }}
              onPaste={(t) => setInput(t)}
              samples={[
                { key: "ransom_note", label: "Ransomware Note", hint: "BTC/XMR wallets, regkey, UNC" },
                { key: "cloud_trail", label: "AWS CloudTrail", hint: "AWS ARNs, JWT, IP, S3" },
                { key: "phishing", label: "Phishing Email", hint: "headers + suspicious link" },
                { key: "powershell", label: "PowerShell Encoded", hint: "Base64 -EncodedCommand" },
                { key: "sysmon", label: "Sysmon EVTX", hint: "EID 1 process creation" },
                { key: "zeek", label: "Zeek conn.log", hint: "TSV network connection log" },
                { key: "nginx", label: "Nginx Access Log", hint: "HTTP web access requests" },
                { key: "windows", label: "Windows 4688", hint: "EID 4688 process creation" },
                { key: "suricata", label: "Suricata EVE", hint: "JSON IDS security alert" },
                { key: "access", label: "Web Log SQLi", hint: "SQL injection probe" },
                { key: "secrets", label: "Code w/ Secrets", hint: "API keys & credentials" },
                { key: "sigma", label: "Sigma Rule", hint: "PowerShell detection rule" },
                { key: "headers", label: "Email Headers", hint: "SPF, DKIM, DMARC auth" },
                { key: "ioc_list", label: "Mixed IOC Sheet", hint: "IPs, hashes, domains, CVEs" },
                { key: "linux", label: "Linux SSH Auth", hint: "sshd failed / accepted logins" },
                { key: "csv", label: "CSV IOC Sheet", hint: "type, value, source, note" },
              ]}
              onLoadSample={(k) => setInput(SAMPLES[k]?.text ?? "")}
              onFile={(txt) => setInput(txt)}
              run={{
                label: "clear",
                icon: X,
                onClick: () => {
                  setInput("");
                  deepScanMutation.reset();
                  clear();
                  notify.info("Buffer cleared");
                },
                disabled: !input.trim(),
              }}
            />

            {/* ── Recent Inputs Pill Strip ── */}
            {recentItems.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 rounded border border-subtle bg-surface-1 px-2.5 py-1.5">
                <span className="text-mono ba-text-3xs text-muted-foreground">recent:</span>
                {recentItems.slice(0, 5).map((item, i) => (
                  <button
                    key={i}
                    onClick={() => { setInput(item); pushRecent(item); }}
                    className="max-w-[140px] truncate rounded border border-subtle bg-surface-0 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:border-primary/40 hover:text-primary transition-colors"
                    title={item}
                  >
                    {item.slice(0, 32)}{item.length > 32 ? "…" : ""}
                  </button>
                ))}
                <button onClick={clearRecent} className="ml-auto text-mono ba-text-3xs text-muted-foreground hover:text-destructive">
                  clear
                </button>
              </div>
            )}

            {/* ── Deep Scan Trigger ── */}
            {canDeepScan && (
              <div className="flex items-center justify-between rounded-lg border border-dashed border-primary/40 bg-primary/[0.03] p-3">
                <div className="flex items-center gap-2.5">
                  <Scan className="h-4 w-4 text-primary shrink-0" />
                  <div>
                    <span className="text-mono ba-text-2xs font-semibold text-primary">Deep Forensic Scan</span>
                    <p className="ba-text-3xs text-muted-foreground">
                      Header auth verification & MITRE API technique correlation.
                    </p>
                  </div>
                </div>
                <button
                  onClick={handleDeepScan}
                  disabled={deepScanMutation.isPending}
                  className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs font-medium text-primary hover:bg-primary/20 disabled:opacity-40 shrink-0 transition-colors"
                >
                  {deepScanMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Scan className="h-3 w-3" />}
                  {deepScanMutation.isPending ? "Scanning..." : "Deep Scan"}
                </button>
              </div>
            )}
          </div>

          {/* ══ RIGHT COLUMN: Observable Command Deck & Analysis Workbench (7 cols) ══ */}
          <div className="lg:col-span-7 space-y-4 min-w-0">
            <SectionBar
              id="COMMAND_DECK"
              label="Observable Command Deck"
              meta={`${filteredObservables.length} observable${filteredObservables.length === 1 ? "" : "s"} visible`}
              action={
                result ? (
                  <AttachButton
                    body={JSON.stringify(scoredObservables, null, 2)}
                    kind="evidence"
                    source="/parser"
                  />
                ) : undefined
              }
            />

            {/* ── Toolbar: Search, Filters & Bulk Actions ── */}
            <div className="rounded-lg border border-subtle bg-surface-1 p-3 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2.5">
                {/* Search Bar */}
                <div className="relative flex-1 min-w-[220px]">
                  <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                  <input
                    ref={searchInputRef}
                    type="text"
                    placeholder="Filter observables or tags... (Press '/' to focus)"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full rounded-md border border-subtle bg-surface-0 pl-8 pr-7 py-1.5 text-mono ba-text-xs text-foreground placeholder:text-muted-foreground outline-none focus:border-primary/60 transition-colors"
                  />
                  {searchQuery && (
                    <button
                      onClick={() => setSearchQuery("")}
                      className="absolute right-2 top-2 text-muted-foreground hover:text-foreground"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>

                {/* Defang / Raw Toggle */}
                <div className="flex items-center rounded border border-subtle bg-surface-0 p-0.5">
                  <button
                    onClick={() => setDefanged(true)}
                    className={`px-2 py-0.5 text-mono ba-text-2xs rounded transition-colors ${
                      defanged ? "bg-primary/15 text-primary font-semibold" : "text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    defanged
                  </button>
                  <button
                    onClick={() => setDefanged(false)}
                    className={`px-2 py-0.5 text-mono ba-text-2xs rounded transition-colors ${
                      !defanged ? "bg-primary/15 text-primary font-semibold" : "text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    raw
                  </button>
                </div>

                {/* Bulk Actions */}
                <div className="flex items-center gap-1.5 relative">
                  {/* 1-Click Promote to Case */}
                  <button
                    onClick={() => handlePromoteToCase()}
                    disabled={filteredObservables.length === 0}
                    className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs font-medium text-primary hover:bg-primary/20 disabled:opacity-40 transition-colors"
                    title={`Add ${selectedIds.size > 0 ? selectedIds.size : filteredObservables.length} observable(s) to active case`}
                  >
                    <ShieldCheck className="h-3.5 w-3.5" />
                    {selectedIds.size > 0 ? `Add Selected (${selectedIds.size})` : "Add All to Case"}
                  </button>

                  {/* Target Case Selector */}
                  {cases.length > 1 && (
                    <select
                      aria-label="Target Case"
                      value={targetCase}
                      onChange={(e) => setTargetCaseId(e.target.value)}
                      className="max-w-[120px] truncate rounded border border-subtle bg-surface-0 px-1.5 py-1 text-mono ba-text-3xs text-foreground outline-none"
                    >
                      {cases.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.title}
                        </option>
                      ))}
                    </select>
                  )}

                  {/* Export Dropdown */}
                  <div className="relative">
                    <button
                      onClick={() => setShowExportMenu(!showExportMenu)}
                      disabled={filteredObservables.length === 0}
                      className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground disabled:opacity-40 transition-colors"
                    >
                      <Download className="h-3.5 w-3.5" /> Export <ChevronDown className="h-3 w-3" />
                    </button>
                    {showExportMenu && (
                      <div className="absolute right-0 top-full mt-1 z-30 w-44 rounded-md border border-subtle bg-surface-0 shadow-lg p-1 space-y-0.5">
                        <button
                          onClick={() => triggerExport("csv")}
                          className="w-full text-left rounded px-2 py-1.5 text-mono ba-text-2xs hover:bg-surface-1 text-foreground transition-colors"
                        >
                          CSV (RFC 4180)
                        </button>
                        <button
                          onClick={() => triggerExport("json")}
                          className="w-full text-left rounded px-2 py-1.5 text-mono ba-text-2xs hover:bg-surface-1 text-foreground transition-colors"
                        >
                          JSON Artifact
                        </button>
                        <button
                          onClick={() => triggerExport("markdown")}
                          className="w-full text-left rounded px-2 py-1.5 text-mono ba-text-2xs hover:bg-surface-1 text-foreground transition-colors"
                        >
                          Markdown Table
                        </button>
                        <button
                          onClick={() => triggerExport("defanged")}
                          className="w-full text-left rounded px-2 py-1.5 text-mono ba-text-2xs hover:bg-surface-1 text-foreground transition-colors"
                        >
                          Defanged Text List
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* ── Category Pill Filter Strip ── */}
              <div className="flex flex-wrap items-center gap-1 border-t border-subtle pt-2.5">
                {Object.entries(categoryCounts).map(([cat, count]) => {
                  const isActive = activeTab.toUpperCase() === cat.toUpperCase();
                  return (
                    <button
                      key={cat}
                      onClick={() => setActiveTab(cat)}
                      className={`rounded px-2 py-0.5 text-mono ba-text-3xs font-medium transition-colors ${
                        isActive
                          ? "bg-primary text-primary-foreground font-semibold"
                          : "bg-surface-0 text-muted-foreground hover:bg-surface-2 hover:text-foreground border border-subtle"
                      }`}
                    >
                      {cat.toLowerCase()} <span className="opacity-75">({count})</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* ── Interactive Observable Inventory Table ── */}
            {filteredObservables.length === 0 ? (
              <div className="rounded-lg border border-dashed border-subtle p-8 text-center space-y-2">
                <SlidersHorizontal className="mx-auto h-6 w-6 text-muted-foreground/60" />
                <p className="text-mono ba-text-sm text-muted-foreground">
                  {scoredObservables.length === 0
                    ? "No observables extracted yet. Paste or load an artifact in the intake station."
                    : "No observables match the current category or search filters."}
                </p>
                {scoredObservables.length > 0 && (
                  <button
                    onClick={() => { setActiveTab("ALL"); setSearchQuery(""); }}
                    className="text-mono ba-text-2xs text-primary hover:underline"
                  >
                    Reset filters
                  </button>
                )}
              </div>
            ) : (
              <div className="rounded-lg border border-subtle bg-surface-0 overflow-hidden">
                {/* Table Header with select all */}
                <div className="flex items-center justify-between border-b border-subtle bg-surface-1 px-3 py-2 text-mono ba-text-3xs text-muted-foreground">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={toggleSelectAll}
                      className="text-muted-foreground hover:text-foreground transition-colors"
                      title={selectedIds.size === filteredObservables.length ? "Deselect All" : "Select All"}
                    >
                      {selectedIds.size === filteredObservables.length ? (
                        <CheckSquare className="h-3.5 w-3.5 text-primary" />
                      ) : (
                        <Square className="h-3.5 w-3.5" />
                      )}
                    </button>
                    <span>
                      {selectedIds.size > 0 ? `${selectedIds.size} selected` : "Observable Indicator"}
                    </span>
                  </div>
                  <div className="flex items-center gap-4">
                    <span>Type</span>
                    <span>Risk Score</span>
                    <span>Actions</span>
                  </div>
                </div>

                {/* Table Body */}
                <div className="max-h-[620px] overflow-y-auto divide-y divide-subtle">
                  {filteredObservables.map((o) => {
                    const meta = KIND_META[o.type] ?? { icon: Hash, tone: "default" };
                    const Icon = meta.icon;
                    const isSelected = selectedIds.has(o.id);
                    const displayVal = defanged ? o.defanged : o.raw;

                    return (
                      <div
                        key={o.id}
                        className={`group flex items-start justify-between gap-3 px-3 py-2.5 transition-colors ${
                          isSelected ? "bg-primary/[0.04]" : "hover:bg-surface-1/60"
                        }`}
                      >
                        {/* Select checkbox & Value */}
                        <div className="flex items-start gap-2.5 min-w-0 flex-1">
                          <button
                            onClick={() => toggleSelectOne(o.id)}
                            className="mt-0.5 text-muted-foreground hover:text-foreground transition-colors"
                          >
                            {isSelected ? (
                              <CheckSquare className="h-3.5 w-3.5 text-primary" />
                            ) : (
                              <Square className="h-3.5 w-3.5" />
                            )}
                          </button>
                          <div className="min-w-0 flex-1 space-y-1">
                            <div className="flex items-center gap-1.5">
                              <code
                                className="text-mono ba-text-xs font-medium text-foreground break-all select-all hover:text-primary transition-colors cursor-pointer"
                                onClick={() => handleCopy(o.id, displayVal)}
                                title="Click to copy value"
                              >
                                {displayVal}
                              </code>
                              <button
                                onClick={() => handleCopy(o.id, displayVal)}
                                className="opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-foreground transition-opacity"
                                title="Copy to clipboard"
                              >
                                {copiedKey === o.id ? (
                                  <Check className="h-3 w-3 text-success" />
                                ) : (
                                  <Copy className="h-3 w-3" />
                                )}
                              </button>
                            </div>

                            {/* Tags */}
                            {o.tags.length > 0 && (
                              <div className="flex flex-wrap items-center gap-1">
                                {o.tags.map((tag, tIdx) => (
                                  <span
                                    key={tIdx}
                                    className="rounded border border-subtle bg-surface-1 px-1.5 py-0.2 text-mono ba-text-3xs text-muted-foreground"
                                  >
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Type, Score & Actions */}
                        <div className="flex items-center gap-3 shrink-0">
                          {/* Type Pill */}
                          <span className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-0.5 text-mono ba-text-3xs text-fg-dim">
                            <Icon className="h-3 w-3 text-primary/80" />
                            {o.type}
                          </span>

                          {/* Risk Score Badge */}
                          <span
                            className={`rounded px-1.5 py-0.5 text-mono ba-text-3xs font-semibold ${
                              o.score >= 80
                                ? "bg-destructive/15 text-destructive border border-destructive/30"
                                : o.score >= 60
                                ? "bg-warning/15 text-warning border border-warning/30"
                                : o.score >= 40
                                ? "bg-warning/10 text-warning/90 border border-warning/20"
                                : "bg-surface-2 text-muted-foreground border border-subtle"
                            }`}
                            title={`Risk Score: ${o.score}/100 (${o.severity})`}
                          >
                            {o.score}
                          </span>

                          {/* Action Buttons */}
                          <div className="flex items-center gap-1">
                            {/* 1-Click Add to Case */}
                            <button
                              onClick={() => handlePromoteToCase([o])}
                              className="rounded border border-subtle bg-surface-1 p-1 text-muted-foreground hover:border-primary/40 hover:text-primary transition-colors"
                              title="Add this observable to active case"
                            >
                              <ShieldCheck className="h-3 w-3" />
                            </button>

                            {/* Pivot Route */}
                            {o.pivotRoute && (
                              <Link
                                to={o.pivotRoute as any}
                                search={{ q: o.raw } as any}
                                className="rounded border border-subtle bg-surface-1 p-1 text-muted-foreground hover:border-primary/40 hover:text-primary transition-colors"
                                title={`Pivot to ${o.pivotRoute}`}
                              >
                                <CornerDownRight className="h-3 w-3" />
                              </Link>
                            )}

                            {/* Locker */}
                            <button
                              onClick={() => {
                                locker.add({ value: o.raw, type: o.type.toLowerCase() as LockerItem["type"], source: "/parser" });
                                notify.success("Added to locker");
                              }}
                              className="rounded border border-subtle bg-surface-1 p-1 text-muted-foreground hover:border-primary/40 hover:text-primary transition-colors"
                              title="Save to session locker"
                            >
                              <Hash className="h-3 w-3" />
                            </button>

                            {/* OSINT Tools Menu */}
                            {OSINT_TOOLS_PER_KIND[o.type] && (
                              <div className="relative">
                                <button
                                  onClick={() => setShowOsintMenu(showOsintMenu === o.id ? null : o.id)}
                                  className="rounded border border-subtle bg-surface-1 p-1 text-muted-foreground hover:border-primary/40 hover:text-primary transition-colors"
                                  title="OSINT Lookups"
                                >
                                  <Globe className="h-3 w-3" />
                                </button>
                                {showOsintMenu === o.id && (
                                  <div className="absolute right-0 top-full mt-1 z-30 w-36 rounded-md border border-subtle bg-surface-0 shadow-lg p-1 space-y-0.5">
                                    {OSINT_TOOLS_PER_KIND[o.type].map((tool) => (
                                      <a
                                        key={tool.label}
                                        href={tool.url(o.raw)}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="flex items-center justify-between rounded px-2 py-1 text-mono ba-text-3xs text-foreground hover:bg-surface-1 transition-colors"
                                      >
                                        <span>{tool.label}</span>
                                        <ExternalLink className="h-2.5 w-2.5 text-muted-foreground" />
                                      </a>
                                    ))}
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ══ Collapsible Deep Forensic Intelligence Panels ══ */}
        <div className="space-y-4 pt-2">

          {/* 1. Log Field Mapping (when structured logs detected) */}
          {fieldGuess && (
            <Panel
              title="Log Field Mapping & Structured Normalizer"
              meta={`${fieldGuess.source} · ${fieldGuess.columns.length} columns`}
              collapsible
              storageKey="ba.panel.parser.mapping"
            >
              <p className="mb-2 text-mono ba-text-2xs text-muted-foreground">
                Auto-guessed from column headers and keys. Persists mapping fixes locally for this format grammar.
              </p>
              <div className="grid gap-2 grid-cols-1 md:grid-cols-5">
                {SEMANTIC_FIELDS.map((f) => {
                  const val = effective[f];
                  const conf: GuessConfidence | undefined = fieldGuess.confidence[f];
                  return (
                    <div key={f} className={"rounded border p-2 " + (isCorrected(f) ? "border-info/40 bg-info/5" : val ? "border-subtle bg-surface-1" : "border-dashed border-subtle")}>
                      <div className="mb-1 flex items-center justify-between gap-1">
                        <span className="font-mono ba-text-3xs uppercase text-muted-foreground">{f}</span>
                        {isCorrected(f)
                          ? <Chip tone="primary">corrected</Chip>
                          : conf ? <Chip tone={conf === "high" ? "success" : conf === "medium" ? "warning" : "default"}>{conf}</Chip>
                          : <Chip tone="default">—</Chip>}
                      </div>
                      <select
                        aria-label={`mapping for ${f}`}
                        value={val ?? ""}
                        onChange={(e) => {
                          saveFieldMapping(fieldGuess.source, f, e.target.value || null);
                          setMappingVersion((v) => v + 1);
                        }}
                        className="w-full rounded border border-subtle bg-surface-0 px-1.5 py-1 font-mono ba-text-2xs text-foreground outline-none focus:border-primary/50"
                      >
                        <option value="">— unmapped</option>
                        {fieldGuess.columns.map((c) => <option key={c} value={c}>{c}</option>)}
                      </select>
                    </div>
                  );
                })}
              </div>

              {/* Mapped Row Preview */}
              {(() => {
                const rows = input.split(/\r?\n/).filter((l) => l.trim() && !l.startsWith("#")).slice(0, 3);
                const mapped = SEMANTIC_FIELDS.filter((f) => effective[f]);
                if (mapped.length === 0 || rows.length === 0) return null;
                return (
                  <div className="mt-3 overflow-x-auto">
                    <table className="w-full border-collapse">
                      <thead>
                        <tr>
                          {mapped.map((f) => (
                            <th key={f} className="border-b border-subtle px-2 py-1 text-left font-mono ba-text-3xs uppercase text-muted-foreground">
                              {f}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {rows.map((row, i) => (
                          <tr key={i}>
                            {mapped.map((f) => (
                              <td key={f} className="max-w-[220px] truncate border-b border-subtle/50 px-2 py-1 font-mono ba-text-2xs text-fg-dim" title={extractValue(row, fieldGuess.source, effective[f]!) ?? undefined}>
                                {extractValue(row, fieldGuess.source, effective[f]!) ?? "—"}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    <p className="mt-1.5 text-mono ba-text-3xs text-muted-foreground/70">first 3 data rows · preview of mapped values</p>
                  </div>
                );
              })()}
            </Panel>
          )}

          {/* 2. Timeline Event Importer */}
          {fieldGuess && timelineGuess && (
            <Panel
              title="Forensic Timeline Importer"
              meta={`${fieldGuess.source} · raw rows → case timeline`}
              collapsible
              storageKey="ba.panel.parser.timeline"
            >
              <p className="mb-2 text-mono ba-text-2xs text-muted-foreground">
                Map row fields onto case chronicle timeline events. Validates timestamp integrity and rejects corrupted lines.
              </p>
              <div className="grid gap-2 grid-cols-1 md:grid-cols-4">
                {TIMELINE_FIELDS.map((f) => {
                  const val = effTimeline[f];
                  const conf: GuessConfidence | undefined = timelineGuess.confidence[f];
                  const corrected = val !== undefined && timelineGuess.guess[f] !== val;
                  return (
                    <div key={f} className={"rounded border p-2 " + (corrected ? "border-info/40 bg-info/5" : val ? "border-subtle bg-surface-1" : "border-dashed border-subtle")}>
                      <div className="mb-1 flex items-center justify-between gap-1">
                        <span className="font-mono ba-text-3xs uppercase text-muted-foreground">{f}</span>
                        {corrected
                          ? <Chip tone="primary">corrected</Chip>
                          : conf ? <Chip tone={conf === "high" ? "success" : conf === "medium" ? "warning" : "default"}>{conf}</Chip>
                          : <Chip tone="default">—</Chip>}
                      </div>
                      <select
                        aria-label={`timeline field for ${f}`}
                        value={val ?? ""}
                        onChange={(e) => {
                          saveTimelineMapping(fieldGuess.source, f, e.target.value || null);
                          setTimelineVersion((v) => v + 1);
                        }}
                        className="w-full rounded border border-subtle bg-surface-0 px-1.5 py-1 font-mono ba-text-2xs text-foreground outline-none focus:border-primary/50"
                      >
                        <option value="">— unmapped</option>
                        {fieldGuess.columns.map((c) => <option key={c} value={c}>{c}</option>)}
                      </select>
                    </div>
                  );
                })}
              </div>

              <div className="mt-3 flex flex-wrap items-center gap-2">
                <button
                  onClick={runTimelineImport}
                  disabled={!effTimeline.ts || !targetCase}
                  className="rounded border border-primary/40 bg-primary/10 px-3 py-1 font-mono ba-text-2xs text-primary hover:bg-primary/20 disabled:pointer-events-none disabled:opacity-40 transition-colors"
                >
                  Import Rows → {targetCase ? cases.find((c) => c.id === targetCase)?.title ?? "Selected Case" : "Select Case"}
                </button>
                {!effTimeline.ts && <span className="text-mono ba-text-3xs text-warning">Timestamp mapping required</span>}
              </div>

              {importReport && (
                <p className="mt-1.5 text-mono ba-text-3xs text-muted-foreground">
                  Last import: {importReport.imported} added · {importReport.skipped.length} skipped
                  {importReport.skipped.slice(0, 3).map((s) => ` · row ${s.row}: ${s.reason}`).join("")}
                </p>
              )}
            </Panel>
          )}

          {/* 3. Adversary Command Lines & Secrets Review */}
          {(result?.secrets.length || 0) > 0 || (result?.cmds.length || 0) > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {result && result.secrets.length > 0 && (
                <EntitySection title="Credentials & Secrets Exposed" icon={Key} meta={`${result.secrets.length} exposed tokens`}>
                  <div className="space-y-1.5">
                    {result.secrets.map((s, i) => (
                      <div key={i} className="flex items-center justify-between gap-2 rounded border border-destructive/30 bg-destructive/5 px-2.5 py-1.5 min-w-0">
                        <span className="text-mono ba-text-2xs text-destructive shrink-0">{s.type}</span>
                        <code className="text-mono ba-text-xs text-foreground select-all truncate min-w-0 flex-1" title={s.value}>{s.value}</code>
                        <button
                          onClick={() => handleCopy(`sec-${i}`, s.value)}
                          className="text-muted-foreground hover:text-foreground shrink-0"
                          title="Copy secret"
                        >
                          {copiedKey === `sec-${i}` ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                        </button>
                      </div>
                    ))}
                  </div>
                </EntitySection>
              )}

              {result && result.cmds.length > 0 && (
                <EntitySection title="LOLBins & Command Analysis" icon={Terminal} meta={`${result.cmds.length} findings`}>
                  <div className="space-y-1.5">
                    {result.cmds.map((c, i) => (
                      <div key={i} className="flex items-center gap-2 rounded border border-warning/30 bg-warning/5 px-2.5 py-1.5 min-w-0">
                        <ShieldAlert className="h-3.5 w-3.5 text-warning shrink-0" />
                        <span className="text-mono ba-text-2xs font-semibold text-warning shrink-0">{c.type}</span>
                        <span className="text-mono ba-text-xs text-foreground truncate min-w-0 flex-1" title={c.detail}>{c.detail}</span>
                      </div>
                    ))}
                  </div>
                </EntitySection>
              )}
            </div>
          ) : null}

          {/* 4. MITRE ATT&CK Matrix */}
          {result && result.mitre.length > 0 && (
            <EntitySection title="MITRE ATT&CK Mapping" icon={Crosshair} meta={`${result.mitre.length} techniques identified`}>
              <div className="grid gap-2 grid-cols-1 sm:grid-cols-2 md:grid-cols-3">
                {result.mitre.map((m) => (
                  <div key={m.technique} className="flex items-center gap-2.5 rounded border border-subtle bg-surface-1 px-3 py-2">
                    <span className="grid h-7 w-7 place-items-center rounded border border-destructive/40 bg-destructive/10">
                      <Crosshair className="h-3.5 w-3.5 text-destructive" />
                    </span>
                    <div className="min-w-0">
                      <div className="text-mono ba-text-2xs font-semibold text-destructive">{m.technique}</div>
                      <div className="truncate text-mono ba-text-xs text-foreground">{m.name}</div>
                      <div className="mt-0.5 flex flex-wrap items-center gap-1">
                        <Chip tone="info">{m.tactic}</Chip>
                        {m.confidence && m.confidence.level !== "unknown" && (
                          <Chip tone="primary">{m.confidence.level}</Chip>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </EntitySection>
          )}

          {/* 5. Deep Scan Results */}
          {deepScanError && (
            <div className="rounded border border-destructive/40 bg-destructive/5 p-3 text-mono ba-text-sm text-destructive">
              {deepScanError}
            </div>
          )}
          {Boolean(deepScanMutation.data) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Boolean(deepScanMutation.data?.phishing && !(deepScanMutation.data.phishing as Record<string, string>).error) && (
                <EntitySection title="Phishing Authentication Verdict" icon={Mail} meta="from deep scan">
                  <div className="space-y-1">
                    {[
                      ["Verdict", (deepScanMutation.data?.phishing as Record<string, string>)?.verdict],
                      ["SPF", (deepScanMutation.data?.phishing as any)?.authentication?.spf],
                      ["DKIM", (deepScanMutation.data?.phishing as any)?.authentication?.dkim],
                      ["DMARC", (deepScanMutation.data?.phishing as any)?.authentication?.dmarc],
                    ].filter(([, v]) => v).map(([k, v]) => (
                      <div key={k} className="flex items-center justify-between text-mono ba-text-xs py-0.5 border-b border-subtle/40">
                        <span className="text-muted-foreground">{k}</span>
                        <span className="text-foreground font-semibold">{v}</span>
                      </div>
                    ))}
                  </div>
                </EntitySection>
              )}
              {Boolean(deepScanMutation.data?.mitre && !(deepScanMutation.data.mitre as Record<string, string>).error) && (
                <EntitySection title="Enriched MITRE Detections" icon={Crosshair} meta="from deep scan">
                  <div className="flex flex-wrap gap-1.5">
                    {((deepScanMutation.data?.mitre as any)?.matches ?? []).map((m: any) => (
                      <Chip key={m.technique_id} tone="warning">
                        {m.technique_id} — {m.technique}
                      </Chip>
                    ))}
                  </div>
                </EntitySection>
              )}
            </div>
          )}

          {/* 6. Universal Handoff Row */}
          <div className="pt-2">
            <SendToRow
              targets={[
                { label: "SIEM Workspace", to: "/siem", icon: Database },
                { label: "Phishing Triage", to: "/phishing", icon: Mail },
                { label: "Safe URL Analyzer", to: "/url", icon: Link2 },
                { label: "Malware & File", to: "/file", icon: FileWarning },
                { label: "Detection & MITRE", to: "/mitre", icon: Crosshair },
                { label: "Forensic Timeline", to: "/timeline", icon: Activity },
                { label: "Case Command Deck", to: "/case", icon: ArrowRight },
              ]}
            />
          </div>
        </div>
      </PageShell>
    </ErrorBoundary>
  );
}
