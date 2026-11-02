import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, useMemo, useEffect } from "react";
import { PageShell } from "@/components/PageShell";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import {
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
  Clock,
  Play,
  Copy,
  Check,
  Download,
  ExternalLink,
  Code2,
  Terminal,
  Database,
  Sparkles,
  Layers,
  ArrowRight,
  Send,
  RefreshCw,
  FileCode,
} from "lucide-react";
import {
  DETECTION_PRESETS,
  lintDetectionRule,
  compileSigmaToQueries,
  parseAndEvaluateSigma,
  parseAndEvaluateYara,
  type RuleFormat,
  type EvaluationResult,
  type LintIssue,
} from "@/lib/detection-sandbox";
import { useActiveCase } from "@/data/case";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/sigma-tester")({
  component: SigmaSandboxPage,
});

function SigmaSandboxPage() {
  const navigate = useNavigate();
  const { activeCase, addEntry } = useActiveCase();

  // State
  const [format, setFormat] = useState<RuleFormat>("sigma");
  const [selectedPresetId, setSelectedPresetId] = useState<string>(DETECTION_PRESETS[0].id);
  const [ruleText, setRuleText] = useState(DETECTION_PRESETS[0].rule);
  const [sampleEvents, setSampleEvents] = useState(DETECTION_PRESETS[0].sampleEvents);
  const [activeQueryTab, setActiveQueryTab] = useState<"splunk" | "sentinel" | "elastic" | "qradar">("splunk");

  const [copiedQuery, setCopiedQuery] = useState(false);
  const [filedToCase, setFiledToCase] = useState(false);

  // Linting & Evaluation
  const lintIssues = useMemo(() => lintDetectionRule(ruleText, format), [ruleText, format]);
  const transpiledQueries = useMemo(() => {
    if (format === "sigma") {
      return compileSigmaToQueries(ruleText);
    }
    return {
      splunk: "# YARA rules cannot be directly transpiled to SPL — use yara_scan modular command",
      sentinel: "// YARA signature scanning supported via Defender for Endpoint memory artifacts",
      elastic: "// YARA integration available through Elastic Defend integration",
      qradar: "-- YARA evaluation in QRadar via custom AQL user defined function",
    };
  }, [ruleText, format]);

  const [evalResult, setEvalResult] = useState<EvaluationResult>(() => {
    return parseAndEvaluateSigma(DETECTION_PRESETS[0].rule, DETECTION_PRESETS[0].sampleEvents);
  });

  const handleRunTest = () => {
    if (format === "sigma") {
      const res = parseAndEvaluateSigma(ruleText, sampleEvents);
      setEvalResult(res);
      toast.success(`Evaluated Sigma rule against ${res.totalEvents} events: ${res.matchCount} matched`);
    } else {
      const res = parseAndEvaluateYara(ruleText, sampleEvents);
      setEvalResult(res);
      toast.success(res.matched ? "YARA signature match confirmed!" : "No YARA match found");
    }
  };

  const handlePresetSelect = (id: string) => {
    setSelectedPresetId(id);
    const preset = DETECTION_PRESETS.find((p) => p.id === id);
    if (preset) {
      setFormat(preset.format);
      setRuleText(preset.rule);
      setSampleEvents(preset.sampleEvents);
      if (preset.format === "sigma") {
        setEvalResult(parseAndEvaluateSigma(preset.rule, preset.sampleEvents));
      } else {
        setEvalResult(parseAndEvaluateYara(preset.rule, preset.sampleEvents));
      }
      toast.info(`Loaded preset: ${preset.name}`);
    }
  };

  const handleCopyQuery = async () => {
    const q = transpiledQueries[activeQueryTab];
    const ok = await copyText(q);
    if (ok) {
      setCopiedQuery(true);
      setTimeout(() => setCopiedQuery(false), 2000);
      toast.success(`Copied ${activeQueryTab.toUpperCase()} query to clipboard`);
    }
  };

  const handleOpenInSiem = () => {
    const q = transpiledQueries[activeQueryTab];
    try {
      localStorage.setItem("ba.siem.keyword", q);
    } catch {
      // ignore
    }
    navigate({ to: "/siem" });
    toast.success("Navigating to SIEM Hunter with query loaded");
  };

  const handleFileToCase = () => {
    if (!activeCase) {
      toast.error("No active case. Please initiate or select an incident case first.");
      return;
    }

    const md = [
      `### Detection Rule Engineering Artifact (${format.toUpperCase()})`,
      `- **Status:** Evaluated (${evalResult.matchCount}/${evalResult.totalEvents} events matched)`,
      `- **Latency:** ${evalResult.executionMs} ms`,
      `- **Target Dialects:** Splunk SPL, Microsoft Sentinel KQL, Elastic EQL`,
      "",
      "```yaml",
      ruleText,
      "```",
      "",
      `#### Transpiled ${activeQueryTab.toUpperCase()} Query`,
      "```text",
      transpiledQueries[activeQueryTab],
      "```",
    ].join("\n");

    addEntry(md, "action", "Detection Rule Sandbox");
    setFiledToCase(true);
    toast.success(`Filed detection rule to active case: ${activeCase.title}`);
  };

  const errorCount = lintIssues.filter((i) => i.severity === "error").length;
  const warningCount = lintIssues.filter((i) => i.severity === "warning").length;

  return (
    <ErrorBoundary name="SigmaTester">
      <PageShell
        eyebrow="DETECTION // SIGMA & YARA RULE TESTBENCH"
        title="Detection Engineering Sandbox"
        description="Author, lint, transpile, and evaluate Sigma rules and YARA signatures against real-world multi-event telemetry."
        crumbs={[{ label: "Detection" }, { label: "Sigma Tester" }]}
      >
        <div className="space-y-6">
          {/* Header Action Strip */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-xl border border-border/70 bg-card/60 p-4 backdrop-blur-sm">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-primary/30 bg-primary/10 text-primary">
                <FileCode className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-foreground">Detection Engineering Lab</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/30 font-medium">
                    SIGMA HQ AST v2
                  </span>
                </div>
                <div className="text-xs text-muted-foreground">
                  Multi-dialect compilation to Splunk SPL, Sentinel KQL, Elastic EQL, and QRadar AQL
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={handleRunTest}
                className="inline-flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2 text-xs font-semibold text-primary-foreground shadow-sm hover:bg-primary/90 transition-colors"
              >
                <Play className="h-3.5 w-3.5 fill-current" />
                <span>Evaluate Rule</span>
              </button>

              <button
                type="button"
                onClick={handleOpenInSiem}
                className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-card px-3 py-2 text-xs font-medium text-foreground hover:bg-muted transition-colors"
                title="Pivot query to SIEM"
              >
                <Database className="h-3.5 w-3.5 text-muted-foreground" />
                <span>Run in SIEM</span>
              </button>

              <button
                type="button"
                onClick={handleFileToCase}
                disabled={filedToCase || !activeCase}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-semibold transition-colors disabled:opacity-50",
                  filedToCase
                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-500"
                    : "border-primary/40 bg-primary/10 text-primary hover:bg-primary/20"
                )}
              >
                {filedToCase ? <Check className="h-3.5 w-3.5" /> : <Send className="h-3.5 w-3.5" />}
                <span>{filedToCase ? "Filed to Case" : "File to Case"}</span>
              </button>
            </div>
          </div>

          {/* 4-KPI Detection Engineering Ribbon */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Engine Status</span>
                <Code2 className="h-4 w-4 text-primary" />
              </div>
              <div className="text-xl font-bold tracking-tight text-foreground font-mono">
                {format === "sigma" ? "Sigma AST Engine" : "YARA Scanner"}
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">Real-time condition parsing</div>
            </div>

            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Syntax Linter</span>
                {errorCount > 0 ? (
                  <XCircle className="h-4 w-4 text-destructive" />
                ) : warningCount > 0 ? (
                  <AlertTriangle className="h-4 w-4 text-warning" />
                ) : (
                  <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                )}
              </div>
              <div className="text-xl font-bold tracking-tight font-mono">
                {errorCount === 0 && warningCount === 0 ? (
                  <span className="text-emerald-500">100% Compliant</span>
                ) : (
                  <span className={errorCount > 0 ? "text-destructive" : "text-warning"}>
                    {errorCount} err / {warningCount} warn
                  </span>
                )}
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">Sigma HQ specification</div>
            </div>

            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Evaluation Latency</span>
                <Clock className="h-4 w-4 text-primary" />
              </div>
              <div className="text-xl font-bold tracking-tight text-foreground font-mono">
                {evalResult.executionMs}
                <span className="text-xs font-normal text-muted-foreground ml-1">ms</span>
              </div>
              <div className="mt-1 text-[11px] text-emerald-500 font-medium">Sub-millisecond AST parser</div>
            </div>

            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Matches Verified</span>
                <Shield className="h-4 w-4 text-emerald-500" />
              </div>
              <div className="text-xl font-bold tracking-tight text-emerald-500 font-mono">
                {evalResult.matchCount}
                <span className="text-xs font-normal text-muted-foreground ml-1.5">
                  / {evalResult.totalEvents} events
                </span>
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">True positive confirmation</div>
            </div>
          </div>

          {/* Preset Attack Rules Selector Strip */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-xl border border-border/70 bg-card p-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Attack Presets:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {DETECTION_PRESETS.map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => handlePresetSelect(preset.id)}
                    className={cn(
                      "px-2.5 py-1 rounded-md text-xs font-medium transition-all",
                      selectedPresetId === preset.id
                        ? "bg-primary text-primary-foreground font-semibold shadow-sm"
                        : "bg-muted text-foreground/80 hover:bg-muted/80 border border-border/50"
                    )}
                  >
                    {preset.name}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center rounded-lg border border-border bg-muted/40 p-1 text-xs">
              <button
                type="button"
                onClick={() => {
                  setFormat("sigma");
                  handlePresetSelect(DETECTION_PRESETS[0].id);
                }}
                className={cn(
                  "px-3 py-1 rounded-md font-medium transition-all",
                  format === "sigma"
                    ? "bg-card text-foreground shadow-sm border border-border"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                Sigma Rule
              </button>
              <button
                type="button"
                onClick={() => {
                  setFormat("yara");
                  handlePresetSelect(DETECTION_PRESETS[3].id);
                }}
                className={cn(
                  "px-3 py-1 rounded-md font-medium transition-all",
                  format === "yara"
                    ? "bg-card text-foreground shadow-sm border border-border"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                YARA Signature
              </button>
            </div>
          </div>

          {/* Main Dual-Pane Testbench Stage */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Left Pane: Rule Editor & Linter */}
            <div className="flex flex-col space-y-4">
              <div className="rounded-xl border border-border/70 bg-card p-4 space-y-3 flex-1">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                      {format.toUpperCase()} Rule Definition
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-muted text-muted-foreground border border-border">
                      YAML / AST
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      const def = DETECTION_PRESETS.find((p) => p.format === format);
                      if (def) {
                        setRuleText(def.rule);
                        toast.info("Reset rule to standard preset");
                      }
                    }}
                    className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
                  >
                    <RefreshCw className="h-3 w-3" />
                    Reset
                  </button>
                </div>

                <textarea
                  rows={16}
                  value={ruleText}
                  onChange={(e) => setRuleText(e.target.value)}
                  className="w-full rounded-lg border border-border bg-black/90 p-3.5 font-mono text-xs text-emerald-400 focus:outline-none focus:ring-1 focus:ring-primary leading-relaxed resize-y"
                  spellCheck={false}
                />

                {/* Syntax Linter Drawer */}
                {lintIssues.length > 0 && (
                  <div className="rounded-lg border border-border/60 bg-muted/20 p-3 space-y-2">
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground flex items-center justify-between">
                      <span>Sigma HQ Linter Report ({lintIssues.length})</span>
                      <span className="text-[10px] font-mono">
                        {errorCount} errors · {warningCount} warnings
                      </span>
                    </div>
                    <div className="space-y-1.5 max-h-32 overflow-y-auto">
                      {lintIssues.map((issue, idx) => (
                        <div
                          key={idx}
                          className={cn(
                            "flex items-start gap-2 text-xs p-1.5 rounded",
                            issue.severity === "error"
                              ? "bg-destructive/10 text-destructive border border-destructive/20"
                              : issue.severity === "warning"
                                ? "bg-warning/10 text-warning border border-warning/20"
                                : "bg-primary/10 text-primary border border-primary/20"
                          )}
                        >
                          {issue.severity === "error" ? (
                            <XCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                          ) : issue.severity === "warning" ? (
                            <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                          ) : (
                            <Info className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                          )}
                          <span className="leading-snug">{issue.message}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Transpiled Queries Drawer */}
              <div className="rounded-xl border border-border/70 bg-card p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Transpiled SIEM Queries
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={handleCopyQuery}
                      className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                    >
                      {copiedQuery ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                      <span>{copiedQuery ? "Copied" : "Copy Query"}</span>
                    </button>
                    <button
                      type="button"
                      onClick={handleOpenInSiem}
                      className="inline-flex items-center gap-1 text-xs text-primary hover:underline ml-2"
                    >
                      <span>Open in SIEM</span>
                      <ExternalLink className="h-3 w-3" />
                    </button>
                  </div>
                </div>

                {/* Dialect Tabs */}
                <div className="flex items-center rounded-lg border border-border bg-muted/40 p-1 text-xs">
                  {(["splunk", "sentinel", "elastic", "qradar"] as const).map((dialect) => (
                    <button
                      key={dialect}
                      type="button"
                      onClick={() => setActiveQueryTab(dialect)}
                      className={cn(
                        "flex-1 py-1 rounded-md font-medium uppercase tracking-wider transition-all text-center",
                        activeQueryTab === dialect
                          ? "bg-card text-foreground shadow-sm border border-border font-semibold"
                          : "text-muted-foreground hover:text-foreground"
                      )}
                    >
                      {dialect === "splunk"
                        ? "Splunk SPL"
                        : dialect === "sentinel"
                          ? "Sentinel KQL"
                          : dialect === "elastic"
                            ? "Elastic EQL"
                            : "QRadar AQL"}
                    </button>
                  ))}
                </div>

                <pre className="p-3 rounded-lg bg-black/90 text-emerald-400 font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed select-all">
                  {transpiledQueries[activeQueryTab]}
                </pre>
              </div>
            </div>

            {/* Right Pane: Multi-Event Sample Playground & Match Results */}
            <div className="flex flex-col space-y-4">
              <div className="rounded-xl border border-border/70 bg-card p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                      Sample Event Telemetry / In-Memory Payload
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-muted text-muted-foreground border border-border">
                      Multi-Event (--- separator)
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={handleRunTest}
                    className="text-xs text-primary hover:underline flex items-center gap-1 font-semibold"
                  >
                    <Play className="h-3 w-3 fill-current" />
                    Re-Evaluate
                  </button>
                </div>

                <textarea
                  rows={8}
                  value={sampleEvents}
                  onChange={(e) => setSampleEvents(e.target.value)}
                  placeholder="Paste multi-line Sysmon, Security Event 4688, Suricata EVE, or Linux audit events. Separate distinct events with '---'..."
                  className="w-full rounded-lg border border-border bg-background p-3 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary leading-relaxed resize-y"
                  spellCheck={false}
                />
              </div>

              {/* Evaluation Match Matrix */}
              <div className="rounded-xl border border-border/70 bg-card p-4 space-y-3 flex-1">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                      Evaluation Verification Matrix
                    </span>
                    <span
                      className={cn(
                        "text-[10px] font-mono px-2 py-0.5 rounded font-semibold",
                        evalResult.matched
                          ? "bg-emerald-500/20 text-emerald-500 border border-emerald-500/30"
                          : "bg-muted text-muted-foreground border border-border"
                      )}
                    >
                      {evalResult.matched ? "RULE FIRED" : "NO MATCH"}
                    </span>
                  </div>

                  <span className="text-xs font-mono text-muted-foreground">
                    {evalResult.matchCount} / {evalResult.totalEvents} events matched ({evalResult.executionMs}ms)
                  </span>
                </div>

                {/* Event Match Cards */}
                <div className="space-y-2.5">
                  {evalResult.eventMatches.map((evMatch) => (
                    <div
                      key={evMatch.eventIndex}
                      className={cn(
                        "p-3.5 rounded-lg border transition-all space-y-2",
                        evMatch.matched
                          ? "border-emerald-500/40 bg-emerald-500/5"
                          : "border-border/60 bg-muted/10 opacity-75"
                      )}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="grid h-5 w-5 place-items-center rounded-full border border-border text-[11px] font-mono text-muted-foreground">
                            {evMatch.eventIndex + 1}
                          </span>
                          <span className="text-xs font-semibold text-foreground truncate max-w-[280px]">
                            {evMatch.eventSummary}
                          </span>
                        </div>

                        <span
                          className={cn(
                            "text-[10px] font-mono uppercase px-2 py-0.5 rounded font-semibold",
                            evMatch.matched
                              ? "bg-emerald-500/20 text-emerald-500 border border-emerald-500/30"
                              : "bg-muted text-muted-foreground border border-border"
                          )}
                        >
                          {evMatch.matched ? "MATCH CONFIRMED" : "DID NOT MATCH"}
                        </span>
                      </div>

                      <p className="text-xs text-muted-foreground">{evMatch.details}</p>

                      {evMatch.matchedTokens.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1 pt-1">
                          <span className="text-[10px] font-medium text-muted-foreground mr-1">
                            Tokens:
                          </span>
                          {evMatch.matchedTokens.map((tok, i) => (
                            <span
                              key={i}
                              className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                            >
                              {tok}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </PageShell>
    </ErrorBoundary>
  );
}
