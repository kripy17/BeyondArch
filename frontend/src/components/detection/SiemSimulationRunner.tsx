import { useState } from "react";
import { Play, FlaskConical, CheckCircle2, AlertTriangle, ShieldCheck, Zap, Filter, Plus, Clock, Terminal, ChevronDown, ChevronUp } from "lucide-react";
import { Chip } from "@/components/soc";
import { runClientSimulation, ENTERPRISE_TELEMETRY_SUITE, type SimulationReport, type TelemetryScenario } from "@/lib/detection/detection-simulator";
import { notify } from "@/lib/notify";

import type { Format } from "@/data/detection";

interface SiemSimulationRunnerProps {
  ruleContent: string;
  format: Format;
  onApplyTuningFilter?: (filterSnippet: string) => void;
}

export function SiemSimulationRunner({
  ruleContent,
  format,
  onApplyTuningFilter,
}: SiemSimulationRunnerProps) {
  const [report, setReport] = useState<SimulationReport | null>(null);
  const [mode, setMode] = useState<"suite" | "custom">("suite");
  const [customLogText, setCustomLogText] = useState("");
  const [customLogLabel, setCustomLogLabel] = useState("Custom Log Event");
  const [customExpected, setCustomExpected] = useState<"match" | "benign">("match");
  const [running, setRunning] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const handleRunSimulation = () => {
    if (!ruleContent.trim()) {
      notify.error("Rule body is empty. Please enter or select a rule first.");
      return;
    }

    setRunning(true);
    try {
      let scenariosToRun = ENTERPRISE_TELEMETRY_SUITE;
      if (mode === "custom") {
        if (!customLogText.trim()) {
          notify.error("Custom log text is empty");
          setRunning(false);
          return;
        }
        const customScen: TelemetryScenario = {
          id: "custom-1",
          title: customLogLabel || "User Custom Event",
          category: "process",
          expected: customExpected,
          event: customLogText,
          source: "Custom Analyst Input",
          fields: {},
        };
        scenariosToRun = [customScen];
      }

      const simRes = runClientSimulation(ruleContent, format, scenariosToRun);
      setReport(simRes);

      if (simRes.falsePositives > 0) {
        notify.warning(`Simulation completed: ${simRes.falsePositives} False Positive(s) flagged!`, {
          description: "Review tuning suggestions to avoid alert fatigue in production.",
        });
      } else if (simRes.truePositives > 0) {
        notify.success(`Simulation completed: ${simRes.truePositives} True Positive match(es) verified!`);
      } else {
        notify.info("Simulation completed: No events triggered the rule.");
      }
    } catch (err: any) {
      notify.error("Simulation failed: " + (err?.message || "Unknown error"));
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="rounded border border-border bg-surface-1 p-3 text-mono ba-text-2xs">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-2.5">
        <div className="flex items-center gap-2">
          <FlaskConical className="h-4 w-4 text-primary" />
          <span className="text-sm font-semibold text-foreground">SIEM Telemetry Simulation Runner</span>
          <Chip tone="info">{format.toUpperCase()}</Chip>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex rounded border border-border bg-surface-0 p-0.5">
            <button
              onClick={() => setMode("suite")}
              className={`rounded px-2 py-0.5 text-mono ba-text-3xs transition-colors ${
                mode === "suite" ? "bg-primary/20 text-primary font-medium" : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Enterprise Suite (6 Scenarios)
            </button>
            <button
              onClick={() => setMode("custom")}
              className={`rounded px-2 py-0.5 text-mono ba-text-3xs transition-colors ${
                mode === "custom" ? "bg-primary/20 text-primary font-medium" : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Custom Log Event
            </button>
          </div>

          <button
            onClick={handleRunSimulation}
            disabled={running}
            className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/20 px-3 py-1 text-primary hover:bg-primary/30 transition-colors disabled:opacity-50"
          >
            <Play className="h-3 w-3 fill-current" />
            <span>{running ? "Simulating..." : "Run Simulation"}</span>
          </button>
        </div>
      </div>

      {/* Custom log input if custom mode selected */}
      {mode === "custom" && (
        <div className="mt-3 space-y-2 rounded border border-subtle bg-surface-0 p-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <input
              value={customLogLabel}
              onChange={(e) => setCustomLogLabel(e.target.value)}
              placeholder="Event label / title..."
              className="h-7 w-60 rounded border border-border bg-surface-1 px-2 text-mono ba-text-3xs text-foreground outline-none focus:border-primary/50"
            />
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Expected Disposition:</span>
              <button
                onClick={() => setCustomExpected("match")}
                className={`rounded border px-2 py-0.5 ${
                  customExpected === "match" ? "border-destructive/60 bg-destructive/20 text-destructive font-medium" : "border-border text-muted-foreground"
                }`}
              >
                Attack / Malicious (Match)
              </button>
              <button
                onClick={() => setCustomExpected("benign")}
                className={`rounded border px-2 py-0.5 ${
                  customExpected === "benign" ? "border-success/60 bg-success/20 text-success font-medium" : "border-border text-muted-foreground"
                }`}
              >
                Benign (No Match)
              </button>
            </div>
          </div>
          <textarea
            rows={3}
            value={customLogText}
            onChange={(e) => setCustomLogText(e.target.value)}
            placeholder="Paste raw log string, JSON event, or key-value syslog here..."
            className="w-full rounded border border-border bg-surface-1 p-2 text-mono ba-text-3xs text-foreground placeholder:text-muted-foreground outline-none focus:border-primary/50"
          />
        </div>
      )}

      {/* Simulation Diagnostic Metrics */}
      {report && (
        <div className="mt-3 space-y-3">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
            <div className="rounded border border-subtle bg-surface-0 p-2 text-center">
              <span className="text-muted-foreground ba-text-3xs block">Latency</span>
              <span className="text-sm font-semibold text-foreground">{report.durationMs} ms</span>
            </div>
            <div className="rounded border border-subtle bg-surface-0 p-2 text-center">
              <span className="text-muted-foreground ba-text-3xs block">True Positives</span>
              <span className="text-sm font-semibold text-success">{report.truePositives}</span>
            </div>
            <div className="rounded border border-subtle bg-surface-0 p-2 text-center">
              <span className="text-muted-foreground ba-text-3xs block">False Positives</span>
              <span className={`text-sm font-semibold ${report.falsePositives > 0 ? "text-destructive" : "text-muted-foreground"}`}>
                {report.falsePositives}
              </span>
            </div>
            <div className="rounded border border-subtle bg-surface-0 p-2 text-center">
              <span className="text-muted-foreground ba-text-3xs block">Precision</span>
              <span className="text-sm font-semibold text-primary">{Math.round(report.precision * 100)}%</span>
            </div>
            <div className="rounded border border-subtle bg-surface-0 p-2 text-center">
              <span className="text-muted-foreground ba-text-3xs block">Recall</span>
              <span className="text-sm font-semibold text-primary">{Math.round(report.recall * 100)}%</span>
            </div>
          </div>

          {/* Tuning Recommendations when False Positives detected */}
          {report.tuningSuggestions.length > 0 && (
            <div className="rounded border border-amber-500/40 bg-amber-500/10 p-2.5 text-foreground">
              <div className="flex items-center gap-1.5 font-semibold text-amber-400 mb-1">
                <AlertTriangle className="h-4 w-4" />
                <span>Detection Engineering Tuning Alert</span>
              </div>
              <p className="ba-text-3xs text-amber-200/90 mb-2">
                Benign baseline activity triggered this rule. Consider incorporating an exclusion filter:
              </p>
              {report.tuningSuggestions.map((s, idx) => (
                <div key={idx} className="rounded border border-amber-500/30 bg-black/40 p-2 text-mono ba-text-3xs mb-1.5">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-muted-foreground">{s.suggestion}</span>
                    {onApplyTuningFilter && (
                      <button
                        onClick={() => {
                          onApplyTuningFilter(s.filterSnippet);
                          notify.success("Appended filter to rule editor");
                        }}
                        className="inline-flex items-center gap-1 text-primary hover:underline"
                      >
                        <Plus className="h-3 w-3" /> Append to Rule
                      </button>
                    )}
                  </div>
                  <pre className="text-amber-300 overflow-x-auto whitespace-pre">{s.filterSnippet}</pre>
                </div>
              ))}
            </div>
          )}

          {/* Scenario Results List */}
          <div className="rounded border border-subtle bg-surface-0 divide-y divide-border/60">
            {report.results.map((r) => {
              const isExpanded = expandedId === r.id;
              const verdictTone: Record<string, "success" | "destructive" | "warning" | "default"> = {
                tp: "success",
                fp: "destructive",
                fn: "warning",
                tn: "default",
              };
              const verdictLabels: Record<string, string> = {
                tp: "True Positive",
                fp: "False Positive",
                fn: "False Negative",
                tn: "True Negative",
              };

              return (
                <div key={r.id} className="p-2.5">
                  <div
                    onClick={() => setExpandedId(isExpanded ? null : r.id)}
                    className="flex cursor-pointer items-center justify-between gap-2"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <Chip tone={verdictTone[r.verdict]}>{verdictLabels[r.verdict]}</Chip>
                      <span className="truncate font-medium text-foreground">{r.title}</span>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      {r.matchedTokens.length > 0 && (
                        <div className="flex items-center gap-1">
                          {r.matchedTokens.map((t) => (
                            <span key={t} className="rounded bg-primary/15 px-1.5 py-0.5 text-primary ba-text-3xs">
                              {t}
                            </span>
                          ))}
                        </div>
                      )}
                      {isExpanded ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="mt-2 rounded border border-border/60 bg-background/50 p-2 text-mono ba-text-3xs">
                      <div className="text-muted-foreground mb-1">Raw Telemetry Snippet:</div>
                      <pre className="text-fg-dim overflow-x-auto whitespace-pre-wrap select-all">
                        {r.eventSnippet}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
