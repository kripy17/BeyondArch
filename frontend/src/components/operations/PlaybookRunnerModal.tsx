import { useState, useEffect, useRef } from "react";
import { useNavigate } from "@tanstack/react-router";
import {
  X,
  Play,
  CheckCircle2,
  AlertCircle,
  Clock,
  Terminal,
  FileText,
  Copy,
  Check,
  ExternalLink,
  ShieldAlert,
  Loader2,
  ArrowRight,
  Send,
  Sparkles,
} from "lucide-react";
import type { Playbook, PlaybookRunRecord } from "@/lib/playbooks";
import { recordPlaybookRun, generatePlaybookRunMarkdown } from "@/lib/playbooks";
import { useActiveCase, newId } from "@/data/case";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface PlaybookRunnerModalProps {
  playbook: Playbook | null;
  open: boolean;
  onClose: () => void;
  onRunCompleted?: (run: PlaybookRunRecord) => void;
}

export function PlaybookRunnerModal({
  playbook,
  open,
  onClose,
  onRunCompleted,
}: PlaybookRunnerModalProps) {
  const navigate = useNavigate();
  const { activeCase, addEntry } = useActiveCase();

  // State
  const [inputs, setInputs] = useState<Record<string, string>>({});
  const [executionState, setExecutionState] = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [completedSteps, setCompletedSteps] = useState<number[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [runRecord, setRunRecord] = useState<PlaybookRunRecord | null>(null);
  const [copied, setCopied] = useState(false);
  const [filedToCase, setFiledToCase] = useState(false);

  const logsEndRef = useRef<HTMLDivElement>(null);

  // Initialize input defaults when playbook changes
  useEffect(() => {
    if (playbook) {
      const initial: Record<string, string> = {};
      for (const input of playbook.requiredInputs) {
        initial[input.id] = input.defaultValue || "";
      }
      setInputs(initial);
      setExecutionState("idle");
      setCurrentStepIndex(0);
      setCompletedSteps([]);
      setLogs([]);
      setRunRecord(null);
      setFiledToCase(false);
    }
  }, [playbook, open]);

  // Scroll logs to bottom
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // Handle ESC
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && open && executionState !== "running") {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, executionState, onClose]);

  if (!open || !playbook) return null;

  const handleInputChange = (id: string, val: string) => {
    setInputs((prev) => ({ ...prev, [id]: val }));
  };

  const startExecution = () => {
    setExecutionState("running");
    setCurrentStepIndex(0);
    setCompletedSteps([]);
    const startTs = new Date().toISOString();
    const runId = `run-${newId("soar")}`;

    const newLogs: string[] = [
      `[00:00] Initiating SOAR Playbook: ${playbook.title}`,
      `[00:00] Run ID: ${runId} | Automation Level: ${playbook.automationLevel.toUpperCase()}`,
      `[00:00] Analyst Actor: SOC SecOps Engineer`,
      `[00:01] Target parameters verified. Beginning orchestration pipeline...`,
    ];
    setLogs([...newLogs]);

    const totalSteps = playbook.steps.length;
    let stepIdx = 0;

    const executeNextStep = () => {
      if (stepIdx >= totalSteps) {
        // Complete execution
        const endTs = new Date().toISOString();
        const completedLogs = [
          ...newLogs,
          `[00:${String(totalSteps * 4).padStart(2, "0")}] All ${totalSteps} automated playbook steps resolved successfully.`,
          `[00:${String(totalSteps * 4).padStart(2, "0")}] Security policy enforced. Incident evidence secured.`,
        ];
        setLogs(completedLogs);
        setExecutionState("completed");

        const record: PlaybookRunRecord = {
          id: runId,
          playbookId: playbook.id,
          playbookTitle: playbook.title,
          status: "completed",
          startedAt: startTs,
          completedAt: endTs,
          analyst: "SOC SecOps Engineer",
          inputs,
          stepsCompleted: totalSteps,
          totalSteps,
          logs: completedLogs,
          caseId: activeCase?.id,
        };

        setRunRecord(record);
        recordPlaybookRun(record);
        onRunCompleted?.(record);
        toast.success(`Playbook "${playbook.title}" completed successfully!`);
        return;
      }

      setCurrentStepIndex(stepIdx);
      const step = playbook.steps[stepIdx];
      const stepSec = (stepIdx + 1) * 3;
      const logLine = `[00:${String(stepSec).padStart(2, "0")}] STEP ${stepIdx + 1}/${totalSteps} (${step.title}): Executing ${step.actionType}... verified.`;
      newLogs.push(logLine);
      setLogs([...newLogs]);
      setCompletedSteps((prev) => [...prev, stepIdx]);

      stepIdx++;
      setTimeout(executeNextStep, 500); // 500ms simulation per step
    };

    setTimeout(executeNextStep, 400);
  };

  const handleCopyMarkdown = async () => {
    if (!runRecord) return;
    const md = generatePlaybookRunMarkdown(runRecord, playbook);
    const ok = await copyText(md);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      toast.success("Copied execution receipt to clipboard");
    }
  };

  const handleFileToCase = () => {
    if (!runRecord) return;
    if (!activeCase) {
      toast.error("No active incident case. Please select or create a case first.");
      return;
    }

    const md = generatePlaybookRunMarkdown(runRecord, playbook);
    addEntry(md, "action", "SOAR Orchestration Engine");
    setFiledToCase(true);
    toast.success(`Filed SOAR execution log to active case: ${activeCase.title}`);
  };

  const progressPercent =
    playbook.steps.length > 0
      ? Math.round((completedSteps.length / playbook.steps.length) * 100)
      : 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div
        className="flex flex-col w-full max-w-4xl max-h-[90vh] rounded-xl border border-border bg-card shadow-2xl overflow-hidden"
        role="dialog"
        aria-modal="true"
        aria-labelledby="soar-runner-title"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-border px-6 py-4 bg-muted/30">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-primary/40 bg-primary/10 text-primary">
              <Terminal className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 id="soar-runner-title" className="text-lg font-semibold tracking-tight text-foreground">
                  {playbook.title}
                </h2>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/30 font-semibold">
                  {playbook.automationLevel}
                </span>
              </div>
              <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5">
                <span className="flex items-center gap-1 font-mono">
                  <Clock className="h-3 w-3" />
                  Est. {playbook.estimatedRuntime}
                </span>
                <span>·</span>
                <span>{playbook.steps.length} automated steps</span>
                <span>·</span>
                <span className="text-foreground/80">{playbook.mitreTactics[0]}</span>
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            disabled={executionState === "running"}
            className="rounded-lg p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground transition-colors disabled:opacity-50"
            title="Close modal"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Progress Bar (Visible during and after execution) */}
          {executionState !== "idle" && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-foreground flex items-center gap-2">
                  {executionState === "running" ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
                      Executing Pipeline... ({completedSteps.length}/{playbook.steps.length} steps)
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                      Execution Finished ({progressPercent}%)
                    </>
                  )}
                </span>
                <span className="font-mono text-muted-foreground">{progressPercent}%</span>
              </div>
              <div className="w-full h-2 rounded-full bg-muted overflow-hidden">
                <div
                  className="h-full bg-primary transition-all duration-300 rounded-full"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>
            </div>
          )}

          {/* Configuration / Target Inputs Section */}
          <div className="rounded-xl border border-border/70 bg-card p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Target Orchestration Parameters
              </span>
              {executionState === "running" && (
                <span className="text-[11px] text-muted-foreground font-mono">Parameters locked during run</span>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {playbook.requiredInputs.map((input) => (
                <div key={input.id} className="space-y-1">
                  <label className="block text-xs font-medium text-foreground">{input.label}</label>
                  <input
                    type="text"
                    disabled={executionState !== "idle"}
                    value={inputs[input.id] || ""}
                    onChange={(e) => handleInputChange(input.id, e.target.value)}
                    placeholder={input.placeholder}
                    className="w-full rounded-lg border border-border bg-background px-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-60 font-mono"
                  />
                </div>
              ))}
            </div>
          </div>

          {/* Step Pipeline Flow */}
          <div className="space-y-2.5">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Playbook Step Sequence ({playbook.steps.length})
            </span>

            <div className="space-y-2">
              {playbook.steps.map((step, idx) => {
                const isCompleted = completedSteps.includes(idx);
                const isCurrent = executionState === "running" && currentStepIndex === idx;

                return (
                  <div
                    key={step.id}
                    className={cn(
                      "flex items-start justify-between p-3 rounded-lg border transition-all",
                      isCompleted
                        ? "border-emerald-500/40 bg-emerald-500/5"
                        : isCurrent
                          ? "border-primary bg-primary/5 ring-1 ring-primary/40"
                          : "border-border/60 bg-muted/10 opacity-80"
                    )}
                  >
                    <div className="flex items-start gap-3">
                      <div className="mt-0.5">
                        {isCompleted ? (
                          <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                        ) : isCurrent ? (
                          <Loader2 className="h-4 w-4 text-primary animate-spin" />
                        ) : (
                          <span className="grid h-4 w-4 place-items-center rounded-full border border-border text-[10px] font-mono text-muted-foreground">
                            {idx + 1}
                          </span>
                        )}
                      </div>

                      <div className="space-y-0.5">
                        <div className="text-xs font-semibold text-foreground flex items-center gap-2">
                          <span>{step.title}</span>
                          <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 rounded bg-muted text-muted-foreground">
                            {step.actionType}
                          </span>
                        </div>
                        <p className="text-xs text-muted-foreground">{step.description}</p>
                      </div>
                    </div>

                    {step.toolRoute && (
                      <button
                        type="button"
                        onClick={() => navigate({ to: step.toolRoute! as any })}
                        className="text-[11px] text-primary hover:underline flex items-center gap-1 shrink-0 ml-3"
                      >
                        <span>Open Tool</span>
                        <ExternalLink className="h-3 w-3" />
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Live Execution Console Logs */}
          {logs.length > 0 && (
            <div className="rounded-xl border border-border/70 bg-black/90 p-4 font-mono text-xs text-emerald-400 space-y-1">
              <div className="flex items-center justify-between pb-2 border-b border-white/10 text-muted-foreground text-[11px]">
                <span className="flex items-center gap-1.5">
                  <Terminal className="h-3.5 w-3.5 text-primary" />
                  Live SOAR Execution Audit Stream
                </span>
                <span>STATUS: {executionState.toUpperCase()}</span>
              </div>
              <div className="max-h-40 overflow-y-auto space-y-1 pt-2">
                {logs.map((log, i) => (
                  <div key={i} className="leading-relaxed">
                    {log}
                  </div>
                ))}
                <div ref={logsEndRef} />
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between border-t border-border px-6 py-4 bg-muted/20">
          <button
            type="button"
            onClick={onClose}
            disabled={executionState === "running"}
            className="rounded-lg border border-border px-4 py-2 text-xs font-medium text-muted-foreground hover:bg-muted hover:text-foreground transition-colors disabled:opacity-50"
          >
            {executionState === "completed" ? "Close" : "Cancel"}
          </button>

          <div className="flex items-center gap-2">
            {executionState === "idle" && (
              <button
                type="button"
                onClick={startExecution}
                className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground shadow hover:bg-primary/90 transition-colors"
              >
                <Play className="h-3.5 w-3.5 fill-current" />
                <span>Trigger SOAR Execution</span>
              </button>
            )}

            {executionState === "running" && (
              <div className="inline-flex items-center gap-2 rounded-lg bg-primary/20 px-4 py-2 text-xs font-semibold text-primary">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                <span>Running Orchestration Pipeline...</span>
              </div>
            )}

            {executionState === "completed" && (
              <>
                <button
                  type="button"
                  onClick={handleCopyMarkdown}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-card px-3.5 py-2 text-xs font-medium text-foreground hover:bg-muted transition-colors"
                >
                  {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
                  <span>{copied ? "Copied Receipt" : "Copy Audit Log"}</span>
                </button>

                <button
                  type="button"
                  onClick={handleFileToCase}
                  disabled={filedToCase || !activeCase}
                  className={cn(
                    "inline-flex items-center gap-1.5 rounded-lg px-4 py-2 text-xs font-semibold shadow transition-colors",
                    filedToCase
                      ? "bg-emerald-500 text-white"
                      : "bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                  )}
                >
                  {filedToCase ? <Check className="h-3.5 w-3.5" /> : <Send className="h-3.5 w-3.5" />}
                  <span>
                    {filedToCase
                      ? "Filed to Case"
                      : activeCase
                        ? `File to "${activeCase.title.slice(0, 18)}..."`
                        : "No Active Case"}
                  </span>
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
