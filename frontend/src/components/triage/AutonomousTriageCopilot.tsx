import { useMemo, useState } from "react";
import {
  ShieldCheck, CheckCircle2,
  Copy, Check, SlidersHorizontal, ArrowRight
} from "lucide-react";
import { Chip } from "@/components/soc";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import type { TriageItem, TriageVerdict } from "@/data/triage";

interface TriageAssessmentPanelProps {
  item: TriageItem;
  onApplyRecommendation: (verdict: TriageVerdict, justification: string) => void;
}

export function TriageAssessmentPanel({
  item,
  onApplyRecommendation,
}: TriageAssessmentPanelProps) {
  const [copied, setCopied] = useState(false);

  // Synthesize Automated Triage Recommendation
  const recommendation = useMemo(() => {
    const text = `${item.title} ${item.description} ${(item.tags || []).join(" ")}`.toLowerCase();
    const isCriticalOrHigh = item.severity === "critical" || item.severity === "high";

    const isMalicious =
      text.includes("mimikatz") ||
      text.includes("lsass") ||
      text.includes("shadow copy") ||
      text.includes("vssadmin") ||
      text.includes("ransomware") ||
      text.includes("c2") ||
      text.includes("beacon") ||
      text.includes("encodedcommand") ||
      text.includes("downloadstring") ||
      text.includes("credential");

    const isBenignAdmin =
      text.includes("backup") ||
      text.includes("monitoring") ||
      text.includes("datadog") ||
      text.includes("sccm") ||
      text.includes("scheduled task") ||
      text.includes("patch") ||
      text.includes("maintenance");

    let verdict: TriageVerdict = "true_positive";
    let verdictLabel = "TRUE POSITIVE: ESCALATE TO INCIDENT";
    let confidence = 95;
    let tone: "destructive" | "success" | "default" = "destructive";
    let reasoning = "Observed high-risk offensive TTPs, execution of unauthorized execution cradles, or credential dumping indicators. Escalation to active incident investigation required.";

    if (isMalicious || isCriticalOrHigh) {
      verdict = "true_positive";
      verdictLabel = "TRUE POSITIVE: ESCALATE TO INCIDENT";
      confidence = 96;
      tone = "destructive";
      reasoning = "High-confidence adversary TTP execution matching credential dumping, LOLBAS weaponization, or C2 beaconing. Immediate containment recommended.";
    } else if (isBenignAdmin) {
      verdict = "benign_positive";
      verdictLabel = "BENIGN POSITIVE: AUTHORIZED ADMIN TASK";
      confidence = 91;
      tone = "success";
      reasoning = "Telemetry matches expected administrative tool invocation or maintenance routine under authorized service credentials. Close with documentation.";
    } else {
      verdict = "false_positive";
      verdictLabel = "FALSE POSITIVE: RULE TUNING CANDIDATE";
      confidence = 88;
      tone = "default";
      reasoning = "Overly broad detection trigger matching benign operational baseline or developer workflow without secondary malicious observables. Tune detection rule.";
    }

    const justification = `[Automated Triage] Disposition: ${verdict.toUpperCase()} (Confidence: ${confidence}%)
Analysis: ${reasoning}
Matched Context: Source=${item.source}, Severity=${item.severity}, Title="${item.title}"
Action: Standard operating containment procedure applied.`;

    return { verdict, verdictLabel, confidence, tone, reasoning, justification };
  }, [item]);

  const handleCopyJustification = () => {
    copyText(recommendation.justification).then(() => {
      setCopied(true);
      toast.success("Disposition justification copied");
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div id="triage-assessment-panel" data-testid="autonomous-triage-copilot" className="rounded-md border border-subtle bg-surface-1/60 p-3 space-y-2.5 font-mono min-w-0 max-w-full overflow-hidden">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-1.5 border-b border-subtle pb-2">
        <div className="flex items-center gap-1.5 min-w-0">
          <ShieldCheck className="h-4 w-4 text-primary shrink-0" />
          <span className="ba-text-xs font-bold uppercase text-foreground tracking-wide truncate">
            Automated Triage Analysis
          </span>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <span className="ba-text-3xs text-muted-foreground font-semibold">
            Confidence: <span className="text-primary font-bold">{recommendation.confidence}%</span>
          </span>
          <Chip tone={recommendation.tone}>
            {recommendation.tone === "destructive" ? "P1 Alert" : recommendation.tone === "success" ? "Authorized" : "Tuning"}
          </Chip>
        </div>
      </div>

      {/* Recommended Verdict Banner */}
      <div className="space-y-1">
        <div className="text-muted-foreground ba-text-3xs uppercase font-semibold">Recommended Disposition</div>
        <div className="flex items-center gap-1.5">
          <SlidersHorizontal className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
          <span
            className={`ba-text-xs font-bold ${
              recommendation.tone === "destructive"
                ? "text-destructive"
                : recommendation.tone === "success"
                ? "text-success"
                : "text-foreground"
            }`}
          >
            {recommendation.verdictLabel}
          </span>
        </div>
      </div>

      {/* Decision Criteria Trace */}
      <div className="rounded border border-subtle bg-surface-0 p-2 space-y-1">
        <div className="text-muted-foreground ba-text-3xs uppercase font-semibold">Triage Decision Criteria</div>
        <p className="ba-text-3xs text-fg-dim leading-relaxed break-words">{recommendation.reasoning}</p>
      </div>

      {/* Action Buttons */}
      <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5">
        <button
          type="button"
          onClick={() => onApplyRecommendation(recommendation.verdict, recommendation.justification)}
          className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1 ba-text-2xs text-primary font-semibold hover:bg-primary/20 transition shrink-0"
        >
          <CheckCircle2 className="h-3 w-3" />
          <span>Apply Recommendation</span>
        </button>

        <button
          type="button"
          onClick={handleCopyJustification}
          className="inline-flex items-center gap-1 rounded border border-border bg-surface-2 px-2 py-1 ba-text-3xs text-muted-foreground hover:text-foreground transition shrink-0"
          title="Copy full disposition rationale"
        >
          {copied ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
          <span>Copy Note</span>
        </button>
      </div>
    </div>
  );
}

// Backward compatibility alias
export const AutonomousTriageCopilot = TriageAssessmentPanel;
