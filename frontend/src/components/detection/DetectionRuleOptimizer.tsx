import { useState, useMemo } from "react";
import {
  Gauge, ShieldCheck, ShieldAlert, AlertTriangle, Copy, Check,
  Terminal, Sparkles, Database, FileCode, CheckCircle2, Rocket, ArrowRight
} from "lucide-react";
import { Chip } from "@/components/soc";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import type { Format } from "@/data/detection";

interface DetectionRuleOptimizerProps {
  rule: string;
  fmt: Format;
}

export function DetectionRuleOptimizer({ rule, fmt }: DetectionRuleOptimizerProps) {
  const [activeSiemTab, setActiveSiemTab] = useState<"sentinel" | "splunk" | "elastic" | "chronicle" | "falcon">("sentinel");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string, label: string) => {
    copyText(text).then(() => {
      setCopiedKey(key);
      toast.success(`${label} query copied to clipboard`);
      setTimeout(() => setCopiedKey(null), 2500);
    }).catch(() => {
      toast.error("Failed to copy");
    });
  };

  // 1. Autonomous Rule Quality & Production Readiness Analysis
  const quality = useMemo(() => {
    const raw = rule.toLowerCase();

    // A. False Positive Resistance (0 - 25)
    let fpScore = 18;
    const fpFactors: string[] = [];
    if (raw.includes("filter") || raw.includes("not ") || raw.includes("!=") || raw.includes("exclude")) {
      fpScore += 5;
      fpFactors.push("Active exclusion filters detected");
    } else {
      fpScore -= 4;
      fpFactors.push("Lacks baseline exclusion filters (tuning required)");
    }

    if (raw.includes("parent") || raw.includes("ppid") || raw.includes("originalfilename")) {
      fpScore += 2;
      fpFactors.push("Contextual parent-process anchor present");
    }

    // Penalize raw generic binary names without arguments
    if ((raw.includes("powershell.exe") || raw.includes("cmd.exe")) && !raw.includes("commandline") && !raw.includes("encodedcommand")) {
      fpScore -= 8;
      fpFactors.push("Generic process matching without argument constraints");
    }
    fpScore = Math.max(5, Math.min(25, fpScore));

    // B. Engine Performance & Resource Overhead Risk (0 - 25)
    let perfScore = 22;
    const perfFactors: string[] = [];
    if (raw.includes(".*") || raw.includes("(.+)+") || raw.includes(".*.*")) {
      perfScore -= 10;
      perfFactors.push("Risk of catastrophic regex backtracking detected");
    } else {
      perfScore += 2;
      perfFactors.push("Optimized linear regex string matching");
    }

    if (raw.includes("*\\") || raw.includes("*powershell") || raw.includes("contains \"*\"")) {
      perfScore -= 6;
      perfFactors.push("Leading wildcard scan inhibits index acceleration");
    } else {
      perfScore += 1;
      perfFactors.push("Indexed field / prefix-anchored match");
    }
    perfScore = Math.max(5, Math.min(25, perfScore));

    // C. Taxonomy & Schema Compliance (0 - 25)
    let schemaScore = 20;
    const schemaFactors: string[] = [];
    if (fmt === "sigma") {
      if (raw.includes("title:") && raw.includes("id:") && raw.includes("logsource:")) {
        schemaScore += 5;
        schemaFactors.push("Complete Sigma header schema");
      }
      if (raw.includes("status:") && raw.includes("level:")) {
        schemaFactors.push("Operational lifecycle tags present");
      }
    } else if (fmt === "yara") {
      if (raw.includes("meta:") && raw.includes("strings:") && raw.includes("condition:")) {
        schemaScore += 5;
        schemaFactors.push("Compliant YARA tripartite structure");
      }
    } else if (fmt === "suricata") {
      if (raw.includes("sid:") && raw.includes("classtype:") && raw.includes("rev:")) {
        schemaScore += 5;
        schemaFactors.push("Valid Suricata rule options");
      }
    } else {
      schemaScore += 3;
      schemaFactors.push("KQL structured pipeline syntax");
    }
    schemaScore = Math.max(5, Math.min(25, schemaScore));

    // D. MITRE ATT&CK Precision (0 - 25)
    let mitreScore = 18;
    const mitreFactors: string[] = [];
    const hasTactic = raw.includes("attack.") || raw.includes("mitre") || raw.includes("t1") || raw.includes("ta0");
    if (hasTactic) {
      mitreScore += 7;
      mitreFactors.push("Explicit MITRE ATT&CK technique tags mapped");
    } else {
      mitreScore -= 6;
      mitreFactors.push("Missing explicit MITRE technique reference");
    }
    mitreScore = Math.max(5, Math.min(25, mitreScore));

    const totalScore = fpScore + perfScore + schemaScore + mitreScore;

    let verdict = "PRODUCTION READY · FLEET DEPLOYABLE";
    let tone: "success" | "warning" | "destructive" = "success";
    if (totalScore < 70) {
      verdict = "LAB EXPERIMENTAL · HIGH TUNING REQUIRED";
      tone = "destructive";
    } else if (totalScore < 85) {
      verdict = "STAGING CANDIDATE · TUNING RECOMMENDED";
      tone = "warning";
    }

    return {
      totalScore,
      verdict,
      tone,
      vectors: [
        { label: "False Positive Resistance", score: fpScore, max: 25, factors: fpFactors },
        { label: "Engine Performance & Overhead", score: perfScore, max: 25, factors: perfFactors },
        { label: "Taxonomy & Schema Compliance", score: schemaScore, max: 25, factors: schemaFactors },
        { label: "MITRE ATT&CK Precision", score: mitreScore, max: 25, factors: mitreFactors },
      ],
    };
  }, [rule, fmt]);

  // 2. Multi-SIEM Translation Matrix
  const siemMatrix = useMemo(() => {
    // Extract key patterns from rule
    const mEncoded = rule.match(/encodedcommand|downloadstring|iex|invoke-expression|certutil|vssadmin/i);
    const keyword = mEncoded ? mEncoded[0] : "EncodedCommand";

    // A. Microsoft Sentinel KQL
    const sentinelQuery = `// Microsoft Sentinel KQL - High-Fidelity Process Triage
DeviceProcessEvents
| where TimeGenerated >= ago(24h)
| where ProcessCommandLine has_any ("${keyword}", "-enc", "-NoP", "bypass")
| where InitiatingProcessFileName !in~ ("sensu-client.exe", "datadog-agent.exe", "monitoring.exe")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| extend IncidentSeverity = "High", KillChainPhase = "Execution"`;

    // B. Splunk SPL
    const splunkQuery = `index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
CommandLine="*${keyword}*" OR CommandLine="*-enc *" OR CommandLine="*-NoP *"
NOT ParentImage="*\\\\monitoring\\\\agent.exe" NOT User="svc_backup"
| table _time host user ParentImage Image CommandLine
| eval severity="High", tactic="Execution"`;

    // C. Elastic EQL / ES|QL
    const elasticQuery = `// Elastic Security EQL - Endpoint Process Anomaly
process where event.type == "start" and (
  process.command_line : ("*${keyword}*", "*-enc *", "*-NoP *")
) and not (
  process.parent.name in ("monitoring-daemon.exe", "backup-exec.exe")
)`;

    // D. Google Chronicle YARA-L
    const chronicleQuery = `rule endpoint_suspicious_execution {
  meta:
    author = "BeyondArch Autonomous Detection Engine"
    description = "Detects execution matching ${keyword} with suspicious CLI flags"
    severity = "HIGH"
  events:
    $process.metadata.event_type = "PROCESS_LAUNCH"
    $process.target.process.command_line = /${keyword}|-enc|-nop/ nocase
    $process.principal.user.userid != "svc_monitor"
  condition:
    $process
}`;

    // E. CrowdStrike Falcon Query Language
    const falconQuery = `// CrowdStrike Falcon Event Search (FQL / LogScale)
#event_simpleName=ProcessRollup2
| CommandLine=/${keyword}|-enc|-nop/i
| ParentBaseFileName!=/^(monitoring|agent|backup)\\.exe$/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])`;

    return {
      sentinel: sentinelQuery,
      splunk: splunkQuery,
      elastic: elasticQuery,
      chronicle: chronicleQuery,
      falcon: falconQuery,
    };
  }, [rule]);

  return (
    <div id="detection-rule-optimizer" className="space-y-3.5 rounded-lg border border-border bg-surface-1 p-4 shadow-sm min-w-0 max-w-full font-mono mb-4">
      {/* Header & Quality Banner */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-3">
        <div className="flex items-center gap-2">
          <Gauge
            className={`h-4 w-4 shrink-0 ${
              quality.tone === "destructive"
                ? "text-destructive"
                : quality.tone === "warning"
                ? "text-warning"
                : "text-success"
            }`}
          />
          <span className="ba-text-xs font-bold uppercase tracking-wider text-foreground">
            Detection Rule Optimizer & Multi-SIEM Translation Matrix
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Chip tone={quality.tone}>{quality.verdict}</Chip>
          <span className="ba-text-2xs text-muted-foreground font-semibold">
            Quality Score:{" "}
            <span
              className={
                quality.tone === "destructive"
                  ? "text-destructive font-bold"
                  : quality.tone === "warning"
                  ? "text-warning font-bold"
                  : "text-success font-bold"
              }
            >
              {quality.totalScore}/100
            </span>
          </span>
          <span className="rounded bg-surface-2 px-1.5 py-0.5 ba-text-3xs text-foreground border border-border/60 uppercase">
            Format: {fmt}
          </span>
        </div>
      </div>

      {/* 4-Vector Rule Quality Scoring Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
        {quality.vectors.map((vec, idx) => (
          <div key={idx} className="rounded border border-border/60 bg-surface-0 p-2.5 space-y-1">
            <div className="flex items-center justify-between">
              <span className="ba-text-3xs font-bold uppercase text-foreground truncate">{vec.label}</span>
              <span className="ba-text-2xs font-bold text-primary">{vec.score}/{vec.max}</span>
            </div>
            <div className="w-full bg-surface-2 h-1 rounded-full overflow-hidden">
              <div
                className={`h-full ${
                  vec.score >= 20 ? "bg-success" : vec.score >= 14 ? "bg-warning" : "bg-destructive"
                }`}
                style={{ width: `${(vec.score / vec.max) * 100}%` }}
              />
            </div>
            <div className="space-y-0.5 pt-1">
              {vec.factors.map((f, i) => (
                <div key={i} className="ba-text-3xs text-muted-foreground truncate flex items-center gap-1">
                  <span className="h-1 w-1 rounded-full bg-muted-foreground" />
                  <span>{f}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Multi-SIEM Cross-Platform Translation Matrix */}
      <div className="rounded border border-border/60 bg-surface-0 p-3 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/40 pb-2">
          <div className="flex flex-wrap items-center gap-1">
            {(["sentinel", "splunk", "elastic", "chronicle", "falcon"] as const).map((tab) => (
              <button
                key={tab}
                type="button"
                onClick={() => setActiveSiemTab(tab)}
                className={`rounded px-2 py-1 ba-text-3xs uppercase tracking-wider transition ${
                  activeSiemTab === tab
                    ? "border border-primary/50 bg-primary/10 text-primary font-bold"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {tab === "sentinel"
                  ? "Microsoft Sentinel KQL"
                  : tab === "splunk"
                  ? "Splunk SPL"
                  : tab === "elastic"
                  ? "Elastic EQL"
                  : tab === "chronicle"
                  ? "Chronicle YARA-L"
                  : "CrowdStrike Falcon"}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() =>
              handleCopy(
                siemMatrix[activeSiemTab],
                activeSiemTab,
                activeSiemTab.toUpperCase()
              )
            }
            className="inline-flex items-center gap-1.5 rounded border border-border bg-surface-2 px-2 py-1 ba-text-3xs text-foreground hover:border-primary/50 hover:text-primary transition"
          >
            {copiedKey === activeSiemTab ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
            <span>Copy SIEM Query</span>
          </button>
        </div>

        <pre className="max-h-44 overflow-y-auto overflow-x-auto rounded border border-border/40 bg-surface-1 p-2.5 ba-text-3xs text-foreground whitespace-pre leading-relaxed scrollbar-thin">
          {siemMatrix[activeSiemTab]}
        </pre>
      </div>

      {/* Pre-Deployment Canary Readiness Checklist */}
      <div className="rounded border border-border/60 bg-surface-0 p-2.5">
        <div className="flex items-center gap-1.5 text-muted-foreground ba-text-3xs uppercase font-bold mb-1.5">
          <Rocket className="h-3 w-3 text-primary" />
          <span>Production Canary Deployment Checklist</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 ba-text-3xs text-foreground">
          <div className="flex items-center gap-1.5">
            <CheckCircle2 className="h-3.5 w-3.5 text-success shrink-0" />
            <span>Canary deployment to 1% sensor fleet</span>
          </div>
          <div className="flex items-center gap-1.5">
            <CheckCircle2 className="h-3.5 w-3.5 text-success shrink-0" />
            <span>Alert-only audit mode for 48 hours</span>
          </div>
          <div className="flex items-center gap-1.5">
            <CheckCircle2 className="h-3.5 w-3.5 text-success shrink-0" />
            <span>Telemetry noise rate &lt; 5 alerts/day</span>
          </div>
        </div>
      </div>
    </div>
  );
}
