import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useState, useRef, useCallback, useMemo } from "react";
import { PageShell } from "@/components/PageShell";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { HomeSection, QuickLinks, RecentTools, RecentCases, KbdHints } from "@/components/WorkspaceHome";
import {
  UploadCloud, FileCode, CheckCircle, Copy, ArrowRight, ShieldAlert,
  Hash, ExternalLink, Sparkles, AlertTriangle, Layers, BookmarkPlus,
  RefreshCw, FileText, Globe, MailWarning, Link2, File, ScrollText,
  Paperclip, ListChecks,
} from "lucide-react";
import {
  digestArtifact,
  type IntakeDigest,
  type IntakePreset,
  INTAKE_PRESETS,
} from "@/lib/intake-engine";
import { sendArtifact, sendToCase } from "@/lib/handoff";
import { useActiveCase } from "@/data/case";
import { useLocker } from "@/lib/locker";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/intake")({
  component: IntakeHome,
});

function IntakeHome() {
  const navigate = useNavigate();
  const { activeCase, addEntry } = useActiveCase();
  const { add: addLockerItem } = useLocker();

  const [activeTab, setActiveTab] = useState<"drop" | "paste">("drop");
  const [pasteText, setPasteText] = useState("");
  const [pasteTitle, setPasteTitle] = useState("pasted_artifact.txt");
  const [isDragging, setIsDragging] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [digest, setDigest] = useState<IntakeDigest | null>(null);
  const [filterType, setFilterType] = useState<string>("all");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleProcess = useCallback(async (name: string, content: Uint8Array | string, mimeType = "text/plain") => {
    setAnalyzing(true);
    try {
      const res = await digestArtifact(name, content, mimeType);
      setDigest(res);
      toast.success(`Ingested ${name} (${(res.fileSize / 1024).toFixed(1)} KB)`);
    } catch (err) {
      toast.error("Failed to process artifact");
    } finally {
      setAnalyzing(false);
    }
  }, []);

  const handleFileDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const files = e.dataTransfer.files;
    if (files.length === 0) return;
    const file = files[0];
    const reader = new FileReader();
    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) {
        handleProcess(file.name, new Uint8Array(reader.result), file.type || "application/octet-stream");
      }
    };
    reader.readAsArrayBuffer(file);
  }, [handleProcess]);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    const file = files[0];
    const reader = new FileReader();
    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) {
        handleProcess(file.name, new Uint8Array(reader.result), file.type || "application/octet-stream");
      }
    };
    reader.readAsArrayBuffer(file);
  }, [handleProcess]);

  const handleLoadPreset = useCallback((preset: IntakePreset) => {
    handleProcess(preset.fileName, preset.content, "text/plain");
  }, [handleProcess]);

  const handlePasteSubmit = useCallback(() => {
    if (!pasteText.trim()) {
      toast.error("Paste text content before processing");
      return;
    }
    handleProcess(pasteTitle.trim() || "pasted_artifact.txt", pasteText.trim(), "text/plain");
  }, [pasteText, pasteTitle, handleProcess]);

  const handleHandoffToRoute = useCallback((targetPath: string) => {
    if (!digest) return;
    sendArtifact({
      kind: digest.kind,
      value: digest.preview.slice(0, 10000),
      source: "/intake",
    });
    toast.success(`Handoff prepared for ${digest.recommendedRoute.label}`);
    navigate({ to: targetPath });
  }, [digest, navigate]);

  const handleAttachToCase = useCallback(() => {
    if (!digest) return;
    const body = `### Evidence Intake: ${digest.fileName}
- **Artifact Kind:** ${digest.kind.toUpperCase()}
- **File Size:** ${digest.fileSize} bytes
- **SHA-256:** \`${digest.sha256}\`
- **MD5:** \`${digest.md5}\`
- **Shannon Entropy:** ${digest.entropy} (${digest.entropyLabel})
- **Extracted Observables (${digest.observables.length}):**
${digest.observables.map((o) => `  - [${o.kind.toUpperCase()}] ${o.defanged}${o.meta ? ` (${o.meta})` : ""}`).join("\n")}

**Preview:**
\`\`\`
${digest.preview.slice(0, 500)}
\`\`\``;

    if (activeCase) {
      addEntry(body, "evidence", "intake-station");
    } else {
      sendToCase({ body, source: "intake-station", kind: "evidence" });
      toast.success("Artifact queued for new case — navigate to Cases to initialize.");
    }
  }, [digest, activeCase, addEntry]);

  const handleStashToLocker = useCallback(() => {
    if (!digest || digest.observables.length === 0) {
      toast.info("No observables to add");
      return;
    }
    let addedCount = 0;
    for (const obs of digest.observables) {
      if (obs.kind === "ip") {
        addLockerItem({ value: obs.value, type: "ipv4", source: `intake:${digest.fileName}` });
        addedCount++;
      } else if (obs.kind === "url") {
        addLockerItem({ value: obs.value, type: "url", source: `intake:${digest.fileName}` });
        addedCount++;
      } else if (obs.kind === "domain") {
        addLockerItem({ value: obs.value, type: "domain", source: `intake:${digest.fileName}` });
        addedCount++;
      } else if (obs.kind === "hash") {
        addLockerItem({ value: obs.value, type: obs.value.length === 64 ? "sha256" : "md5", source: `intake:${digest.fileName}` });
        addedCount++;
      }
    }
    toast.success(`Added ${addedCount} observables to Locker`);
  }, [digest, addLockerItem]);

  const handleCopyMarkdown = useCallback(async () => {
    if (!digest) return;
    const md = `## Intake Analysis: ${digest.fileName}
- SHA256: \`${digest.sha256}\`
- MD5: \`${digest.md5}\`
- Entropy: \`${digest.entropy}\` (${digest.entropyLabel})
- Observables: ${digest.observables.length} indicators extracted
${digest.observables.map((o) => `- ${o.kind.toUpperCase()}: ${o.defanged}`).join("\n")}`;
    await copyText(md);
    toast.success("Markdown summary copied to clipboard");
  }, [digest]);

  const filteredObservables = useMemo(() => {
    if (!digest) return [];
    if (filterType === "all") return digest.observables;
    return digest.observables.filter((o) => o.kind === filterType);
  }, [digest, filterType]);

  return (
    <ErrorBoundary name="Intake">
      <PageShell
        eyebrow="intake / universal workbench"
        title="Evidence Intake Station"
        description="Unified multi-artifact ingestion — pre-flight hashing, Shannon entropy, observable extraction, and zero-tab forensic routing."
        crumbs={[{ label: "Intake" }, { label: "Evidence Intake" }]}
      >
        <div className="space-y-6">
          {/* Universal Dropzone & Ingestion Card */}
          <div className="rounded-lg border border-border/80 bg-card/60 p-5 shadow-sm space-y-4 backdrop-blur-sm">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/60 pb-3">
              <div className="flex items-center gap-2">
                <UploadCloud className="h-5 w-5 text-primary" />
                <h2 className="text-mono ba-text-base font-semibold tracking-tight text-foreground">
                  Universal Artifact Ingestion
                </h2>
                <span className="rounded border border-primary/30 bg-primary/10 px-2 py-0.5 text-mono ba-text-3xs text-primary font-medium">
                  pre-flight telemetry
                </span>
              </div>

              {/* Ingestion Mode Toggle */}
              <div className="flex items-center rounded-md border border-border/70 bg-surface-0 p-0.5 text-mono ba-text-2xs">
                <button
                  type="button"
                  onClick={() => setActiveTab("drop")}
                  className={cn(
                    "rounded px-2.5 py-1 transition-colors",
                    activeTab === "drop" ? "bg-primary text-primary-foreground font-medium" : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  File Upload
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab("paste")}
                  className={cn(
                    "rounded px-2.5 py-1 transition-colors",
                    activeTab === "paste" ? "bg-primary text-primary-foreground font-medium" : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  Raw Text / Log Paste
                </button>
              </div>
            </div>

            {/* Attack Simulation Presets */}
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <span className="flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground font-medium">
                <Sparkles className="h-3 w-3 text-warning" /> Attack presets:
              </span>
              {INTAKE_PRESETS.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  onClick={() => handleLoadPreset(preset)}
                  className="rounded border border-border/70 bg-surface-1/70 px-2 py-0.5 text-mono ba-text-3xs text-foreground/80 hover:border-primary/60 hover:text-primary hover:bg-primary/5 transition-all"
                  title={preset.description}
                >
                  {preset.label}
                </button>
              ))}
            </div>

            {/* Drop / Paste Area */}
            {activeTab === "drop" ? (
              <div
                onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={handleFileDrop}
                onClick={() => fileInputRef.current?.click()}
                className={cn(
                  "relative flex min-h-[160px] cursor-pointer flex-col items-center justify-center rounded-md border-2 border-dashed p-6 text-center transition-all",
                  isDragging
                    ? "border-primary bg-primary/10 shadow-glow"
                    : "border-border/70 bg-surface-0/60 hover:border-primary/50 hover:bg-surface-0",
                )}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  onChange={handleFileInput}
                  className="hidden"
                />
                <div className="rounded-full bg-primary/10 p-3 mb-2 text-primary">
                  {analyzing ? (
                    <RefreshCw className="h-6 w-6 animate-spin" />
                  ) : (
                    <UploadCloud className="h-6 w-6" />
                  )}
                </div>
                <div className="text-mono ba-text-sm font-medium text-foreground">
                  Drop artifact here or click to browse
                </div>
                <div className="mt-1 text-mono ba-text-3xs text-muted-foreground max-w-md">
                  Accepts .eml, .msg, .pcap, .pcapng, .json, .log, .csv, .exe, .dll, .ps1, .pdf, or archive payloads.
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <span className="text-mono ba-text-2xs text-muted-foreground">Virtual Filename:</span>
                  <input
                    type="text"
                    value={pasteTitle}
                    onChange={(e) => setPasteTitle(e.target.value)}
                    className="flex-1 rounded border border-border/70 bg-surface-0 px-2 py-1 text-mono ba-text-2xs text-foreground focus:border-primary focus:outline-none"
                    placeholder="e.g. suspicious_c2_event.log"
                  />
                </div>
                <textarea
                  rows={6}
                  value={pasteText}
                  onChange={(e) => setPasteText(e.target.value)}
                  placeholder="Paste email headers, raw JSON event, PowerShell cradle script, or base64 stream..."
                  className="w-full rounded-md border border-border/70 bg-surface-0 p-3 text-mono ba-text-xs text-foreground placeholder:text-muted-foreground/60 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                />
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={handlePasteSubmit}
                    disabled={analyzing || !pasteText.trim()}
                    className="flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-mono ba-text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors shadow-sm"
                  >
                    {analyzing ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <FileCode className="h-3.5 w-3.5" />}
                    Ingest & Dissect Payload
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Pre-Flight Analysis Telemetry & Routing Dock */}
          {digest && (
            <div className="rounded-lg border border-primary/40 bg-card/80 p-5 shadow-glow space-y-5 backdrop-blur-md">
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border/60 pb-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-primary/20 border border-primary/40 px-2 py-0.5 text-mono ba-text-3xs font-bold uppercase text-primary">
                      {digest.kind}
                    </span>
                    <h3 className="text-mono ba-text-lg font-bold text-foreground">
                      {digest.fileName}
                    </h3>
                  </div>
                  <div className="text-mono ba-text-3xs text-muted-foreground flex items-center gap-3">
                    <span>Size: <strong>{digest.fileSize} bytes</strong></span>
                    <span>•</span>
                    <span>MIME: <strong>{digest.mimeType}</strong></span>
                    <span>•</span>
                    <span>Observables: <strong>{digest.observables.length} extracted</strong></span>
                  </div>
                </div>

                {/* Primary Action Button */}
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={() => handleHandoffToRoute(digest.recommendedRoute.path)}
                    className="flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-mono ba-text-xs font-bold text-primary-foreground hover:bg-primary/90 transition-all shadow-[0_0_12px_var(--primary)]"
                  >
                    <span>{digest.recommendedRoute.label}</span>
                    <ArrowRight className="h-4 w-4" />
                  </button>
                  <button
                    type="button"
                    onClick={handleAttachToCase}
                    className="flex items-center gap-1.5 rounded-md border border-border bg-surface-1 px-3 py-2 text-mono ba-text-xs text-foreground hover:bg-surface-2 transition-colors"
                    title="Attach to active investigation notebook"
                  >
                    <BookmarkPlus className="h-3.5 w-3.5 text-primary" />
                    <span>Attach to Case</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleStashToLocker}
                    className="flex items-center gap-1.5 rounded-md border border-border bg-surface-1 px-3 py-2 text-mono ba-text-xs text-foreground hover:bg-surface-2 transition-colors"
                    title="Save extracted IOCs into Evidence Locker"
                  >
                    <Layers className="h-3.5 w-3.5 text-amber-400" />
                    <span>Stash to Locker</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleCopyMarkdown}
                    className="flex items-center gap-1.5 rounded-md border border-border bg-surface-1 px-2.5 py-2 text-mono ba-text-xs text-muted-foreground hover:text-foreground transition-colors"
                    title="Copy Markdown Brief"
                  >
                    <Copy className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>

              {/* Cryptographic & Entropy Metrics */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {/* Hashes Card */}
                <div className="rounded-md border border-border/70 bg-surface-0/60 p-3 space-y-2">
                  <div className="flex items-center gap-1.5 text-mono ba-text-3xs font-semibold uppercase text-muted-foreground">
                    <Hash className="h-3.5 w-3.5 text-primary" />
                    <span>Cryptographic Fingerprints</span>
                  </div>
                  <div className="space-y-1 text-mono ba-text-3xs">
                    <div>
                      <span className="text-muted-foreground">SHA256: </span>
                      <code className="text-foreground select-all break-all">{digest.sha256}</code>
                    </div>
                    <div>
                      <span className="text-muted-foreground">MD5: </span>
                      <code className="text-foreground select-all">{digest.md5}</code>
                    </div>
                  </div>
                </div>

                {/* Shannon Entropy Card */}
                <div className="rounded-md border border-border/70 bg-surface-0/60 p-3 space-y-2">
                  <div className="flex items-center justify-between text-mono ba-text-3xs font-semibold uppercase text-muted-foreground">
                    <span className="flex items-center gap-1.5">
                      <ShieldAlert className="h-3.5 w-3.5 text-warning" />
                      <span>Shannon Entropy</span>
                    </span>
                    <span
                      className={cn(
                        "rounded px-1.5 py-0.2 text-[9px] font-bold uppercase",
                        digest.entropyRisk === "high"
                          ? "bg-destructive/20 text-destructive border border-destructive/30"
                          : digest.entropyRisk === "medium"
                          ? "bg-warning/20 text-warning border border-warning/30"
                          : "bg-success/20 text-success border border-success/30",
                      )}
                    >
                      {digest.entropyRisk} risk
                    </span>
                  </div>
                  <div className="space-y-1">
                    <div className="flex items-baseline justify-between text-mono">
                      <span className="ba-text-xl font-bold text-foreground">{digest.entropy}</span>
                      <span className="ba-text-3xs text-muted-foreground">/ 8.00 bits/byte</span>
                    </div>
                    <div className="text-mono ba-text-3xs text-muted-foreground truncate">
                      {digest.entropyLabel}
                    </div>
                  </div>
                </div>

                {/* Recommended Pivot Card */}
                <div className="rounded-md border border-border/70 bg-surface-0/60 p-3 space-y-2">
                  <div className="flex items-center gap-1.5 text-mono ba-text-3xs font-semibold uppercase text-muted-foreground">
                    <ExternalLink className="h-3.5 w-3.5 text-primary" />
                    <span>Target Workbench Intent</span>
                  </div>
                  <div className="text-mono ba-text-3xs text-foreground/80 leading-relaxed">
                    {digest.recommendedRoute.intent}
                  </div>
                  <div className="text-mono ba-text-3xs text-primary font-medium">
                    Route: {digest.recommendedRoute.path}
                  </div>
                </div>
              </div>

              {/* Extracted Observables Table */}
              {digest.observables.length > 0 && (
                <div className="space-y-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-mono ba-text-xs font-semibold text-foreground">
                        Extracted Observables ({filteredObservables.length})
                      </span>
                    </div>

                    {/* Filter Pills */}
                    <div className="flex items-center gap-1 text-mono ba-text-3xs">
                      {["all", "ip", "url", "email", "hash", "command"].map((type) => (
                        <button
                          key={type}
                          type="button"
                          onClick={() => setFilterType(type)}
                          className={cn(
                            "rounded px-2 py-0.5 uppercase transition-colors",
                            filterType === type
                              ? "bg-primary/20 text-primary border border-primary/40 font-bold"
                              : "text-muted-foreground hover:text-foreground",
                          )}
                        >
                          {type}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="max-h-60 overflow-y-auto rounded-md border border-border/60 bg-surface-0">
                    <table className="w-full text-left text-mono ba-text-xs border-collapse">
                      <thead className="sticky top-0 bg-surface-1 border-b border-border/60 text-muted-foreground ba-text-3xs font-semibold uppercase">
                        <tr>
                          <th className="px-3 py-1.5">Kind</th>
                          <th className="px-3 py-1.5">Defanged Indicator</th>
                          <th className="px-3 py-1.5">Context</th>
                          <th className="px-3 py-1.5 text-right">Quick Pivots</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border/30">
                        {filteredObservables.map((obs, idx) => (
                          <tr key={idx} className="hover:bg-surface-1/50 transition-colors">
                            <td className="px-3 py-1.5 text-muted-foreground uppercase text-[10px] font-bold">
                              {obs.kind}
                            </td>
                            <td className="px-3 py-1.5 font-medium text-foreground select-all break-all">
                              {obs.defanged}
                            </td>
                            <td className="px-3 py-1.5 text-muted-foreground text-[10px]">
                              {obs.meta || "—"}
                            </td>
                            <td className="px-3 py-1.5 text-right space-x-1">
                              {obs.kind === "ip" || obs.kind === "domain" || obs.kind === "hash" ? (
                                <Link
                                  to="/intel"
                                  className="rounded border border-border px-1.5 py-0.5 text-[9px] text-muted-foreground hover:text-primary hover:border-primary/50 transition-colors"
                                  title="Pivot to Threat Intelligence"
                                >
                                  Intel
                                </Link>
                              ) : null}
                              {obs.kind === "url" ? (
                                <Link
                                  to="/url"
                                  className="rounded border border-border px-1.5 py-0.5 text-[9px] text-muted-foreground hover:text-primary hover:border-primary/50 transition-colors"
                                  title="Pivot to URL Dissection"
                                >
                                  Dissect
                                </Link>
                              ) : null}
                              <button
                                type="button"
                                onClick={async () => {
                                  await copyText(obs.defanged);
                                  toast.success(`Copied: ${obs.defanged}`);
                                }}
                                className="rounded border border-border px-1.5 py-0.5 text-[9px] text-muted-foreground hover:text-foreground hover:border-border/80 transition-colors"
                                title="Copy defanged value"
                              >
                                Copy
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Quick Artifact Jump Links */}
          <HomeSection title="Specialized Forensic Workbenches">
            <QuickLinks
              cols={3}
              links={[
                { to: "/phishing", icon: MailWarning, title: "Email & Phishing", desc: "Auth headers, RFC822 parser & lure analysis" },
                { to: "/url", icon: Link2, title: "URL Dissection", desc: "Redirect tracing, domain reputation & unshortening" },
                { to: "/file", icon: File, title: "File & Binary Forensics", desc: "Hashes, section entropy, PE headers & markers" },
                { to: "/attachment", icon: Paperclip, title: "Attachment Dissector", desc: "Extract payloads from documents & archives" },
                { to: "/pcap", icon: Globe, title: "PCAP Inspector", desc: "Packet stream extraction, TLS & DNS analysis" },
                { to: "/logs", icon: ScrollText, title: "Log Analyzer", desc: "Multi-format log filtering and normalization" },
                { to: "/triage", icon: ListChecks, title: "Alert Triage Queue", desc: "SOAR alert ingestion, deduplication & escalation" },
              ]}
            />
          </HomeSection>

          {/* Recent History */}
          <HomeSection title="Recent Analyses">
            <RecentTools group="Intake" limit={8} empty="No artifact analyses yet — ingest an artifact above or launch a forensic tool." />
          </HomeSection>

          <HomeSection title="Recent Investigations">
            <RecentCases limit={5} />
          </HomeSection>
        </div>
      </PageShell>
    </ErrorBoundary>
  );
}
