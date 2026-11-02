import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { PageShell } from "@/components/PageShell";
import { AnalyzerShell, type AnalyzerState } from "@/components/soc/AnalyzerShell";
import { Panel, SectionBar, Chip } from "@/components/soc";
import { Empty, AnalysisLoading, ResultBanner } from "@/components/output";
import { IOCTable, MitrePanel } from "@/components/investigation";
import { useLocker } from "@/lib/locker";
import { sendArtifact } from "@/lib/handoff";
import { pushTimelineEvent } from "@/lib/timeline";
import { toast } from "sonner";
import { createCaseFromAnalysis } from "@/data/case-factory";
import { uploadPcap } from "@/api/network";
import { Upload, Terminal, Globe, AlertTriangle, Network, Play, Trash2,
  FileText, CheckCircle, Download, Server, Activity,
  Database, ShieldAlert, BookMarked, ListFilter, ShieldCheck } from "lucide-react";
import { generateMdReport, generateTextMdReport,
  SAMPLE_OUTPUTS, formatBytes } from "@/data/pcap";
import { analyzePcapBackend, analyzePcapText, type PcapAnalysisResult } from "@/lib/pcapArtifact";
import { runBatchEnrichment } from "@/lib/enrichment";
import { buildLocalHistory } from "@/lib/correlation/history";
import { rememberCorrelation } from "@/lib/correlation";
import { useWorkspaceState } from "@/lib/use-workspace-state";
import { ResumeBanner } from "@/components/ResumeBanner";
import { type Severity } from "@/lib/severity";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { WiresharkFilterBar } from "@/components/pcap/WiresharkFilterBar";
import { ZeekLogViewer } from "@/components/pcap/ZeekLogViewer";
import { TcpStreamModal, type StreamDialogueItem } from "@/components/pcap/TcpStreamModal";
import { SuricataRuleModal } from "@/components/pcap/SuricataRuleModal";
import { PcapContainmentConsole } from "@/components/pcap/PcapContainmentConsole";
import type { ZeekConn } from "@/lib/pcap/zeek-models";
import { generateRulesetFromPcap } from "@/lib/pcap/suricata-generator";

export const Route = createFileRoute("/pcap")({ component: PcapPage });

function getStreamDialogue(conn: ZeekConn | null, analysis: PcapAnalysisResult | null): StreamDialogueItem[] {
  if (!conn) return [];
  const httpReq = (analysis?.zeek_http || []).find(
    (h) => (h.src === conn.orig_h || h.src === conn.resp_h) && (h.dst === conn.orig_h || h.dst === conn.resp_h)
  );

  if (httpReq) {
    return [
      {
        origin: "client",
        text: `${httpReq.method} ${httpReq.path} HTTP/1.1\r\nHost: ${httpReq.host}\r\nUser-Agent: ${httpReq.user_agent || "Mozilla/5.0"}\r\nAccept: */*\r\n\r\n`,
      },
      {
        origin: "server",
        text: `HTTP/1.1 ${httpReq.status_code || 200} OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: ${conn.resp_bytes || 184}\r\n\r\n<!DOCTYPE html><html><body><h1>Response</h1></body></html>`,
      },
    ];
  }

  const dnsReq = (analysis?.zeek_dns || []).find((d) => d.query);
  if (conn.service === "dns" && dnsReq) {
    return [
      {
        origin: "client",
        text: `Standard query 0x1234 A ${dnsReq.query}`,
      },
      {
        origin: "server",
        text: `Standard query response 0x1234 A ${dnsReq.query} A 104.21.32.18`,
      },
    ];
  }

  return [
    {
      origin: "client",
      text: `[SYN] Sequence=0 Win=65535 Len=0 MSS=1460 WS=256\nPayload (${conn.orig_bytes} bytes):\n${conn.orig_h}:${conn.orig_p} -> ${conn.resp_h}:${conn.resp_p} [${conn.proto.toUpperCase()}]`,
    },
    {
      origin: "server",
      text: `[SYN, ACK] Sequence=0 Ack=1 Win=65535 Len=0 MSS=1460\nConnection State: ${conn.conn_state} (${conn.service.toUpperCase()})`,
    },
  ];
}

function EmptyPreview() {
  return (
    <Empty
      icon={Network}
      title="No capture loaded"
      hint="Upload a .pcap file for full Scapy-based analysis (IPs, DNS, HTTP, TLS, beaconing, IOCs), or paste tcpdump/tshark output for quick client-side triage."
    />
  );
}

function PcapPage() {
  const navigate = useNavigate({ from: "/pcap" });
  const fileRef = useRef<HTMLInputElement>(null);
  const locker = useLocker();

  const [toolState, setToolState] = useState<AnalyzerState>("empty");
  const [errorMsg, setErrorMsg] = useState("");
  const [activeTab, setActiveTab] = useState<"signals" | "zeek" | "iocs" | "mitre">("signals");
  const [wiresharkFilter, setWiresharkFilter] = useState("");
  const [activeConnForStream, setActiveConnForStream] = useState<ZeekConn | null>(null);
  const [showSuricataModal, setShowSuricataModal] = useState(false);
  const [inputMode, setInputMode] = useState<"file" | "text">("file");
  const [fileName, setFileName] = useState("");
  const [fileData, setFileData] = useState<File | null>(null);
  const [rawText, setRawText] = useState("");
  const [hashEnrichRunning, setHashEnrichRunning] = useState(false);
  const [activeSample, setActiveSample] = useState("");
  const [filterSeverity, setFilterSeverity] = useState<Severity | "all">("all");

  const [analysis, setAnalysis] = useState<PcapAnalysisResult | null>(null);

  const filteredConns = useMemo(() => {
    const list = analysis?.zeek_conn || [];
    if (!wiresharkFilter.trim()) return list;
    const q = wiresharkFilter.toLowerCase();
    return list.filter(
      (c) =>
        c.orig_h.toLowerCase().includes(q) ||
        c.resp_h.toLowerCase().includes(q) ||
        c.proto.toLowerCase().includes(q) ||
        c.service.toLowerCase().includes(q) ||
        c.orig_p.includes(q) ||
        c.resp_p.includes(q) ||
        c.conn_state.toLowerCase().includes(q)
    );
  }, [analysis?.zeek_conn, wiresharkFilter]);

  const generatedRuleset = useMemo(() => {
    if (!analysis) return "";
    if (analysis.suricata_rules?.length) {
      return analysis.suricata_rules.join("\n");
    }
    return generateRulesetFromPcap(
      analysis.displayFindings,
      analysis.backendResult?.beaconing_candidates || [],
      analysis.backendResult?.dns_queries || [],
      analysis.zeek_http || []
    );
  }, [analysis]);

  const hasContent = inputMode === "file" ? !!fileData : rawText.trim().length > 0;

  const uploadMutate = useMutation({
    mutationFn: () => {
      if (!fileData) throw new Error("No file selected");
      return uploadPcap(fileData);
    },
    onSuccess: (res) => {
      if (res.status === "dependency_missing") {
        setErrorMsg("Scapy not installed on backend. PCAP files require the scapy Python package.");
        setToolState("error");
        toast.error("Scapy dependency missing on backend");
        return;
      }
      const r = analyzePcapBackend(res, { history: buildLocalHistory() });
      setAnalysis(r);
      if (r?.correlation?.length) rememberCorrelation(r.correlation, { source: "pcap" });
      setToolState("loaded");
      setErrorMsg("");
      pushTimelineEvent({
        source: "pcap", verb: "analyzed",
        detail: `Analyzed ${res.filename}: ${res.summary.packets} packets, ${res.summary.findings} findings`,
        result: `${res.summary.findings} findings`,
      });
    },
    onError: (e: Error) => {
      setErrorMsg(e?.message || "Analysis failed");
      setToolState("error");
      toast.error("PCAP upload failed", { description: e?.message });
    },
  });

  const committed = toolState === "analyzing" || toolState === "loaded";
  const { pending, accept, save, clear } = useWorkspaceState("pcap");

  const textResult = useMemo(() => {
    if (inputMode !== "text" || !committed || !rawText.trim()) return null;
    return analyzePcapText(rawText, { history: buildLocalHistory() });
  }, [inputMode, rawText, committed]);

  useEffect(() => {
    if (!textResult) return;
    setAnalysis(textResult);
    setToolState("loaded");
    setErrorMsg("");
    save({ artifact: rawText, analysis: textResult });
    if (textResult?.correlation?.length) rememberCorrelation(textResult.correlation, { source: "pcap" });
    const parsed = textResult.textAnalysis;
    if (parsed) {
      pushTimelineEvent({
        source: "pcap", verb: "parsed",
        detail: `Parsed pasted output: ${parsed.totalPackets} lines, ${parsed.ips.length} IPs`,
        result: `${parsed.suspicious.length} indicators`,
      });
    }
  }, [textResult, save, rawText]);

  useEffect(() => {
    if (activeSample && SAMPLE_OUTPUTS[activeSample]) {
      setRawText(SAMPLE_OUTPUTS[activeSample]);
      setToolState("analyzing");
      setActiveSample(activeSample);
    }
  }, [activeSample]);

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (f) {
      setFileName(f.name);
      setFileData(f);
      setAnalysis(null);
      setErrorMsg("");
    }
  }

  function handleClear() {
    setFileName("");
    setFileData(null);
    setRawText("");
    setAnalysis(null);
    setErrorMsg("");
    setToolState("empty");
    if (fileRef.current) fileRef.current.value = "";
  }

  function handleAnalyze() {
    if (inputMode === "file") {
      uploadMutate.mutate();
    } else {
      setToolState("analyzing");
    }
  }

  const totalIocs = useMemo(() => {
    if (!analysis) return 0;
    return analysis.iocs.length;
  }, [analysis]);

  const backendResult = analysis?.backendResult;
  const textAnalysis = analysis?.textAnalysis;
  const isBackend = analysis?.inputMode === "file" && !!backendResult;
  const pcapHashes = useMemo(() => backendResult?.iocs.hashes ?? [], [backendResult]);

  async function runPcapHashReputation() {
    if (!pcapHashes.length || hashEnrichRunning) return;
    setHashEnrichRunning(true);
    try {
      const result = await runBatchEnrichment(pcapHashes);
      toast.success(`hash reputation: ${result.processed} enriched · ${result.skipped.length} skipped`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Batch reputation failed");
    } finally {
      setHashEnrichRunning(false);
    }
  }
  const isText = analysis?.inputMode === "text" && !!textAnalysis;

  const filteredFindings = useMemo(() => {
    if (!analysis) return [];
    if (filterSeverity === "all") return analysis.displayFindings;
    return analysis.displayFindings.filter((f) => f.severity === filterSeverity);
  }, [analysis, filterSeverity]);

  const [cliInput, setCliInput] = useState("");
  const [cliOutput, setCliOutput] = useState("");
  const [cliLoading, setCliLoading] = useState(false);

  async function runCli() {
    if (!cliInput.trim()) return;
    setCliLoading(true);
    try {
      const { runToolRemote } = await import("@/lib/backend");
      const result = await runToolRemote({ category_id: "pcap", tool_id: "tshark", args: cliInput.trim() });
      setCliOutput(JSON.stringify(result, null, 2));
    } catch (e: any) {
      setCliOutput(e?.message || "Command failed");
    }
    setCliLoading(false);
  }

  return (
    <ErrorBoundary name="PcapPage">
    <PageShell
      title="PCAP Analysis"
      eyebrow="triage / pcap"
      description="Upload a .pcap file for full Scapy-based analysis, or paste tcpdump/tshark output for quick triage."
      crumbs={[{ label: "Intake" }, { label: "PCAP Analysis" }]}
    >
      <AnalyzerShell
        icon={Network}
        title="PCAP Analysis"
        purpose="Upload a .pcap file for full Scapy-based analysis, or paste tcpdump/tshark output for quick triage."
        state={toolState}
        resumeBanner={pending && (
          <ResumeBanner
            artifact={pending.artifact}
            updatedAt={pending.updatedAt}
            onResume={() => {
              const s = accept();
              if (s) {
                setInputMode("text");
                setRawText(s.artifact);
                setToolState("analyzing");
                if (s.analysis) setAnalysis(s.analysis as PcapAnalysisResult);
              }
            }}
            onStartFresh={clear}
          />
        )}
        intake={
          <div className="space-y-4">
            <Panel title="Input Mode">
              <div className="flex items-center gap-2 mb-3">
                <button onClick={() => { setInputMode("file"); handleClear(); }}
                  className={"rounded border px-2.5 py-1 text-mono ba-text-2xs transition-colors duration-150" + (inputMode === "file" ? "border-primary bg-primary/15 text-primary" : "border-border bg-surface-1 text-muted-foreground hover:text-foreground")}>
                  <Upload className="h-3 w-3 inline mr-1" /> Upload .pcap
                </button>
                <button onClick={() => { setInputMode("text"); handleClear(); }}
                  className={"rounded border px-2.5 py-1 text-mono ba-text-2xs transition-colors duration-150" + (inputMode === "text" ? "border-primary bg-primary/15 text-primary" : "border-border bg-surface-1 text-muted-foreground hover:text-foreground")}>
                  <FileText className="h-3 w-3 inline mr-1" /> Paste Output
                </button>
              </div>
              {inputMode === "file" ? (
                <div>
                  <label className="flex cursor-pointer items-center gap-2 rounded border border-dashed border-border bg-surface-1 px-4 py-3 text-mono ba-text-2xs text-muted-foreground hover:border-primary/40 hover:text-primary">
                    <Upload className="h-4 w-4" />
                    Choose .pcap / .pcapng file
                    <input ref={fileRef} type="file" accept=".pcap,.pcapng" onChange={handleFileChange} className="hidden" />
                  </label>
                  {fileName && (
                    <div className="mt-2 flex items-center gap-2">
                      <span className="font-mono text-sm text-fg-dim">{fileName}</span>
                      <span className="text-mono ba-text-2xs text-muted-foreground">({formatBytes(fileData?.size || 0)})</span>
                    </div>
                  )}
                </div>
              ) : (
                <div>
                  <textarea
                    value={rawText}
                    onChange={(e) => setRawText(e.target.value)}
                    aria-label="Paste capture output"
                    placeholder="Paste tcpdump or tshark output — IPs, protocols, DNS queries, and suspicious indicators will be extracted automatically."
                    className="h-44 w-full resize-y rounded border border-border bg-surface-0 p-3 font-mono text-sm text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50"
                  />
                  {rawText.trim() && (
                    <span className="mt-1 block text-mono ba-text-2xs text-muted-foreground">
                      {rawText.split("\n").filter(Boolean).length} lines — {rawText.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g)?.length || 0} IPs detected
                    </span>
                  )}
                </div>
              )}
            </Panel>

            {inputMode === "text" && (
              <Panel title="Samples" priority="secondary">
                <div className="space-y-1.5">
                  {Object.entries(SAMPLE_OUTPUTS).map(([name, text]) => (
                    <button key={name} onClick={() => { setActiveSample(name); }}
                      className={"group flex w-full items-center gap-2 rounded border px-2 py-1.5 text-left transition-colors duration-150 " + (activeSample === name ? "border-primary/50 bg-primary/10" : "border-border/60 bg-surface-0 hover:border-primary/40")}>
                      <Terminal className="h-3.5 w-3.5 shrink-0 text-muted-foreground group-hover:text-primary" />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-mono ba-text-sm text-foreground">{name}</div>
                        <div className="text-mono ba-text-2xs text-muted-foreground">{text.split("\n").length} lines</div>
                      </div>
                    </button>
                  ))}
                </div>
              </Panel>
            )}
          </div>
        }
        resultBanner={toolState === "loaded" && analysis ? (
          <ResultBanner
            badge={analysis.summary.verdict === "malicious" ? "critical" as const : analysis.summary.verdict === "suspicious" ? "warning" as const : "success" as const}
            title={`PCAP Analysis \u2014 ${analysis.totalPackets} packets`}
            subtitle={analysis.fileName || "Pasted output"}
            metrics={[
              { label: "Score", value: analysis.summary.score, tone: analysis.summary.score > 60 ? "destructive" : analysis.summary.score > 20 ? "warning" : "primary" },
              { label: "Findings", value: analysis.displayFindings.length, tone: "primary" },
              { label: "Critical/High", value: analysis.displayFindings.filter(f => f.severity === "critical" || f.severity === "high").length, tone: "destructive" },
              { label: "IOCs", value: analysis.iocs.length, tone: "destructive" },
            ]}
          />
        ) : undefined}
        exportMd={toolState === "loaded" && analysis ? () => {
          if (isBackend && backendResult) {
            const md = generateMdReport(backendResult);
            const blob = new Blob([md], { type: "text/markdown" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url; a.download = `pcap-report-${backendResult.sha256.slice(0, 8)}.md`;
            a.click(); URL.revokeObjectURL(url);
          } else if (isText && textAnalysis) {
            const md = generateTextMdReport(textAnalysis);
            const blob = new Blob([md], { type: "text/markdown" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url; a.download = "pcap-text-report-" + Date.now() + ".md";
            a.click(); URL.revokeObjectURL(url);
          }
        } : undefined}
        exportJson={toolState === "loaded" && analysis ? () => {
          const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = `pcap-analysis-${Date.now()}.json`; a.click();
          URL.revokeObjectURL(url);
        } : undefined}
        onCreateInvestigation={toolState === "loaded" && analysis ? () => {
          const { investigation } = createCaseFromAnalysis(analysis);
          toast.success(`Investigation created: ${investigation.case.title}`);
          navigate({ to: "/case" });
        } : undefined}
        sendToTargets={toolState === "loaded" && analysis ? [
          { label: "Detection", to: "/detection", icon: ShieldAlert, onClick: () => sendArtifact({ kind: "raw", value: `${analysis.totalPackets} packets \u00b7 ${analysis.displayFindings.length} findings`, source: "/pcap" }) },
          { label: "Case Notebook", to: "/case", icon: Database, onClick: () => sendArtifact({ kind: "raw", value: `${analysis.totalPackets} packets from ${analysis.artifact.title}`, source: "/pcap" }) },
          { label: "SIEM", to: "/siem", icon: Activity, onClick: () => sendArtifact({ kind: "raw", value: `${analysis.totalPackets} packets \u00b7 ${analysis.uniqueIPs} IPs`, source: "/pcap" }) },
        ] : undefined}
        onRun={handleAnalyze}
        onClear={handleClear}
        canRun={hasContent && toolState !== "analyzing" && !uploadMutate.isPending}
        runLabel="analyse"
      >
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

        {uploadMutate.isPending && (
          <Panel><AnalysisLoading label="Uploading and analyzing capture..." /></Panel>
        )}

        {toolState === "analyzing" && !analysis && inputMode === "text" && (
          <Panel><AnalysisLoading label="Analyzing capture..." /></Panel>
        )}

        {toolState === "loaded" && analysis && (
          <>
            <PcapContainmentConsole analysis={analysis} />
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-2 mb-3">
              <div className="flex items-center gap-1">
                {(["signals", "zeek", "iocs", "mitre"] as const).map(tab => (
                  <button key={tab} onClick={() => setActiveTab(tab)}
                    className={"rounded px-2.5 py-1 text-mono ba-text-2xs transition " + (activeTab === tab ? "border border-primary/50 bg-primary/10 text-primary font-medium" : "text-muted-foreground hover:text-foreground")}>
                    {tab === "signals" ? `Signals (${analysis.displayFindings.length})` : tab === "zeek" ? `Zeek Logs (${analysis.zeek_conn?.length || 0})` : tab === "iocs" ? `IOCs (${analysis.iocs.length})` : `MITRE (${analysis.mitre.length})`}
                  </button>
                ))}
              </div>

              <button
                type="button"
                onClick={() => setShowSuricataModal(true)}
                className="inline-flex items-center gap-1.5 rounded border border-warning/40 bg-warning/10 px-2.5 py-1 text-mono ba-text-2xs text-warning hover:bg-warning/20 transition"
              >
                <ShieldAlert className="h-3.5 w-3.5" />
                Suricata IDS Rules
              </button>
            </div>

            {activeTab === "signals" && (
              <div className="space-y-4">
                  {/* Severity filter */}
                  {analysis.displayFindings.length > 0 && (
                    <div className="flex items-center gap-2">
                      <ListFilter className="h-3 w-3 text-muted-foreground" />
                      {(["all", "high", "medium", "low", "info"] as const).map((s) => (
                        <button key={s} onClick={() => setFilterSeverity(s)}
                          className={"rounded border px-1.5 py-0.5 text-mono ba-text-2xs" + (filterSeverity === s ? "border-primary bg-primary/15 text-primary" : "border-subtle text-muted-foreground hover:text-foreground")}>
                          {s}
                        </button>
                      ))}
                    </div>
                  )}

                  {analysis.displayFindings.length === 0 ? (
                    <Panel>
                      <div className="flex items-center justify-center py-8">
                        <div className="text-center">
                          <CheckCircle className="mx-auto h-8 w-8 text-success/80" />
                          <p className="mt-2 text-mono ba-text-sm text-fg-dim">No findings</p>
                          <p className="text-mono ba-text-xs text-muted-foreground">Capture appears clean based on available signals.</p>
                        </div>
                      </div>
                    </Panel>
                  ) : (
                    filteredFindings.map((f, i) => (
                      <div key={i} className="mb-2 last:mb-0">
                        <Panel title="" bodyClassName="p-0">
                          <div className={"border-l-2 px-4 py-3 " + (
                            f.severity === "critical" ? "border-destructive/40" : f.severity === "high" ? "border-destructive/30" : f.severity === "medium" ? "border-warning/30" : "border-info/30"
                          )}>
                            <div className="flex items-start justify-between gap-2">
                              <div className="flex items-center gap-2">
                                <Chip tone={f.severity === "critical" || f.severity === "high" ? "destructive" : f.severity === "medium" ? "warning" : "info"}>{f.severity}</Chip>
                                <span className="text-mono ba-text-sm font-medium text-foreground">{f.title}</span>
                              </div>
                            </div>
                            <p className="mt-1.5 text-mono ba-text-sm text-fg-dim">{f.reason}</p>
                            <p className="mt-1 text-mono ba-text-2xs text-muted-foreground">Recommendation: {f.action}</p>
                          </div>
                        </Panel>
                      </div>
                    ))
                  )}

                  {/* Backend-specific visualizations */}
                  {isBackend && backendResult && (
                    <>
                      <SectionBar id="OT" label="Network Analysis" meta={`${backendResult.summary.packets} packets \u00b7 ${backendResult.summary.unique_ips} IPs`} />

                      {/* Metrics grid */}
                      <div className="grid grid-cols-3 gap-3">
                        {[
                          { label: "DNS Queries", value: String(backendResult.summary.dns_queries), icon: Globe },
                          { label: "HTTP Requests", value: String(backendResult.summary.http_requests), icon: Activity },
                          { label: "TLS SNI", value: String(backendResult.summary.tls_sni), icon: ShieldAlert },
                        ].map((m, i) => (
                          <div key={i} className="rounded border border-border/60 bg-surface-1 p-3 text-center">
                            <m.icon className="mx-auto h-4 w-4 text-muted-foreground" />
                            <div className="mt-1 font-mono text-lg font-bold text-foreground">{m.value}</div>
                            <div className="text-mono ba-text-2xs text-muted-foreground">{m.label}</div>
                          </div>
                        ))}
                      </div>

                      {/* Top talkers */}
                      <Panel title="Top Talkers" bodyClassName="p-0" icon={Server} meta={`${backendResult.top_ips.length} IPs`}>
                        <div className="divide-y divide-border/50">
                          {backendResult.top_ips.slice(0, 10).map((t, i) => (
                            <div key={i} className="group flex items-center justify-between px-3 py-2 hover:bg-surface-1">
                              <div className="flex items-center gap-2 min-w-0">
                                <span className="font-mono text-sm text-foreground">{t.ip}</span>
                                <Chip tone={/^(10\.|192\.168\.)/.test(t.ip) ? "default" : "info"}>
                                  {/^(10\.|192\.168\.)/.test(t.ip) ? "Internal" : "External"}
                                </Chip>
                              </div>
                              <div className="flex items-center gap-2 shrink-0">
                                <span className="font-mono ba-text-2xs text-muted-foreground">{t.packets} packets</span>
                                <button onClick={() => { locker.add({ value: t.ip, type: "ipv4", source: "/pcap" }); toast("Added IP to locker"); }}
                                  className="grid h-5 w-5 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-opacity" title="Add to locker">
                                  <Database className="h-3 w-3" />
                                </button>
                              </div>
                            </div>
                          ))}
                        </div>
                      </Panel>

                      {/* DNS + TLS */}
                      <div className="grid grid-cols-2 gap-4">
                        <Panel title="DNS Queries" bodyClassName="p-0" icon={Globe} meta={`${backendResult.dns_queries.length} queries`}>
                          <div className="divide-y divide-border/50 max-h-48 overflow-y-auto">
                            {backendResult.dns_queries.map((q, i) => (
                              <div key={i} className="flex items-center justify-between gap-2 px-3 py-1.5 hover:bg-surface-1 group">
                                <code className="font-mono text-sm text-foreground">{q}</code>
                                <button onClick={() => { locker.add({ value: q, type: "domain", source: "/pcap" }); toast("Added domain"); }}
                                  className="grid h-5 w-5 shrink-0 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100" title="Add to locker">
                                  <Database className="h-3 w-3" />
                                </button>
                              </div>
                            ))}
                            {backendResult.dns_queries.length === 0 && (
                              <div className="px-3 py-4 text-center text-mono ba-text-2xs text-muted-foreground">No DNS queries</div>
                            )}
                          </div>
                        </Panel>
                        <Panel title="TLS Server Names" bodyClassName="p-0" icon={ShieldAlert} meta={`${backendResult.tls_server_names.length} SNI`}>
                          <div className="divide-y divide-border/50 max-h-48 overflow-y-auto">
                            {backendResult.tls_server_names.map((n, i) => (
                              <div key={i} className="flex items-center justify-between gap-2 px-3 py-1.5 hover:bg-surface-1 group">
                                <code className="font-mono text-sm text-foreground">{n}</code>
                                <button onClick={() => { locker.add({ value: n, type: "domain", source: "/pcap" }); toast("Added domain"); }}
                                  className="grid h-5 w-5 shrink-0 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100" title="Add to locker">
                                  <Database className="h-3 w-3" />
                                </button>
                              </div>
                            ))}
                          </div>
                        </Panel>
                      </div>

                      {/* HTTP */}
                      {backendResult.http_requests.length > 0 && (
                        <section className="rounded border border-border/60 bg-surface-1">
                          <SectionBar id="HTTP" label="HTTP Requests" meta={`${backendResult.http_requests.length} requests`} />
                          <div className="divide-y divide-border/50">
                            {backendResult.http_requests.map((r, i) => (
                              <div key={i} className="grid grid-cols-[60px_1fr_auto] items-center gap-3 px-3 py-2 hover:bg-surface-1">
                                <Chip tone={r.method === "POST" ? "warning" : "info"}>{r.method}</Chip>
                                <div className="min-w-0">
                                  <code className="font-mono text-sm text-foreground">{r.host}{r.path}</code>
                                  {r.user_agent && <div className="ba-text-2xs text-muted-foreground truncate">{r.user_agent}</div>}
                                </div>
                                <div className="shrink-0 text-mono ba-text-2xs text-muted-foreground">
                                  {r.src && <span>{r.src} →</span>} {r.dst}
                                </div>
                              </div>
                            ))}
                          </div>
                        </section>
                      )}

                      {/* Beaconing */}
                      {backendResult.beaconing_candidates.length > 0 && (
                        <section className="rounded border border-border/60 bg-surface-1">
                          <SectionBar id="BN" label="Beaconing Candidates" meta={`${backendResult.beaconing_candidates.length} pairs`} />
                          <div className="divide-y divide-border/50">
                            {backendResult.beaconing_candidates.map((b, i) => (
                              <div key={i} className="flex items-center justify-between px-3 py-2 hover:bg-surface-1 group">
                                <div className="flex items-center gap-2 min-w-0">
                                  <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-warning" />
                                  <code className="font-mono text-sm text-foreground">{b.src}</code>
                                  <span className="text-muted-foreground">→</span>
                                  <code className="font-mono text-sm text-foreground">{b.dst}</code>
                                </div>
                                <span className="font-mono ba-text-2xs text-warning">{b.packets} packets</span>
                              </div>
                            ))}
                          </div>
                        </section>
                      )}

                      {/* Backend limitations */}
                      {backendResult.limitations.length > 0 && (
                        <Panel title="Limitations" priority="secondary">
                          <ul className="space-y-1">
                            {backendResult.limitations.map((l, i) => (
                              <li key={i} className="flex items-start gap-2 text-mono ba-text-sm text-muted-foreground">
                                <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />{l}
                              </li>
                            ))}
                          </ul>
                        </Panel>
                      )}

                      {/* Backend actions */}
                      <div className="flex items-center gap-2">
                        <button onClick={() => {
                          backendResult.iocs.ips.forEach((ip) => locker.add({ value: ip, type: "ipv4", source: "/pcap" }));
                          backendResult.iocs.domains.forEach((d) => locker.add({ value: d, type: "domain", source: "/pcap" }));
                          pcapHashes.forEach((h) => locker.add({ value: h, type: h.length === 32 ? "md5" : h.length === 40 ? "sha1" : "sha256", source: "/pcap" }));
                          toast.success(`Added ${totalIocs} IOCs to locker`);
                        }} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs text-primary hover:bg-primary/20">
                          <BookMarked className="h-3 w-3" /> all IOCs to locker
                        </button>
                        <button onClick={() => {
                          const md = generateMdReport(backendResult);
                          const blob = new Blob([md], { type: "text/markdown" });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url; a.download = `pcap-report-${backendResult.sha256.slice(0, 8)}.md`;
                          a.click(); URL.revokeObjectURL(url);
                        }} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs text-primary hover:bg-primary/20">
                          <Download className="h-3 w-3" /> Markdown Report
                        </button>
                        {pcapHashes.length > 0 && (
                          <button
                            onClick={() => void runPcapHashReputation()}
                            disabled={hashEnrichRunning}
                            title="Runs the same opt-in batch reputation check as the Intel page — local deterministic checks unless an external key is configured. Nothing is sent without this explicit click."
                            className="inline-flex items-center gap-1.5 rounded border border-info/40 bg-info/10 px-2.5 py-1.5 text-mono ba-text-2xs text-info hover:bg-info/20 disabled:opacity-50"
                          >
                            <ShieldCheck className={hashEnrichRunning ? "h-3 w-3 animate-pulse" : "h-3 w-3"} />
                            hash reputation ({pcapHashes.length})
                          </button>
                        )}
                      </div>
                    </>
                  )}

                  {/* Text-specific visualizations */}
                  {isText && textAnalysis && (
                    <>
                      <SectionBar id="OT" label="Network Analysis" meta={`${textAnalysis.totalPackets} lines \u00b7 ${textAnalysis.ips.length} IPs`} />

                      <div className="grid grid-cols-3 gap-4">
                        <Panel title="Top Talkers" bodyClassName="p-0" icon={Server}>
                          <div className="divide-y divide-border/50">
                            {textAnalysis.topTalkers.map((t, i) => (
                              <div key={i} className="flex items-center justify-between px-3 py-2 hover:bg-surface-1 group">
                                <div className="flex items-center gap-2 min-w-0">
                                  <span className="font-mono text-sm text-foreground truncate">{t.ip}</span>
                                  <Chip tone={t.role.includes("suspicious") ? "destructive" : "default"}>{t.role}</Chip>
                                </div>
                                <div className="flex items-center gap-2 shrink-0">
                                  <div className="text-right font-mono ba-text-2xs text-muted-foreground">
                                    <div>{t.packets} pkts</div>
                                    <div>{t.bytes}</div>
                                  </div>
                                  <button onClick={() => { locker.add({ value: t.ip, type: "ipv4", source: "/pcap" }); toast("Added IP"); }}
                                    className="grid h-5 w-5 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100" title="Add to locker">
                                    <Database className="h-3 w-3" />
                                  </button>
                                </div>
                              </div>
                            ))}
                          </div>
                        </Panel>

                        <Panel title="Protocol Breakdown" bodyClassName="p-0">
                          <div className="divide-y divide-border/50">
                            {textAnalysis.protocols.map((p, i) => (
                              <div key={i} className="px-3 py-2">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="font-mono text-sm text-foreground">{p.protocol}</span>
                                  <span className="font-mono ba-text-2xs text-muted-foreground">{p.packets} ({p.percentage}%)</span>
                                </div>
                                <div className="h-1.5 w-full rounded-full bg-border/50">
                                  <div className="h-1.5 rounded-full bg-primary" style={{ width: `${p.percentage}%` }} />
                                </div>
                              </div>
                            ))}
                          </div>
                        </Panel>

                        <Panel title="Identified Domains" bodyClassName="p-0" icon={Globe}>
                          <div className="divide-y divide-border/50 max-h-48 overflow-y-auto">
                            {textAnalysis.dnsQueries.map((q, i) => (
                              <div key={i} className="flex items-center justify-between gap-2 px-3 py-1.5 group hover:bg-surface-1">
                                <code className="font-mono text-sm text-foreground">{q}</code>
                                <button onClick={() => { locker.add({ value: q, type: "domain", source: "/pcap" }); toast("Added domain"); }}
                                  className="grid h-5 w-5 shrink-0 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100" title="Add to locker">
                                  <Database className="h-3 w-3" />
                                </button>
                              </div>
                            ))}
                            {textAnalysis.dnsQueries.length === 0 && (
                              <div className="px-3 py-4 text-center text-mono ba-text-2xs text-muted-foreground">No DNS queries</div>
                            )}
                          </div>
                        </Panel>
                      </div>

                      <div className="flex items-center gap-2">
                        <button onClick={() => {
                          textAnalysis.ips.forEach((ip) => locker.add({ value: ip, type: "ipv4", source: "/pcap" }));
                          textAnalysis.dnsQueries.forEach((d) => locker.add({ value: d, type: "domain", source: "/pcap" }));
                          toast.success("Added " + (textAnalysis.ips.length + textAnalysis.dnsQueries.length) + " IOCs to locker");
                        }} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs text-primary hover:bg-primary/20">
                          <BookMarked className="h-3 w-3" /> all IOCs to locker
                        </button>
                        <button onClick={() => {
                          const md = generateTextMdReport(textAnalysis);
                          const blob = new Blob([md], { type: "text/markdown" });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url; a.download = "pcap-text-report-" + Date.now() + ".md";
                          a.click(); URL.revokeObjectURL(url);
                        }} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs text-primary hover:bg-primary/20">
                          <Download className="h-3 w-3" /> Markdown Report
                        </button>
                      </div>

                      {textAnalysis.suspicious.length === 0 && (
                        <Panel priority="secondary">
                          <div className="flex items-center gap-2 text-mono ba-text-sm text-muted-foreground">
                            <CheckCircle className="h-4 w-4 text-success" />
                            No suspicious indicators detected in pasted output.
                          </div>
                        </Panel>
                      )}
                    </>
                  )}
                </div>
              )}

              {activeTab === "zeek" && (
                <div className="space-y-4">
                  <WiresharkFilterBar
                    filter={wiresharkFilter}
                    onFilterChange={setWiresharkFilter}
                    onApplyPreset={(p) => setWiresharkFilter(p.filter)}
                    pcapFilename={fileName || "capture.pcap"}
                    matchedCount={filteredConns.length}
                    totalCount={analysis.zeek_conn?.length || 0}
                  />

                  <ZeekLogViewer
                    conns={filteredConns}
                    dns={analysis.zeek_dns || []}
                    http={analysis.zeek_http || []}
                    ssl={analysis.zeek_ssl || []}
                    credentials={analysis.credentials || []}
                    extractedFiles={analysis.extracted_files || []}
                    onFollowStream={(c) => setActiveConnForStream(c)}
                  />
                </div>
              )}

              {activeTab === "iocs" && (
                <IOCTable iocs={analysis.iocs} source="/pcap" />
              )}

              {activeTab === "mitre" && (
                <MitrePanel techniques={analysis.mitre} />
              )}
            </>
          )}

        {toolState === "empty" && <EmptyPreview />}
      </AnalyzerShell>
 {/* ── CLI section (full width) ── */}
      {toolState !== "empty" && (
        <div className="mt-6 space-y-3">
          <SectionBar id="CLI" label="SOC CLI Tools" meta="tshark / tcpdump" />
          <Panel title="Command Builder" icon={Terminal}>
            <div className="flex items-center gap-2 mb-3">
              <input
                value={cliInput}
                onChange={(e) => setCliInput(e.target.value)}
                aria-label="Capture CLI command"
                placeholder="e.g. tcpdump -r capture.pcap -nn -c 100"
                onKeyDown={(e) => { if (e.key === "Enter") runCli(); }}
                className="flex-1 rounded border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50"
              />
              <button onClick={runCli} disabled={cliLoading || !cliInput.trim()}
                className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs text-primary hover:bg-primary/20 disabled:opacity-40">
                <Play className="h-3.5 w-3.5" /> Run
              </button>
              <button onClick={() => { setCliInput(""); setCliOutput(""); }}
                className="inline-flex items-center gap-1 rounded border border-border px-2 py-2 text-mono ba-text-2xs text-muted-foreground hover:text-foreground">
                <Trash2 className="h-3 w-3" />
              </button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {["tshark -r capture.pcap -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -nr | head -10", "tcpdump -r capture.pcap -nn -c 50", "tshark -r capture.pcap -Y dns -T fields -e dns.qry.name", "tshark -r capture.pcap -Y http.request -T fields -e http.host -e http.request.uri", "tcpdump -r capture.pcap -X -c 20"].map((cmd) => (
                <button key={cmd} onClick={() => setCliInput(cmd)}
                  className="rounded border border-subtle bg-surface-1 px-2 py-0.5 font-mono ba-text-2xs text-muted-foreground hover:text-foreground transition-colors duration-150">
                  {cmd}
                </button>
              ))}
            </div>
            {cliOutput && (
              <div className="mt-3">
                <pre className="max-h-48 overflow-auto rounded border border-subtle bg-surface-0 p-3 font-mono text-sm text-foreground whitespace-pre-wrap">{cliOutput}</pre>
              </div>
            )}
          </Panel>
        </div>
      )}

      <TcpStreamModal
        isOpen={!!activeConnForStream}
        onClose={() => setActiveConnForStream(null)}
        streamTitle={activeConnForStream ? `${activeConnForStream.orig_h}:${activeConnForStream.orig_p} → ${activeConnForStream.resp_h}:${activeConnForStream.resp_p} (${activeConnForStream.proto.toUpperCase()})` : ""}
        dialogue={getStreamDialogue(activeConnForStream, analysis)}
      />

      <SuricataRuleModal
        isOpen={showSuricataModal}
        onClose={() => setShowSuricataModal(false)}
        ruleset={generatedRuleset}
      />
    </PageShell>
    </ErrorBoundary>
  );
}
