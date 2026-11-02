import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import ReactDiffViewer from "react-diff-viewer-continued";
import { PageShell } from "@/components/PageShell";
import { Chip, SendToRow } from "@/components/soc";
import { Empty } from "@/components/output";
import { EntitySection } from "@/components/entity";
import {
  Code2, FileText, Monitor, ScrollText, Search, ArrowUpDown, AlertTriangle,
  Copy, Check, Database, Download, Columns2, Rows2, Upload, ExternalLink, ShieldAlert,
} from "lucide-react";
import { notify } from "@/lib/notify";
import { pushTimelineEvent } from "@/lib/timeline";
import { useLocker } from "@/lib/locker";
import { copyText } from "@/lib/copy";
import { computeIocDelta } from "@/lib/diff/ioc-delta";
import { ErrorBoundary } from "@/components/ErrorBoundary";

export const Route = createFileRoute("/diff")({ component: DiffPage });

const SAMPLES: Record<string, { old: string; new: string }> = {
  "Nmap scans": {
    old: `PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
443/tcp open  https
3306/tcp closed mysql
8080/tcp open  http-proxy`,
    new: `PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
443/tcp open  https
3306/tcp open   mysql
8080/tcp closed http-proxy
8443/tcp open  https-alt
4444/tcp open  metasploit-c2`,
  },
  "Email headers": {
    old: `Received: from mail.evil.com (203.0.113.44)
  by mx.example.org with ESMTPS
SPF: fail
DKIM: fail
DMARC: fail
Reply-To: support@evil.com`,
    new: `Received: from mail.legit.com (198.51.100.22)
  by mx.example.org with ESMTPS
SPF: pass
DKIM: pass
DMARC: pass
Reply-To: support@legit.com`,
  },
  "JSON reports": {
    old: JSON.stringify({ version: "1.0", iocs: { ip: [], domain: [] }, verdict: "clean" }, null, 2),
    new: JSON.stringify({ version: "2.0", iocs: { ip: ["185.220.101.5"], domain: ["evil-c2.ru"] }, verdict: "malicious", mitre: ["T1071", "T1566"] }, null, 2),
  },
  "Firewall ACL": {
    old: `# iptables production baseline
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT`,
    new: `# iptables modified after compromise
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -p tcp --dport 4444 -s 185.220.101.5 -j ACCEPT
-A INPUT -p tcp --dport 1337 -j ACCEPT
COMMIT`,
  },
  "Windows Registry": {
    old: `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]
"SecurityHealth"="C:\\\\Windows\\\\system32\\\\SecurityHealthSystray.exe"`,
    new: `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]
"SecurityHealth"="C:\\\\Windows\\\\system32\\\\SecurityHealthSystray.exe"
"WindowsUpdate"="powershell.exe -WindowStyle Hidden -enc cwBhAG0AcABsAGUA"
"BackdoorClient"="C:\\\\Users\\\\Public\\\\beacon.exe"`,
  },
};


function extractIOCs(text: string): { ips: string[]; domains: string[]; urls: string[]; hashes: string[] } {
  const ips = [...new Set(text.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || [])];
  const domains = [...new Set(text.match(/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g) || [])].filter(d => !d.startsWith("mail.") && !d.startsWith("mx."));
  const urls = [...new Set(text.match(/https?:\/\/[^\s)"']+/g) || [])];
  const hashes = [...new Set(text.match(/\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi) || [])];
  return { ips, domains, urls, hashes };
}

function DiffPage() {
  const navigate = useNavigate();
  const locker = useLocker();
  const [oldText, setOldText] = useState("");
  const [newText, setNewText] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [copied, setCopied] = useState(false);
  const [splitView, setSplitView] = useState(true);
  const oldInputRef = useRef<HTMLInputElement>(null);
  const newInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") setSearchQuery("");
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  function loadSample(key: string) {
    const s = SAMPLES[key];
    if (s) {
      setOldText(s.old);
      setNewText(s.new);
      pushTimelineEvent({ source: "diff", verb: "loaded", detail: key, result: "sample" });
    }
  }

  function handleFileRead(file: File, target: "old" | "new") {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = (e.target?.result as string) || "";
      if (target === "old") setOldText(content);
      else setNewText(content);
      notify.success(`Loaded ${file.name}`);
    };
    reader.readAsText(file);
  }

  const stats = useMemo(() => {
    if (!oldText && !newText) return null;
    const oldLines = oldText ? oldText.split("\n") : [];
    const newLines = newText ? newText.split("\n") : [];
    const added = newLines.filter((l) => !oldLines.includes(l)).length;
    const removed = oldLines.filter((l) => !newLines.includes(l)).length;
    const unchanged = newLines.filter((l) => oldLines.includes(l)).length;
    return { added, removed, unchanged, oldSize: oldText.length, newSize: newText.length, netChange: newText.length - oldText.length };
  }, [oldText, newText]);

  const iocDelta = useMemo(() => computeIocDelta(oldText, newText), [oldText, newText]);

  useEffect(() => {
    if (stats && stats.added + stats.removed > 0) {
      pushTimelineEvent({
        source: "diff",
        verb: "compared",
        detail: `${stats.added} added, ${stats.removed} removed`,
        result: `${iocDelta.totalAdded} new IOCs`,
      });
    }
  }, [stats, iocDelta.totalAdded]);

  const filteredOldText = useMemo(() => {
    if (!searchQuery.trim()) return oldText;
    return oldText.split("\n").filter((l) => l.toLowerCase().includes(searchQuery.toLowerCase())).join("\n");
  }, [oldText, searchQuery]);

  const filteredNewText = useMemo(() => {
    if (!searchQuery.trim()) return newText;
    return newText.split("\n").filter((l) => l.toLowerCase().includes(searchQuery.toLowerCase())).join("\n");
  }, [newText, searchQuery]);

  function handleExport() {
    const md = [
      "# Diff Comparison Report",
      "",
      `**Generated:** ${new Date().toISOString()}`,
      `**Added:** ${stats?.added ?? 0} lines · **Removed:** ${stats?.removed ?? 0} lines · **Net:** ${stats ? (stats.netChange > 0 ? "+" : "") + stats.netChange : 0} bytes`,
      `**New IOCs Detected:** ${iocDelta.totalAdded}`,
      "",
      "## Original (Baseline)",
      "",
      "```",
      oldText || "(empty)",
      "```",
      "",
      "## Changed (Incident)",
      "",
      "```",
      newText || "(empty)",
      "```",
      "",
    ].join("\n");
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `diff-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
    notify.success("Exported markdown report");
  }

  function handlePatchExport() {
    const oldLines = oldText ? oldText.split("\n") : [];
    const newLines = newText ? newText.split("\n") : [];
    const lines = [
      "--- baseline.txt",
      "+++ incident.txt",
      `@@ -1,${oldLines.length || 1} +1,${newLines.length || 1} @@`,
    ];
    oldLines.forEach((l) => lines.push("-" + l));
    newLines.forEach((l) => lines.push("+" + l));
    const blob = new Blob([lines.join("\n")], { type: "text/x-diff" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident-${Date.now()}.patch`;
    a.click();
    URL.revokeObjectURL(url);
    notify.success("Exported unified patch file");
  }

  return (
    <ErrorBoundary name="DiffPage">
      <PageShell
        eyebrow="tools / diff"
        title="Diff View"
        description="Side-by-side comparison for artifacts — baseline vs incident configs, network ACLs, registry hives, and SIEM reports with automated Net-New IOC isolation."
        crumbs={[{ label: "Operations" }, { label: "Diff" }]}
        actions={
          <div className="flex flex-wrap items-center gap-1.5">
            {Object.keys(SAMPLES).map((k) => (
              <button
                key={k}
                onClick={() => loadSample(k)}
                className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:border-primary/40 hover:text-primary transition-colors"
              >
                <FileText className="h-3 w-3" /> {k}
              </button>
            ))}
            <button
              onClick={() => setSplitView((v) => !v)}
              className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:border-primary/40 hover:text-primary transition-colors"
              title={splitView ? "Switch to unified view" : "Switch to split side-by-side view"}
            >
              {splitView ? <Columns2 className="h-3 w-3" /> : <Rows2 className="h-3 w-3" />}
              {splitView ? "Split" : "Unified"}
            </button>
            <button
              onClick={handlePatchExport}
              disabled={!oldText && !newText}
              className="inline-flex items-center gap-1 rounded border border-subtle px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground disabled:opacity-40 transition-colors"
            >
              <Download className="h-3 w-3" /> .patch
            </button>
            <button
              onClick={handleExport}
              disabled={!oldText && !newText}
              className="inline-flex items-center gap-1 rounded border border-subtle px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground disabled:opacity-40 transition-colors"
            >
              <Download className="h-3 w-3" /> md
            </button>
          </div>
        }
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <EntitySection
            title="Original (Baseline)"
            icon={Code2}
            headingLevel="h2"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-mono ba-text-3xs text-fg-dim">Input buffer</span>
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => oldInputRef.current?.click()}
                  title="Upload file"
                  className="rounded border border-subtle bg-surface-0 px-2 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-primary transition-colors flex items-center gap-1"
                >
                  <Upload className="h-3 w-3 inline" /> Upload
                </button>
                <input
                  ref={oldInputRef}
                  type="file"
                  onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFileRead(f, "old"); }}
                  className="hidden"
                />
              </div>
            </div>
            <textarea
              value={oldText}
              onChange={(e) => setOldText(e.target.value)}
              aria-label="Original content"
              placeholder="Paste original/baseline content, or upload file..."
              className="h-64 w-full resize-y rounded border border-subtle bg-surface-0 p-3 font-mono text-sm text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50"
            />
          </EntitySection>
          <EntitySection
            title="Changed (Incident)"
            icon={ScrollText}
            headingLevel="h2"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-mono ba-text-3xs text-fg-dim">Input buffer</span>
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => newInputRef.current?.click()}
                  title="Upload file"
                  className="rounded border border-subtle bg-surface-0 px-2 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-primary transition-colors flex items-center gap-1"
                >
                  <Upload className="h-3 w-3 inline" /> Upload
                </button>
                <input
                  ref={newInputRef}
                  type="file"
                  onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFileRead(f, "new"); }}
                  className="hidden"
                />
              </div>
            </div>
            <textarea
              value={newText}
              onChange={(e) => setNewText(e.target.value)}
              aria-label="Modified content"
              placeholder="Paste modified/incident content, or upload file..."
              className="h-64 w-full resize-y rounded border border-border bg-surface-0 p-3 font-mono text-sm text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50"
            />
          </EntitySection>
        </div>

        {(oldText || newText) && stats && (
          <>
            <div className="flex flex-wrap items-center justify-between gap-3 px-1">
              <div className="flex items-center gap-1 text-mono ba-text-2xs text-muted-foreground">
                <span className="inline-block h-2.5 w-5 rounded bg-[rgba(34,197,94,0.2)]" />
                <span className="text-success">+{stats.added}</span> added
              </div>
              <div className="flex items-center gap-1 text-mono ba-text-2xs text-muted-foreground">
                <span className="inline-block h-2.5 w-5 rounded bg-[rgba(239,68,68,0.2)]" />
                <span className="text-destructive">-{stats.removed}</span> removed
              </div>
              <span className="text-mono ba-text-2xs text-muted-foreground">
                {stats.unchanged} unchanged · {stats.netChange > 0 ? "+" : ""}{stats.netChange} bytes net
              </span>
              <div className="ml-auto flex items-center gap-2">
                {searchQuery && (
                  <span className="text-mono ba-text-2xs text-muted-foreground">
                    Filtering: "{searchQuery}"
                  </span>
                )}
                <div className="relative">
                  <Search className="absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-fg-dim" />
                  <input
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search diff…"
                    className="w-40 rounded border border-subtle bg-surface-0 py-1 pl-6 pr-2 font-mono ba-text-2xs text-foreground outline-none placeholder:text-muted-foreground"
                  />
                </div>
              </div>
            </div>

            {/* Net-New IOCs Introduced in Incident */}
            {iocDelta.totalAdded > 0 && (
              <div className="rounded-lg border border-destructive/40 bg-destructive/5 p-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-mono ba-text-xs font-semibold text-destructive">
                    <ShieldAlert className="h-4 w-4" />
                    <span>Net-New Incident IOCs ({iocDelta.totalAdded} detected) — Potential Attack Infrastructure</span>
                  </div>
                  <span className="text-mono ba-text-3xs text-muted-foreground">
                    New observables introduced in modified artifact
                  </span>
                </div>
                <div className="mt-2.5 flex flex-wrap gap-2">
                  {iocDelta.added.map((ioc) => (
                    <div
                      key={ioc.value}
                      className="inline-flex items-center gap-1.5 rounded border border-divider-strong bg-surface-1 px-2 py-1 text-mono ba-text-2xs"
                    >
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${
                          ioc.risk === "critical" || ioc.risk === "high" ? "bg-destructive" : "bg-warning"
                        }`}
                      />
                      <span className="font-semibold text-foreground">{ioc.value}</span>
                      <span className="rounded bg-surface-2 px-1 py-0.2 text-mono ba-text-3xs text-muted-foreground uppercase">
                        {ioc.type}
                      </span>
                      <button
                        onClick={() => navigate({ to: "/siem", search: { q: ioc.value } as any })}
                        title="Pivot to SIEM Hunt"
                        className="ml-1 text-muted-foreground hover:text-primary transition-colors"
                      >
                        <Search className="h-3 w-3" />
                      </button>
                      <button
                        onClick={() => navigate({ to: "/intel", search: { q: ioc.value } as any })}
                        title="Enrich in Threat Intel"
                        className="text-muted-foreground hover:text-primary transition-colors"
                      >
                        <ExternalLink className="h-3 w-3" />
                      </button>
                      <button
                        onClick={() => {
                          locker.add({ value: ioc.value, type: ioc.type as any, source: "/diff" });
                          notify.success(`Added ${ioc.value} to locker`);
                        }}
                        title="Save to Evidence Locker"
                        className="text-muted-foreground hover:text-primary transition-colors"
                      >
                        <Database className="h-3 w-3" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <EntitySection title="Diff" icon={Monitor}>
              <div className="mb-2 flex justify-end">
                <button
                  onClick={() => {
                    copyText(JSON.stringify({ added: newText, removed: oldText, stats, iocDelta }, null, 2));
                    setCopied(true);
                    setTimeout(() => setCopied(false), 1200);
                  }}
                  className="inline-flex items-center gap-1 rounded border border-subtle px-2 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-foreground"
                >
                  {copied ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> export</>}
                </button>
              </div>
              <div className="overflow-auto rounded border border-subtle [&_*]:!font-mono [&_*]:!ba-text-xs">
                <ReactDiffViewer
                  oldValue={filteredOldText}
                  newValue={filteredNewText}
                  splitView={splitView}
                  showDiffOnly={false}
                  leftTitle="Original (Baseline)"
                  rightTitle="Changed (Incident)"
                  styles={{
                    variables: {
                      dark: {
                        diffViewerBackground: "transparent",
                        addedBackground: "color-mix(in oklab, var(--success) 8%, transparent)",
                        removedBackground: "color-mix(in oklab, var(--destructive) 8%, transparent)",
                        addedGutterBackground: "color-mix(in oklab, var(--success) 12%, transparent)",
                        removedGutterBackground: "color-mix(in oklab, var(--destructive) 12%, transparent)",
                        gutterBackground: "transparent",
                        gutterColor: "var(--fg-dim)",
                        addedColor: "var(--success)",
                        removedColor: "var(--destructive)",
                        diffViewerColor: "var(--foreground)",
                        emptyLineBackground: "color-mix(in oklab, var(--border) 40%, transparent)",
                        wordAddedBackground: "color-mix(in oklab, var(--success) 20%, transparent)",
                        wordRemovedBackground: "color-mix(in oklab, var(--destructive) 20%, transparent)",
                      },
                    },
                  }}
                />
              </div>
            </EntitySection>
          </>
        )}

        {!oldText && !newText && (
          <Empty
            icon={ArrowUpDown}
            title="No comparison yet"
            hint="Paste two versions of an artifact above — or load a sample to see what changed between baseline and incident"
            examples={Object.keys(SAMPLES)}
            onSample={loadSample}
          />
        )}

        {stats && iocDelta.totalAdded > 0 && (
          <div className="mt-4">
            <SendToRow
              targets={[
                { label: "Case Notebook", to: "/case", icon: Database },
                { label: "Lookup & Intel", to: "/intel", icon: Search },
                { label: "SIEM Threat Hunt", to: "/siem", icon: Search },
              ]}
            />
          </div>
        )}
      </PageShell>
    </ErrorBoundary>
  );
}

