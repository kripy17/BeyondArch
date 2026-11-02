import { useState, useMemo, useRef, useEffect } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import {
  Search, ShieldAlert, Copy, Check, ArrowUpRight, Plus, FolderPlus,
  Terminal, Sparkles, ExternalLink, RefreshCw, Layers,
} from "lucide-react";
import { classifyOmniInput, type OmniTriageResult } from "@/lib/omni-triage";
import { copyText } from "@/lib/copy";
import { useLocker } from "@/lib/locker";
import { useActiveCase, loadCases, saveCases, addCaseEvent, newId } from "@/data/case";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

const SAMPLES = [
  { label: "Public IP", val: "185.220.101.5" },
  { label: "Suspicious URL", val: "hxxps://auth-microsoft[.]verify-portal[.]net/login" },
  { label: "MD5 Hash", val: "44d88612fea8a8f36de82e1278abb02f" },
  { label: "Critical CVE", val: "CVE-2024-21413" },
  { label: "Encoded Cmd", val: "cG93ZXJzaGVsbCAtdyBoaWRkZW4gLWMgIklFWChtZW0pIg==" },
];

export function OmniTriageDock() {
  const [input, setInput] = useState("");
  const [copied, setCopied] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const { add: addLockerItem } = useLocker();
  const { activeCase, addEntry } = useActiveCase();
  const navigate = useNavigate();

  const triage: OmniTriageResult | null = useMemo(() => {
    if (!input.trim()) return null;
    return classifyOmniInput(input);
  }, [input]);

  const handleCopyDefanged = async () => {
    if (!triage) return;
    const ok = await copyText(triage.defanged);
    if (ok) {
      setCopied(true);
      toast.success("Copied safe defanged indicator to clipboard");
      setTimeout(() => setCopied(false), 1600);
    }
  };

  const handleAddToLocker = () => {
    if (!triage) return;
    const typeMap: Record<string, any> = {
      ipv4: "ipv4",
      ipv6: "ipv6",
      domain: "domain",
      url: "url",
      "hash-md5": "md5",
      "hash-sha1": "sha1",
      "hash-sha256": "sha256",
      cve: "cve",
      email: "email",
    };
    const iocType = typeMap[triage.kind] || "unknown";
    addLockerItem({ value: triage.refanged, type: iocType, source: "Omni-Triage Dock" });
    toast.success(`Added ${triage.defanged} to IOC Locker`);
  };

  const handleAttachToCase = () => {
    if (!triage) return;
    const cases = loadCases();
    const targetCase = activeCase || cases.find((c) => c.state === "active");

    if (!targetCase) {
      // create a quick new case
      const newCaseId = newId("case");
      const createdCase = {
        id: newCaseId,
        title: `Investigation: ${triage.defanged}`,
        tags: ["omni-triage", triage.kind],
        createdAt: new Date().toISOString(),
        state: "active" as const,
        entries: [
          {
            id: newId("entry"),
            ts: new Date().toISOString(),
            kind: "evidence" as const,
            body: `Initial artifact intake via Command Deck Omni-Dock:\nType: ${triage.label}\nValue: ${triage.defanged}`,
          },
        ],
        events: [
          {
            id: newId("ev"),
            ts: new Date().toISOString(),
            kind: "artifact_uploaded" as const,
            category: "artifact" as const,
            importance: "high" as const,
            actor: "analyst" as const,
            origin: "omni-dock",
            title: `Artifact Added: ${triage.defanged}`,
            detail: `Triaged indicator of type ${triage.label}`,
            references: [],
          },
        ],
      };
      saveCases([createdCase, ...cases]);
      toast.success(`Created and attached to new investigation ${newCaseId}`);
      navigate({ to: "/case" });
      return;
    }

    addEntry(
      `Omni-Dock evidence attached:\nIndicator: ${triage.defanged}\nType: ${triage.label}`,
      "evidence",
      "omni-dock",
    );
    toast.success(`Attached ${triage.defanged} to case ${targetCase.title}`);
  };

  return (
    <div className="rounded-lg border border-primary/30 bg-gradient-to-br from-surface-1/90 via-surface-1/50 to-surface-0 p-3.5 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2">
        <div className="flex items-center gap-2 font-mono ba-text-2xs font-semibold uppercase tracking-wider text-primary">
          <Sparkles className="h-3.5 w-3.5 text-primary animate-pulse" />
          <span>Universal Fast-Triage Dock</span>
          <span className="rounded border border-primary/30 bg-primary/10 px-1.5 py-0.2 text-mono ba-text-3xs lowercase font-normal text-muted-foreground">
            press &apos;/&apos; to focus
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-1">
          <span className="font-mono ba-text-3xs text-muted-foreground mr-1 hidden sm:inline">Try sample:</span>
          {SAMPLES.map((s) => (
            <button
              key={s.label}
              onClick={() => setInput(s.val)}
              className="rounded border border-subtle bg-surface-0 px-2 py-0.5 font-mono ba-text-3xs text-muted-foreground transition-colors hover:border-primary/50 hover:text-foreground"
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Omni Search Bar */}
      <div className="relative mt-1">
        <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
          <Search className="h-4 w-4 text-muted-foreground" />
        </div>
        <input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Paste anything — IP, domain, hash, URL, CVE, email, encoded command, or raw event log..."
          className="w-full rounded-md border border-border/80 bg-surface-0/90 py-2.5 pl-9 pr-24 font-mono ba-text-xs text-foreground placeholder:text-muted-foreground/60 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/40 shadow-inner"
        />
        {input && (
          <button
            onClick={() => setInput("")}
            className="absolute inset-y-0 right-2 my-auto h-6 rounded px-2 font-mono ba-text-3xs text-muted-foreground hover:bg-surface-2 hover:text-foreground"
          >
            clear
          </button>
        )}
      </div>

      {/* Triage Preview & Fast-Actions */}
      {triage && (
        <div className="mt-3 rounded-md border border-subtle bg-surface-0/80 p-3 space-y-2.5 transition-all">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-subtle pb-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded border border-primary/40 bg-primary/10 px-2 py-0.5 font-mono ba-text-2xs font-medium text-primary">
                {triage.label}
              </span>
              <span className="font-mono ba-text-xs font-semibold text-foreground break-all">
                {triage.defanged}
              </span>
            </div>

            <div className="flex items-center gap-1.5">
              <button
                onClick={handleCopyDefanged}
                className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-1 font-mono ba-text-3xs text-muted-foreground hover:border-primary/40 hover:text-foreground"
                title="Copy defanged format for tickets, chats, or documentation"
              >
                {copied ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                <span>{copied ? "copied" : "copy defanged"}</span>
              </button>
              <button
                onClick={handleAddToLocker}
                className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-1 font-mono ba-text-3xs text-muted-foreground hover:border-primary/40 hover:text-foreground"
                title="Add to IOC Locker"
              >
                <Plus className="h-3 w-3" />
                <span>add to locker</span>
              </button>
              <button
                onClick={handleAttachToCase}
                className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-1 font-mono ba-text-3xs text-primary hover:bg-primary/20"
                title="Attach as evidence to current active investigation"
              >
                <FolderPlus className="h-3 w-3" />
                <span>attach to case</span>
              </button>
            </div>
          </div>

          {/* Metadata badges if present */}
          {triage.metadata && Object.keys(triage.metadata).length > 0 && (
            <div className="flex flex-wrap gap-2 text-mono ba-text-3xs">
              {Object.entries(triage.metadata).map(([k, v]) => (
                <div key={k} className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-1.5 py-0.5">
                  <span className="text-muted-foreground">{k}:</span>
                  <span className="font-medium text-foreground">{v}</span>
                </div>
              ))}
            </div>
          )}

          {/* Decoded Command Preview if Base64 */}
          {triage.decodedPreview && (
            <div className="rounded border border-warning/30 bg-warning/5 p-2 font-mono ba-text-3xs">
              <div className="text-warning font-semibold mb-0.5">// Decoded Payload Preview:</div>
              <div className="text-foreground break-all whitespace-pre-wrap">{triage.decodedPreview}</div>
            </div>
          )}

          {/* Instant Zero-Tab Pivots */}
          <div className="flex flex-wrap items-center gap-1.5 pt-1">
            <span className="font-mono ba-text-3xs text-muted-foreground mr-1">Instant Pivots:</span>
            {triage.pivots.map((p) => (
              <Link
                key={p.label}
                to={p.to}
                search={p.search}
                className={cn(
                  "inline-flex items-center gap-1 rounded px-2 py-1 font-mono ba-text-2xs transition-colors",
                  p.primary
                    ? "border border-primary/50 bg-primary/15 text-primary hover:bg-primary/25 font-medium"
                    : "border border-subtle bg-surface-1 text-fg-dim hover:border-primary/40 hover:text-foreground"
                )}
              >
                <span>{p.label}</span>
                <ArrowUpRight className="h-3 w-3 shrink-0" />
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
