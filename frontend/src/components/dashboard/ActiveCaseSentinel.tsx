import { useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import {
  ShieldAlert, Clock, ArrowRight, ExternalLink, Copy, Check,
  Share2, Plus, Crosshair, Tag, FileText, ChevronRight
} from "lucide-react";
import type { Case } from "@/data/case";
import { useActiveCase, loadCases, saveCases, newId } from "@/data/case";
import { extractActiveSentinel } from "@/lib/command-deck";
import { copyText } from "@/lib/copy";
import { defang } from "@/lib/ioc-patterns";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface ActiveCaseSentinelProps {
  cases: Case[];
}

export function ActiveCaseSentinel({ cases }: ActiveCaseSentinelProps) {
  const { activeCase, setActiveId } = useActiveCase();
  const navigate = useNavigate();
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const sentinel = extractActiveSentinel(activeCase);

  const handleCopyIoc = async (value: string, id: string) => {
    const safeVal = defang(value);
    const ok = await copyText(safeVal);
    if (ok) {
      setCopiedId(id);
      toast.success(`Copied ${safeVal}`);
      setTimeout(() => setCopiedId(null), 1500);
    }
  };

  const handleCreateDrill = () => {
    const newCaseId = newId("case");
    const freshCase: Case = {
      id: newCaseId,
      title: `Incident Drill — ${new Date().toLocaleDateString()}`,
      tags: ["incident-response", "triage"],
      createdAt: new Date().toISOString(),
      state: "active",
      entries: [
        {
          id: newId("entry"),
          ts: new Date().toISOString(),
          kind: "note",
          body: "Initiated incident investigation from Command Deck Sentinel.",
        },
      ],
      events: [
        {
          id: newId("ev"),
          ts: new Date().toISOString(),
          kind: "case_created",
          category: "case",
          importance: "high",
          actor: "analyst",
          origin: "sentinel",
          title: "Investigation Initiated",
          detail: "Case workspace instantiated",
          references: [],
        },
      ],
    };
    saveCases([freshCase, ...cases]);
    setActiveId(newCaseId);
    toast.success(`Active case switched to ${freshCase.title}`);
    navigate({ to: "/case" });
  };

  if (!sentinel) {
    const recentCases = cases.slice(0, 3);
    return (
      <div className="rounded-lg border border-subtle bg-surface-1/70 p-4 shadow-sm">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-primary/30 bg-primary/10">
              <ShieldAlert className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h3 className="font-mono ba-text-sm font-semibold text-foreground">
                Incident Command Sentinel
              </h3>
              <p className="font-mono ba-text-3xs text-muted-foreground">
                No active incident selected. Select an existing case or initiate a fresh investigation.
              </p>
            </div>
          </div>
          <button
            onClick={handleCreateDrill}
            className="inline-flex items-center gap-1.5 rounded-md border border-primary/50 bg-primary/15 px-3 py-1.5 font-mono ba-text-2xs font-medium text-primary transition-colors hover:bg-primary/25"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Initiate Incident</span>
          </button>
        </div>

        {recentCases.length > 0 && (
          <div className="mt-3 border-t border-subtle pt-3">
            <div className="mb-2 font-mono ba-text-3xs text-muted-foreground uppercase tracking-wider">
              Recent Case Queue:
            </div>
            <div className="grid gap-2 grid-cols-1 sm:grid-cols-3">
              {recentCases.map((c) => (
                <button
                  key={c.id}
                  onClick={() => setActiveId(c.id)}
                  className="flex items-center justify-between rounded border border-subtle bg-surface-0 px-2.5 py-2 text-left transition-colors hover:border-primary/40 hover:bg-surface-2 group"
                >
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono ba-text-xs font-medium text-foreground group-hover:text-primary">
                      {c.title}
                    </div>
                    <div className="font-mono ba-text-3xs text-muted-foreground">
                      {c.state} · {c.entries?.length ?? 0} notes
                    </div>
                  </div>
                  <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground group-hover:text-primary group-hover:translate-x-0.5 transition-transform" />
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-primary/40 bg-gradient-to-br from-surface-1 via-surface-1/70 to-surface-0 p-4 shadow-sm">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-subtle">
        <div className="flex items-start sm:items-center gap-3 min-w-0">
          <div className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-primary/50 bg-primary/15 text-primary shadow-sm">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded border border-warning/50 bg-warning/15 px-2 py-0.5 font-mono ba-text-3xs font-semibold uppercase text-warning">
                {sentinel.state}
              </span>
              <span className="font-mono ba-text-3xs text-muted-foreground">
                ID: {sentinel.id}
              </span>
            </div>
            <h3 className="mt-0.5 truncate font-mono ba-text-base font-bold text-foreground" title={sentinel.title}>
              {sentinel.title}
            </h3>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <div className="inline-flex items-center gap-1.5 rounded border border-subtle bg-surface-0 px-2.5 py-1.5 font-mono ba-text-2xs text-muted-foreground">
            <Clock className="h-3.5 w-3.5 text-primary" />
            <span>Active for:</span>
            <span className="font-semibold text-foreground">{sentinel.elapsedFormatted}</span>
          </div>

          <Link
            to="/case"
            className="inline-flex items-center gap-1.5 rounded-md border border-primary/60 bg-primary/20 px-3 py-1.5 font-mono ba-text-2xs font-semibold text-primary transition-all hover:bg-primary/30 hover:shadow"
          >
            <span>Resume Notebook</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>

          <Link
            to="/investigation"
            className="inline-flex items-center gap-1.5 rounded-md border border-subtle bg-surface-0 px-2.5 py-1.5 font-mono ba-text-2xs text-fg-dim transition-colors hover:border-primary/40 hover:text-foreground"
            title="Open Case Desk"
          >
            <Share2 className="h-3.5 w-3.5" />
            <span className="hidden md:inline">Case Desk</span>
          </Link>
        </div>
      </div>

      {/* Observables & MITRE Matrix Strip */}
      <div className="mt-3 grid gap-3 grid-cols-1 lg:grid-cols-3">
        {/* Left 2 Cols: Lead IOCs */}
        <div className="lg:col-span-2 space-y-2">
          <div className="flex items-center justify-between font-mono ba-text-3xs text-muted-foreground uppercase tracking-wider">
            <span>Lead Indicators of Compromise ({sentinel.leadIocs.length} of {activeCase?.iocs?.length ?? 0}):</span>
            <Link to="/parser" className="text-primary hover:underline lowercase">
              + extract more
            </Link>
          </div>

          {sentinel.leadIocs.length > 0 ? (
            <div className="grid gap-1.5 grid-cols-1 sm:grid-cols-2">
              {sentinel.leadIocs.map((ioc) => {
                const safeVal = defang(ioc.value);
                const sevTone =
                  ioc.severity === "critical"
                    ? "border-destructive/60 bg-destructive/10 text-destructive"
                    : ioc.severity === "high"
                    ? "border-warning/60 bg-warning/10 text-warning"
                    : "border-primary/40 bg-primary/10 text-primary";

                return (
                  <div
                    key={ioc.id || ioc.value}
                    className="flex items-center justify-between gap-2 rounded border border-subtle bg-surface-0/90 px-2.5 py-1.5"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5">
                        <span className={cn("rounded border px-1.5 py-0.2 font-mono ba-text-3xs uppercase font-semibold", sevTone)}>
                          {ioc.severity}
                        </span>
                        <span className="font-mono ba-text-3xs text-muted-foreground">
                          {ioc.type}
                        </span>
                      </div>
                      <div className="mt-0.5 truncate font-mono ba-text-xs text-foreground" title={safeVal}>
                        {safeVal}
                      </div>
                    </div>

                    <div className="flex items-center gap-1 shrink-0">
                      <button
                        onClick={() => handleCopyIoc(ioc.value, ioc.id || ioc.value)}
                        className="rounded p-1 text-muted-foreground hover:bg-surface-2 hover:text-foreground"
                        title="Copy defanged observable"
                      >
                        {copiedId === (ioc.id || ioc.value) ? (
                          <Check className="h-3 w-3 text-success" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                      </button>
                      <Link
                        to="/intel"
                        search={{ q: ioc.value }}
                        className="rounded p-1 text-muted-foreground hover:bg-surface-2 hover:text-primary"
                        title="Intel Pivot"
                      >
                        <ExternalLink className="h-3 w-3" />
                      </Link>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="rounded border border-dashed border-subtle bg-surface-0/50 p-3 text-center font-mono ba-text-2xs text-muted-foreground">
              No lead observables attached. Paste artifacts into Omni-Dock or Universal Parser to attach.
            </div>
          )}
        </div>

        {/* Right Col: Posture & MITRE Techniques */}
        <div className="space-y-2 rounded border border-subtle bg-surface-0/60 p-2.5">
          <div className="flex items-center gap-1.5 font-mono ba-text-3xs text-muted-foreground uppercase tracking-wider">
            <Crosshair className="h-3 w-3 text-primary" />
            <span>Active Posture & Findings</span>
          </div>

          <div className="grid grid-cols-2 gap-1.5 font-mono ba-text-3xs">
            <div className="rounded border border-subtle bg-surface-1 px-2 py-1">
              <span className="text-muted-foreground">Findings: </span>
              <span className="font-bold text-foreground">{sentinel.findingsCount}</span>
            </div>
            <div className="rounded border border-subtle bg-surface-1 px-2 py-1">
              <span className="text-muted-foreground">Evidence: </span>
              <span className="font-bold text-foreground">{sentinel.evidenceCount}</span>
            </div>
          </div>

          {sentinel.mitreTechniques.length > 0 && (
            <div className="space-y-1 pt-1 border-t border-subtle">
              <div className="font-mono ba-text-3xs text-muted-foreground">MITRE Techniques:</div>
              <div className="flex flex-wrap gap-1">
                {sentinel.mitreTechniques.slice(0, 4).map((tech) => (
                  <Link
                    key={tech}
                    to="/mitre"
                    search={{ technique: tech }}
                    className="rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 font-mono ba-text-3xs text-primary hover:bg-primary/20"
                  >
                    {tech}
                  </Link>
                ))}
              </div>
            </div>
          )}

          {sentinel.tags.length > 0 && (
            <div className="flex flex-wrap gap-1 pt-1">
              {sentinel.tags.slice(0, 4).map((t) => (
                <span key={t} className="inline-flex items-center gap-0.5 rounded border border-subtle bg-surface-1 px-1.5 py-0.2 font-mono ba-text-3xs text-fg-dim">
                  <Tag className="h-2.5 w-2.5" />
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
