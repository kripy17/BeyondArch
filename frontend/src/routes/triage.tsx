import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, SectionBar, SendToRow, Chip, BulkActionBar, useSelection } from "@/components/soc";
import { StatusBar } from "@/components/output";
import { usePanelNav } from "@/lib/usePanelNav";
import { sendToCase } from "@/lib/handoff";
import { pushTimelineEvent } from "@/lib/timeline";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { PieChart, Pie, Cell } from "recharts";
import {
  AlertTriangle, CheckCircle, XCircle, Eye, ArrowUpRight,
  Trash2, Plus, MessageSquare, Download, Inbox, Loader2, Tag,
} from "lucide-react";
import { type Severity } from "@/lib/severity";
import {
  type TriageItem, type TriageStatus, type TriageVerdict,
  STATUS_TONE, STATUS_ORDER, STATUSES,
  loadItems, saveItems, genId, statusLabel,
} from "@/data/triage";
import { ingestAlert } from "@/lib/alerts/ingest";
import { escalateToCase, escalateItems } from "@/lib/alerts/escalate";
import { clusterItems } from "@/lib/alerts/clusters";
import { setActiveCaseId } from "@/data/case";
import { detectAlertFormat, type AlertFormat } from "@/lib/alerts/parse";
import { ALERT_SAMPLES } from "@/data/alert-samples";
import { AutonomousTriageCopilot } from "@/components/triage/AutonomousTriageCopilot";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/triage")({ component: TriagePage });

const SEV_ORDER: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function TriagePage() {
  const navigate = useNavigate();
  const [items, setItems] = useState<TriageItem[]>(() => loadItems());
  const [filterStatus, setFilterStatus] = useState<TriageStatus | "all">(() => (localStorage.getItem("ba.triage.filter.status") as TriageStatus | "all") ?? "all");
  const [filterSev, setFilterSev] = useState<Severity | "all">(() => (localStorage.getItem("ba.triage.filter.sev") as Severity | "all") ?? "all");
  const [sortBy, setSortBy] = useState<"ts" | "severity" | "status">(() => (localStorage.getItem("ba.triage.sort") as "ts" | "severity" | "status") ?? "ts");
  const [view, setView] = useState<"list" | "clusters">(() => (localStorage.getItem("ba.triage.view") === "clusters" ? "clusters" : "list"));
  const [newTitle, setNewTitle] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newSev, setNewSev] = useState<Severity>("medium");
  const [noteDraft, setNoteDraft] = useState("");
  const bulkSel = useSelection();
  const [alertRaw, setAlertRaw] = useState("");
  const [alertFormat, setAlertFormat] = useState<"auto" | AlertFormat>("auto");
  const [ingesting, setIngesting] = useState(false);
  const [lastIngest, setLastIngest] = useState<ReturnType<typeof ingestAlert> | null>(null);
  const alertRef = useRef<HTMLTextAreaElement>(null);

  const detectedFormat = useMemo(() => (alertRaw.trim() ? detectAlertFormat(alertRaw) : null), [alertRaw]);

  const persist = useCallback((next: TriageItem[]) => {
    setItems(next);
    saveItems(next);
  }, []);

  const addItem = useCallback(() => {
    if (!newTitle.trim()) { toast.error("Title is required"); return; }
    const item: TriageItem = {
      id: genId(),
      ts: new Date().toISOString(),
      title: newTitle.trim(),
      description: newDesc.trim(),
      severity: newSev,
      source: "manual",
      status: "open",
      notes: "",
      tags: [],
      updated: Date.now(),
    };
    persist([item, ...items]);
    setNewTitle("");
    setNewDesc("");
    setNewSev("medium");
    toast.success("Item added to triage queue");
    pushTimelineEvent({ source: "triage", verb: "added", detail: item.title, target: "triage", result: statusLabel("open") });
  }, [newTitle, newDesc, newSev, items, persist]);

  const escalateItem = useCallback((id: string) => {
    const item = items.find((i) => i.id === id);
    if (!item || item.status === "escalated") return;
    const res = escalateToCase(item);
    persist(items.map((i) => i.id === id ? { ...i, status: "escalated", caseId: res.caseId, updated: Date.now() } : i));
    if (res.existing) {
      toast.success(`Already linked to case ${res.caseId}`);
    } else {
      toast.success(`Case ${res.caseId} opened · ${res.iocCount} IOC(s) carried${res.edgeWritten ? " · alert edge written" : ""}`);
    }
    pushTimelineEvent({
      source: "triage",
      verb: "escalated",
      detail: `${item.title} → case ${res.caseId} (${res.existing ? "linked existing" : "new"}, ${res.iocCount} IOCs)`,
      target: "triage",
      result: res.caseId,
    });
  }, [items, persist]);

  const runBulkEscalate = useCallback((ids: string[]) => {
    const targets = items.filter((i) => ids.includes(i.id) && i.status !== "escalated");
    if (targets.length === 0) { toast.info("No eligible items selected"); return; }
    const { summary, updated: escalatedRows } = escalateItems(targets);
    const byId = new Map(escalatedRows.map((r) => [r.id, r]));
    persist(items.map((i) => byId.get(i.id) ?? i));
    toast.success(
      `Escalated ${targets.length}: ${summary.created} new case(s), ${summary.linked} linked to existing · ${summary.iocsCarried} IOC(s) carried` +
      (summary.failed > 0 ? ` · ${summary.failed} failed` : ""),
    );
    pushTimelineEvent({
      source: "triage",
      verb: "bulk_escalated",
      detail: `${targets.length} item(s) → ${summary.created} new / ${summary.linked} existing case(s), ${summary.iocsCarried} IOCs`,
      target: "triage",
    });
  }, [items, persist]);

  const updateStatus = useCallback((id: string, status: TriageStatus) => {
    if (status === "escalated") {
      escalateItem(id);
      return;
    }
    const next = items.map((i) => i.id === id ? { ...i, status, updated: Date.now() } : i);
    persist(next);
    pushTimelineEvent({ source: "triage", verb: "status_changed", detail: `${items.find((i) => i.id === id)?.title} → ${statusLabel(status)}`, target: "triage" });
  }, [items, persist, escalateItem]);

  const setVerdict = useCallback((id: string, verdict: TriageVerdict, reason?: string) => {
    const item = items.find((i) => i.id === id);
    if (!item) return;

    const noteAppend = reason ? (item.notes ? "\n---\n" : "") + `[${new Date().toLocaleString()}] ${reason}` : "";

    if (verdict === "true_positive") {
      escalateItem(id);
      const updated = items.map((i) =>
        i.id === id
          ? {
              ...i,
              verdict,
              verdictReason: reason || "Confirmed malicious threat",
              notes: noteAppend ? i.notes + noteAppend : i.notes,
              dispositionAt: Date.now(),
            }
          : i,
      );
      persist(updated);
      toast.success("True Positive: Escalated to incident case");
    } else if (verdict === "benign_positive") {
      const updated = items.map((i) =>
        i.id === id
          ? {
              ...i,
              status: "dismissed" as TriageStatus,
              verdict,
              verdictReason: reason || "Authorized benign activity",
              notes: noteAppend ? i.notes + noteAppend : i.notes,
              dispositionAt: Date.now(),
            }
          : i,
      );
      persist(updated);
      toast.info("Benign Positive: Marked dismissed (authorized)");
    } else if (verdict === "false_positive") {
      const updated = items.map((i) =>
        i.id === id
          ? {
              ...i,
              status: "dismissed" as TriageStatus,
              verdict,
              verdictReason: reason || "Detection tuning candidate",
              notes: noteAppend ? i.notes + noteAppend : i.notes,
              dispositionAt: Date.now(),
            }
          : i,
      );
      persist(updated);
      toast.info("False Positive: Marked dismissed (tuning candidate)");
    } else if (verdict === "test") {
      const updated = items.map((i) =>
        i.id === id
          ? {
              ...i,
              status: "dismissed" as TriageStatus,
              verdict,
              verdictReason: reason || "Security drill / test simulation",
              notes: noteAppend ? i.notes + noteAppend : i.notes,
              dispositionAt: Date.now(),
            }
          : i,
      );
      persist(updated);
      toast.info("Test / Drill: Marked dismissed");
    }
  }, [items, persist, escalateItem]);

  const bulkSetVerdict = useCallback((ids: string[], verdict: TriageVerdict) => {
    if (ids.length === 0) return;
    if (verdict === "true_positive") {
      runBulkEscalate(ids);
      return;
    }
    const updated = items.map((item) => {
      if (!ids.includes(item.id)) return item;
      return {
        ...item,
        status: "dismissed" as TriageStatus,
        verdict,
        verdictReason: verdict === "benign_positive" ? "Batch benign positive" : "Batch false positive",
        dispositionAt: Date.now(),
      };
    });
    persist(updated);
    bulkSel.clear();
    toast.success(`Dispositioned ${ids.length} item(s) as ${verdict.replace("_", " ")}`);
  }, [items, persist, runBulkEscalate, bulkSel]);

  const [labelDraft, setLabelDraft] = useState("");
  const applyLabel = useCallback((indices: number[]) => {
    const label = labelDraft.trim();
    if (!label) { toast.error("Enter a label first"); return; }
    let count = 0;
    const next = items.map((item, idx) => {
      if (!indices.includes(idx)) return item;
      count++;
      return item.tags.includes(label) ? item : { ...item, tags: [...item.tags, label], updated: Date.now() };
    });
    persist(next);
    setLabelDraft("");
    pushTimelineEvent({ source: "triage", verb: "labeled", detail: `${count} item(s) → "${label}"`, target: "triage" });
    toast.success(`Labeled ${count} item(s)`);
  }, [items, labelDraft, persist]);

  const addNote = useCallback((id: string) => {
    if (!noteDraft.trim()) return;
    const next = items.map((i) => i.id === id ? { ...i, notes: i.notes + (i.notes ? "\n---\n" : "") + `[${new Date().toLocaleString()}] ${noteDraft.trim()}`, updated: Date.now() } : i);
    persist(next);
    setNoteDraft("");
    toast.success("Note added");
  }, [noteDraft, items, persist]);

  const removeItem = useCallback((id: string) => {
    const next = items.filter((i) => i.id !== id);
    persist(next);
    toast.success("Item removed");
  }, [items, persist]);

  const runIngest = useCallback(() => {
    if (!alertRaw.trim()) { toast.error("Paste an alert to ingest"); return; }
    setIngesting(true);
    try {
      const out = ingestAlert(alertRaw);
      setLastIngest(out);
      if (out.ok) {
        const item: TriageItem = {
          id: genId(),
          ts: new Date().toISOString(),
          title: out.alert.title,
          description: `${out.alert.summary} — case ${out.case?.id ?? out.ledger.caseId}`,
          severity: out.alert.severity,
          source: `alert-ingest:${out.alert.format}`,
          status: "open",
          notes: "",
          tags: [],
          updated: Date.now(),
          alertNodeId: out.alertId,
          caseId: out.case?.id ?? out.ledger.caseId,
        };
        persist([item, ...items]);
        toast.success(out.isNew ? `Alert ingested — case ${out.case?.id ?? out.ledger.caseId} opened` : "Duplicate alert — existing case returned");
        pushTimelineEvent({
          source: "triage",
          verb: out.isNew ? "ingested" : "deduped",
          detail: `${out.alert.format} · ${out.alert.title} → case ${out.case?.id ?? out.ledger.caseId} (${out.edgesWritten} edges)`,
          target: "triage",
          result: out.isNew ? "case opened" : "ledger hit",
        });
      } else {
        toast.error(out.error);
      }
    } finally {
      setIngesting(false);
    }
  }, [alertRaw, items, persist]);

  const exportQueue = useCallback(() => {
    const blob = new Blob([JSON.stringify(items, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `triage-queue-${new Date().toISOString().slice(0, 10)}.json`;
    a.click(); URL.revokeObjectURL(url);
    toast.success("Queue exported");
  }, [items]);

  const filtered = useMemo(() => {
    let result = [...items];
    if (filterStatus !== "all") result = result.filter((i) => i.status === filterStatus);
    if (filterSev !== "all") result = result.filter((i) => i.severity === filterSev);
    if (sortBy === "ts") result.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());
    else if (sortBy === "severity") result.sort((a, b) => SEV_ORDER[b.severity] - SEV_ORDER[a.severity]);
    else if (sortBy === "status") result.sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]);
    return result;
  }, [items, filterStatus, filterSev, sortBy]);

  const clusters = useMemo(() => (view === "clusters" ? clusterItems(filtered) : []), [filtered, view]);

  const { index, setIndex, selected } = usePanelNav(filtered, {
    onCopy: (item) => {
      const text = `${item.title}\n${item.description}\nSev: ${item.severity} | Status: ${statusLabel(item.status)}`;
      copyText(text);
      toast.success("Copied to clipboard");
    },
    onAttach: (item) => {
      sendToCase({ body: `**From Triage Queue**\n\n**${item.title}**\n${item.description}\n\n*Severity: ${item.severity} | Source: ${item.source}*`, source: "triage", kind: "evidence" });
      toast.success("Sent to case");
    },
  });

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") { setIndex(-1); }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [setIndex]);

  const counts = useMemo(() => ({
    total: items.length,
    open: items.filter((i) => i.status === "open").length,
    in_review: items.filter((i) => i.status === "in_review").length,
    escalated: items.filter((i) => i.status === "escalated").length,
    dismissed: items.filter((i) => i.status === "dismissed").length,
    high: items.filter((i) => i.severity === "high" || i.severity === "critical").length,
  }), [items]);

  return (
    <ErrorBoundary name="TriagePage">
      <PageShell
        eyebrow="// triage"
        title="Triage Queue"
      description="Review, prioritize, and disposition security events. Use j/k to navigate, y to copy, c to send to case."
      crumbs={[{ label: "Triage" }]}
      actions={
        <button onClick={exportQueue} className="inline-flex items-center gap-1.5 rounded border border-border bg-surface-2 px-2 py-1 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:border-primary/40 hover:text-foreground">
          <Download className="h-3 w-3" /> export
        </button>
      }
    >
      <StatusBar
        stats={[
          { label: "total", value: counts.total, tone: counts.total > 0 ? "default" : "muted" },
          { label: "open", value: counts.open, tone: counts.open > 0 ? "warning" : "muted" },
          { label: "in review", value: counts.in_review, tone: counts.in_review > 0 ? "primary" : "muted" },
          { label: "escalated", value: counts.escalated, tone: counts.escalated > 0 ? "destructive" : "muted" },
          { label: "dismissed", value: counts.dismissed, tone: "muted" },
          { label: "high/critical", value: counts.high, tone: counts.high > 0 ? "destructive" : "muted" },
        ]}
      />

      <SectionBar id="AI" label="alert intake" icon={Inbox} meta={`${detectedFormat ?? "auto-detect"} · 8 enterprise formats`}>
        <div className="mt-3 space-y-3">
          <textarea
            ref={alertRef}
            value={alertRaw}
            onChange={(e) => { setAlertRaw(e.target.value); setLastIngest(null); }}
            onKeyDown={(e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); runIngest(); } }}
            aria-label="Alert payload"
            placeholder={"Paste an alert — BeyondLabs, Sigma, Suricata EVE, Sysmon, CrowdStrike Falcon, Defender 365, AWS GuardDuty, or Elastic ECS…"}
            rows={5}
            className="w-full resize-y rounded border border-border bg-surface-0 px-3 py-2 font-mono ba-text-2xs leading-[1.5] text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50"
          />
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={alertFormat}
              onChange={(e) => setAlertFormat(e.target.value as "auto" | AlertFormat)}
              aria-label="Alert format"
              className="w-44 appearance-none rounded border border-border bg-surface-2 px-2 py-1.5 text-mono ba-text-2xs text-foreground outline-none"
            >
              <option value="auto">auto-detect</option>
              {ALERT_SAMPLES.map((s) => <option key={s.format} value={s.format}>{s.label}</option>)}
            </select>
            <button
              onClick={runIngest}
              disabled={ingesting}
              className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-3 py-1.5 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20 disabled:opacity-40"
            >
              {ingesting ? <Loader2 className="h-3 w-3 animate-spin" /> : <Inbox className="h-3 w-3" />}
              ingest alert
            </button>
            {detectedFormat && <Chip tone="info">{detectedFormat} detected</Chip>}
            <span className="ml-auto text-mono ba-text-2xs text-muted-foreground">or load a sample:</span>
            {ALERT_SAMPLES.map((s) => (
              <button
                key={s.format}
                onClick={() => { setAlertRaw(s.text); setAlertFormat("auto"); setLastIngest(null); alertRef.current?.focus(); }}
                className="rounded border border-subtle px-2 py-1 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:border-primary/40 hover:text-primary"
              >
                {s.label}
              </button>
            ))}
          </div>
          {lastIngest && (
            lastIngest.ok ? (
              <div className="rounded border border-subtle bg-background/30 px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <Chip tone="info">{lastIngest.alert.format}</Chip>
                  <span className="truncate text-mono ba-text-sm text-foreground">{lastIngest.alert.title}</span>
                  <Chip tone={lastIngest.alert.severity === "critical" || lastIngest.alert.severity === "high" ? "destructive" : lastIngest.alert.severity === "medium" ? "warning" : "default"}>
                    {lastIngest.alert.severity}
                  </Chip>
                  <Chip tone={lastIngest.isNew ? "success" : "default"}>{lastIngest.isNew ? "new case" : "ledger hit"}</Chip>
                  <span className="text-mono ba-text-2xs text-muted-foreground">· {lastIngest.edgesWritten} edge{lastIngest.edgesWritten === 1 ? "" : "s"} written</span>
                  {lastIngest.resolvedRule && <Chip tone="primary">fires {lastIngest.resolvedRule.ruleKey}</Chip>}
                </div>
                {lastIngest.case && (
                  <Link to="/case" className="mt-1 inline-flex items-center gap-1 text-mono ba-text-2xs text-primary hover:underline">
                    <ArrowUpRight className="h-3 w-3" /> case {lastIngest.case.id}
                  </Link>
                )}
              </div>
            ) : (
              <div className="rounded border border-destructive/30 bg-destructive/5 px-3 py-2 text-mono ba-text-2xs text-destructive">
                {lastIngest.error}
              </div>
            )
          )}
        </div>
      </SectionBar>

      <SectionBar id="IN" label="intake" icon={Plus} meta="add item">
        <div className="mt-3 space-y-3">
          <div className="flex gap-3">
            <input
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") addItem(); }}
              aria-label="New item title"
              placeholder="Item title…"
              className="min-w-0 flex-1 rounded border border-border bg-surface-0 px-3 py-2 text-mono ba-text-sm text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50"
            />
            <select
              value={newSev}
              onChange={(e) => setNewSev(e.target.value as Severity)}
              aria-label="New item severity"
              className="w-28 appearance-none rounded border border-border bg-surface-2 px-2 py-2 text-mono ba-text-2xs text-foreground outline-none"
            >
              <option value="info">info</option>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
            <button
              onClick={addItem}
              className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-3 py-2 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"
            >
              <Plus className="h-3 w-3" /> add
            </button>
          </div>
          <textarea
            value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)}
            aria-label="New item description"
            placeholder="Description (optional)…"
            rows={2}
            className="w-full resize-none rounded border border-border bg-surface-0 px-3 py-2 text-mono ba-text-sm text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50"
          />
        </div>
      </SectionBar>

      <BulkActionBar
        selected={bulkSel.selected}
        total={filtered.length}
        onSelectAll={() => bulkSel.selectAll(filtered.length)}
        onClear={bulkSel.clear}
        actions={[
          {
            label: "export", icon: Download,
            onClick: (indices) => {
              const rows = indices.map((i) => filtered[i]).filter(Boolean);
              const blob = new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url; a.download = `triage-selection-${new Date().toISOString().slice(0, 10)}.json`;
              a.click(); URL.revokeObjectURL(url);
              toast.success(`Exported ${rows.length} item(s)`);
            },
          },
          {
            label: "escalate", icon: ArrowUpRight, tone: "primary" as const,
            onClick: (indices) => {
              runBulkEscalate(indices.map((i) => filtered[i]?.id).filter((id): id is string => Boolean(id)));
              bulkSel.clear();
            },
          },
          {
            label: "mark benign", icon: CheckCircle, tone: "default" as const,
            onClick: (indices) => {
              bulkSetVerdict(indices.map((i) => filtered[i]?.id).filter((id): id is string => Boolean(id)), "benign_positive");
            },
          },
          {
            label: "mark false pos", icon: XCircle, tone: "default" as const,
            onClick: (indices) => {
              bulkSetVerdict(indices.map((i) => filtered[i]?.id).filter((id): id is string => Boolean(id)), "false_positive");
            },
          },
          {
            label: "delete", icon: Trash2, tone: "destructive" as const,
            onClick: (indices) => {
              for (const i of indices) {
                const item = filtered[i];
                if (item) removeItem(item.id);
              }
              bulkSel.clear();
            },
          },
        ]}
        extra={
          <span className="inline-flex items-center gap-1">
            <input
              value={labelDraft}
              onChange={(e) => setLabelDraft(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") applyLabel([...bulkSel.selected]); }}
              placeholder="label…"
              aria-label="Label for selected items"
              className="w-24 rounded border border-border bg-surface-0 px-1.5 py-1 text-mono ba-text-2xs text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50"
            />
            <button
              onClick={() => applyLabel([...bulkSel.selected])}
              className="inline-flex items-center gap-1 rounded border border-border bg-surface-2 px-2 py-1 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:text-foreground"
            >
              <Tag className="h-3 w-3" /> label
            </button>
          </span>
        }
      />

      <SectionBar id="FL" label="filter" icon={AlertTriangle}>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <span className="text-mono ba-text-2xs text-muted-foreground">status</span>
          {["all" as const, ...STATUSES].map((s) => (
            <button
              key={s}
              onClick={() => { setFilterStatus(s); localStorage.setItem("ba.triage.filter.status", s); }}
              className={"rounded border px-2 py-1 text-mono ba-text-2xs transition-colors duration-150" + (filterStatus === s ? "border-primary bg-primary/15 text-primary" : "border-subtle text-muted-foreground hover:text-foreground")}
            >
              {s === "all" ? "all" : statusLabel(s)}
            </button>
          ))}
          <span className="ml-2 text-mono ba-text-2xs text-muted-foreground">severity</span>
          {["all" as const, "info", "low", "medium", "high", "critical"].map((s) => (
            <button
              key={s}
              onClick={() => { setFilterSev(s as Severity | "all"); localStorage.setItem("ba.triage.filter.sev", s); }}
              className={"rounded border px-2 py-1 text-mono ba-text-2xs transition-colors duration-150" + (filterSev === s ? "border-primary bg-primary/15 text-primary" : "border-subtle text-muted-foreground hover:text-foreground")}
            >
              {s}
            </button>
          ))}
          <span className="ml-2 text-mono ba-text-2xs text-muted-foreground">sort</span>
          <select
            value={sortBy}
            onChange={(e) => { setSortBy(e.target.value as "ts" | "severity" | "status"); localStorage.setItem("ba.triage.sort", e.target.value); }}
            aria-label="Sort triage items"
            className="rounded border border-border bg-surface-2 px-2 py-1 text-mono ba-text-2xs text-foreground outline-none"
          >
            <option value="ts">newest</option>
            <option value="severity">severity</option>
            <option value="status">status</option>
          </select>
          <span className="ml-2 text-mono ba-text-2xs text-muted-foreground">view</span>
          {(["list", "clusters"] as const).map((v) => (
            <button
              key={v}
              onClick={() => { setView(v); localStorage.setItem("ba.triage.view", v); }}
              aria-pressed={view === v}
              className={"rounded border px-2 py-1 text-mono ba-text-2xs transition-colors duration-150" + (view === v ? "border-primary bg-primary/15 text-primary" : "border-subtle text-muted-foreground hover:text-foreground")}
            >
              {v}
            </button>
          ))}
        </div>
      </SectionBar>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_380px] min-w-0 max-w-full">
        <div className="space-y-1 min-w-0 max-w-full">
          {view === "clusters" ? (
            clusters.length === 0 ? (
              <div className="flex items-center justify-center rounded border border-dashed border-subtle bg-background/30 py-12">
                <span className="text-mono ba-text-2xs text-fg-dim">no open or in-review items to cluster</span>
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                {clusters.map((cluster) => {
                  const maxSev = cluster.items.reduce<Severity>((acc, i) => (SEV_ORDER[i.severity] > SEV_ORDER[acc] ? i.severity : acc), "info");
                  return (
                    <div key={cluster.key} className="rounded-md border border-border/70 bg-surface-0 p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Chip tone={maxSev === "critical" || maxSev === "high" ? "destructive" : maxSev === "medium" ? "warning" : "default"}>
                          {cluster.items.length} item{cluster.items.length === 1 ? "" : "s"}
                        </Chip>
                        <span className="min-w-0 truncate text-mono ba-text-sm font-medium text-foreground">{cluster.label}</span>
                        <Chip tone={cluster.kind === "technique" ? "info" : cluster.kind === "unclustered" ? "default" : "success"}>
                          {cluster.iocType ?? cluster.kind}
                        </Chip>
                        <button
                          onClick={() => runBulkEscalate(cluster.items.map((i) => i.id))}
                          className="ml-auto inline-flex items-center gap-1 rounded border border-destructive/50 bg-destructive/10 px-2 py-1 text-mono ba-text-2xs text-destructive transition-colors duration-150 hover:bg-destructive/20"
                          title={`Escalate all ${cluster.items.length} item(s)`}
                        >
                          <ArrowUpRight className="h-3 w-3" /> escalate
                        </button>
                      </div>
                      <div className="mt-2 space-y-1">
                        {cluster.items.map((item) => (
                          <div key={item.id} className="flex items-center gap-2 rounded px-1.5 py-1 text-mono ba-text-2xs text-muted-foreground hover:bg-accent/10">
                            <span className={"h-1.5 w-1.5 shrink-0 rounded-full " + (item.severity === "critical" || item.severity === "high" ? "bg-destructive" : item.severity === "medium" ? "bg-warning" : "bg-muted-foreground/40")} />
                            <button onClick={() => setIndex(filtered.findIndex((f) => f.id === item.id))} className="min-w-0 truncate text-left hover:text-foreground">
                              {item.title}
                            </button>
                            <span className="ml-auto shrink-0 capitalize">{item.status.replace("_", " ")}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )
          ) : filtered.length === 0 ? (
            <div className="flex items-center justify-center rounded border border-dashed border-subtle bg-background/30 py-12">
              <span className="text-mono ba-text-2xs text-fg-dim">
                {items.length === 0 ? "queue is empty — add items above" : "no items match filters"}
              </span>
            </div>
          ) : (
            filtered.map((item, i) => (
              <div
                key={item.id}
                onClick={() => setIndex(i)}
                className={"group flex cursor-pointer items-start gap-3 rounded-md border px-3 py-2.5 transition-all " + (index === i ? "border-primary/60 bg-primary/[0.06] shadow-[0_0_12px_-4px_color-mix(in_oklab,var(--primary)_30%,transparent)]" : "border-transparent bg-transparent hover:border-border/60 hover:bg-accent/10")}
              >
                <div className="flex h-5 w-5 shrink-0 items-center justify-center">
                  <button
                    onClick={(e) => { e.stopPropagation(); bulkSel.toggle(i, e.shiftKey); }}
                    aria-label={bulkSel.selected.has(i) ? `Deselect ${item.title}` : `Select ${item.title}`}
                    aria-pressed={bulkSel.selected.has(i)}
                    className={"grid h-4 w-4 place-items-center rounded border text-mono ba-text-3xs " + (bulkSel.selected.has(i) ? "border-warning bg-warning/20 text-warning" : "border-subtle text-transparent hover:border-warning/60")}
                  >
                    ✓
                  </button>
                </div>
                <div className="flex h-5 w-5 shrink-0 items-center justify-center">
                  {item.status === "dismissed" ? <XCircle className="h-4 w-4 text-muted-foreground" /> :
                   item.status === "escalated" ? <ArrowUpRight className="h-4 w-4 text-destructive" /> :
                   item.status === "in_review" ? <Eye className="h-4 w-4 text-primary" /> :
                   <AlertTriangle className={"h-4 w-4 " + (item.severity === "high" || item.severity === "critical" ? "text-destructive" : item.severity === "medium" ? "text-warning" : "text-muted-foreground")} />}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 min-w-0">
                    <span className="truncate text-mono ba-text-sm font-medium text-foreground">{item.title}</span>
                    <Chip tone={item.severity === "critical" || item.severity === "high" ? "destructive" : item.severity === "medium" ? "warning" : "default"}>
                      {item.severity}
                    </Chip>
                    <Chip tone={STATUS_TONE[item.status] as "default" | "warning" | "destructive" | "info" | "success"}>
                      {statusLabel(item.status)}
                    </Chip>
                    {item.verdict && (
                      <span
                        className={cn(
                          "rounded px-1.5 py-0.5 text-mono text-[9px] font-bold uppercase shrink-0",
                          item.verdict === "true_positive"
                            ? "bg-destructive/20 text-destructive border border-destructive/30"
                            : item.verdict === "benign_positive"
                            ? "bg-success/20 text-success border border-success/30"
                            : item.verdict === "false_positive"
                            ? "bg-muted-foreground/20 text-muted-foreground border border-muted-foreground/30"
                            : "bg-primary/20 text-primary border border-primary/30",
                        )}
                      >
                        {item.verdict === "true_positive"
                          ? "TP: Incident"
                          : item.verdict === "benign_positive"
                          ? "BP: Benign"
                          : item.verdict === "false_positive"
                          ? "FP: Tune"
                          : "Test Drill"}
                      </span>
                    )}
                  </div>
                  {item.description && (
                    <div className="mt-0.5 truncate text-mono ba-text-sm text-muted-foreground">{item.description}</div>
                  )}
                  <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-mono ba-text-2xs text-muted-foreground min-w-0">
                    <span className="shrink-0">{new Date(item.ts).toLocaleString()}</span>
                    <span>·</span>
                    <span className="capitalize shrink-0">{item.source}</span>
                    {item.notes && <><span>·</span><span className="shrink-0">{item.notes.split("\n").length} note(s)</span></>}
                    {item.caseId && (
                      <>
                        <span>·</span>
                        <button
                          onClick={(e) => { e.stopPropagation(); setActiveCaseId(item.caseId!); navigate({ to: "/case" }); }}
                          title={`Open ${item.caseId}`}
                          className="rounded border border-border px-1 py-px text-mono ba-text-3xs text-primary transition-colors duration-150 hover:bg-primary/10 shrink-0"
                        >
                          case {item.caseId}
                        </button>
                      </>
                    )}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                  {item.status === "open" && (
                    <button onClick={(e) => { e.stopPropagation(); updateStatus(item.id, "in_review"); }} title="Review" className="rounded p-1 text-muted-foreground hover:bg-primary/10 hover:text-primary">
                      <Eye className="h-3.5 w-3.5" />
                    </button>
                  )}
                  {item.status === "in_review" && (
                    <button onClick={(e) => { e.stopPropagation(); updateStatus(item.id, "escalated"); }} title="Escalate to case" className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive">
                      <ArrowUpRight className="h-3.5 w-3.5" />
                    </button>
                  )}
                  {(item.status === "open" || item.status === "in_review") && (
                    <button onClick={(e) => { e.stopPropagation(); updateStatus(item.id, "dismissed"); }} title="Dismiss" className="rounded p-1 text-muted-foreground hover:bg-muted-foreground/10 hover:text-muted-foreground">
                      <XCircle className="h-3.5 w-3.5" />
                    </button>
                  )}
                  <button onClick={(e) => { e.stopPropagation(); removeItem(item.id); }} title="Remove" className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive">
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>

        <div className="space-y-4 min-w-0 max-w-full">
          {/* Severity distribution donut */}
          {items.length > 0 && (() => {
            const sevChartConfig = {
              critical: { label: "Critical", color: "hsl(var(--destructive))" },
              high: { label: "High", color: "hsl(0 72% 51% / 0.7)" },
              medium: { label: "Medium", color: "hsl(var(--warning))" },
              low: { label: "Low", color: "hsl(var(--success))" },
              info: { label: "Info", color: "hsl(var(--muted-foreground) / 0.4)" },
            } satisfies ChartConfig;
            const pieData = (["critical", "high", "medium", "low", "info"] as const)
              .map((s) => ({ name: s, value: items.filter((i) => i.severity === s).length, color: sevChartConfig[s].color }))
              .filter((d) => d.value > 0);
            if (pieData.length === 0) return null;
            return (
              <Panel title="Severity Distribution" icon={AlertTriangle} priority="secondary" collapsible>
                <ChartContainer config={sevChartConfig} className="mx-auto aspect-square w-full max-w-[200px]">
                  <PieChart>
                    <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={45} outerRadius={80} paddingAngle={2}>
                      {pieData.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                    <ChartTooltip content={<ChartTooltipContent />} />
                  </PieChart>
                </ChartContainer>
                <div className="mt-1 flex flex-wrap justify-center gap-2">
                  {pieData.map((d) => (
                    <div key={d.name} className="flex items-center gap-1">
                      <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: d.color }} />
                      <span className="text-mono ba-text-2xs capitalize text-muted-foreground">{d.name}</span>
                      <span className="text-mono ba-text-sm font-medium text-foreground">{d.value}</span>
                    </div>
                  ))}
                </div>
              </Panel>
            );
          })()}

          {selected ? (
            <Panel title="Detail" icon={AlertTriangle}>
              <div className="space-y-3 min-w-0 max-w-full overflow-hidden">
                <div>
                  <div className="flex items-center gap-2 min-w-0">
                    <h3 className="text-mono ba-text-base font-bold text-foreground break-words min-w-0">{selected.title}</h3>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  <Chip tone={selected.severity === "critical" || selected.severity === "high" ? "destructive" : selected.severity === "medium" ? "warning" : "default"}>
                    {selected.severity}
                  </Chip>
                  <Chip tone={STATUS_TONE[selected.status] as "default" | "warning" | "destructive" | "info" | "success"}>
                    {statusLabel(selected.status)}
                  </Chip>
                  <Chip tone="default">{selected.source}</Chip>
                  {selected.caseId && (
                    <button
                      onClick={() => { setActiveCaseId(selected.caseId!); navigate({ to: "/case" }); }}
                      className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2 py-0.5 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"
                      title="Open linked case"
                    >
                      case {selected.caseId} ↗
                    </button>
                  )}
                </div>

                {selected.description && (
                  <div>
                    <div className="text-mono ba-text-2xs text-muted-foreground">description</div>
                    <p className="mt-1 text-mono ba-text-sm text-fg-dim whitespace-pre-wrap">{selected.description}</p>
                  </div>
                )}

                <div className="space-y-1">
                  <div className="flex gap-2">
                    {selected.status === "open" && (
                      <button onClick={() => updateStatus(selected.id, "in_review")} className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20">
                        <Eye className="h-3 w-3" /> start review
                      </button>
                    )}
                    {selected.status === "in_review" && (
                      <button onClick={() => updateStatus(selected.id, "escalated")} className="inline-flex items-center gap-1.5 rounded border border-destructive/50 bg-destructive/10 px-2.5 py-1.5 text-mono ba-text-2xs text-destructive transition-colors duration-150 hover:bg-destructive/20">
                        <ArrowUpRight className="h-3 w-3" /> escalate to case
                      </button>
                    )}
                    {(selected.status === "open" || selected.status === "in_review") && (
                      <button onClick={() => updateStatus(selected.id, "dismissed")} className="inline-flex items-center gap-1.5 rounded border border-border bg-surface-2 px-2.5 py-1.5 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:text-foreground">
                        <XCircle className="h-3 w-3" /> dismiss
                      </button>
                    )}
                    {selected.status === "dismissed" && (
                      <button onClick={() => updateStatus(selected.id, "open")} className="inline-flex items-center gap-1.5 rounded border border-border bg-surface-2 px-2.5 py-1.5 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:text-foreground">
                        <CheckCircle className="h-3 w-3" /> reopen
                      </button>
                    )}
                  </div>
                </div>

                <AutonomousTriageCopilot
                  item={selected}
                  onApplyRecommendation={(verdict, justification) => setVerdict(selected.id, verdict, justification)}
                />

                {/* Analyst Disposition Verdict Bar */}
                <div className="rounded-md border border-border/70 bg-surface-0/60 p-3 space-y-2 min-w-0 max-w-full overflow-hidden">
                  <div className="flex flex-wrap items-center justify-between gap-1 text-mono ba-text-3xs font-semibold uppercase text-muted-foreground">
                    <span>Analyst Disposition Verdict</span>
                    {selected.verdict && (
                      <span className="font-bold text-primary">
                        {selected.verdict.replace("_", " ")}
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-4 min-w-0 max-w-full">
                    <button
                      type="button"
                      onClick={() => setVerdict(selected.id, "true_positive")}
                      className={cn(
                        "flex items-center justify-center gap-1 rounded border px-2 py-1.5 text-mono ba-text-2xs font-semibold transition-all",
                        selected.verdict === "true_positive"
                          ? "border-destructive bg-destructive/20 text-destructive shadow-sm"
                          : "border-destructive/40 bg-destructive/5 text-destructive hover:bg-destructive/15",
                      )}
                    >
                      🚨 True Pos
                    </button>
                    <button
                      type="button"
                      onClick={() => setVerdict(selected.id, "benign_positive")}
                      className={cn(
                        "flex items-center justify-center gap-1 rounded border px-2 py-1.5 text-mono ba-text-2xs font-semibold transition-all",
                        selected.verdict === "benign_positive"
                          ? "border-success bg-success/20 text-success shadow-sm"
                          : "border-success/40 bg-success/5 text-success hover:bg-success/15",
                      )}
                    >
                      🟡 Benign
                    </button>
                    <button
                      type="button"
                      onClick={() => setVerdict(selected.id, "false_positive")}
                      className={cn(
                        "flex items-center justify-center gap-1 rounded border px-2 py-1.5 text-mono ba-text-2xs font-semibold transition-all",
                        selected.verdict === "false_positive"
                          ? "border-muted-foreground bg-muted-foreground/20 text-foreground shadow-sm"
                          : "border-border bg-surface-1 text-muted-foreground hover:bg-surface-2",
                      )}
                    >
                      ⚪ False Pos
                    </button>
                    <button
                      type="button"
                      onClick={() => setVerdict(selected.id, "test")}
                      className={cn(
                        "flex items-center justify-center gap-1 rounded border px-2 py-1.5 text-mono ba-text-2xs font-semibold transition-all",
                        selected.verdict === "test"
                          ? "border-primary bg-primary/20 text-primary shadow-sm"
                          : "border-primary/40 bg-primary/5 text-primary hover:bg-primary/15",
                      )}
                    >
                      🧪 Test Drill
                    </button>
                  </div>
                  {selected.verdictReason && (
                    <div className="text-mono ba-text-3xs text-muted-foreground italic">
                      Note: {selected.verdictReason}
                    </div>
                  )}
                </div>

                {/* Observables Table if present */}
                {selected.iocs && selected.iocs.length > 0 && (
                  <div className="space-y-1.5">
                    <div className="text-mono ba-text-2xs text-muted-foreground font-semibold">
                      Extracted Observables ({selected.iocs.length})
                    </div>
                    <div className="max-h-40 overflow-y-auto rounded border border-border bg-surface-0 p-1.5 space-y-1">
                      {selected.iocs.map((ioc, idx) => (
                        <div key={idx} className="flex items-center justify-between text-mono ba-text-3xs px-1.5 py-0.5 rounded hover:bg-surface-1">
                          <span className="text-muted-foreground uppercase text-[9px] font-bold">{ioc.type}:</span>
                          <span className="font-medium text-foreground select-all truncate max-w-[180px]">{ioc.value}</span>
                          <button
                            type="button"
                            onClick={async () => { await copyText(ioc.value); toast.success(`Copied: ${ioc.value}`); }}
                            className="text-primary hover:underline text-[9px]"
                          >
                            copy
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <div className="text-mono ba-text-2xs text-muted-foreground">notes</div>
                  <div className="mt-1 max-h-32 overflow-y-auto whitespace-pre-wrap text-mono ba-text-sm text-fg-dim">
                    {selected.notes || <span className="italic text-muted-foreground">No notes</span>}
                  </div>
                  <div className="mt-2 flex gap-2">
                    <textarea
                      value={noteDraft}
                      onChange={(e) => setNoteDraft(e.target.value)}
                      aria-label={`Note for ${selected.title}`}
                      placeholder="Add note…"
                      rows={2}
                      className="min-w-0 flex-1 resize-none rounded border border-border bg-surface-0 px-2 py-1.5 text-mono ba-text-sm text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50"
                    />
                    <button
                      onClick={() => addNote(selected.id)}
                      disabled={!noteDraft.trim()}
                      className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2 py-1.5 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20 disabled:opacity-40"
                    >
                      <MessageSquare className="h-3 w-3" /> add
                    </button>
                  </div>
                </div>

                <div className="border-t border-border pt-2 text-mono ba-text-2xs text-fg-dim">
                  <div>Created: {new Date(selected.ts).toLocaleString()}</div>
                  <div>Updated: {new Date(selected.updated).toLocaleString()}</div>
                  <div>ID: {selected.id}</div>
                </div>
              </div>
            </Panel>
          ) : (
            <Panel title="Detail" icon={AlertTriangle}>
              <div className="flex items-center justify-center py-12">
                <span className="text-mono ba-text-2xs text-fg-dim">
                  {filtered.length > 0 ? "select an item (j/k)" : "queue is empty"}
                </span>
              </div>
            </Panel>
          )}
        </div>
      </div>

      <SendToRow
        targets={[
          { label: "Case & Report", to: "/case", icon: ArrowUpRight, onClick: () => { if (selected) { sendToCase({ body: `**From Triage Queue**\n\n**${selected.title}**\n${selected.description}\n\n*Severity: ${selected.severity} | Source: ${selected.source}*`, source: "triage", kind: "evidence" }); toast.success("Sent to case"); } } },
          { label: "Detection", to: "/detection", icon: AlertTriangle },
          { label: "SIEM", to: "/siem", icon: Eye },
        ]}
      />
    </PageShell>
    </ErrorBoundary>
  );
}
