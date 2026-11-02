import { useState } from "react";
import { Lightbulb, Plus, Trash2, Check, X, ArrowRight } from "lucide-react";
import type {
  HypothesisConfidence,
  HypothesisStatus,
  NotebookHypothesis,
} from "@/data/notebook";
import { HYPOTHESIS_CONFIDENCE_ORDER, HYPOTHESIS_STATUS_ORDER } from "@/data/notebook";
import { cn } from "@/lib/utils";

const STATUS_TONE: Record<HypothesisStatus, string> = {
  open: "border-warning/50 bg-warning/10 text-warning",
  supported: "border-success/50 bg-success/10 text-success",
  refuted: "border-destructive/50 bg-destructive/10 text-destructive",
  inconclusive: "border-border text-muted-foreground",
};

const CONFIDENCE_TONE: Record<HypothesisConfidence, string> = {
  low: "border-border text-muted-foreground",
  medium: "border-warning/50 text-warning",
  high: "border-success/50 text-success",
};

export function HypothesesPanel({
  caseId,
  hypotheses,
  onChange,
  onDecision,
}: {
  caseId: string;
  hypotheses: NotebookHypothesis[];
  onChange: (list: NotebookHypothesis[]) => void;
  onDecision: (h: NotebookHypothesis, verdict: Exclude<HypothesisStatus, "open">) => void;
}) {
  const [adding, setAdding] = useState(false);

  return (
    <div className="mb-4 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-mono ba-text-3xs uppercase tracking-wider text-muted-foreground">
          Structured Hypotheses · {hypotheses.length}
        </span>
        <button
          onClick={() => setAdding(!adding)}
          className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-mono ba-text-3xs text-primary transition-colors duration-150 hover:bg-primary/20"
        >
          <Plus className="h-3 w-3" /> hypothesis
        </button>
      </div>

      {adding && (
        <NewHypothesisForm
          caseId={caseId}
          onAdd={(h) => onChange([h, ...hypotheses])}
          onCancel={() => setAdding(false)}
        />
      )}

      {hypotheses.length === 0 && !adding && (
        <div className="rounded border border-dashed border-border bg-surface-1/50 px-3 py-2 text-mono ba-text-2xs text-muted-foreground">
          No hypotheses yet. Add one to record supporting / contradicting evidence, confidence, and a decision attached to the timeline.
        </div>
      )}

      {hypotheses.map((h) => (
        <HypothesisCard
          key={h.id}
          h={h}
          onChange={(next) => onChange(hypotheses.map((x) => (x.id === h.id ? next : x)))}
          onDelete={() => onChange(hypotheses.filter((x) => x.id !== h.id))}
          onDecision={onDecision}
        />
      ))}
    </div>
  );
}

function NewHypothesisForm({ caseId, onAdd, onCancel }: { caseId: string; onAdd: (h: NotebookHypothesis) => void; onCancel: () => void }) {
  const [hypothesis, setHypothesis] = useState("");
  const [supporting, setSupporting] = useState("");
  const [contradicting, setContradicting] = useState("");
  const [nextStep, setNextStep] = useState("");

  const canAdd = hypothesis.trim().length > 0;

  return (
    <div className="space-y-2 rounded-lg border border-primary/30 bg-primary/[0.04] p-3">
      <div>
        <label className="text-mono ba-text-3xs uppercase tracking-wider text-muted-foreground">Hypothesis</label>
        <textarea
          value={hypothesis}
          onChange={(e) => setHypothesis(e.target.value)}
          rows={2}
          placeholder="What do we believe is happening…"
          className="mt-1 w-full resize-y rounded border border-divider-strong bg-surface-0 p-2 font-mono ba-text-xs text-foreground outline-none focus:border-primary/50"
        />
      </div>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <FieldInput label="Supporting evidence" value={supporting} onChange={setSupporting} placeholder="word, IOC, artifact…" />
        <FieldInput label="Contradicting evidence" value={contradicting} onChange={setContradicting} placeholder="word, IOC, artifact…" />
      </div>
      <div className="flex items-center gap-2">
        <FieldInput label="Next step" value={nextStep} onChange={setNextStep} placeholder="e.g. pull DNS logs for the domain" />
        <div className="pt-4" />
        <button
          onClick={() => {
            if (!canAdd) return;
            onAdd({
              id: "",
              caseId,
              hypothesis: hypothesis.trim(),
              supporting: supporting.trim() ? [supporting.trim()] : [],
              contradicting: contradicting.trim() ? [contradicting.trim()] : [],
              confidence: "low",
              status: "open",
              decision: "",
              nextStep: nextStep.trim(),
              createdAt: "",
              updatedAt: "",
            });
            setHypothesis(""); setSupporting(""); setContradicting(""); setNextStep("");
            onCancel();
          }}
          disabled={!canAdd}
          className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono ba-text-3xs text-primary hover:bg-primary/20 disabled:opacity-40"
        >
          <Plus className="h-3 w-3" /> add
        </button>
        <button onClick={onCancel} className="rounded border border-border px-2 py-1 text-mono ba-text-3xs text-muted-foreground hover:text-foreground">
          cancel
        </button>
      </div>
    </div>
  );
}

function FieldInput({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <div>
      <label className="text-mono ba-text-3xs uppercase tracking-wider text-muted-foreground">{label}</label>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="mt-1 w-full rounded border border-divider-strong bg-surface-0 px-2 py-1 font-mono ba-text-sm text-foreground outline-none focus:border-primary/50"
      />
    </div>
  );
}

function HypothesisCard({
  h,
  onChange,
  onDelete,
  onDecision,
}: {
  h: NotebookHypothesis;
  onChange: (h: NotebookHypothesis) => void;
  onDelete: () => void;
  onDecision: (h: NotebookHypothesis, verdict: Exclude<HypothesisStatus, "open">) => void;
}) {
  const [newEvidence, setNewEvidence] = useState({ supporting: "", contradicting: "" });

  const addEvidence = (side: "supporting" | "contradicting") => {
    const text = newEvidence[side].trim();
    if (!text) return;
    onChange({ ...h, [side]: [...h[side], text] });
    setNewEvidence((prev) => ({ ...prev, [side]: "" }));
  };

  const removeEvidence = (side: "supporting" | "contradicting", idx: number) => {
    onChange({ ...h, [side]: h[side].filter((_, i) => i !== idx) });
  };

  const setStatus = (status: HypothesisStatus) => {
    onChange({ ...h, status });
    if (status !== "open") onDecision({ ...h, status }, status);
  };

  return (
    <div className={cn("rounded-lg border bg-surface-1 p-3", h.status === "open" ? "border-border" : STATUS_TONE[h.status] + " border")}>
      <div className="mb-2 flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="grid h-5 w-5 shrink-0 place-items-center rounded border border-primary/40 bg-primary/10 text-primary">
            <Lightbulb className="h-3 w-3" />
          </span>
          <span className="font-mono ba-text-xs font-semibold leading-tight text-foreground">{h.hypothesis}</span>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <span className={cn("rounded border px-1.5 py-0.5 font-mono ba-text-3xs", STATUS_TONE[h.status])}>{h.status}</span>
          <button onClick={onDelete} title="Delete hypothesis" className="rounded border border-border p-1 text-muted-foreground hover:border-destructive/50 hover:text-destructive">
            <Trash2 className="h-3 w-3" />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <EvidenceList label="Supporting" items={h.supporting} tone="success" inputValue={newEvidence.supporting} setInputValue={(v) => setNewEvidence((p) => ({ ...p, supporting: v }))} onAdd={() => addEvidence("supporting")} onRemove={(i) => removeEvidence("supporting", i)} />
        <EvidenceList label="Contradicting" items={h.contradicting} tone="destructive" inputValue={newEvidence.contradicting} setInputValue={(v) => setNewEvidence((p) => ({ ...p, contradicting: v }))} onAdd={() => addEvidence("contradicting")} onRemove={(i) => removeEvidence("contradicting", i)} />
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1 rounded border border-divider-strong bg-surface-0 px-1 py-0.5">
          {HYPOTHESIS_CONFIDENCE_ORDER.map((c) => (
            <button
              key={c}
              onClick={() => onChange({ ...h, confidence: c })}
              className={cn("rounded px-1.5 py-0.5 font-mono ba-text-3xs transition-colors duration-150",
                h.confidence === c ? CONFIDENCE_TONE[c] + " bg-surface-2" : "text-muted-foreground hover:text-foreground")}
            >
              {c}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1 rounded border border-divider-strong bg-surface-0 px-1 py-0.5">
          {HYPOTHESIS_STATUS_ORDER.map((s) => (
            <button
              key={s}
              onClick={() => { if (s === "open") { onChange({ ...h, status: "open" }); } else { setStatus(s); } }}
              className={cn("rounded px-1.5 py-0.5 font-mono ba-text-3xs transition-colors duration-150",
                h.status === s ? STATUS_TONE[s] + " bg-surface-2" : "text-muted-foreground hover:text-foreground")}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {h.status !== "open" && (
        <div className="mt-2">
          <label className="text-mono ba-text-3xs uppercase tracking-wider text-muted-foreground">Decision note (attached to timeline)</label>
          <textarea
            value={h.decision}
            onChange={(e) => onChange({ ...h, decision: e.target.value })}
            rows={2}
            placeholder="Why did you decide this?…"
            className="mt-1 w-full resize-y rounded border border-divider-strong bg-surface-0 p-2 font-mono ba-text-sm text-foreground outline-none focus:border-primary/50"
          />
        </div>
      )}

      <div className="mt-2 flex items-center gap-2">
        <input
          value={h.nextStep}
          onChange={(e) => onChange({ ...h, nextStep: e.target.value })}
          placeholder="Next step…"
          className="w-full rounded border border-divider-strong bg-surface-0 px-2 py-1 font-mono ba-text-3xs text-foreground outline-none focus:border-primary/50"
        />
        <span className="inline-flex items-center gap-1 font-mono ba-text-3xs text-muted-foreground">
          <ArrowRight className="h-3 w-3" /> next
        </span>
      </div>
    </div>
  );
}

function EvidenceList({
  label,
  items,
  tone,
  inputValue,
  setInputValue,
  onAdd,
  onRemove,
}: {
  label: string;
  items: string[];
  tone: "success" | "destructive";
  inputValue: string;
  setInputValue: (v: string) => void;
  onAdd: () => void;
  onRemove: (idx: number) => void;
}) {
  const Icon = tone === "success" ? Check : X;
  return (
    <div className="rounded border border-divider-strong bg-surface-0/60 p-2">
      <div className={cn("mb-1 font-mono ba-text-3xs uppercase tracking-wider", tone === "success" ? "text-success" : "text-destructive")}>{label}</div>
      {items.length > 0 && (
        <ul className="mb-1 space-y-0.5">
          {items.map((it, i) => (
            <li key={i} className="flex items-center gap-1.5 font-mono ba-text-3xs text-foreground/90">
              <Icon className={cn("h-2.5 w-2.5 shrink-0", tone === "success" ? "text-success" : "text-destructive")} />
              <span className="min-w-0 flex-1 truncate">{it}</span>
              <button onClick={() => onRemove(i)} className="shrink-0 rounded p-0.5 text-muted-foreground hover:text-destructive" title="Remove">
                <X className="h-2.5 w-2.5" />
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="flex items-center gap-1">
        <input
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); onAdd(); } }}
          placeholder={`add ${label.toLowerCase()}…`}
          className="w-full rounded border border-divider-strong bg-surface-1 px-1.5 py-0.5 font-mono text-xs text-foreground outline-none focus:border-primary/50"
        />
        <button onClick={onAdd} className="shrink-0 rounded border border-border px-1 py-0.5 text-muted-foreground hover:text-foreground" title="Add evidence">
          <Plus className="h-3 w-3" />
        </button>
      </div>
    </div>
  );
}