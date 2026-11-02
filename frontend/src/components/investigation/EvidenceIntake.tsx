import { useState } from "react";
import { toast } from "sonner";
import { Plus, Link2 } from "lucide-react";
import type { Case } from "@/data/case";
import type { EvidenceItem } from "@/types/analysis";
import { getUnifiedFindings } from "@/components/investigation";
import { addEdge, getEdgesFor } from "@/lib/provenance";
import { pushTimelineEvent } from "@/lib/timeline";
import { appendEvidence, createEvidenceItem, evidenceLinks, findDuplicateEvidence, EVIDENCE_TYPES } from "@/lib/evidence";

const inputCls =
  "w-full rounded border border-subtle bg-surface-0 px-2 py-1.5 font-mono ba-text-sm text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50";
const labelCls = "mb-1 block font-mono ba-text-3xs uppercase tracking-wide text-muted-foreground";

export function EvidenceIntake({ caseData, updateActive }: { caseData: Case; updateActive: (fn: (c: Case) => Case) => void }) {
  const [title, setTitle] = useState("");
  const [type, setType] = useState<string>("log");
  const [source, setSource] = useState("");
  const [detail, setDetail] = useState("");
  const [artifactId, setArtifactId] = useState("");
  const [findingId, setFindingId] = useState("");

  const findings = getUnifiedFindings(caseData);
  const artifacts = caseData.artifacts ?? [];
  const items = caseData.evidenceItems ?? [];

  function submit() {
    if (!title.trim()) {
      toast.error("Evidence needs a title");
      return;
    }
    const item = createEvidenceItem({ type, title, detail, source });
    if (findDuplicateEvidence(items, item)) {
      toast.error("Identical evidence already filed (same type/title/source)");
      return;
    }
    for (const link of evidenceLinks(item, { artifactId: artifactId || undefined, findingId: findingId || undefined })) {
      addEdge({ relation: link.relation, from: link.from, to: link.to, source: "/case evidence-intake", confidence: 1 });
    }
    const filedTitle = item.title;
    updateActive((c) => appendEvidence(c, item));
    pushTimelineEvent({
      source: "case",
      verb: "filed-evidence",
      detail: `Filed evidence "${filedTitle}"`,
      result:
        [artifactId && "artifact linked", findingId && "finding linked"].filter(Boolean).join(" · ") || "no links",
    });
    setTitle("");
    setDetail("");
    setSource("");
    setArtifactId("");
    setFindingId("");
    toast.success("Evidence filed");
  }

  return (
    <div className="space-y-3">
      <div className="rounded-md border border-subtle bg-surface-1 p-3">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_140px]">
          <div>
            <label className={labelCls} htmlFor="ev-title">title</label>
            <input id="ev-title" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="What was collected…" className={inputCls} />
          </div>
          <div>
            <label className={labelCls} htmlFor="ev-type">type</label>
            <select id="ev-type" value={type} onChange={(e) => setType(e.target.value)} aria-label="evidence type" className={inputCls}>
              {EVIDENCE_TYPES.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label className={labelCls} htmlFor="ev-source">source</label>
            <input id="ev-source" value={source} onChange={(e) => setSource(e.target.value)} placeholder="manual" className={inputCls} />
          </div>
          <div>
            <label className={labelCls} htmlFor="ev-artifact">produced by artifact (optional)</label>
            <select id="ev-artifact" value={artifactId} onChange={(e) => setArtifactId(e.target.value)} aria-label="source artifact for evidence" className={inputCls}>
              <option value="">— none —</option>
              {artifacts.map((a) => (
                <option key={a.id} value={a.id}>{a.title}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="mt-3">
          <label className={labelCls} htmlFor="ev-detail">detail</label>
          <textarea id="ev-detail" value={detail} onChange={(e) => setDetail(e.target.value)} rows={2} placeholder="Chain-of-custody notes, collection method…" className={inputCls} />
        </div>
        <div className="mt-3">
          <label className={labelCls} htmlFor="ev-finding">supports finding (optional)</label>
          <select id="ev-finding" value={findingId} onChange={(e) => setFindingId(e.target.value)} aria-label="finding supported by evidence" className={inputCls}>
            <option value="">— none —</option>
            {findings.map((f) => (
              <option key={f.id} value={f.id}>{f.title}</option>
            ))}
          </select>
        </div>
        <button
          onClick={submit}
          className="mt-3 inline-flex items-center gap-1.5 rounded-md border border-primary/40 bg-primary/15 px-2.5 py-1 font-mono ba-text-xs text-primary hover:bg-primary/25"
        >
          <Plus className="h-3 w-3" /> file evidence
        </button>
      </div>

      {items.length > 0 && <LinkExisting items={items} findings={findings} updateActive={updateActive} />}
    </div>
  );
}

function LinkExisting({
  items,
  findings,
  updateActive,
}: {
  items: EvidenceItem[];
  findings: ReturnType<typeof getUnifiedFindings>;
  updateActive: (fn: (c: Case) => Case) => void;
}) {
  const [evidenceId, setEvidenceId] = useState("");
  const [findingId, setFindingId] = useState("");

  function link() {
    if (!evidenceId || !findingId) return;
    addEdge({ relation: "supports", from: { kind: "evidence", id: evidenceId }, to: { kind: "finding", id: findingId }, source: "/case evidence-intake", confidence: 1 });
    const ev = items.find((e) => e.id === evidenceId);
    const f = findings.find((x) => x.id === findingId);
    pushTimelineEvent({ source: "case", verb: "linked-evidence", detail: `Linked evidence "${ev?.title ?? evidenceId}" → finding "${f?.title ?? findingId}"`, result: "supports" });
    setEvidenceId("");
    setFindingId("");
    // force re-render so link counts refresh
    updateActive((c) => ({ ...c }));
    toast.success("Evidence linked to finding");
  }

  return (
    <div className="rounded-md border border-subtle bg-surface-1 p-3">
      <div className="mb-2 flex items-center gap-1.5 font-mono ba-text-2xs uppercase tracking-wide text-muted-foreground">
        <Link2 className="h-3 w-3" /> link existing evidence
      </div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_1fr_auto]">
        <select value={evidenceId} onChange={(e) => setEvidenceId(e.target.value)} aria-label="evidence to link" className={inputCls}>
          <option value="">— evidence —</option>
          {items.map((e) => (
            <option key={e.id} value={e.id}>
              {e.title} ({linkCount(e.id!)} links)
            </option>
          ))}
        </select>
        <select value={findingId} onChange={(e) => setFindingId(e.target.value)} aria-label="target finding for evidence link" className={inputCls}>
          <option value="">— finding —</option>
          {findings.map((f) => (
            <option key={f.id} value={f.id}>{f.title}</option>
          ))}
        </select>
        <button
          onClick={link}
          disabled={!evidenceId || !findingId}
          className="inline-flex items-center gap-1.5 self-start rounded-md border border-subtle px-2.5 py-1 font-mono ba-text-xs text-foreground hover:border-primary/40 hover:text-primary disabled:cursor-not-allowed disabled:opacity-40"
        >
          supports
        </button>
      </div>
    </div>
  );
}

export function linkCount(evidenceId: string): number {
  const { out, in: inEdges } = getEdgesFor("evidence", evidenceId);
  return out.length + inEdges.length;
}
