import { useState } from "react";
import { Bot, CornerDownLeft, ShieldAlert } from "lucide-react";
import type { Case } from "@/data/case";
import { getUnifiedFindings, getUnifiedIOCs } from "@/components/investigation/legacy-adapter";
import { explainObject } from "@/lib/explain";
import { getAllEdges } from "@/lib/provenance";

const INTENTS: { id: string; label: string; chip: string }[] = [
  { id: "summarize", label: "Summarize this case", chip: "summarize" },
  { id: "missing", label: "Show missing evidence", chip: "missing evidence" },
  { id: "alerts", label: "Show related alerts", chip: "related alerts" },
  { id: "unresolved", label: "List unresolved findings", chip: "unresolved findings" },
  { id: "explain", label: "Explain an IOC", chip: "explain ioc" },
];

type Turn = { id: number; prompt: string; answer: string[]; kind: "answer" | "fallback" | "unknown" };

const SEV_ORDER = ["critical", "high", "medium", "low", "informational"];

function severityRank(s: string): number {
  const i = SEV_ORDER.indexOf(s);
  return i === -1 ? SEV_ORDER.length : i;
}

export function InvestigationAssistant({ case: c }: { case: Case }) {
  const [turns, setTurns] = useState<Turn[]>([]);
  const [draft, setDraft] = useState("");

  const answer = (prompt: string): Turn => {
    const edges = getAllEdges();
    const q = prompt.toLowerCase().trim();
    const findings = getUnifiedFindings(c);
    const iocs = getUnifiedIOCs(c);
    const artifacts = c.artifacts ?? [];
    const evidenceItems = c.evidenceItems ?? [];
    const events = c.events ?? [];

    if (q.includes("summarize") || q.includes("summary") || q.includes("overview")) {
      const top = [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity)).slice(0, 3);
      const lines = [
        `Case "${c.title}" is ${c.state} with ${artifacts.length} artifact(s), ${findings.length} finding(s), ${iocs.length} IOC(s), ${evidenceItems.length} evidence item(s).`,
      ];
      if (top.length) lines.push("Top findings: " + top.map((f) => `${f.severity} · ${f.title}`).join(" | "));
      if (iocs.length) lines.push("IOCs: " + iocs.map((i) => i.value).join(", "));
      if (events.length) lines.push("Latest activity: " + events.slice(-3).map((e) => e.title).join(" · "));
      return { id: Date.now(), prompt, answer: lines, kind: "answer" };
    }

    if (q.includes("missing") || q.includes("gap")) {
      const lines: string[] = [];
      const covered = new Set(evidenceItems.map((e) => e.source));
      const unattached = artifacts.filter((a) => a.id && !covered.has(a.id));
      if (unattached.length) lines.push(`Artifacts without attributed evidence (${unattached.length}): ${unattached.map((a) => a.title).join(", ")}.`);
      else if (artifacts.length) lines.push("Every artifact has attributed evidence.");
      else lines.push("No artifacts on record — upload one to analyse.");
      if (findings.length === 0) lines.push("No findings yet — analyse an artifact to close the evidence gap.");
      if (lines.length === 0) lines.push("No evidence gaps detected.");
      return { id: Date.now(), prompt, answer: lines, kind: "answer" };
    }

    if (q.includes("alert") || q.includes("fires")) {
      const fired = edges.filter((e) => e.relation === "fires" && e.to.kind === "finding");
      const lines = fired.length
        ? [`${fired.length} alert edge(s) firing into findings: ` + fired.map((e) => `${e.from.id} → ${e.to.id} (${e.source})`).join("; ") + "."]
        : ["0 alerts on record. Alert ingestion is a future capability — counts below are live edge reads, not imported alerts."];
      return { id: Date.now(), prompt, answer: lines, kind: "answer" };
    }

    if (q.includes("unresolved") || q.includes("open")) {
      const open = [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
      const lines = open.length
        ? ["Unresolved findings: " + open.map((f) => `${f.severity} · ${f.title}${f.technique ? ` (${f.technique})` : ""}`).join(" | ") + "."]
        : ["No findings on record — nothing unresolved."];
      return { id: Date.now(), prompt, answer: lines, kind: "answer" };
    }

    if (q.includes("explain") || q.includes("why") || q.startsWith("explain ")) {
      const want = q.replace(/^(explain|why|what)\s+/, "");
      const iocHit = iocs.find((i) => i.id && want.includes(i.value.toLowerCase()));
      const findingHit = iocHit ? undefined : findings.find((f) => want.includes(f.title.toLowerCase()));
      const ref = iocHit
        ? { kind: "ioc" as const, id: iocHit.id! }
        : findingHit
          ? { kind: "finding" as const, id: findingHit.id }
          : null;
      if (!ref) return { id: Date.now(), prompt, answer: ["I could not match an IOC or finding by that name. Try an IOC value or finding title from this case."], kind: "fallback" };
      const ex = explainObject(c, ref, edges);
      return {
        id: Date.now(),
        prompt,
        answer: [`Why: ${ex.why}`, `Source: ${ex.source.length ? ex.source.join(", ") : "—"}`, `Confidence: ${ex.confidence != null ? `${Math.round(ex.confidence * 100)}%` : "no confidence"}`],
        kind: "answer",
      };
    }

    return {
      id: Date.now(),
      prompt,
      answer: ["I can only answer from local investigation data. Try one of: " + INTENTS.map((i) => `"${i.chip}"`).join(", ") + "."],
      kind: "unknown",
    };
  };

  const ask = (prompt: string) => {
    const t = answer(prompt);
    setTurns((prev) => [...prev, t]);
    setDraft("");
  };

  return (
    <div className="rounded-lg border border-border bg-surface-1 p-3">
      <div className="mb-2 flex items-center gap-1.5 text-mono ba-text-2xs text-muted-foreground">
        <Bot className="h-3 w-3 text-warning" />
        Investigation assistant
        <span className="ml-auto text-muted-foreground/60">local-only answers</span>
      </div>
      <div className="mb-2 flex flex-wrap gap-1.5">
        {INTENTS.map((i) => (
          <button
            key={i.id}
            onClick={() => ask(i.chip)}
            className="rounded border border-border bg-card/60 px-1.5 py-0.5 text-mono ba-text-3xs text-foreground transition-colors duration-150 hover:border-primary/40 hover:text-primary"
          >
            {i.chip}
          </button>
        ))}
      </div>
      <div className="space-y-1.5">
        {turns.map((t) => (
          <div key={t.id} className="rounded-md border border-border/70 bg-card/60 p-2">
            <div className="text-mono ba-text-3xs text-muted-foreground">› {t.prompt}</div>
            <div className="mt-1 space-y-0.5 text-mono ba-text-3xs text-foreground">
              {t.answer.map((a, i) => (
                <div key={i}>{a}</div>
              ))}
            </div>
          </div>
        ))}
        {turns.length === 0 && (
          <p className="text-mono ba-text-3xs text-muted-foreground/70">Ask a question — the assistant answers from this case's data only, no external calls.</p>
        )}
      </div>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (draft.trim()) ask(draft);
        }}
        className="mt-2 flex gap-1.5"
      >
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          aria-label="Ask about this case"
          placeholder="Ask about this case…"
          className="min-w-0 flex-1 rounded border border-border bg-background px-2 py-1 font-mono ba-text-3xs text-foreground outline-none focus:border-primary/50"
        />
        <button
          type="submit"
          className="inline-flex shrink-0 items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-1 text-mono ba-text-3xs text-primary transition-colors duration-150 hover:bg-primary/20"
        >
          ask <CornerDownLeft className="h-2.5 w-2.5" />
        </button>
      </form>
      <div className="mt-2 flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground/60">
        <ShieldAlert className="h-2.5 w-2.5" />
        deterministic answers derived from local provenance, findings, IOCs, and events
      </div>
    </div>
  );
}
