import { useState, useEffect } from "react";
import { useNavigate } from "@tanstack/react-router";
import { X, ShieldAlert, FolderPlus, ArrowRight, Tag, Layers, CheckCircle2, Siren, Cloud, Cpu, UserX } from "lucide-react";
import type { Case, Entry } from "@/data/case";
import { loadCases, saveCases, setActiveCaseId, newId, newCaseTitle } from "@/data/case";
import { IR_TEMPLATES, type IrIncidentTemplate, instantiateCaseFromTemplate } from "@/lib/case-desk";
import type { Severity } from "@/lib/severity";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface NewCaseModalProps {
  open: boolean;
  onClose: () => void;
  onCaseCreated?: (created: Case) => void;
}

const TEMPLATE_ICONS: Record<string, typeof ShieldAlert> = {
  "spear-phishing": ShieldAlert,
  ransomware: Siren,
  "cloud-iam": Cloud,
  "supply-chain": Cpu,
  "insider-threat": UserX,
};

export function NewCaseModal({ open, onClose, onCaseCreated }: NewCaseModalProps) {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"template" | "custom">("template");
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>(IR_TEMPLATES[0].id);
  const [customTitle, setCustomTitle] = useState("");
  const [customSeverity, setCustomSeverity] = useState<Severity>("high");
  const [customTags, setCustomTags] = useState("incident, triage");
  const [customSummary, setCustomSummary] = useState("");
  const [pivotImmediately, setPivotImmediately] = useState(true);

  useEffect(() => {
    if (open) {
      setCustomTitle("");
      setCustomSummary("");
    }
  }, [open]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && open) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const selectedTemplate = IR_TEMPLATES.find((t) => t.id === selectedTemplateId) || IR_TEMPLATES[0];

  const handleCreate = () => {
    let newCase: Case;

    if (mode === "template") {
      newCase = instantiateCaseFromTemplate(selectedTemplate, customTitle);
    } else {
      const title = customTitle.trim() || `Incident Investigation - ${newCaseTitle()}`;
      const parsedTags = customTags
        .split(",")
        .map((t) => t.trim().toLowerCase())
        .filter(Boolean);
      if (!parsedTags.includes(customSeverity)) {
        parsedTags.push(customSeverity);
      }
      if (!parsedTags.includes("incident")) {
        parsedTags.push("incident");
      }

      const entries: Entry[] = [];
      const now = new Date().toISOString();

      if (customSummary.trim()) {
        entries.push({
          id: newId("e"),
          ts: now,
          kind: "note",
          body: `[INITIAL INTAKE] Severity: ${customSeverity.toUpperCase()}\n\nSummary:\n${customSummary.trim()}`,
        });
      }

      newCase = {
        id: newId("case"),
        title,
        tags: parsedTags,
        createdAt: now,
        state: "active",
        entries,
      };
    }

    const existing = loadCases();
    saveCases([newCase, ...existing]);
    setActiveCaseId(newCase.id);

    toast.success(`Created incident: ${newCase.title}`);
    onCaseCreated?.(newCase);
    onClose();

    if (pivotImmediately) {
      navigate({ to: "/case" });
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div
        className="flex flex-col w-full max-w-3xl max-h-[90vh] rounded-xl border border-border bg-card shadow-2xl overflow-hidden"
        role="dialog"
        aria-modal="true"
        aria-labelledby="new-case-modal-title"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-border px-6 py-4 bg-muted/30">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-primary/40 bg-primary/10 text-primary">
              <FolderPlus className="h-5 w-5" />
            </div>
            <div>
              <h2 id="new-case-modal-title" className="text-lg font-semibold tracking-tight text-foreground">
                Initiate Incident Case
              </h2>
              <p className="text-xs text-muted-foreground">
                Deploy an enterprise IR response template or register a custom operational dossier.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
            title="Close dialog (Esc)"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Mode Selector Tabs */}
          <div className="flex rounded-lg border border-border bg-muted/40 p-1 text-xs">
            <button
              onClick={() => setMode("template")}
              className={cn(
                "flex-1 flex items-center justify-center gap-2 rounded-md py-2 font-medium transition-all",
                mode === "template"
                  ? "bg-card text-foreground shadow-sm border border-border"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              <Layers className="h-3.5 w-3.5 text-primary" />
              Enterprise IR Templates (Recommended)
            </button>
            <button
              onClick={() => setMode("custom")}
              className={cn(
                "flex-1 flex items-center justify-center gap-2 rounded-md py-2 font-medium transition-all",
                mode === "custom"
                  ? "bg-card text-foreground shadow-sm border border-border"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              <Layers className="h-3.5 w-3.5 text-primary" />
              Custom / Manual Intake
            </button>
          </div>

          {mode === "template" ? (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                  Select Incident Template
                </label>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                  {IR_TEMPLATES.map((tmpl) => {
                    const Icon = TEMPLATE_ICONS[tmpl.id] || ShieldAlert;
                    const isSelected = selectedTemplateId === tmpl.id;
                    return (
                      <button
                        key={tmpl.id}
                        type="button"
                        onClick={() => setSelectedTemplateId(tmpl.id)}
                        className={cn(
                          "flex flex-col text-left p-3.5 rounded-lg border transition-all relative",
                          isSelected
                            ? "border-primary bg-primary/5 ring-1 ring-primary/40"
                            : "border-border/70 hover:border-border hover:bg-muted/20"
                        )}
                      >
                        <div className="flex items-center justify-between w-full mb-1.5">
                          <div className="flex items-center gap-2">
                            <Icon className={cn("h-4 w-4", isSelected ? "text-primary" : "text-muted-foreground")} />
                            <span className="text-xs font-semibold text-foreground">{tmpl.category}</span>
                          </div>
                          <span
                            className={cn(
                              "text-[10px] font-mono uppercase px-1.5 py-0.5 rounded font-semibold",
                              tmpl.severity === "critical"
                                ? "bg-destructive/20 text-destructive border border-destructive/30"
                                : tmpl.severity === "high"
                                  ? "bg-warning/20 text-warning border border-warning/30"
                                  : "bg-primary/20 text-primary border border-primary/30"
                            )}
                          >
                            {tmpl.severity}
                          </span>
                        </div>
                        <div className="text-sm font-medium text-foreground mb-1 line-clamp-1">{tmpl.name}</div>
                        <p className="text-xs text-muted-foreground line-clamp-2">{tmpl.summary}</p>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Template Preview Card */}
              <div className="rounded-lg border border-border/70 bg-muted/20 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="text-xs font-semibold uppercase tracking-wider text-primary flex items-center gap-1.5">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Pre-Configured Playbook Provisions
                  </div>
                  <div className="text-[11px] text-muted-foreground font-mono">
                    {selectedTemplate.initialChecklist.length} IR tasks · {selectedTemplate.hypotheses.length} hypotheses
                  </div>
                </div>

                <div className="space-y-1.5 text-xs text-muted-foreground">
                  <div className="font-medium text-foreground">Standard Checklist Tasks:</div>
                  <ul className="list-disc pl-4 space-y-0.5">
                    {selectedTemplate.initialChecklist.slice(0, 3).map((item, idx) => (
                      <li key={idx} className="line-clamp-1">
                        {item}
                      </li>
                    ))}
                    {selectedTemplate.initialChecklist.length > 3 && (
                      <li className="text-muted-foreground/70 italic">
                        +{selectedTemplate.initialChecklist.length - 3} more automated checklist tasks
                      </li>
                    )}
                  </ul>
                </div>

                <div className="flex flex-wrap gap-1.5 pt-1">
                  {selectedTemplate.recommendedTags.map((tag) => (
                    <span
                      key={tag}
                      className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-muted border border-border text-foreground/80"
                    >
                      <Tag className="h-2.5 w-2.5 text-muted-foreground" />
                      {tag}
                    </span>
                  ))}
                </div>
              </div>

              {/* Custom Title Override */}
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                  Case Title Override (Optional)
                </label>
                <input
                  type="text"
                  value={customTitle}
                  onChange={(e) => setCustomTitle(e.target.value)}
                  placeholder={`${selectedTemplate.name} - ${newCaseTitle()}`}
                  className="w-full rounded-lg border border-border bg-background px-3.5 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                  Case Title <span className="text-destructive">*</span>
                </label>
                <input
                  type="text"
                  value={customTitle}
                  onChange={(e) => setCustomTitle(e.target.value)}
                  placeholder={`Incident Investigation - ${newCaseTitle()}`}
                  className="w-full rounded-lg border border-border bg-background px-3.5 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                    Initial Severity
                  </label>
                  <select
                    value={customSeverity}
                    onChange={(e) => setCustomSeverity(e.target.value as Severity)}
                    className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                  >
                    <option value="critical">Critical (P1)</option>
                    <option value="high">High (P2)</option>
                    <option value="medium">Medium (P3)</option>
                    <option value="low">Low (P4)</option>
                    <option value="info">Info / Triage</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                    Tags (comma separated)
                  </label>
                  <input
                    type="text"
                    value={customTags}
                    onChange={(e) => setCustomTags(e.target.value)}
                    placeholder="incident, endpoint, triage"
                    className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                  Initial Triage Note / Executive Summary
                </label>
                <textarea
                  rows={4}
                  value={customSummary}
                  onChange={(e) => setCustomSummary(e.target.value)}
                  placeholder="Record initial indicators, alert triggers, impacted assets, or user report details..."
                  className="w-full rounded-lg border border-border bg-background px-3.5 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono text-xs"
                />
              </div>
            </div>
          )}

          {/* Pivot immediately toggle */}
          <div className="flex items-center gap-2 pt-2 border-t border-border/50">
            <input
              type="checkbox"
              id="pivotImmediately"
              checked={pivotImmediately}
              onChange={(e) => setPivotImmediately(e.target.checked)}
              className="h-4 w-4 rounded border-border text-primary focus:ring-primary"
            />
            <label htmlFor="pivotImmediately" className="text-xs text-foreground font-medium cursor-pointer">
              Automatically switch active case and navigate to Case Workbench (`/case`)
            </label>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between border-t border-border px-6 py-4 bg-muted/20">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-border px-4 py-2 text-xs font-medium text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={handleCreate}
            className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground shadow hover:bg-primary/90 transition-colors"
          >
            <span>Create Incident Dossier</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}
