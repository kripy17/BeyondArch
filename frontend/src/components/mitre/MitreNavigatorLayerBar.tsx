import { useState, useRef } from "react";
import { Download, Upload, Layers, Laptop, Cloud, Filter, RotateCcw, AlertCircle, CheckCircle2, Shield, X } from "lucide-react";
import { Chip } from "@/components/soc";
import { PRESET_LAYERS, importNavigatorLayerJson, type CoverageLevel } from "@/lib/detection/navigator-layer-engine";
import { notify } from "@/lib/notify";

export type PlatformFilter = "all" | "Windows" | "Linux" | "macOS" | "Cloud";

interface MitreNavigatorLayerBarProps {
  platform: PlatformFilter;
  onPlatformChange: (p: PlatformFilter) => void;
  onApplyPreset: (techniqueIds: string[], presetName: string) => void;
  onImportLayer: (importedCov: Record<string, CoverageLevel>, notes: Record<string, string>, name: string) => void;
  onExportLayer: () => void;
  onResetCoverage: () => void;
  activePreset: string | null;
  actorMatch?: { title: string; techniques: string[] } | null;
  onClearActor?: () => void;
}

export function MitreNavigatorLayerBar({
  platform,
  onPlatformChange,
  onApplyPreset,
  onImportLayer,
  onExportLayer,
  onResetCoverage,
  activePreset,
  actorMatch,
  onClearActor,
}: MitreNavigatorLayerBarProps) {
  const [showImportModal, setShowImportModal] = useState(false);
  const [importPasteText, setImportPasteText] = useState("");
  const [importError, setImportError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      processImportContent(content);
    };
    reader.readAsText(file);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const processImportContent = (jsonStr: string) => {
    setImportError(null);
    const res = importNavigatorLayerJson(jsonStr);
    if (res.success) {
      onImportLayer(res.coverageMap, res.notes, res.name);
      notify.success(`Imported layer: ${res.name}`, {
        description: `${res.stats.full} full, ${res.stats.partial} partial, ${res.stats.none} gaps loaded.`,
      });
      setShowImportModal(false);
      setImportPasteText("");
    } else {
      setImportError(res.error || "Failed to parse Navigator layer");
    }
  };

  return (
    <div className="mb-3 rounded border border-border bg-surface-1/80 p-2 text-mono ba-text-2xs backdrop-blur">
      <div className="flex flex-wrap items-center justify-between gap-2">
        {/* Platform filters */}
        <div className="flex flex-wrap items-center gap-1.5">
          <div className="flex items-center gap-1 text-muted-foreground mr-1">
            <Filter className="h-3 w-3" />
            <span>Platform:</span>
          </div>
          {(["all", "Windows", "Linux", "macOS", "Cloud"] as PlatformFilter[]).map((p) => {
            const isSel = platform === p;
            return (
              <button
                key={p}
                onClick={() => onPlatformChange(p)}
                className={`flex items-center gap-1 rounded border px-2 py-0.5 transition-all ${
                  isSel
                    ? "border-primary bg-primary/20 text-primary font-medium shadow-xs"
                    : "border-border text-muted-foreground hover:text-foreground"
                }`}
              >
                {p === "Cloud" ? <Cloud className="h-2.5 w-2.5" /> : <Laptop className="h-2.5 w-2.5" />}
                <span>{p}</span>
              </button>
            );
          })}
        </div>

        {/* Preset Layers & Navigator Actions */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Preset Selector */}
          <div className="flex items-center gap-1 max-w-full">
            <Layers className="h-3 w-3 shrink-0 text-muted-foreground" />
            <select
              value={activePreset || ""}
              onChange={(e) => {
                const p = PRESET_LAYERS.find((x) => x.id === e.target.value);
                if (p) onApplyPreset(p.techniqueIds, p.name);
              }}
              aria-label="Layer presets"
              className="h-7 max-w-[170px] sm:max-w-xs truncate rounded border border-border bg-surface-0 px-2 text-mono ba-text-3xs text-foreground outline-none focus:border-primary/50"
            >
              <option value="">-- Layer Presets --</option>
              {PRESET_LAYERS.map((preset) => (
                <option key={preset.id} value={preset.id}>
                  {preset.name} ({preset.techniqueIds.length} TTPs)
                </option>
              ))}
            </select>
          </div>

          {/* Import Navigator Layer */}
          <button
            onClick={() => setShowImportModal(true)}
            className="inline-flex items-center gap-1 rounded border border-border bg-surface-0 px-2 py-1 text-muted-foreground hover:text-foreground hover:border-primary/40 transition-colors"
          >
            <Upload className="h-3 w-3" /> Import Layer
          </button>

          {/* Export Official Navigator JSON */}
          <button
            onClick={onExportLayer}
            className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-1 text-primary hover:bg-primary/20 transition-colors"
          >
            <Download className="h-3 w-3" /> Export Navigator v4.5
          </button>

          {/* Reset button */}
          <button
            onClick={onResetCoverage}
            title="Clear all coverage annotations"
            className="inline-flex items-center gap-1 rounded border border-border px-1.5 py-1 text-muted-foreground hover:text-foreground transition-colors"
          >
            <RotateCcw className="h-3 w-3" /> Reset
          </button>
        </div>
      </div>

      {/* Adversary Profile Active Banner */}
      {actorMatch && (
        <div className="mt-2 flex items-center justify-between rounded border border-amber-500/40 bg-amber-500/10 px-2.5 py-1.5">
          <div className="flex items-center gap-2">
            <Shield className="h-3.5 w-3.5 text-amber-400" />
            <span className="text-foreground">
              Adversary Overlay: <strong className="text-amber-300">{actorMatch.title}</strong>
            </span>
            <Chip tone="warning">{actorMatch.techniques.length} Cataloged TTPs</Chip>
          </div>
          {onClearActor && (
            <button
              onClick={onClearActor}
              className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground"
            >
              <X className="h-3 w-3" /> Clear overlay
            </button>
          )}
        </div>
      )}

      {/* Import Layer Modal */}
      {showImportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-xs">
          <div className="w-full max-w-lg rounded-lg border border-border bg-surface-1 p-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-2">
              <div className="flex items-center gap-2">
                <Upload className="h-4 w-4 text-primary" />
                <span className="text-sm font-semibold text-foreground">Import MITRE ATT&CK® Navigator Layer</span>
              </div>
              <button
                onClick={() => {
                  setShowImportModal(false);
                  setImportError(null);
                }}
                className="text-muted-foreground hover:text-foreground"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-3 space-y-3">
              <p className="ba-text-2xs text-muted-foreground">
                Upload or paste a standard Navigator layer JSON file (v4.0 - v5.0).
                Technique scores will update your local SOC coverage matrix and preserve comments.
              </p>

              <div>
                <input
                  type="file"
                  ref={fileInputRef}
                  accept=".json"
                  onChange={handleFileUpload}
                  className="block w-full text-xs text-muted-foreground file:mr-2 file:rounded file:border file:border-border file:bg-surface-0 file:px-2.5 file:py-1 file:text-xs file:text-foreground file:hover:bg-surface-2"
                />
              </div>

              <div className="relative">
                <textarea
                  rows={6}
                  value={importPasteText}
                  onChange={(e) => setImportPasteText(e.target.value)}
                  placeholder={'Or paste layer JSON directly here:\n{\n  "name": "Layer",\n  "domain": "enterprise-attack",\n  "techniques": [...]\n}'}
                  className="w-full rounded border border-border bg-surface-0 p-2 text-mono ba-text-3xs text-foreground placeholder:text-muted-foreground outline-none focus:border-primary/50"
                />
              </div>

              {importError && (
                <div className="flex items-center gap-2 rounded border border-destructive/40 bg-destructive/10 p-2 text-destructive">
                  <AlertCircle className="h-4 w-4 shrink-0" />
                  <span className="ba-text-2xs">{importError}</span>
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-border">
                <button
                  onClick={() => {
                    setShowImportModal(false);
                    setImportError(null);
                  }}
                  className="rounded border border-border px-3 py-1 text-muted-foreground hover:text-foreground"
                >
                  Cancel
                </button>
                <button
                  onClick={() => processImportContent(importPasteText)}
                  disabled={!importPasteText.trim()}
                  className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/20 px-3 py-1 text-primary hover:bg-primary/30 disabled:opacity-50"
                >
                  <CheckCircle2 className="h-3.5 w-3.5" /> Parse & Load Layer
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
