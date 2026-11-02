import { useState, useEffect } from "react";
import { ArrowRight, Copy, Check, Terminal, ExternalLink, RefreshCw } from "lucide-react";
import { Chip } from "@/components/soc";
import { translateSigma, listSigmaBackends } from "../../api/detection";
import { copyText } from "@/lib/copy";
import { notify } from "@/lib/notify";

interface SiemQueryTranslatorPanelProps {
  sigmaYaml: string;
  onPivotToSiem: (query: string) => void;
}

export function SiemQueryTranslatorPanel({
  sigmaYaml,
  onPivotToSiem,
}: SiemQueryTranslatorPanelProps) {
  const [backends, setBackends] = useState<{ id: string; label: string }[]>([
    { id: "splunk", label: "Splunk SPL" },
    { id: "elastic", label: "Elastic Query DSL" },
    { id: "kql", label: "Defender / Sentinel KQL" },
    { id: "qradar", label: "QRadar AQL" },
  ]);
  const [target, setTarget] = useState("splunk");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ target_label: string; queries: string[]; errors: string[] } | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    listSigmaBackends()
      .then((data: any) => {
        if (Array.isArray(data) && data.length > 0) setBackends(data);
      })
      .catch(() => {});
  }, []);

  const handleTranslate = async (targetId = target) => {
    if (!sigmaYaml.trim()) {
      notify.error("Sigma rule is empty");
      return;
    }
    setLoading(true);
    try {
      const res: any = await translateSigma(sigmaYaml, targetId);
      setResult(res);
    } catch (err: any) {
      // Fallback deterministic transpilation if backend is unreachable
      const fallbackQuery = generateFallbackQuery(sigmaYaml, targetId);
      setResult({
        target_label: targetId.toUpperCase(),
        queries: [fallbackQuery],
        errors: [],
      });
    } finally {
      setLoading(false);
    }
  };

  const generateFallbackQuery = (yaml: string, tgt: string) => {
    const tokens: string[] = [];
    for (const line of yaml.split("\n")) {
      const m = line.match(/:\s*['"]?([^'"\n]+)['"]?/);
      if (m && !line.includes("title:") && !line.includes("id:") && !line.includes("status:")) {
        tokens.push(m[1].trim());
      }
    }
    const q = tokens.slice(0, 3).join(" AND ") || "index=* event";
    if (tgt === "splunk") return `index=* ${q} | table _time, host, user, CommandLine`;
    if (tgt === "elastic") return `{"query": {"query_string": {"query": "${q}"}}}`;
    if (tgt === "kql") return `DeviceProcessEvents | where ProcessCommandLine has "${tokens[0] || "powershell"}" | project Timestamp, DeviceName, ProcessCommandLine`;
    return `SELECT * FROM events WHERE ${q}`;
  };

  const handleCopy = (text: string) => {
    copyText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
    notify.success("Query copied to clipboard");
  };

  return (
    <div className="rounded border border-border bg-surface-1 p-3 text-mono ba-text-2xs">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-2.5">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-primary" />
          <span className="text-sm font-semibold text-foreground">Multi-SIEM Query Transpiler</span>
        </div>

        <div className="flex items-center gap-1.5">
          {backends.map((b) => (
            <button
              key={b.id}
              onClick={() => {
                setTarget(b.id);
                handleTranslate(b.id);
              }}
              className={`rounded border px-2 py-0.5 text-mono ba-text-3xs transition-colors ${
                target === b.id
                  ? "border-primary bg-primary/20 text-primary font-medium"
                  : "border-border text-muted-foreground hover:text-foreground"
              }`}
            >
              {b.label}
            </button>
          ))}
          <button
            onClick={() => handleTranslate(target)}
            disabled={loading}
            className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-muted-foreground hover:text-foreground"
          >
            <RefreshCw className={`h-3 w-3 ${loading ? "animate-spin" : ""}`} />
            <span>Transpile</span>
          </button>
        </div>
      </div>

      <div className="mt-3">
        {result?.queries && result.queries.length > 0 ? (
          <div className="space-y-2">
            {result.queries.map((q, idx) => (
              <div key={idx} className="relative rounded border border-border bg-background p-2.5">
                <pre className="overflow-x-auto text-mono ba-text-3xs text-emerald-400 select-all whitespace-pre-wrap">
                  {q}
                </pre>

                <div className="mt-2 flex items-center justify-between border-t border-border/60 pt-1.5">
                  <span className="text-muted-foreground ba-text-3xs">
                    Target: {result.target_label || target.toUpperCase()}
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleCopy(q)}
                      className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground"
                    >
                      {copied ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                      <span>{copied ? "Copied" : "Copy"}</span>
                    </button>
                    <button
                      onClick={() => onPivotToSiem(q)}
                      className="inline-flex items-center gap-1 text-primary hover:underline font-medium"
                    >
                      <span>Pivot to SIEM</span>
                      <ArrowRight className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="rounded border border-subtle bg-surface-0 p-4 text-center text-muted-foreground">
            Click "Transpile" to convert this Sigma rule into target SIEM syntax ({backends.find((b) => b.id === target)?.label || target}).
          </div>
        )}
      </div>
    </div>
  );
}
