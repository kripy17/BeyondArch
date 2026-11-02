import { Panel } from "@/components/soc";

export function MitrePanel({ techniques }: { techniques: { id?: string; technique?: string; name: string }[] }) {
  if (techniques.length === 0) return null;
  return (
    <Panel title="MITRE ATT&CK Mapping">
      <div className="space-y-2">
        {techniques.map((m, i) => (
          <div key={i} className="flex items-center gap-3 rounded border border-border/60 bg-surface-0 px-3 py-2">
            <code className="rounded bg-surface-2 px-1.5 py-0.5 text-mono ba-text-2xs font-bold text-primary">{m.id ?? m.technique}</code>
            <span className="text-mono ba-text-sm text-fg-dim">{m.name}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}
