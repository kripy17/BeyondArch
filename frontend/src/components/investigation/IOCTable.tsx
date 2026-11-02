import type { IOC } from "@/types/security";
import { Panel, Chip } from "@/components/soc";
import { DataTable, type Column } from "@/components/output";
import { Database } from "lucide-react";
import { useLocker } from "@/lib/locker";
import { toast } from "sonner";

export function IOCTable({ iocs, source }: { iocs: IOC[]; source?: string }) {
  const locker = useLocker();
  if (iocs.length === 0) return null;
  const columns: Column<IOC>[] = [
    {
      key: "value",
      label: "Value",
      sortable: true,
      sortValue: (ioc) => ioc.value,
      render: (ioc) => <span className="font-medium text-foreground">{ioc.value}</span>,
    },
    {
      key: "context",
      label: "Context",
      render: (ioc) => <span className="text-fg-dim">{ioc.context || "—"}</span>,
    },
    {
      key: "type",
      label: "Type",
      render: (ioc) => <Chip tone="destructive">{ioc.type}</Chip>,
    },
    {
      key: "action",
      label: "Action",
      align: "right",
      render: (ioc) => (
        <button
          onClick={() => { locker.add({ value: ioc.value, type: ioc.type, source: source ?? "/unknown", note: "" }); toast("Added to locker"); }}
          className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-primary"
        >
          <Database className="h-3 w-3" /> locker
        </button>
      ),
    },
  ];
  return (
    <Panel title="Extracted IOCs">
      <DataTable columns={columns} rows={iocs} />
    </Panel>
  );
}
