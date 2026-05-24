"use client";

import { type ColumnDef } from "@tanstack/react-table";
import { Chip } from "@/components/severity";
import { Metric } from "@/components/metric";
import { DataTable, SortHeader } from "@/components/data-table";
import { useData } from "@/lib/use-data";
import { ago } from "@/lib/format";
import type { ResponseAction } from "@/lib/types";
import { Crosshair, Bot, CheckCircle2, XCircle } from "lucide-react";

const LABEL: Record<string, string> = {
  kill_process: "Kill Process", isolate: "Isolate Endpoint", unisolate: "Lift Isolation",
  disable_account: "Disable Account", block_upload: "Block Upload", block_usb: "Block USB",
};

function statusColor(s: string) {
  return s === "completed" ? "var(--signal)" : s === "failed" ? "var(--sev-critical)" : s === "pending" ? "var(--sev-medium)" : "var(--muted-foreground)";
}

const columns: ColumnDef<ResponseAction>[] = [
  { accessorKey: "ts", header: ({ column }) => <SortHeader column={column} title="Time" />, cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{ago(row.original.ts)}</span> },
  { accessorKey: "type", header: ({ column }) => <SortHeader column={column} title="Action" />, cell: ({ row }) => <span className="font-mono">{LABEL[row.original.type] || row.original.type}</span> },
  { id: "target", header: "Target", cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{Object.entries(row.original.target || {}).map(([k, v]) => `${k}=${v}`).join(" ") || "—"}</span> },
  { accessorKey: "hostname", header: ({ column }) => <SortHeader column={column} title="Host" /> },
  { id: "source", header: "Source", cell: ({ row }) => row.original.automated ? <Chip color="var(--signal)">auto</Chip> : <Chip>manual</Chip> },
  { accessorKey: "issued_by", header: "By", cell: ({ row }) => <span className="text-muted-foreground">{row.original.issued_by}</span> },
  { accessorKey: "status", header: ({ column }) => <SortHeader column={column} title="Status" />, cell: ({ row }) => <Chip color={statusColor(row.original.status)}>{row.original.status}</Chip> },
  { accessorKey: "result", header: "Result", cell: ({ row }) => <span className="block max-w-[20rem] truncate text-xs text-muted-foreground" title={row.original.result}>{row.original.result}</span> },
];

export default function ResponsesPage() {
  const { data: responses } = useData<ResponseAction[]>("responses", 3000, "response");
  const r = responses || [];
  const auto = r.filter((x) => x.automated).length;
  const done = r.filter((x) => x.status === "completed").length;
  const failed = r.filter((x) => x.status === "failed").length;

  return (
    <div className="space-y-5">
      <div className="reveal grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Total Responses" value={r.length} icon={Crosshair} />
        <Metric label="Automated" value={auto} icon={Bot} accent="var(--chart-2)" />
        <Metric label="Completed" value={done} icon={CheckCircle2} accent="var(--signal)" />
        <Metric label="Failed" value={failed} icon={XCircle} accent="var(--sev-critical)" emphasize={failed > 0} />
      </div>
      <DataTable
        columns={columns}
        data={r}
        rowId={(x) => x.id}
        filterPlaceholder="Filter responses…"
        pageSize={25}
        initialSort={[{ id: "ts", desc: true }]}
        empty="no response actions yet"
      />
    </div>
  );
}
