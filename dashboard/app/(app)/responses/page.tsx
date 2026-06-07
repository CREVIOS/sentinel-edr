"use client";

import { toast } from "sonner";
import { type ColumnDef } from "@tanstack/react-table";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/severity";
import { Metric } from "@/components/metric";
import { DataTable, SortHeader } from "@/components/data-table";
import { useData, respond } from "@/lib/use-data";
import { responseLabel } from "@/lib/response-actions";
import { ago } from "@/lib/format";
import type { ResponseAction } from "@/lib/types";
import { Crosshair, Bot, CheckCircle2, XCircle, RotateCw } from "lucide-react";

function statusColor(s: string) {
  return s === "completed" ? "var(--signal)" : s === "failed" ? "var(--sev-critical)" : s === "pending" ? "var(--sev-medium)" : "var(--muted-foreground)";
}

export default function ResponsesPage() {
  const { data: responses } = useData<ResponseAction[]>("responses", 3000, "response");
  const r = responses || [];
  const auto = r.filter((x) => x.automated).length;
  const done = r.filter((x) => x.status === "completed").length;
  const failed = r.filter((x) => x.status === "failed").length;

  async function retry(x: ResponseAction) {
    const res = await respond({ type: x.type, agentId: x.agent_id, target: x.target as Record<string, unknown>, reason: `retry of ${x.id}`, detectionId: x.detection_id });
    if (res.ok) toast.success(`Re-issued ${responseLabel(x.type)} to ${x.hostname}`);
    else toast.error(res.error || `Retry failed (HTTP ${res.status})`);
  }

  const columns: ColumnDef<ResponseAction>[] = [
    { accessorKey: "ts", header: ({ column }) => <SortHeader column={column} title="Time" />, cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{ago(row.original.ts)}</span> },
    { accessorKey: "type", header: ({ column }) => <SortHeader column={column} title="Action" />, cell: ({ row }) => <span className="font-mono">{responseLabel(row.original.type)}</span> },
    { id: "target", header: "Target", cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{Object.entries(row.original.target || {}).map(([k, v]) => `${k}=${v}`).join(" ") || "—"}</span> },
    { accessorKey: "hostname", header: ({ column }) => <SortHeader column={column} title="Host" /> },
    { id: "source", header: "Source", cell: ({ row }) => row.original.automated ? <Chip color="var(--signal)">auto</Chip> : <Chip>manual</Chip> },
    { accessorKey: "issued_by", header: "By", cell: ({ row }) => <span className="text-muted-foreground">{row.original.issued_by}</span> },
    { accessorKey: "status", header: ({ column }) => <SortHeader column={column} title="Status" />, cell: ({ row }) => <span className="inline-flex items-center gap-2 font-mono text-xs capitalize text-foreground"><span className="size-2 rounded-full" style={{ background: statusColor(row.original.status) }} />{row.original.status}</span> },
    { accessorKey: "result", header: "Result", cell: ({ row }) => <span className="block max-w-[20rem] truncate text-xs text-muted-foreground" title={row.original.result}>{row.original.result}</span> },
    {
      id: "actions", enableHiding: false,
      cell: ({ row }) =>
        row.original.status === "failed" ? (
          <div className="text-right" onClick={(e) => e.stopPropagation()}>
            <Button variant="ghost" size="sm" className="h-7 gap-1 text-muted-foreground hover:text-foreground" onClick={() => retry(row.original)} aria-label="Retry action">
              <RotateCw className="size-3.5" /> Retry
            </Button>
          </div>
        ) : null,
    },
  ];

  return (
    <div className="space-y-5">
      <div className="reveal grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Responses" value={r.length} icon={Crosshair} />
        <Metric label="Automated" value={auto} icon={Bot} accent="var(--signal)" />
        <Metric label="Completed" value={done} icon={CheckCircle2} accent="var(--signal)" />
        <Metric label="Failed" value={failed} icon={XCircle} accent="var(--sev-critical)" emphasize={failed > 0} />
      </div>
      <DataTable
        columns={columns}
        data={r}
        rowId={(x) => x.id}
        tableId="responses"
        filterPlaceholder="Filter responses…"
        pageSize={25}
        initialSort={[{ id: "ts", desc: true }]}
        empty="No response actions"
        loading={responses === undefined}
      />
    </div>
  );
}
