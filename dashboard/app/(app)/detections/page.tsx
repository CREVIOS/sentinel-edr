"use client";

import { useMemo, useState } from "react";
import { toast } from "sonner";
import { type ColumnDef } from "@tanstack/react-table";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sev, Chip } from "@/components/severity";
import { InfoSheet, type Field } from "@/components/info-sheet";
import { Inspect } from "@/components/inspect";
import { DataTable, SortHeader } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { useData, post } from "@/lib/use-data";
import { ago } from "@/lib/format";
import type { Detection } from "@/lib/types";
import { MoreHorizontal, Check, X, ShieldOff } from "lucide-react";

function StatusBadge({ s }: { s: string }) {
  const color = s === "open" ? "var(--sev-high)" : s === "acknowledged" ? "var(--sev-low)" : "var(--muted-foreground)";
  return <Chip color={color}>{s}</Chip>;
}

export default function DetectionsPage() {
  const [status, setStatus] = useState("all");
  const [sev, setSev] = useState("all");
  const [sel, setSel] = useState<Detection | null>(null);
  const [pending, setPending] = useState<Detection | null>(null);
  const path = useMemo(() => `detections?limit=300${status !== "all" ? `&status=${status}` : ""}`, [status]);
  const { data: all } = useData<Detection[]>(path, 3000, "detection");
  const dets = (all || []).filter((d) => sev === "all" || d.severity === sev);

  async function setStat(d: Detection, s: string) {
    const r = await post(`detections/${d.id}/status`, { status: s });
    if (r.ok) toast.success(`Detection ${s}`); else toast.error("Update failed");
  }
  async function respond(d: Detection, type: string) {
    const r = await post("respond", { type, agent_id: d.agent_id, reason: `from ${d.rule_id}`, detection_id: d.id });
    if (r.ok) toast.success(`${type} dispatched to ${d.hostname}`); else toast.error("Action failed");
  }

  function fields(d: Detection): Field[] {
    return [
      { label: "Rule", value: d.rule_id, mono: true },
      { label: "Summary", value: d.summary, wrap: true },
      { label: "Host", value: d.hostname, mono: true },
      { label: "User", value: d.user },
      { label: "Tactic", value: d.tactic },
      { label: "ATT&CK", value: <div className="flex flex-wrap gap-1">{(d.mitre || []).map((m) => <Chip key={m} color="var(--chart-1)">{m}</Chip>)}</div> },
      { label: "Engine", value: <Chip>{d.engine}</Chip> },
      { label: "Status", value: <StatusBadge s={d.status} /> },
      { label: "Assigned", value: d.assigned_to },
      { label: "Detected", value: new Date(d.ts).toLocaleString(), mono: true },
      { label: "Events", value: (d.event_ids || []).join(", "), mono: true, wrap: true },
    ];
  }

  const columns: ColumnDef<Detection>[] = [
    { accessorKey: "severity", header: ({ column }) => <SortHeader column={column} title="Sev" />, cell: ({ row }) => <Sev s={row.original.severity} /> },
    { accessorKey: "rule_name", header: ({ column }) => <SortHeader column={column} title="Detection" />, cell: ({ row }) => <span className="font-mono">{row.original.rule_name}</span> },
    { accessorKey: "hostname", header: ({ column }) => <SortHeader column={column} title="Host" />, cell: ({ row }) => <span className="text-muted-foreground">{row.original.hostname}</span> },
    { accessorKey: "tactic", header: "Tactic", cell: ({ row }) => <span className="text-muted-foreground">{row.original.tactic || "—"}</span> },
    { id: "mitre", header: "ATT&CK", cell: ({ row }) => <div className="flex flex-wrap gap-1">{(row.original.mitre || []).map((m) => <Chip key={m} color="var(--chart-1)">{m}</Chip>)}</div> },
    { accessorKey: "engine", header: "Engine", cell: ({ row }) => <Chip>{row.original.engine}</Chip> },
    { accessorKey: "status", header: ({ column }) => <SortHeader column={column} title="Status" />, cell: ({ row }) => <StatusBadge s={row.original.status} /> },
    { accessorKey: "ts", header: ({ column }) => <SortHeader column={column} title="When" />, cell: ({ row }) => <span className="text-muted-foreground">{ago(row.original.ts)}</span> },
    {
      id: "actions", enableHiding: false,
      cell: ({ row }) => {
        const d = row.original;
        return (
          <div className="flex items-center justify-end gap-0.5" onClick={(e) => e.stopPropagation()}>
            <Inspect onClick={() => setSel(d)} />
            <DropdownMenu>
              <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" className="size-8"><MoreHorizontal className="size-4" /></Button></DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => setStat(d, "acknowledged")}><Check className="size-4" /> Acknowledge</DropdownMenuItem>
                <DropdownMenuItem onClick={() => setStat(d, "closed")}><X className="size-4" /> Close</DropdownMenuItem>
                <DropdownMenuItem variant="destructive" onClick={() => setPending(d)}><ShieldOff className="size-4" /> Isolate host</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        );
      },
    },
  ];

  const filters = (
    <>
      <Select value={status} onValueChange={setStatus}>
        <SelectTrigger className="h-8 w-40"><SelectValue /></SelectTrigger>
        <SelectContent>{["all", "open", "acknowledged", "closed"].map((s) => <SelectItem key={s} value={s}>{s === "all" ? "All statuses" : s}</SelectItem>)}</SelectContent>
      </Select>
      <Select value={sev} onValueChange={setSev}>
        <SelectTrigger className="h-8 w-40"><SelectValue /></SelectTrigger>
        <SelectContent>{["all", "critical", "high", "medium", "low"].map((s) => <SelectItem key={s} value={s}>{s === "all" ? "All severities" : s}</SelectItem>)}</SelectContent>
      </Select>
    </>
  );

  return (
    <div className="reveal space-y-4">
      <DataTable
        columns={columns}
        data={dets}
        rowId={(d) => d.id}
        onRowClick={(d) => setSel(d)}
        toolbar={filters}
        filterPlaceholder="Filter detections…"
        initialSort={[{ id: "ts", desc: true }]}
        empty="no detections"
      />

      <InfoSheet
        open={!!sel}
        onOpenChange={(o) => !o && setSel(null)}
        title={sel?.rule_name || ""}
        sub={sel ? `${sel.severity} · ${sel.engine} engine` : ""}
        badge={sel && <Sev s={sel.severity} />}
        fields={sel ? fields(sel) : []}
      >
        {sel && (
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={() => setStat(sel, "acknowledged")}><Check className="size-4" /> Acknowledge</Button>
            <Button size="sm" variant="outline" onClick={() => setStat(sel, "closed")}><X className="size-4" /> Close</Button>
            <Button size="sm" variant="destructive" onClick={() => setPending(sel)}><ShieldOff className="size-4" /> Isolate host</Button>
          </div>
        )}
      </InfoSheet>

      <ConfirmDialog
        open={!!pending}
        onOpenChange={(o) => !o && setPending(null)}
        title={pending ? `Isolate ${pending.hostname}?` : ""}
        description={pending ? `Cut all network traffic from ${pending.hostname} (except the management server) in response to "${pending.rule_name}". Lift isolation from the Endpoints page when remediated.` : ""}
        confirmLabel="Isolate host"
        destructive
        onConfirm={() => { if (pending) respond(pending, "isolate"); setPending(null); }}
      />
    </div>
  );
}
