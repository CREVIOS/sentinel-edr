"use client";

import { type ColumnDef } from "@tanstack/react-table";
import { Sev, Chip } from "@/components/severity";
import { Metric } from "@/components/metric";
import { DataTable, SortHeader } from "@/components/data-table";
import { useData } from "@/lib/use-data";
import type { Rule } from "@/lib/types";
import { ScrollText, Crosshair, Bot, BrainCircuit } from "lucide-react";

const columns: ColumnDef<Rule>[] = [
  { accessorKey: "Severity", header: ({ column }) => <SortHeader column={column} title="Sev" />, cell: ({ row }) => <Sev s={row.original.Severity} /> },
  { accessorKey: "Title", header: ({ column }) => <SortHeader column={column} title="Rule" />, cell: ({ row }) => <div><div className="font-mono">{row.original.Title}</div><div className="text-xs text-muted-foreground">{row.original.ID}</div></div> },
  { accessorKey: "Category", header: "Category", cell: ({ row }) => <Chip>{row.original.Category}</Chip> },
  { accessorKey: "Tactic", header: ({ column }) => <SortHeader column={column} title="Tactic" />, cell: ({ row }) => <span className="text-muted-foreground">{row.original.Tactic || "—"}</span> },
  { id: "mitre", header: "ATT&CK", cell: ({ row }) => <div className="flex flex-wrap gap-1">{(row.original.MITRE || []).map((m) => <Chip key={m} color="var(--chart-1)">{m}</Chip>)}</div> },
  { accessorKey: "AutoRespond", header: "Auto-Response", cell: ({ row }) => row.original.AutoRespond ? <Chip color="var(--signal)">{row.original.AutoRespond}</Chip> : <span className="text-muted-foreground">—</span> },
];

export default function RulesPage() {
  const { data: rules } = useData<Rule[]>("rules", 60000);
  const all = rules || [];
  const withResp = all.filter((r) => r.AutoRespond).length;
  const tactics = new Set(all.map((r) => r.Tactic).filter(Boolean)).size;

  return (
    <div className="space-y-5">
      <div className="reveal grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Detection Rules" value={all.length} icon={ScrollText} />
        <Metric label="ATT&CK Tactics" value={tactics} icon={Crosshair} accent="var(--chart-1)" />
        <Metric label="Auto-Response" value={withResp} icon={Bot} accent="var(--signal)" />
        <Metric label="Behavioral" value={4} icon={BrainCircuit} accent="var(--chart-3)" />
      </div>
      <DataTable
        columns={columns}
        data={all}
        rowId={(r) => r.ID}
        filterPlaceholder="Search rules, tactics, technique IDs…"
        pageSize={25}
        initialSort={[{ id: "Severity", desc: false }]}
        empty="no rules loaded"
      />
    </div>
  );
}
