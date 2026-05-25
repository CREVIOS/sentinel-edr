"use client";

import { useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Sev, Chip } from "@/components/severity";
import { Metric } from "@/components/metric";
import { DataTable, SortHeader } from "@/components/data-table";
import { InfoSheet, type Field } from "@/components/info-sheet";
import { Inspect } from "@/components/inspect";
import { useData } from "@/lib/use-data";
import { ago } from "@/lib/format";
import type { Event } from "@/lib/types";
import { FileLock2, ShieldX, ScanText, ScrollText } from "lucide-react";

interface Classifier { name: string; label: string; severity: string; }
interface Policy { Classifier: string; Channel: string; Verdict: string; }

function verdictColor(v?: string) {
  return v === "block" ? "var(--sev-critical)" : v === "alert" ? "var(--sev-high)" : "var(--muted-foreground)";
}

export default function DlpPage() {
  const { data: events } = useData<Event[]>("events?category=dlp&limit=400", 5000, "event");
  const { data: classifiers } = useData<Classifier[]>("dlp/classifiers", 60000);
  const { data: policies } = useData<Policy[]>("dlp/policies", 60000);
  const [sel, setSel] = useState<Event | null>(null);
  const dlp = events || [];
  const blocked = dlp.filter((e) => e.dlp?.verdict === "block").length;

  const cols: ColumnDef<Event>[] = [
    { accessorKey: "severity", header: ({ column }) => <SortHeader column={column} title="Sev" />, cell: ({ row }) => <Sev s={row.original.severity} /> },
    { id: "classifier", header: ({ column }) => <SortHeader column={column} title="Classifier" />, accessorFn: (e) => e.dlp?.classifier, cell: ({ row }) => <span className="font-mono">{row.original.dlp?.classifier}</span> },
    { id: "channel", header: "Channel", cell: ({ row }) => <Chip>{row.original.dlp?.channel}</Chip> },
    { accessorKey: "hostname", header: ({ column }) => <SortHeader column={column} title="Host" />, cell: ({ row }) => <span className="text-muted-foreground">{row.original.hostname}</span> },
    { accessorKey: "user", header: "User", cell: ({ row }) => row.original.user || <span className="text-muted-foreground">—</span> },
    { id: "sample", header: "Sample", cell: ({ row }) => <span className="font-mono text-muted-foreground">{row.original.dlp?.sample}</span> },
    { id: "verdict", header: ({ column }) => <SortHeader column={column} title="Verdict" />, accessorFn: (e) => e.dlp?.verdict, cell: ({ row }) => <Chip color={verdictColor(row.original.dlp?.verdict)}>{row.original.dlp?.verdict || "—"}</Chip> },
    { accessorKey: "ts", header: ({ column }) => <SortHeader column={column} title="When" />, cell: ({ row }) => <span className="text-muted-foreground">{ago(row.original.ts)}</span> },
    { id: "actions", enableHiding: false, cell: ({ row }) => <div className="text-right" onClick={(e) => e.stopPropagation()}><Inspect onClick={() => setSel(row.original)} /></div> },
  ];

  const classCols: ColumnDef<Classifier>[] = [
    { accessorKey: "name", header: "Name", cell: ({ row }) => <span className="font-mono">{row.original.name}</span> },
    { accessorKey: "label", header: "Detects", cell: ({ row }) => <span className="text-muted-foreground">{row.original.label}</span> },
    { accessorKey: "severity", header: "Severity", cell: ({ row }) => <Sev s={row.original.severity} /> },
  ];
  const polCols: ColumnDef<Policy>[] = [
    { accessorKey: "Classifier", header: "Classifier", cell: ({ row }) => <span className="font-mono">{row.original.Classifier}</span> },
    { accessorKey: "Channel", header: "Channel", cell: ({ row }) => <Chip>{row.original.Channel}</Chip> },
    { accessorKey: "Verdict", header: "Verdict", cell: ({ row }) => <Chip color={verdictColor(row.original.Verdict)}>{row.original.Verdict}</Chip> },
  ];

  function fields(e: Event): Field[] {
    return [
      { label: "Time", value: new Date(e.ts).toLocaleString(), mono: true },
      { label: "Severity", value: <Sev s={e.severity} /> },
      { label: "Classifier", value: e.dlp?.classifier, mono: true },
      { label: "Channel", value: <Chip>{e.dlp?.channel}</Chip> },
      { label: "Verdict", value: <Chip color={verdictColor(e.dlp?.verdict)}>{e.dlp?.verdict || "—"}</Chip> },
      { label: "Matches", value: String(e.dlp?.matches ?? ""), mono: true },
      { label: "Sample", value: e.dlp?.sample, mono: true },
      { label: "Host", value: e.hostname, mono: true },
      { label: "User", value: e.user },
      { label: "File", value: e.file?.path, mono: true, wrap: true },
      { label: "Message", value: e.message, wrap: true },
    ];
  }

  return (
    <div className="reveal space-y-5">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="DLP Incidents" value={dlp.length} icon={FileLock2} />
        <Metric label="Blocked Transfers" value={blocked} icon={ShieldX} accent="var(--sev-critical)" emphasize={blocked > 0} />
        <Metric label="Classifiers" value={classifiers?.length ?? 0} icon={ScanText} accent="var(--chart-2)" />
        <Metric label="Policies" value={policies?.length ?? 0} icon={ScrollText} accent="var(--primary)" />
      </div>

      <Card className="panel overflow-hidden">
        <CardHeader className="pb-3"><CardTitle className="flex items-center gap-2 font-mono text-xs tracking-[0.16em] text-muted-foreground"><span className="live-dot size-1.5" /> DLP INCIDENTS</CardTitle></CardHeader>
        <CardContent>
          <DataTable columns={cols} data={dlp} rowId={(e) => e.id} onRowClick={(e) => setSel(e)}
            filterPlaceholder="Filter classifier, host, user…" pageSize={15}
            initialSort={[{ id: "ts", desc: true }]} empty="no DLP incidents" />
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="panel overflow-hidden">
          <CardHeader className="pb-3"><CardTitle className="font-mono text-xs tracking-[0.16em] text-muted-foreground">CLASSIFIERS</CardTitle></CardHeader>
          <CardContent>
            <DataTable columns={classCols} data={classifiers || []} rowId={(c) => c.name} empty="no classifiers" />
          </CardContent>
        </Card>
        <Card className="panel overflow-hidden">
          <CardHeader className="pb-3"><CardTitle className="font-mono text-xs tracking-[0.16em] text-muted-foreground">ENFORCEMENT POLICIES</CardTitle></CardHeader>
          <CardContent>
            <DataTable columns={polCols} data={policies || []} rowId={(p) => p.Classifier + p.Channel} pageSize={10} empty="no policies" />
          </CardContent>
        </Card>
      </div>

      <InfoSheet
        open={!!sel} onOpenChange={(o) => !o && setSel(null)}
        title={sel?.dlp?.classifier || "DLP incident"}
        sub={sel ? `${sel.dlp?.channel} · ${sel.dlp?.verdict || "audit"}` : ""}
        badge={sel && <Sev s={sel.severity} />}
        fields={sel ? fields(sel) : []}
      />
    </div>
  );
}
