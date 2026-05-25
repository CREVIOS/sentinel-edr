"use client";

import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Chip } from "@/components/severity";
import { Metric } from "@/components/metric";
import { Sparkline } from "@/components/sparkline";
import { DataTable, SortHeader } from "@/components/data-table";
import { InfoSheet, type Field } from "@/components/info-sheet";
import { Inspect } from "@/components/inspect";
import { useData } from "@/lib/use-data";
import { ago, bytes } from "@/lib/format";
import type { Event } from "@/lib/types";
import { Globe, UploadCloud, Cloud, Mail } from "lucide-react";

type Dest = { domain: string; hits: number; out: number; in: number; cat: string };

// Strip the port from an "ip:port" / "[v6]:port" peer so connections to the same host collapse
// into one destination row (instead of one row per ephemeral source port).
function hostOf(remote?: string): string {
  if (!remote) return "";
  if (remote.startsWith("[")) return remote.slice(0, remote.indexOf("]") + 1); // [v6]
  const i = remote.lastIndexOf(":");
  return i > 0 ? remote.slice(0, i) : remote;
}

export default function InternetPage() {
  const { data: events } = useData<Event[]>("events?category=network&limit=500", 5000, "event");
  const [sel, setSel] = useState<Event | null>(null);
  const net = useMemo(() => (events || []).filter((e) => e.network), [events]);

  const totalOut = net.reduce((s, e) => s + (e.network!.bytes_out || 0), 0);
  const cloud = net.filter((e) => e.network!.category === "cloud_storage").length;
  const webmail = net.filter((e) => e.network!.category === "webmail").length;

  // upload sparkline: bytes_out bucketed across the recent window (oldest→newest)
  const spark = useMemo(() => {
    const ordered = [...net].reverse();
    const buckets = 24;
    const size = Math.max(1, Math.ceil(ordered.length / buckets));
    const out: number[] = [];
    for (let i = 0; i < ordered.length; i += size) {
      out.push(ordered.slice(i, i + size).reduce((s, e) => s + (e.network!.bytes_out || 0), 0));
    }
    return out.length > 1 ? out : [0, 0];
  }, [net]);

  // Top destinations = real outbound, external targets only (drop inbound clients and
  // intra-host/LAN traffic), keyed by host so all connections to a server group together.
  const dests = useMemo<Dest[]>(() => {
    const m: Record<string, Dest> = {};
    net
      .filter((e) => e.network!.direction !== "inbound" && e.network!.category !== "internal")
      .forEach((e) => {
        const n = e.network!;
        const d = n.domain || hostOf(n.remote) || "unknown";
        if (!m[d]) m[d] = { domain: d, hits: 0, out: 0, in: 0, cat: n.category || "web" };
        m[d].hits++; m[d].out += n.bytes_out || 0; m[d].in += n.bytes_in || 0;
      });
    return Object.values(m).sort((a, b) => b.out - a.out);
  }, [net]);

  const destCols: ColumnDef<Dest>[] = [
    { accessorKey: "domain", header: ({ column }) => <SortHeader column={column} title="Destination" />, cell: ({ row }) => <span className="font-mono">{row.original.domain}</span> },
    { accessorKey: "cat", header: "Category", cell: ({ row }) => <Chip color="var(--chart-2)">{row.original.cat}</Chip> },
    { accessorKey: "hits", header: ({ column }) => <SortHeader column={column} title="Conns" />, cell: ({ row }) => <span className="font-mono tabular-nums">{row.original.hits}</span> },
    { accessorKey: "out", header: ({ column }) => <SortHeader column={column} title="Uploaded" />, cell: ({ row }) => <span className="font-mono tabular-nums">{bytes(row.original.out)}</span> },
    { accessorKey: "in", header: ({ column }) => <SortHeader column={column} title="Downloaded" />, cell: ({ row }) => <span className="font-mono tabular-nums text-muted-foreground">{bytes(row.original.in)}</span> },
  ];

  const actCols: ColumnDef<Event>[] = [
    { accessorKey: "ts", header: ({ column }) => <SortHeader column={column} title="Time" />, cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{ago(row.original.ts)}</span> },
    { accessorKey: "hostname", header: ({ column }) => <SortHeader column={column} title="Host" />, cell: ({ row }) => <span className="font-mono">{row.original.hostname}</span> },
    { accessorKey: "user", header: "User", cell: ({ row }) => row.original.user || <span className="text-muted-foreground">—</span> },
    { id: "domain", header: "Destination", cell: ({ row }) => { const n = row.original.network!; return <span className="font-mono">{n.domain || hostOf(n.remote) || "—"}</span>; } },
    { id: "direction", header: "Dir", cell: ({ row }) => { const d = row.original.network!.direction; return <Chip color={d === "inbound" ? "var(--chart-3)" : "var(--chart-2)"}>{d || "—"}</Chip>; } },
    { id: "category", header: "Category", cell: ({ row }) => <Chip>{row.original.network!.category || "web"}</Chip> },
    { id: "out", header: ({ column }) => <SortHeader column={column} title="↑ Out" />, accessorFn: (e) => e.network?.bytes_out || 0, cell: ({ row }) => <span className="font-mono tabular-nums">{bytes(row.original.network!.bytes_out)}</span> },
    { id: "in", header: "↓ In", cell: ({ row }) => <span className="font-mono tabular-nums text-muted-foreground">{bytes(row.original.network!.bytes_in)}</span> },
    {
      id: "actions", enableHiding: false,
      cell: ({ row }) => (
        <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          {row.original.network!.blocked && <Chip color="var(--sev-critical)">blocked</Chip>}
          <Inspect onClick={() => setSel(row.original)} />
        </div>
      ),
    },
  ];

  function fields(e: Event): Field[] {
    const n = e.network!;
    return [
      { label: "Time", value: new Date(e.ts).toLocaleString(), mono: true },
      { label: "Host", value: e.hostname, mono: true },
      { label: "User", value: e.user },
      { label: "Domain", value: n.domain, mono: true, wrap: true },
      { label: "Remote", value: n.remote, mono: true },
      { label: "Protocol", value: n.proto },
      { label: "Direction", value: n.direction },
      { label: "Category", value: <Chip>{n.category || "web"}</Chip> },
      { label: "Uploaded", value: bytes(n.bytes_out), mono: true },
      { label: "Downloaded", value: bytes(n.bytes_in), mono: true },
      { label: "Blocked", value: n.blocked ? <Chip color="var(--sev-critical)">blocked</Chip> : "no" },
      { label: "Process", value: e.process ? `${e.process.name} (pid ${e.process.pid})` : undefined, mono: true },
    ];
  }

  return (
    <div className="reveal space-y-5">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Connections" value={net.length} icon={Globe} />
        <Metric label="Data Uploaded" value={bytes(totalOut)} icon={UploadCloud} accent="var(--primary)" spark={spark} />
        <Metric label="Cloud Storage" value={cloud} icon={Cloud} accent="var(--chart-1)" />
        <Metric label="Webmail" value={webmail} icon={Mail} accent="var(--chart-3)" />
      </div>

      <Card className="panel overflow-hidden">
        <CardHeader className="pb-3"><CardTitle className="font-mono text-xs tracking-[0.16em] text-muted-foreground">TOP DESTINATIONS · by upload</CardTitle></CardHeader>
        <CardContent>
          <DataTable
            columns={destCols}
            data={dests}
            rowId={(d) => d.domain}
            filterPlaceholder="Filter destinations…"
            pageSize={8}
            initialSort={[{ id: "out", desc: true }]}
            empty="no internet activity captured"
          />
        </CardContent>
      </Card>

      <Card className="panel overflow-hidden">
        <CardHeader className="pb-3 flex flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-2 font-mono text-xs tracking-[0.16em] text-muted-foreground"><span className="live-dot size-1.5" /> WEB ACTIVITY</CardTitle>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={actCols}
            data={net}
            rowId={(e) => e.id}
            onRowClick={(e) => setSel(e)}
            filterPlaceholder="Filter host, user, domain…"
            pageSize={15}
            initialSort={[{ id: "ts", desc: true }]}
            empty="no internet activity captured"
          />
        </CardContent>
      </Card>

      <InfoSheet
        open={!!sel}
        onOpenChange={(o) => !o && setSel(null)}
        title={sel ? (sel.network!.domain || sel.network!.remote || "connection") : ""}
        sub={sel ? `network · ${sel.network!.category || "web"}` : ""}
        badge={sel?.network!.blocked && <Chip color="var(--sev-critical)">blocked</Chip>}
        fields={sel ? fields(sel) : []}
      />
    </div>
  );
}
