"use client";

import { useState } from "react";
import { toast } from "sonner";
import { type ColumnDef } from "@tanstack/react-table";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { StatusDot, Chip } from "@/components/severity";
import { InfoSheet, type Field } from "@/components/info-sheet";
import { Inspect } from "@/components/inspect";
import { DataTable, SortHeader } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { PolicyPanel } from "@/components/policy-panel";
import { Separator } from "@/components/ui/separator";
import { useData, post } from "@/lib/use-data";
import { ago } from "@/lib/format";
import type { Agent } from "@/lib/types";
import { MoreHorizontal, ShieldOff, ShieldCheck, Usb, CloudOff } from "lucide-react";

type Pending = { a: Agent; type: string; label: string; destructive?: boolean; desc: string };

export default function EndpointsPage() {
  const { data: agents } = useData<Agent[]>("agents", 5000, "agent");
  const [sel, setSel] = useState<Agent | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);

  async function act(a: Agent, type: string, label: string) {
    const r = await post("respond", { type, agent_id: a.id, reason: `manual ${type} from console` });
    if (r.ok) toast.success(`${label} dispatched to ${a.hostname}`);
    else toast.error(`Action failed (${r.status})`);
  }

  function fields(a: Agent): Field[] {
    return [
      { label: "Agent ID", value: a.id, mono: true, wrap: true },
      { label: "Status", value: <StatusDot status={a.status} /> },
      { label: "OS", value: a.os },
      { label: "Kernel", value: a.kernel, mono: true },
      { label: "Arch", value: <Chip>{a.arch}</Chip> },
      { label: "IP", value: a.ip, mono: true },
      { label: "MAC", value: a.mac, mono: true },
      { label: "Version", value: a.version, mono: true },
      { label: "Labels", value: <div className="flex flex-wrap gap-1">{(a.labels || []).map((l) => <Chip key={l} color="var(--primary)">{l}</Chip>)}</div> },
      { label: "Events", value: a.event_count?.toLocaleString?.(), mono: true },
      { label: "Enrolled", value: new Date(a.enrolled_at).toLocaleString(), mono: true },
      { label: "Last Seen", value: `${ago(a.last_seen)} · ${new Date(a.last_seen).toLocaleString()}`, mono: true, wrap: true },
    ];
  }

  const columns: ColumnDef<Agent>[] = [
    { accessorKey: "status", header: ({ column }) => <SortHeader column={column} title="Status" />, cell: ({ row }) => <StatusDot status={row.original.status} /> },
    { accessorKey: "hostname", header: ({ column }) => <SortHeader column={column} title="Hostname" />, cell: ({ row }) => <span className="font-mono">{row.original.hostname}</span> },
    { id: "os", header: "OS / Kernel", cell: ({ row }) => <span className="text-muted-foreground">{row.original.os} <span className="opacity-60">{row.original.kernel}</span></span> },
    { accessorKey: "ip", header: "IP", cell: ({ row }) => <span className="font-mono">{row.original.ip || "—"}</span> },
    { accessorKey: "mac", header: "MAC", cell: ({ row }) => <span className="font-mono text-muted-foreground">{row.original.mac || "—"}</span> },
    { accessorKey: "arch", header: "Arch", cell: ({ row }) => <Chip>{row.original.arch || "—"}</Chip> },
    { accessorKey: "event_count", header: ({ column }) => <SortHeader column={column} title="Events" />, cell: ({ row }) => <span className="font-mono tabular-nums">{row.original.event_count?.toLocaleString?.() ?? row.original.event_count}</span> },
    { accessorKey: "last_seen", header: ({ column }) => <SortHeader column={column} title="Last Seen" />, cell: ({ row }) => <span className="text-muted-foreground">{ago(row.original.last_seen)}</span> },
    {
      id: "actions", enableHiding: false,
      cell: ({ row }) => {
        const a = row.original;
        return (
          <div className="flex items-center justify-end gap-0.5" onClick={(e) => e.stopPropagation()}>
            <Inspect onClick={() => setSel(a)} />
            <DropdownMenu>
              <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" className="size-8"><MoreHorizontal className="size-4" /></Button></DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {a.status !== "isolated"
                  ? <DropdownMenuItem variant="destructive" onClick={() => setPending({ a, type: "isolate", label: "Isolate", destructive: true, desc: `Cut all network traffic from ${a.hostname} except the management server. Active sessions and tooling on the host will lose connectivity until isolation is lifted.` })}><ShieldOff className="size-4" /> Isolate endpoint</DropdownMenuItem>
                  : <DropdownMenuItem onClick={() => setPending({ a, type: "unisolate", label: "Lift isolation", desc: `Restore normal network connectivity for ${a.hostname}.` })}><ShieldCheck className="size-4" /> Lift isolation</DropdownMenuItem>}
                <DropdownMenuItem onClick={() => setPending({ a, type: "block_usb", label: "Block USB", desc: `Block USB mass-storage on ${a.hostname}. New removable media will be rejected.` })}><Usb className="size-4" /> Block USB</DropdownMenuItem>
                <DropdownMenuItem onClick={() => setPending({ a, type: "block_upload", label: "Block uploads", desc: `Drop new outbound upload channels (web/ftp/nfs) on ${a.hostname}.` })}><CloudOff className="size-4" /> Block uploads</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        );
      },
    },
  ];

  return (
    <div className="reveal space-y-4">
      <DataTable
        columns={columns}
        data={agents || []}
        rowId={(a) => a.id}
        onRowClick={(a) => setSel(a)}
        filterPlaceholder="Filter endpoints…"
        initialSort={[{ id: "hostname", desc: false }]}
        empty="no endpoints enrolled"
      />

      <InfoSheet
        open={!!sel}
        onOpenChange={(o) => !o && setSel(null)}
        title={sel?.hostname || ""}
        sub={sel ? `endpoint · ${sel.status}` : ""}
        badge={sel && <StatusDot status={sel.status} />}
        fields={sel ? fields(sel) : []}
      >
        {sel && (
          <div className="flex flex-wrap gap-2">
            {sel.status !== "isolated"
              ? <Button size="sm" variant="destructive" onClick={() => setPending({ a: sel, type: "isolate", label: "Isolate", destructive: true, desc: `Cut all network traffic from ${sel.hostname} except the management server.` })}><ShieldOff className="size-4" /> Isolate</Button>
              : <Button size="sm" onClick={() => setPending({ a: sel, type: "unisolate", label: "Lift isolation", desc: `Restore connectivity for ${sel.hostname}.` })}><ShieldCheck className="size-4" /> Lift isolation</Button>}
            <Button size="sm" variant="outline" onClick={() => setPending({ a: sel, type: "block_usb", label: "Block USB", desc: `Block USB mass-storage on ${sel.hostname}.` })}><Usb className="size-4" /> Block USB</Button>
            <Button size="sm" variant="outline" onClick={() => setPending({ a: sel, type: "block_upload", label: "Block uploads", desc: `Block outbound uploads on ${sel.hostname}.` })}><CloudOff className="size-4" /> Block uploads</Button>
          </div>
        )}
        {sel && (
          <>
            <Separator className="my-4" />
            <PolicyPanel agent={sel} />
          </>
        )}
      </InfoSheet>

      <ConfirmDialog
        open={!!pending}
        onOpenChange={(o) => !o && setPending(null)}
        title={pending ? `${pending.label} — ${pending.a.hostname}?` : ""}
        description={pending?.desc}
        confirmLabel={pending?.label}
        destructive={pending?.destructive}
        onConfirm={() => { if (pending) act(pending.a, pending.type, pending.label); setPending(null); }}
      />
    </div>
  );
}
