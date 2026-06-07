"use client";

import { useState } from "react";
import { toast } from "sonner";
import { type ColumnDef } from "@tanstack/react-table";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { StatusDot, Chip } from "@/components/severity";
import { InfoSheet, type Field } from "@/components/info-sheet";
import { Inspect } from "@/components/inspect";
import { DataTable, SortHeader } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { PolicyPanel } from "@/components/policy-panel";
import { AttackStory } from "@/components/attack-story";
import { Separator } from "@/components/ui/separator";
import { useData, respond } from "@/lib/use-data";
import { ago } from "@/lib/format";
import type { Agent, Event } from "@/lib/types";
import { MoreHorizontal, ShieldOff, ShieldCheck, Usb, Plug, CloudOff, Cloud, Snowflake, Flame, Stethoscope } from "lucide-react";

type Pending = { a: Agent; type: string; label: string; target?: Record<string, unknown>; destructive?: boolean; desc: string };

export default function EndpointsPage() {
  const { data: agents } = useData<Agent[]>("agents", 5000, "agent");
  const [sel, setSel] = useState<Agent | null>(null);
  const [event, setEvent] = useState<Event | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);

  async function act(p: Pending) {
    const r = await respond({ type: p.type, agentId: p.a.id, target: p.target, reason: `manual ${p.type} from console` });
    if (r.ok) toast.success(`${p.label} dispatched to ${p.a.hostname}`);
    else toast.error(r.error || `Could not ${p.label.toLowerCase()} ${p.a.hostname} (HTTP ${r.status})`);
  }

  async function triage(a: Agent) {
    const r = await respond({ type: "live_triage", agentId: a.id, reason: "live triage from console" });
    if (r.ok) toast.success(`Triage requested for ${a.hostname} — results will land in Response`);
    else toast.error(r.error || `Triage failed (HTTP ${r.status})`);
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
      { label: "Events", value: <span className="tabular-nums">{a.event_count?.toLocaleString?.()}</span>, mono: true },
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
              <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" className="size-8" aria-label={`Actions for ${a.hostname}`}><MoreHorizontal className="size-4" /></Button></DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {a.status !== "isolated"
                  ? <DropdownMenuItem variant="destructive" onClick={() => setPending({ a, type: "isolate", label: "Isolate", destructive: true, desc: `Cut all network traffic from ${a.hostname} except the management server. Active sessions and tooling on the host will lose connectivity until isolation is lifted.` })}><ShieldOff className="size-4" /> Isolate endpoint</DropdownMenuItem>
                  : <DropdownMenuItem onClick={() => setPending({ a, type: "unisolate", label: "Lift isolation", desc: `Restore normal network connectivity for ${a.hostname}.` })}><ShieldCheck className="size-4" /> Lift isolation</DropdownMenuItem>}
                <DropdownMenuItem onClick={() => triage(a)}><Stethoscope className="size-4" /> Live triage</DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem variant="destructive" onClick={() => setPending({ a, type: "freeze", label: "Freeze", destructive: true, desc: `Freeze every process on ${a.hostname} (cgroup.freeze) for a forensic hold. Unfreeze to resume.` })}><Snowflake className="size-4" /> Freeze processes</DropdownMenuItem>
                <DropdownMenuItem onClick={() => setPending({ a, type: "unfreeze", label: "Unfreeze", desc: `Resume frozen processes on ${a.hostname}.` })}><Flame className="size-4" /> Unfreeze</DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => setPending({ a, type: "block_usb", label: "Block USB", desc: `Block USB mass-storage on ${a.hostname}. New removable media will be rejected.` })}><Usb className="size-4" /> Block USB</DropdownMenuItem>
                <DropdownMenuItem onClick={() => setPending({ a, type: "unblock_usb", label: "Lift USB block", desc: `Re-enable USB mass-storage on ${a.hostname}.` })}><Plug className="size-4" /> Lift USB block</DropdownMenuItem>
                <DropdownMenuItem onClick={() => setPending({ a, type: "block_upload", label: "Block uploads", desc: `Drop new outbound upload channels (web/ftp/nfs) on ${a.hostname}.` })}><CloudOff className="size-4" /> Block uploads</DropdownMenuItem>
                <DropdownMenuItem onClick={() => setPending({ a, type: "unblock_upload", label: "Lift upload block", desc: `Restore outbound upload channels on ${a.hostname}.` })}><Cloud className="size-4" /> Lift upload block</DropdownMenuItem>
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
        loading={agents === undefined}
        rowId={(a) => a.id}
        tableId="endpoints"
        enableSelection
        bulkActions={(rows, clear) => (
          <>
            <Button size="sm" variant="outline" className="border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive" onClick={async () => {
              const targets = rows.filter((a) => a.status !== "isolated");
              const res = await Promise.all(targets.map((a) => respond({ type: "isolate", agentId: a.id, reason: "bulk isolate from console" })));
              const ok = res.filter((r) => r.ok).length;
              toast[ok === res.length ? "success" : "error"](`Isolated ${ok}/${res.length || 0} endpoints`);
              clear();
            }}><ShieldOff className="size-4" /> Isolate selected</Button>
            <Button size="sm" variant="outline" onClick={async () => {
              const targets = rows.filter((a) => a.status === "isolated");
              const res = await Promise.all(targets.map((a) => respond({ type: "unisolate", agentId: a.id, reason: "bulk lift isolation" })));
              const ok = res.filter((r) => r.ok).length;
              toast[ok === res.length ? "success" : "error"](`Lifted isolation on ${ok}/${res.length || 0}`);
              clear();
            }}><ShieldCheck className="size-4" /> Lift isolation</Button>
          </>
        )}
        onRowClick={(a) => setSel(a)}
        filterPlaceholder="Filter endpoints…"
        initialSort={[{ id: "hostname", desc: false }]}
        empty="No endpoints enrolled"
      />

      <InfoSheet
        open={!!sel}
        onOpenChange={(o) => !o && setSel(null)}
        title={sel?.hostname || ""}
        sub={sel ? `Endpoint · ${sel.status.charAt(0).toUpperCase()}${sel.status.slice(1)}` : ""}
        badge={sel && <StatusDot status={sel.status} />}
        fields={sel ? fields(sel) : []}
        footer={sel && (
          <div className="flex flex-wrap gap-2">
            {sel.status !== "isolated"
              ? <Button size="sm" variant="destructive" onClick={() => setPending({ a: sel, type: "isolate", label: "Isolate", destructive: true, desc: `Cut all network traffic from ${sel.hostname} except the management server.` })}><ShieldOff className="size-4" /> Isolate</Button>
              : <Button size="sm" onClick={() => setPending({ a: sel, type: "unisolate", label: "Lift isolation", desc: `Restore connectivity for ${sel.hostname}.` })}><ShieldCheck className="size-4" /> Lift isolation</Button>}
            <Button size="sm" variant="outline" onClick={() => triage(sel)}><Stethoscope className="size-4" /> Live triage</Button>
            <Button size="sm" variant="outline" onClick={() => setPending({ a: sel, type: "freeze", label: "Freeze", destructive: true, desc: `Freeze every process on ${sel.hostname} (cgroup.freeze).` })}><Snowflake className="size-4" /> Freeze</Button>
          </div>
        )}
      >
        {sel && (
          <div className="space-y-4">
            <div>
              <div className="mb-2 font-mono text-[11px] uppercase tracking-wide text-muted-foreground">Recent activity</div>
              <AttackStory agentId={sel.id} onSelectEvent={(e) => setEvent(e)} limit={60} />
            </div>
            <Separator />
            <PolicyPanel agent={sel} />
          </div>
        )}
      </InfoSheet>

      <InfoSheet
        open={!!event}
        onOpenChange={(o) => !o && setEvent(null)}
        title={event ? `${event.category} · ${event.action}` : ""}
        sub="Event detail"
        badge={event && <StatusDot status="online" />}
        fields={event ? [
          { label: "Time", value: new Date(event.ts).toLocaleString(), mono: true },
          { label: "User", value: event.user },
          { label: "Message", value: event.message, wrap: true },
          { label: "Command", value: event.process?.cmdline, mono: true, wrap: true },
          { label: "File", value: event.file?.path, mono: true, wrap: true },
          { label: "Remote", value: event.network?.remote, mono: true },
          { label: "Domain", value: event.network?.domain, mono: true },
        ] : []}
      />

      <ConfirmDialog
        open={!!pending}
        onOpenChange={(o) => !o && setPending(null)}
        title={pending ? `${pending.label} — ${pending.a.hostname}?` : ""}
        description={pending?.desc}
        confirmLabel={pending?.label}
        destructive={pending?.destructive}
        onConfirm={() => { if (pending) act(pending); setPending(null); }}
      />
    </div>
  );
}
