"use client";

import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { type ColumnDef } from "@tanstack/react-table";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sev, Chip } from "@/components/severity";
import { InfoSheet, type Field } from "@/components/info-sheet";
import { Inspect } from "@/components/inspect";
import { DataTable, SortHeader } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { MitreChips, KillChainStrip } from "@/components/mitre";
import { AttackStory } from "@/components/attack-story";
import { IncidentSummary, type Recommendation } from "@/components/incident-summary";
import { AiTriage } from "@/components/ai-triage";
import { useData, respond, postJSON } from "@/lib/use-data";
import { ago } from "@/lib/format";
import type { Detection, Event } from "@/lib/types";
import { MoreHorizontal, Check, X, ShieldOff, UserX, Snowflake, FolderPlus } from "lucide-react";

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function cap(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function StatusBadge({ s }: { s: string }) {
  const color = s === "open" ? "var(--sev-high)" : s === "acknowledged" ? "var(--sev-low)" : "var(--muted-foreground)";
  return <Chip color={color}>{cap(s)}</Chip>;
}

type Pending = { d: Detection; type: string; label: string; target?: Record<string, unknown>; destructive?: boolean; desc: string };

export default function DetectionsPage() {
  const [status, setStatus] = useState("all");
  const [sev, setSev] = useState("all");
  const [sel, setSel] = useState<Detection | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [event, setEvent] = useState<Event | null>(null);
  const path = useMemo(() => `detections?limit=300${status !== "all" ? `&status=${status}` : ""}`, [status]);
  const { data: all } = useData<Detection[]>(path, 3000, "detection");
  const dets = (all || []).filter((d) => sev === "all" || d.severity === sev);

  // Deep-link: /detections?id=<id> opens that detection's drawer (used from the overview, so
  // context is never lost on the jump). Read once data is available.
  useEffect(() => {
    if (!all) return;
    const id = new URLSearchParams(window.location.search).get("id");
    if (id) {
      const d = all.find((x) => x.id === id);
      if (d) setSel(d);
    }
  }, [all]);

  // keep the open drawer's status fresh as the list re-polls
  useEffect(() => {
    if (sel && all) {
      const fresh = all.find((d) => d.id === sel.id);
      if (fresh && fresh.status !== sel.status) setSel(fresh);
    }
  }, [all, sel]);

  async function setStat(d: Detection, s: string) {
    const r = await postJSON(`detections/${d.id}/status`, { status: s });
    const phrase = s === "acknowledged" ? "Detection acknowledged" : s === "closed" ? "Detection closed" : s === "open" ? "Detection reopened" : `Detection ${s}`;
    if (r.ok) toast.success(phrase); else toast.error(r.error || `Update failed (HTTP ${r.status})`);
  }

  async function act(p: Pending) {
    const r = await respond({ type: p.type, agentId: p.d.agent_id, target: p.target, reason: `from ${p.d.rule_id}`, detectionId: p.d.id });
    if (r.ok) toast.success(`${p.label} dispatched to ${p.d.hostname}`);
    else toast.error(r.error || `Action failed (HTTP ${r.status})`);
  }

  async function escalate(d: Detection) {
    const r = await postJSON("cases", {
      title: d.rule_name || `Detection on ${d.hostname}`,
      severity: d.severity,
      agent_id: d.agent_id,
      hostname: d.hostname,
      detection_ids: [d.id],
    });
    if (r.ok) toast.success(`Case opened from ${d.rule_name}`);
    else toast.error(r.error || `Could not open case (HTTP ${r.status})`);
  }

  async function bulkStat(rows: Detection[], s: string, clear: () => void) {
    const res = await Promise.all(rows.map((d) => postJSON(`detections/${d.id}/status`, { status: s })));
    const ok = res.filter((r) => r.ok).length;
    toast[ok === rows.length ? "success" : "error"](`${ok}/${rows.length} ${s === "closed" ? "closed" : "acknowledged"}`);
    clear();
  }

  async function bulkEscalate(rows: Detection[], clear: () => void) {
    const sevTop = rows.map((d) => d.severity).sort((a, b) => (SEV_RANK[b] || 0) - (SEV_RANK[a] || 0))[0];
    const r = await postJSON("cases", {
      title: `Case — ${rows.length} correlated detections`,
      severity: sevTop,
      detection_ids: rows.map((d) => d.id),
    });
    if (r.ok) toast.success(`Case opened from ${rows.length} detections`); else toast.error(r.error || "Could not open case");
    clear();
  }

  function recommend(d: Detection, r: Recommendation) {
    if (r.kind === "isolate") setPending({ d, type: "isolate", label: "Isolation", destructive: true, desc: `Cut all network traffic from ${d.hostname} (except the management server).` });
    else if (r.kind === "disable_account") setPending({ d, type: "disable_account", label: "Account disable", target: { user: r.user }, destructive: true, desc: `Disable login for ${r.user} on ${d.hostname}.` });
    else if (r.kind === "escalate") escalate(d);
  }

  function fields(d: Detection): Field[] {
    return [
      { label: "Rule", value: d.rule_id, mono: true },
      { label: "Summary", value: d.summary, wrap: true },
      { label: "Host", value: <button className="font-mono hover:text-primary" onClick={() => { window.location.href = `/events?agent_id=${encodeURIComponent(d.agent_id)}`; }}>{d.hostname}</button> },
      { label: "User", value: d.user ? <button className="hover:text-primary" onClick={() => { window.location.href = `/events?user=${encodeURIComponent(d.user!)}`; }}>{d.user}</button> : undefined },
      { label: "Tactic", value: d.tactic },
      { label: "ATT&CK", value: <MitreChips ids={d.mitre} /> },
      { label: "Engine", value: <Chip>{d.engine}</Chip> },
      { label: "Status", value: <StatusBadge s={d.status} /> },
      { label: "Assigned", value: d.assigned_to },
      { label: "Detected", value: new Date(d.ts).toLocaleString(), mono: true },
    ];
  }

  const columns: ColumnDef<Detection>[] = [
    { accessorKey: "severity", header: ({ column }) => <SortHeader column={column} title="Sev" />, cell: ({ row }) => <Sev s={row.original.severity} />, sortingFn: (a, b) => (SEV_RANK[a.original.severity] || 0) - (SEV_RANK[b.original.severity] || 0) },
    { accessorKey: "rule_name", header: ({ column }) => <SortHeader column={column} title="Detection" />, cell: ({ row }) => <span className="font-mono">{row.original.rule_name}</span> },
    { accessorKey: "hostname", header: ({ column }) => <SortHeader column={column} title="Host" />, cell: ({ row }) => <span className="text-muted-foreground">{row.original.hostname}</span> },
    { accessorKey: "tactic", header: "Tactic", cell: ({ row }) => <span className="text-muted-foreground">{row.original.tactic || "—"}</span> },
    { id: "mitre", header: "ATT&CK", cell: ({ row }) => <MitreChips ids={row.original.mitre} max={2} /> },
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
              <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" className="size-8" aria-label="Detection actions"><MoreHorizontal className="size-4" /></Button></DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => setStat(d, "acknowledged")}><Check className="size-4" /> Acknowledge</DropdownMenuItem>
                <DropdownMenuItem onClick={() => setStat(d, "closed")}><X className="size-4" /> Close</DropdownMenuItem>
                <DropdownMenuItem onClick={() => escalate(d)}><FolderPlus className="size-4" /> Escalate to case</DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem variant="destructive" onClick={() => setPending({ d, type: "isolate", label: "Isolation", destructive: true, desc: `Cut all network traffic from ${d.hostname} (except the management server).` })}><ShieldOff className="size-4" /> Isolate host</DropdownMenuItem>
                {d.user && d.user !== "root" && <DropdownMenuItem variant="destructive" onClick={() => setPending({ d, type: "disable_account", label: "Account disable", target: { user: d.user }, destructive: true, desc: `Disable login for ${d.user} on ${d.hostname}.` })}><UserX className="size-4" /> Disable {d.user}</DropdownMenuItem>}
                <DropdownMenuItem variant="destructive" onClick={() => setPending({ d, type: "freeze", label: "Freeze", destructive: true, desc: `Freeze all processes on ${d.hostname} (cgroup.freeze) for forensic hold.` })}><Snowflake className="size-4" /> Freeze host</DropdownMenuItem>
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
        <SelectContent>{["all", "open", "acknowledged", "closed"].map((s) => <SelectItem key={s} value={s}>{s === "all" ? "All statuses" : cap(s)}</SelectItem>)}</SelectContent>
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
        tableId="detections"
        enableSelection
        bulkActions={(rows, clear) => (
          <>
            <Button size="sm" variant="outline" onClick={() => bulkStat(rows, "acknowledged", clear)}><Check className="size-4" /> Acknowledge</Button>
            <Button size="sm" variant="outline" onClick={() => bulkStat(rows, "closed", clear)}><X className="size-4" /> Close</Button>
            <Button size="sm" variant="outline" onClick={() => bulkEscalate(rows, clear)}><FolderPlus className="size-4" /> Escalate to case</Button>
          </>
        )}
        onRowClick={(d) => setSel(d)}
        toolbar={filters}
        filterPlaceholder="Filter detections…"
        initialSort={[{ id: "ts", desc: true }]}
        empty="No detections match these filters"
        loading={all === undefined}
      />

      <InfoSheet
        open={!!sel}
        onOpenChange={(o) => !o && setSel(null)}
        title={sel?.rule_name || ""}
        sub={sel ? `${sel.severity} · ${sel.engine} engine` : ""}
        badge={sel && <Sev s={sel.severity} />}
        fields={sel ? fields(sel) : []}
        footer={sel && (
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={() => setStat(sel, "acknowledged")}><Check className="size-4" /> Acknowledge</Button>
            <Button size="sm" variant="outline" onClick={() => setStat(sel, "closed")}><X className="size-4" /> Close</Button>
            <Button size="sm" variant="outline" onClick={() => escalate(sel)}><FolderPlus className="size-4" /> Escalate</Button>
            <Button size="sm" variant="destructive" onClick={() => setPending({ d: sel, type: "isolate", label: "Isolation", destructive: true, desc: `Cut all network traffic from ${sel.hostname} (except the management server).` })}><ShieldOff className="size-4" /> Isolate</Button>
          </div>
        )}
      >
        {sel && (
          <div className="space-y-4">
            <KillChainStrip ids={sel.mitre} tactic={sel.tactic} />
            <IncidentSummary
              incident={{ severity: sel.severity, hostname: sel.hostname, agentId: sel.agent_id, user: sel.user, ruleName: sel.rule_name, summary: sel.summary, engine: sel.engine, tactic: sel.tactic, mitre: sel.mitre, eventCount: (sel.event_ids || []).length }}
              onRecommend={(r) => recommend(sel, r)}
            />
            <AiTriage detectionId={sel.id} />
            <AttackStory agentId={sel.agent_id} eventIds={sel.event_ids} onSelectEvent={(e) => setEvent(e)} />
          </div>
        )}
      </InfoSheet>

      {/* secondary drawer: an event picked from the attack story */}
      <InfoSheet
        open={!!event}
        onOpenChange={(o) => !o && setEvent(null)}
        title={event ? `${event.category} · ${event.action}` : ""}
        sub="Event detail"
        badge={event && <Sev s={event.severity} />}
        fields={event ? [
          { label: "Time", value: new Date(event.ts).toLocaleString(), mono: true },
          { label: "Host", value: event.hostname, mono: true },
          { label: "User", value: event.user },
          { label: "Message", value: event.message, wrap: true },
          { label: "Command", value: event.process?.cmdline, mono: true, wrap: true },
          { label: "File", value: event.file?.path, mono: true, wrap: true },
          { label: "SHA-256", value: event.file?.hash, mono: true, wrap: true },
          { label: "Remote", value: event.network?.remote, mono: true },
          { label: "Domain", value: event.network?.domain, mono: true },
        ] : []}
      />

      <ConfirmDialog
        open={!!pending}
        onOpenChange={(o) => !o && setPending(null)}
        title={pending ? `${pending.label} — ${pending.d.hostname}?` : ""}
        description={pending?.desc}
        confirmLabel={pending?.label}
        destructive={pending?.destructive}
        onConfirm={() => { if (pending) act(pending); setPending(null); }}
      />
    </div>
  );
}
