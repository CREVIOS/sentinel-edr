"use client";

import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { type ColumnDef } from "@tanstack/react-table";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import { Sev, Chip } from "@/components/severity";
import { InfoSheet, type Field } from "@/components/info-sheet";
import { Inspect } from "@/components/inspect";
import { DataTable, SortHeader } from "@/components/data-table";
import { MitreChips, KillChainStrip } from "@/components/mitre";
import { IncidentSummary } from "@/components/incident-summary";
import { AttackStory } from "@/components/attack-story";
import { useData, post, postJSON } from "@/lib/use-data";
import { ago } from "@/lib/format";
import type { Case, CaseDetail, Event } from "@/lib/types";
import { Plus } from "lucide-react";

const STATUSES = ["open", "investigating", "contained", "closed"];

function cap(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
function statusColor(s: string) {
  return s === "open" ? "var(--sev-high)"
    : s === "investigating" ? "var(--sev-medium)"
    : s === "contained" ? "var(--sev-low)"
    : "var(--muted-foreground)";
}
function CaseStatusBadge({ s }: { s: string }) {
  return <Chip color={statusColor(s)}>{cap(s)}</Chip>;
}

export default function CasesPage() {
  const [status, setStatus] = useState("all");
  const [selId, setSelId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [note, setNote] = useState("");
  const [event, setEvent] = useState<Event | null>(null);
  const path = useMemo(() => `cases?limit=300${status !== "all" ? `&status=${status}` : ""}`, [status]);
  const { data: cases } = useData<Case[]>(path, 4000, "case");

  // hydrate the selected case (linked detections + notes) on open and on live updates
  useEffect(() => {
    if (!selId) { setDetail(null); return; }
    let on = true;
    const load = async () => {
      try {
        const r = await fetch(`/api/proxy/cases/${selId}`, { cache: "no-store" });
        if (r.ok && on) setDetail(await r.json());
      } catch { /* keep last */ }
    };
    load();
    return () => { on = false; };
  }, [selId, cases]);

  async function update(id: string, body: Record<string, unknown>, ok: string) {
    const r = await post(`cases/${id}`, body);
    if (r.ok) { toast.success(ok); setDetail(await r.json()); }
    else toast.error(`Failed (${r.status})`);
  }
  async function addNote(id: string) {
    if (!note.trim()) return;
    const r = await post(`cases/${id}/notes`, { body: note });
    if (r.ok) { toast.success("Note added"); setDetail(await r.json()); setNote(""); }
    else toast.error("Failed to add note");
  }

  function fields(c: CaseDetail): Field[] {
    return [
      { label: "Case ID", value: c.id, mono: true, wrap: true },
      { label: "Status", value: <CaseStatusBadge s={c.status} /> },
      { label: "Severity", value: <Sev s={c.severity} /> },
      { label: "Host", value: c.hostname || "—", mono: true },
      { label: "Assigned", value: c.assigned_to || "unassigned" },
      { label: "Detections", value: String(c.detection_ids?.length || 0), mono: true },
      { label: "ATT&CK", value: <MitreChips ids={c.mitre} /> },
      { label: "Opened", value: new Date(c.created_at).toLocaleString(), mono: true },
      { label: "Updated", value: `${ago(c.updated_at)} · ${new Date(c.updated_at).toLocaleString()}`, mono: true, wrap: true },
      { label: "Opened by", value: c.created_by || "—" },
    ];
  }

  const columns: ColumnDef<Case>[] = [
    { accessorKey: "severity", header: ({ column }) => <SortHeader column={column} title="Sev" />, cell: ({ row }) => <Sev s={row.original.severity} /> },
    { accessorKey: "title", header: ({ column }) => <SortHeader column={column} title="Case" />, cell: ({ row }) => <span className="font-medium">{row.original.title}</span> },
    { accessorKey: "hostname", header: "Host", cell: ({ row }) => <span className="font-mono text-muted-foreground">{row.original.hostname || "—"}</span> },
    { id: "count", header: "Detections", cell: ({ row }) => <span className="font-mono tabular-nums">{row.original.detection_ids?.length || 0}</span> },
    { accessorKey: "assigned_to", header: "Assigned", cell: ({ row }) => <span className="text-muted-foreground">{row.original.assigned_to || "—"}</span> },
    { accessorKey: "status", header: ({ column }) => <SortHeader column={column} title="Status" />, cell: ({ row }) => <CaseStatusBadge s={row.original.status} /> },
    { accessorKey: "updated_at", header: ({ column }) => <SortHeader column={column} title="Updated" />, cell: ({ row }) => <span className="text-muted-foreground">{ago(row.original.updated_at)}</span> },
    {
      id: "actions", enableHiding: false,
      cell: ({ row }) => (
        <div className="flex items-center justify-end" onClick={(e) => e.stopPropagation()}>
          <Inspect onClick={() => setSelId(row.original.id)} />
        </div>
      ),
    },
  ];

  const filters = (
    <>
      <Select value={status} onValueChange={setStatus}>
        <SelectTrigger className="h-8 w-44"><SelectValue /></SelectTrigger>
        <SelectContent>{["all", ...STATUSES].map((s) => <SelectItem key={s} value={s}>{s === "all" ? "All statuses" : cap(s)}</SelectItem>)}</SelectContent>
      </Select>
      <NewCase onCreated={(id) => setSelId(id)} />
    </>
  );

  return (
    <div className="reveal space-y-4">
      <DataTable
        columns={columns}
        data={cases || []}
        rowId={(c) => c.id}
        onRowClick={(c) => setSelId(c.id)}
        toolbar={filters}
        filterPlaceholder="Filter cases…"
        initialSort={[{ id: "updated_at", desc: true }]}
        loading={cases === undefined}
        empty="No cases yet. Detections fold into cases automatically — or open one with “New case” or by escalating a detection."
      />

      <InfoSheet
        open={!!selId}
        onOpenChange={(o) => !o && setSelId(null)}
        title={detail?.title || "Case"}
        sub={detail ? `${detail.severity} · ${cap(detail.status)}` : ""}
        badge={detail && <Sev s={detail.severity} />}
        fields={detail ? fields(detail) : []}
        footer={detail && (
          <div className="flex items-end gap-2">
            <Textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              rows={1}
              placeholder="Add an investigation note…"
              className="max-h-28 min-h-9 flex-1 resize-none text-sm"
              onKeyDown={(e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) addNote(detail.id); }}
            />
            <Button size="sm" className="shrink-0" disabled={!note.trim()} onClick={() => addNote(detail.id)}>Add note</Button>
          </div>
        )}
      >
        {detail && (
          <div className="space-y-4">
            <KillChainStrip ids={detail.mitre} />
            <IncidentSummary incident={{ severity: detail.severity, hostname: detail.hostname, mitre: detail.mitre, detectionCount: detail.detections?.length || detail.detection_ids?.length || 0 }} />

            {/* lifecycle controls */}
            <div className="flex flex-wrap items-center gap-2">
              <Select value={detail.status} onValueChange={(v) => update(detail.id, { status: v }, `Case marked ${v}`)}>
                <SelectTrigger className="h-8 w-40"><SelectValue /></SelectTrigger>
                <SelectContent>{STATUSES.map((s) => <SelectItem key={s} value={s}>{cap(s)}</SelectItem>)}</SelectContent>
              </Select>
              <Button size="sm" variant="outline" onClick={() => update(detail.id, { assigned_to: "me" }, "Assigned to you")}>Assign to me</Button>
            </div>

            <Separator />

            {/* linked detections */}
            <div>
              <div className="mb-2 text-sm font-medium text-muted-foreground">Linked detections ({detail.detections?.length || 0})</div>
              <div className="space-y-1.5">
                {(detail.detections || []).map((d) => (
                  <button
                    key={d.id}
                    onClick={() => { window.location.href = `/detections?id=${d.id}`; }}
                    className="flex w-full items-start gap-2 rounded-md border border-border/60 p-2 text-left text-sm transition-colors hover:border-primary/40 hover:bg-primary/[0.04]"
                  >
                    <div className="shrink-0"><Sev s={d.severity} /></div>
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-mono text-xs">{d.rule_name}</div>
                      <div className="truncate text-xs text-muted-foreground">{d.summary}</div>
                    </div>
                    <span className="shrink-0 whitespace-nowrap text-xs text-muted-foreground">{ago(d.ts)}</span>
                  </button>
                ))}
                {(!detail.detections || detail.detections.length === 0) && <div className="text-xs text-muted-foreground">No linked detections</div>}
              </div>
            </div>

            <Separator />

            {/* attack story aggregated across the case's host */}
            {(() => {
              const agentId = detail.agent_id || detail.detections?.[0]?.agent_id;
              const eventIds = (detail.detections || []).flatMap((d) => d.event_ids || []);
              return agentId ? (
                <>
                  <div>
                    <div className="mb-2 text-sm font-medium text-muted-foreground">Attack story</div>
                    <AttackStory agentId={agentId} eventIds={eventIds} onSelectEvent={(e) => setEvent(e)} />
                  </div>
                  <Separator />
                </>
              ) : null;
            })()}

            {/* notes timeline (composer is pinned in the footer) */}
            <div>
              <div className="mb-2 text-sm font-medium text-muted-foreground">Notes</div>
              <div className="space-y-2">
                {(detail.notes || []).map((n, i) => (
                  <div key={i} className="rounded-md bg-muted/40 p-2 text-sm">
                    <div className="mb-0.5 flex items-center justify-between gap-2 text-xs text-muted-foreground">
                      <span className="truncate font-medium text-foreground">{n.author}</span>
                      <span className="shrink-0 whitespace-nowrap">{new Date(n.ts).toLocaleString()}</span>
                    </div>
                    <div className="whitespace-pre-wrap break-words">{n.body}</div>
                  </div>
                ))}
                {(!detail.notes || detail.notes.length === 0) && <div className="text-xs text-muted-foreground">No notes yet</div>}
              </div>
            </div>
          </div>
        )}
      </InfoSheet>

      {/* secondary drawer: an event picked from the case attack story */}
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
          { label: "Remote", value: event.network?.remote, mono: true },
          { label: "Domain", value: event.network?.domain, mono: true },
        ] : []}
      />
    </div>
  );
}

function NewCase({ onCreated }: { onCreated: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [hostname, setHostname] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (!title.trim()) { toast.error("Title required"); return; }
    setBusy(true);
    const r = await postJSON("cases", { title: title.trim(), severity, hostname: hostname.trim() || undefined, detection_ids: [] });
    setBusy(false);
    if (r.ok) {
      toast.success("Case opened");
      setOpen(false); setTitle(""); setHostname("");
      const id = (r.data as { id?: string } | undefined)?.id;
      if (id) onCreated(id);
    } else toast.error(r.error || `Could not create case (HTTP ${r.status})`);
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild><Button size="sm"><Plus className="size-4" /> New case</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Open a case</DialogTitle>
          <DialogDescription>Cases group related detections for investigation. You can also escalate a detection straight into a case from the Detections page.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label className="text-xs text-muted-foreground">Title</Label>
            <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Suspected credential theft on web-01" />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Severity</Label>
              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>{["critical", "high", "medium", "low", "info"].map((s) => <SelectItem key={s} value={s}>{cap(s)}</SelectItem>)}</SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Host (optional)</Label>
              <Input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="hostname" className="font-mono text-sm" />
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
          <Button disabled={busy} onClick={submit}>{busy ? "Opening…" : "Open case"}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
