"use client";

import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { type ColumnDef } from "@tanstack/react-table";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { Sev, Chip } from "@/components/severity";
import { InfoSheet, type Field } from "@/components/info-sheet";
import { Inspect } from "@/components/inspect";
import { DataTable, SortHeader } from "@/components/data-table";
import { useData, post } from "@/lib/use-data";
import { ago } from "@/lib/format";
import type { Case, CaseDetail } from "@/lib/types";

const STATUSES = ["open", "investigating", "contained", "closed"];

function statusColor(s: string) {
  return s === "open" ? "var(--sev-high)"
    : s === "investigating" ? "var(--sev-medium)"
    : s === "contained" ? "var(--sev-low)"
    : "var(--muted-foreground)";
}
function CaseStatusBadge({ s }: { s: string }) {
  return <Chip color={statusColor(s)}>{s}</Chip>;
}

export default function CasesPage() {
  const [status, setStatus] = useState("all");
  const [selId, setSelId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [note, setNote] = useState("");
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
      { label: "ATT&CK", value: <div className="flex flex-wrap gap-1">{(c.mitre || []).map((m) => <Chip key={m} color="var(--chart-1)">{m}</Chip>)}</div> },
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
    <Select value={status} onValueChange={setStatus}>
      <SelectTrigger className="h-8 w-44"><SelectValue /></SelectTrigger>
      <SelectContent>{["all", ...STATUSES].map((s) => <SelectItem key={s} value={s}>{s === "all" ? "All statuses" : s}</SelectItem>)}</SelectContent>
    </Select>
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
        empty="no cases — detections auto-correlate into cases as they fire"
      />

      <InfoSheet
        open={!!selId}
        onOpenChange={(o) => !o && setSelId(null)}
        title={detail?.title || "Case"}
        sub={detail ? `${detail.severity} · ${detail.status}` : ""}
        badge={detail && <Sev s={detail.severity} />}
        fields={detail ? fields(detail) : []}
      >
        {detail && (
          <div className="space-y-4">
            {/* lifecycle controls */}
            <div className="flex flex-wrap items-center gap-2">
              <Select value={detail.status} onValueChange={(v) => update(detail.id, { status: v }, `Case → ${v}`)}>
                <SelectTrigger className="h-8 w-40"><SelectValue /></SelectTrigger>
                <SelectContent>{STATUSES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent>
              </Select>
              <Button size="sm" variant="outline" onClick={() => update(detail.id, { assigned_to: "me" }, "Assigned to you")}>Assign to me</Button>
            </div>

            <Separator />

            {/* linked detections */}
            <div>
              <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Linked detections ({detail.detections?.length || 0})</div>
              <div className="space-y-1.5">
                {(detail.detections || []).map((d) => (
                  <div key={d.id} className="flex items-start gap-2 rounded-md border border-border/60 p-2 text-sm">
                    <Sev s={d.severity} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-mono text-xs">{d.rule_name}</div>
                      <div className="truncate text-xs text-muted-foreground">{d.summary}</div>
                    </div>
                    <span className="shrink-0 text-xs text-muted-foreground">{ago(d.ts)}</span>
                  </div>
                ))}
                {(!detail.detections || detail.detections.length === 0) && <div className="text-xs text-muted-foreground">none</div>}
              </div>
            </div>

            <Separator />

            {/* notes / timeline */}
            <div>
              <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Notes</div>
              <div className="space-y-2">
                {(detail.notes || []).map((n, i) => (
                  <div key={i} className="rounded-md bg-muted/40 p-2 text-sm">
                    <div className="mb-0.5 flex items-center justify-between text-xs text-muted-foreground">
                      <span className="font-medium text-foreground">{n.author}</span>
                      <span>{new Date(n.ts).toLocaleString()}</span>
                    </div>
                    <div className="whitespace-pre-wrap">{n.body}</div>
                  </div>
                ))}
                {(!detail.notes || detail.notes.length === 0) && <div className="text-xs text-muted-foreground">no notes yet</div>}
              </div>
              <div className="mt-2 space-y-2">
                <Textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} placeholder="Add an investigation note…" className="text-sm" />
                <Button size="sm" className="w-full" disabled={!note.trim()} onClick={() => addNote(detail.id)}>Add note</Button>
              </div>
            </div>
          </div>
        )}
      </InfoSheet>
    </div>
  );
}
