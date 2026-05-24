"use client";

import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sev, Chip } from "@/components/severity";
import { InfoSheet, type Field } from "@/components/info-sheet";
import { useData, post } from "@/lib/use-data";
import { ago } from "@/lib/format";
import type { Detection } from "@/lib/types";
import { MoreHorizontal, Check, X, ShieldOff } from "lucide-react";

export default function DetectionsPage() {
  const [status, setStatus] = useState("all");
  const [sev, setSev] = useState("all");
  const [sel, setSel] = useState<Detection | null>(null);
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

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
          <SelectContent>{["all", "open", "acknowledged", "closed"].map((s) => <SelectItem key={s} value={s}>{s === "all" ? "All statuses" : s}</SelectItem>)}</SelectContent>
        </Select>
        <Select value={sev} onValueChange={setSev}>
          <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
          <SelectContent>{["all", "critical", "high", "medium", "low"].map((s) => <SelectItem key={s} value={s}>{s === "all" ? "All severities" : s}</SelectItem>)}</SelectContent>
        </Select>
        <Chip>{dets.length} detections</Chip>
      </div>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow><TableHead>Sev</TableHead><TableHead>Detection</TableHead><TableHead>Host</TableHead><TableHead>Tactic</TableHead><TableHead>ATT&amp;CK</TableHead><TableHead>Engine</TableHead><TableHead>Status</TableHead><TableHead>When</TableHead><TableHead /></TableRow>
            </TableHeader>
            <TableBody>
              {dets.map((d) => (
                <TableRow key={d.id} onClick={() => setSel(d)} className="cursor-pointer">
                  <TableCell><Sev s={d.severity} /></TableCell>
                  <TableCell className="font-mono">{d.rule_name}</TableCell>
                  <TableCell className="text-muted-foreground">{d.hostname}</TableCell>
                  <TableCell className="text-muted-foreground">{d.tactic || "—"}</TableCell>
                  <TableCell><div className="flex flex-wrap gap-1">{(d.mitre || []).map((m) => <Chip key={m} color="var(--chart-1)">{m}</Chip>)}</div></TableCell>
                  <TableCell><Chip>{d.engine}</Chip></TableCell>
                  <TableCell><StatusBadge s={d.status} /></TableCell>
                  <TableCell className="text-muted-foreground">{ago(d.ts)}</TableCell>
                  <TableCell onClick={(e) => e.stopPropagation()}>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" className="size-8"><MoreHorizontal className="size-4" /></Button></DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => setStat(d, "acknowledged")}><Check className="size-4" /> Acknowledge</DropdownMenuItem>
                        <DropdownMenuItem onClick={() => setStat(d, "closed")}><X className="size-4" /> Close</DropdownMenuItem>
                        <DropdownMenuItem variant="destructive" onClick={() => respond(d, "isolate")}><ShieldOff className="size-4" /> Isolate host</DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
              {dets.length === 0 && <TableRow><TableCell colSpan={9} className="py-12 text-center font-mono text-sm text-muted-foreground">no detections</TableCell></TableRow>}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

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
            <Button size="sm" variant="destructive" onClick={() => respond(sel, "isolate")}><ShieldOff className="size-4" /> Isolate host</Button>
          </div>
        )}
      </InfoSheet>
    </div>
  );
}

function StatusBadge({ s }: { s: string }) {
  const color = s === "open" ? "var(--sev-high)" : s === "acknowledged" ? "var(--sev-low)" : "var(--muted-foreground)";
  return <Chip color={color}>{s}</Chip>;
}
