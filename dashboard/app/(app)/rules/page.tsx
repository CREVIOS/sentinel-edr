"use client";

import { useMemo, useState } from "react";
import { toast } from "sonner";
import { type ColumnDef } from "@tanstack/react-table";
import { Sev, Chip } from "@/components/severity";
import { Metric } from "@/components/metric";
import { DataTable, SortHeader } from "@/components/data-table";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import { useData, post, del } from "@/lib/use-data";
import { ago } from "@/lib/format";
import type { Rule, Suppression } from "@/lib/types";
import { ScrollText, Crosshair, Bot, BellOff, Trash2, Plus } from "lucide-react";

const FIELDS = ["host", "user", "agent", "summary", "rule"];

export default function RulesPage() {
  const [bump, setBump] = useState(0);
  const { data: rules } = useData<Rule[]>(`rules?r=${bump}`, 60000);
  const { data: supps } = useData<Suppression[]>(`suppressions?r=${bump}`, 15000);
  const all = rules || [];
  const reload = () => setBump((b) => b + 1);

  const withResp = all.filter((r) => r.AutoRespond).length;
  const tactics = new Set(all.map((r) => r.Tactic).filter(Boolean)).size;
  const disabled = all.filter((r) => !r.Enabled).length;

  async function toggle(r: Rule, enabled: boolean) {
    const res = await post(`rules/${r.ID}/toggle`, { enabled });
    if (res.ok) { toast.success(`${r.Title} ${enabled ? "enabled" : "disabled"}`); reload(); }
    else toast.error(res.status === 403 ? "Admin role required" : `Failed (${res.status})`);
  }
  async function removeSupp(s: Suppression) {
    const res = await del(`suppressions/${s.id}`);
    if (res.ok) { toast.success("Suppression removed"); reload(); }
    else toast.error(`Failed (${res.status})`);
  }

  const columns: ColumnDef<Rule>[] = useMemo(() => [
    { accessorKey: "Severity", header: ({ column }) => <SortHeader column={column} title="Sev" />, cell: ({ row }) => <Sev s={row.original.Severity} /> },
    { accessorKey: "Title", header: ({ column }) => <SortHeader column={column} title="Rule" />, cell: ({ row }) => <div><div className="font-mono">{row.original.Title}</div><div className="text-xs text-muted-foreground">{row.original.ID}</div></div> },
    { accessorKey: "Category", header: "Category", cell: ({ row }) => <Chip>{row.original.Category}</Chip> },
    { accessorKey: "Tactic", header: ({ column }) => <SortHeader column={column} title="Tactic" />, cell: ({ row }) => <span className="text-muted-foreground">{row.original.Tactic || "—"}</span> },
    { id: "mitre", header: "ATT&CK", cell: ({ row }) => <div className="flex flex-wrap gap-1">{(row.original.MITRE || []).map((m) => <Chip key={m} color="var(--chart-1)">{m}</Chip>)}</div> },
    { accessorKey: "AutoRespond", header: "Auto-Response", cell: ({ row }) => row.original.AutoRespond ? <Chip color="var(--signal)">{row.original.AutoRespond}</Chip> : <span className="text-muted-foreground">—</span> },
    {
      id: "enabled", header: "Enabled", enableHiding: false,
      cell: ({ row }) => (
        <div onClick={(e) => e.stopPropagation()}>
          <Switch checked={row.original.Enabled} onCheckedChange={(v) => toggle(row.original, v)} />
        </div>
      ),
    },
  ], []);

  const suppCols: ColumnDef<Suppression>[] = [
    { accessorKey: "rule_id", header: "Rule", cell: ({ row }) => <span className="font-mono text-xs">{row.original.rule_id === "*" ? "any rule" : row.original.rule_id}</span> },
    { id: "match", header: "Match", cell: ({ row }) => <span className="font-mono text-xs">{row.original.field} {row.original.op === "contains" ? "⊃" : "="} {row.original.value}</span> },
    { accessorKey: "hits", header: ({ column }) => <SortHeader column={column} title="Silenced" />, cell: ({ row }) => <span className="font-mono tabular-nums">{row.original.hits || 0}</span> },
    { accessorKey: "reason", header: "Reason", cell: ({ row }) => <span className="text-muted-foreground">{row.original.reason || "—"}</span> },
    { accessorKey: "created_by", header: "By", cell: ({ row }) => <span className="text-muted-foreground">{row.original.created_by || "—"}</span> },
    { accessorKey: "created_at", header: "Added", cell: ({ row }) => <span className="text-muted-foreground">{ago(row.original.created_at)}</span> },
    {
      id: "actions", enableHiding: false,
      cell: ({ row }) => (
        <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
          <Button variant="ghost" size="icon" className="size-8" onClick={() => removeSupp(row.original)}><Trash2 className="size-4" /></Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <div className="reveal grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Detection Rules" value={all.length} icon={ScrollText} />
        <Metric label="ATT&CK Tactics" value={tactics} icon={Crosshair} accent="var(--chart-1)" />
        <Metric label="Auto-Response" value={withResp} icon={Bot} accent="var(--signal)" />
        <Metric label="Disabled" value={disabled} icon={BellOff} accent="var(--sev-medium)" />
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

      <div>
        <div className="mb-3 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold">Suppressions</h2>
            <p className="text-xs text-muted-foreground">Silence known-benign activity without disabling a whole rule.</p>
          </div>
          <NewSuppression rules={all} onCreated={reload} />
        </div>
        <DataTable
          columns={suppCols}
          data={supps || []}
          rowId={(s) => s.id}
          filterPlaceholder="Filter suppressions…"
          pageSize={10}
          empty="no suppressions"
        />
      </div>
    </div>
  );
}

function NewSuppression({ rules, onCreated }: { rules: Rule[]; onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [ruleId, setRuleId] = useState("*");
  const [field, setField] = useState("host");
  const [op, setOp] = useState("equals");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (!value.trim()) { toast.error("Value required"); return; }
    setBusy(true);
    const r = await post("suppressions", { rule_id: ruleId, field, op, value: value.trim(), reason });
    setBusy(false);
    if (r.ok) { toast.success("Suppression added"); setOpen(false); setValue(""); setReason(""); onCreated(); }
    else toast.error(r.status === 403 ? "Analyst role required" : `Failed (${r.status})`);
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild><Button size="sm"><Plus className="size-4" /> Add suppression</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New suppression</DialogTitle>
          <DialogDescription>Matching detections are silenced before they alert or auto-respond.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label className="text-xs text-muted-foreground">Rule</Label>
            <Select value={ruleId} onValueChange={setRuleId}>
              <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="*">Any rule</SelectItem>
                {rules.map((r) => <SelectItem key={r.ID} value={r.ID}>{r.ID}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Field</Label>
              <Select value={field} onValueChange={setField}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>{FIELDS.map((f) => <SelectItem key={f} value={f}>{f}</SelectItem>)}</SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Operator</Label>
              <Select value={op} onValueChange={setOp}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="equals">equals</SelectItem>
                  <SelectItem value="contains">contains</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs text-muted-foreground">Value</Label>
            <Input value={value} onChange={(e) => setValue(e.target.value)} placeholder="e.g. ci-runner-01" className="font-mono text-sm" />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs text-muted-foreground">Reason (optional)</Label>
            <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="why this is benign" className="text-sm" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
          <Button disabled={busy} onClick={submit}>{busy ? "Adding…" : "Add suppression"}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
