"use client";

import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Sev, Chip } from "@/components/severity";
import { useData } from "@/lib/use-data";
import type { Rule } from "@/lib/types";

function StatMini({ label, value, accent }: { label: string; value: React.ReactNode; accent?: string }) {
  return (
    <Card className="transition-colors hover:border-foreground/15">
      <CardContent className="p-5">
        <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
        <div className="mt-3 font-mono text-[2rem] font-semibold leading-none tabular-nums">{value}</div>
      </CardContent>
    </Card>
  );
}

export default function RulesPage() {
  const { data: rules } = useData<Rule[]>("rules", 60000);
  const [q, setQ] = useState("");
  const all = rules || [];
  const rows = useMemo(
    () => all.filter((r) => !q || `${r.Title} ${r.ID} ${r.Tactic} ${(r.MITRE || []).join(" ")}`.toLowerCase().includes(q.toLowerCase())),
    [all, q]
  );
  const withResp = all.filter((r) => r.AutoRespond).length;
  const tactics = new Set(all.map((r) => r.Tactic).filter(Boolean)).size;

  return (
    <div className="space-y-5">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatMini label="Detection Rules" value={all.length} />
        <StatMini label="ATT&CK Tactics" value={tactics} accent="var(--chart-1)" />
        <StatMini label="Auto-Response" value={withResp} accent="var(--chart-2)" />
        <StatMini label="Behavioral" value={4} accent="var(--chart-3)" />
      </div>
      <div className="flex items-center gap-2">
        <Input placeholder="Search rules, tactics, technique IDs…" value={q} onChange={(e) => setQ(e.target.value)} className="max-w-sm" />
        <Chip>{rows.length} rules</Chip>
      </div>
      <Card>
        <CardHeader><CardTitle className="font-mono text-sm tracking-wide">DETECTION RULE CATALOG · Sigma · MITRE ATT&amp;CK</CardTitle></CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader><TableRow><TableHead>Sev</TableHead><TableHead>Rule</TableHead><TableHead>Category</TableHead><TableHead>Tactic</TableHead><TableHead>ATT&amp;CK</TableHead><TableHead>Auto-Response</TableHead></TableRow></TableHeader>
            <TableBody>
              {rows.map((r) => (
                <TableRow key={r.ID}>
                  <TableCell><Sev s={r.Severity} /></TableCell>
                  <TableCell><div className="font-mono">{r.Title}</div><div className="text-xs text-muted-foreground">{r.ID}</div></TableCell>
                  <TableCell><Chip>{r.Category}</Chip></TableCell>
                  <TableCell className="text-muted-foreground">{r.Tactic || "—"}</TableCell>
                  <TableCell><div className="flex flex-wrap gap-1">{(r.MITRE || []).map((m) => <Chip key={m} color="var(--chart-1)">{m}</Chip>)}</div></TableCell>
                  <TableCell>{r.AutoRespond ? <Chip color="var(--chart-2)">{r.AutoRespond}</Chip> : <span className="text-muted-foreground">—</span>}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
