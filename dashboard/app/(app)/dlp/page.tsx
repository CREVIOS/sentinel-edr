"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Sev, Chip } from "@/components/severity";
import { useData } from "@/lib/use-data";
import { ago } from "@/lib/format";
import type { Event } from "@/lib/types";

interface Classifier { name: string; label: string; severity: string; }
interface Policy { Classifier: string; Channel: string; Verdict: string; }

function verdictColor(v?: string) {
  return v === "block" ? "var(--sev-critical)" : v === "alert" ? "var(--sev-high)" : "var(--muted-foreground)";
}

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

export default function DlpPage() {
  const { data: events } = useData<Event[]>("events?category=dlp&limit=200", 5000, "event");
  const { data: classifiers } = useData<Classifier[]>("dlp/classifiers", 60000);
  const { data: policies } = useData<Policy[]>("dlp/policies", 60000);
  const dlp = events || [];
  const blocked = dlp.filter((e) => e.dlp?.verdict === "block").length;

  return (
    <div className="space-y-5">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatMini label="DLP Incidents" value={dlp.length} />
        <StatMini label="Blocked Transfers" value={blocked} accent="var(--sev-critical)" />
        <StatMini label="Classifiers" value={classifiers?.length ?? 0} accent="var(--chart-2)" />
        <StatMini label="Policies" value={policies?.length ?? 0} accent="var(--primary)" />
      </div>

      <Card className="panel overflow-hidden">
        <CardHeader><CardTitle className="font-mono text-sm tracking-wide">DLP INCIDENTS</CardTitle></CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader><TableRow><TableHead>Sev</TableHead><TableHead>Classifier</TableHead><TableHead>Channel</TableHead><TableHead>Host</TableHead><TableHead>User</TableHead><TableHead>Sample</TableHead><TableHead>Verdict</TableHead><TableHead>When</TableHead></TableRow></TableHeader>
            <TableBody>
              {dlp.map((e) => (
                <TableRow key={e.id}>
                  <TableCell><Sev s={e.severity} /></TableCell>
                  <TableCell className="font-mono">{e.dlp?.classifier}</TableCell>
                  <TableCell><Chip>{e.dlp?.channel}</Chip></TableCell>
                  <TableCell className="text-muted-foreground">{e.hostname}</TableCell>
                  <TableCell>{e.user || <span className="text-muted-foreground">—</span>}</TableCell>
                  <TableCell className="font-mono text-muted-foreground">{e.dlp?.sample}</TableCell>
                  <TableCell><Chip color={verdictColor(e.dlp?.verdict)}>{e.dlp?.verdict || "—"}</Chip></TableCell>
                  <TableCell className="text-muted-foreground">{ago(e.ts)}</TableCell>
                </TableRow>
              ))}
              {dlp.length === 0 && <TableRow><TableCell colSpan={8} className="py-12 text-center font-mono text-sm text-muted-foreground">no DLP incidents</TableCell></TableRow>}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="panel overflow-hidden">
          <CardHeader><CardTitle className="font-mono text-sm tracking-wide">CLASSIFIERS</CardTitle></CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Detects</TableHead><TableHead>Severity</TableHead></TableRow></TableHeader>
              <TableBody>{(classifiers || []).map((c) => (
                <TableRow key={c.name}><TableCell className="font-mono">{c.name}</TableCell><TableCell className="text-muted-foreground">{c.label}</TableCell><TableCell><Sev s={c.severity} /></TableCell></TableRow>
              ))}</TableBody>
            </Table>
          </CardContent>
        </Card>
        <Card className="panel overflow-hidden">
          <CardHeader><CardTitle className="font-mono text-sm tracking-wide">ENFORCEMENT POLICIES</CardTitle></CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader><TableRow><TableHead>Classifier</TableHead><TableHead>Channel</TableHead><TableHead>Verdict</TableHead></TableRow></TableHeader>
              <TableBody>{(policies || []).map((p, i) => (
                <TableRow key={i}><TableCell className="font-mono">{p.Classifier}</TableCell><TableCell><Chip>{p.Channel}</Chip></TableCell><TableCell><Chip color={verdictColor(p.Verdict)}>{p.Verdict}</Chip></TableCell></TableRow>
              ))}</TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
