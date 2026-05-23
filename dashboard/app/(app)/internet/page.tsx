"use client";

import { useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Chip } from "@/components/severity";
import { useData } from "@/lib/use-data";
import { ago, bytes } from "@/lib/format";
import type { Event } from "@/lib/types";

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

export default function InternetPage() {
  const { data: events } = useData<Event[]>("events?category=network&limit=300", 4000);
  const net = (events || []).filter((e) => e.network);
  const totalOut = net.reduce((s, e) => s + (e.network!.bytes_out || 0), 0);
  const cloud = net.filter((e) => e.network!.category === "cloud_storage").length;
  const webmail = net.filter((e) => e.network!.category === "webmail").length;

  const top = useMemo(() => {
    const m: Record<string, { hits: number; out: number; cat: string }> = {};
    net.forEach((e) => {
      const d = e.network!.domain || e.network!.remote || "unknown";
      if (!m[d]) m[d] = { hits: 0, out: 0, cat: e.network!.category || "web" };
      m[d].hits++; m[d].out += e.network!.bytes_out || 0;
    });
    return Object.entries(m).sort((a, b) => b[1].out - a[1].out).slice(0, 12);
  }, [net]);

  return (
    <div className="space-y-5">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatMini label="Connections" value={net.length} />
        <StatMini label="Data Uploaded" value={bytes(totalOut)} accent="var(--primary)" />
        <StatMini label="Cloud Storage" value={cloud} accent="var(--chart-1)" />
        <StatMini label="Webmail" value={webmail} accent="var(--chart-3)" />
      </div>

      <Card>
        <CardHeader><CardTitle className="font-mono text-sm tracking-wide">TOP DESTINATIONS · by upload</CardTitle></CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader><TableRow><TableHead>Domain</TableHead><TableHead>Category</TableHead><TableHead className="text-right">Connections</TableHead><TableHead className="text-right">Uploaded</TableHead></TableRow></TableHeader>
            <TableBody>
              {top.map(([d, v]) => (
                <TableRow key={d}><TableCell className="font-mono">{d}</TableCell><TableCell><Chip color="var(--chart-2)">{v.cat}</Chip></TableCell><TableCell className="text-right font-mono">{v.hits}</TableCell><TableCell className="text-right font-mono">{bytes(v.out)}</TableCell></TableRow>
              ))}
              {top.length === 0 && <TableRow><TableCell colSpan={4} className="py-12 text-center font-mono text-sm text-muted-foreground">no internet activity captured</TableCell></TableRow>}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="font-mono text-sm tracking-wide">WEB ACTIVITY · recent</CardTitle></CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader><TableRow><TableHead>Time</TableHead><TableHead>Host</TableHead><TableHead>User</TableHead><TableHead>Domain</TableHead><TableHead>Category</TableHead><TableHead className="text-right">↑ Out</TableHead><TableHead className="text-right">↓ In</TableHead><TableHead /></TableRow></TableHeader>
            <TableBody>
              {net.slice(0, 150).map((e) => (
                <TableRow key={e.id}>
                  <TableCell className="font-mono text-xs text-muted-foreground">{ago(e.ts)}</TableCell>
                  <TableCell className="font-mono">{e.hostname}</TableCell>
                  <TableCell>{e.user || <span className="text-muted-foreground">—</span>}</TableCell>
                  <TableCell className="font-mono">{e.network!.domain || e.network!.remote}</TableCell>
                  <TableCell><Chip>{e.network!.category || "web"}</Chip></TableCell>
                  <TableCell className="text-right font-mono">{bytes(e.network!.bytes_out)}</TableCell>
                  <TableCell className="text-right font-mono text-muted-foreground">{bytes(e.network!.bytes_in)}</TableCell>
                  <TableCell>{e.network!.blocked && <Chip color="var(--sev-critical)">blocked</Chip>}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
