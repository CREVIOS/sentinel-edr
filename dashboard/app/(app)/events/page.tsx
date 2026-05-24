"use client";

import { useMemo, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sev, Chip } from "@/components/severity";
import { InfoSheet, type Field } from "@/components/info-sheet";
import { useLiveList, useDebounced } from "@/lib/use-data";
import { bytes, detail, shortTime } from "@/lib/format";
import type { Event } from "@/lib/types";

const CATS = ["all", "process", "file", "network", "auth", "ssh", "usb", "package", "dlp", "system"];
const SEVS = ["all", "critical", "high", "medium", "low", "info"];

function eventFields(e: Event): Field[] {
  const f: Field[] = [
    { label: "Time", value: new Date(e.ts).toLocaleString(), mono: true },
    { label: "Category", value: <Chip>{e.category}</Chip> },
    { label: "Action", value: e.action, mono: true },
    { label: "Host", value: e.hostname, mono: true },
    { label: "User", value: e.user },
    { label: "Message", value: e.message, wrap: true },
  ];
  if (e.process) f.push(
    { label: "Process", value: `${e.process.name} (pid ${e.process.pid})`, mono: true },
    { label: "User", value: e.process.user ? `${e.process.user} (uid ${e.process.uid ?? 0})` : undefined, mono: true },
    { label: "Lineage", value: e.process.lineage || e.process.parent, mono: true, wrap: true },
    { label: "Container", value: e.process.container, mono: true },
    { label: "Command", value: e.process.cmdline, mono: true, wrap: true },
  );
  if (e.file) f.push(
    { label: "File", value: e.file.path, mono: true, wrap: true },
    { label: "Operation", value: e.file.op },
    { label: "SHA-256", value: e.file.hash, mono: true, wrap: true },
  );
  if (e.network) f.push(
    { label: "Domain", value: e.network.domain, mono: true },
    { label: "Remote", value: e.network.remote, mono: true },
    { label: "Category", value: e.network.category },
    { label: "Transfer", value: `↑ ${bytes(e.network.bytes_out)} · ↓ ${bytes(e.network.bytes_in)}`, mono: true },
  );
  if (e.usb) f.push(
    { label: "Device", value: `${e.usb.vendor} ${e.usb.product}` },
    { label: "Serial", value: e.usb.serial, mono: true },
  );
  if (e.auth) f.push(
    { label: "Method", value: e.auth.method },
    { label: "Source IP", value: e.auth.source_ip, mono: true },
    { label: "Result", value: e.auth.result },
  );
  if (e.dlp) f.push(
    { label: "Classifier", value: e.dlp.classifier, mono: true },
    { label: "Channel", value: e.dlp.channel },
    { label: "Sample", value: e.dlp.sample, mono: true },
    { label: "Verdict", value: e.dlp.verdict },
  );
  return f;
}

export default function EventsPage() {
  const [cat, setCat] = useState("all");
  const [sev, setSev] = useState("all");
  const [q, setQ] = useState("");
  const [live, setLive] = useState(true);
  const [sel, setSel] = useState<Event | null>(null);
  const dq = useDebounced(q, 300);
  const basePath = useMemo(() => {
    const p = new URLSearchParams();
    if (cat !== "all") p.set("category", cat);
    if (sev !== "all") p.set("severity", sev);
    if (dq) p.set("q", dq);
    const qs = p.toString();
    return qs ? `events?${qs}` : "events";
  }, [cat, sev, dq]);
  const { items: events, loading, loadingMore, hasMore, connected, loadMore } =
    useLiveList<Event>(basePath, {
      pageSize: 100, liveMs: 2000, live,
      // real-time push prepends matching events instantly; disabled while a text search is
      // active (server-side search can't be replicated client-side), falling back to poll.
      pushType: dq ? undefined : "event",
      pushFilter: (e) => (cat === "all" || e.category === cat) && (sev === "all" || e.severity === sev),
    });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input placeholder="Search command, path, domain, user…" value={q} onChange={(e) => setQ(e.target.value)} className="max-w-xs" />
        <Select value={cat} onValueChange={setCat}>
          <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
          <SelectContent>{CATS.map((c) => <SelectItem key={c} value={c}>{c === "all" ? "All categories" : c}</SelectItem>)}</SelectContent>
        </Select>
        <Select value={sev} onValueChange={setSev}>
          <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
          <SelectContent>{SEVS.map((s) => <SelectItem key={s} value={s}>{s === "all" ? "All severities" : s}</SelectItem>)}</SelectContent>
        </Select>
        <button
          onClick={() => setLive((v) => !v)}
          className="inline-flex items-center gap-2 rounded-md border px-2.5 py-1.5 font-mono text-[11px] uppercase tracking-wider text-muted-foreground transition-colors hover:bg-secondary/50"
        >
          <span className="size-2 rounded-full" style={{ background: live && connected ? "var(--chart-2)" : "var(--muted-foreground)" }} />
          {live ? "live" : "paused"}
        </button>
        <Chip>{events.length} loaded</Chip>
      </div>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow><TableHead className="w-20">Time</TableHead><TableHead className="w-24">Sev</TableHead><TableHead className="w-28">Category</TableHead><TableHead>Host</TableHead><TableHead>User</TableHead><TableHead>Detail</TableHead></TableRow>
            </TableHeader>
            <TableBody>
              {events.map((e) => (
                <TableRow key={e.id} onClick={() => setSel(e)} className="cursor-pointer">
                  <TableCell className="font-mono text-xs text-muted-foreground">{shortTime(e.ts)}</TableCell>
                  <TableCell><Sev s={e.severity} /></TableCell>
                  <TableCell className="text-muted-foreground"><span className="font-mono text-xs">{e.category}</span></TableCell>
                  <TableCell className="font-mono">{e.hostname}</TableCell>
                  <TableCell>{e.user || <span className="text-muted-foreground">—</span>}</TableCell>
                  <TableCell><span className="block max-w-[42rem] truncate font-mono text-xs text-chart-2">{detail(e)}</span></TableCell>
                </TableRow>
              ))}
              {!loading && events.length === 0 && (
                <TableRow><TableCell colSpan={6} className="py-12 text-center font-mono text-sm text-muted-foreground">no events match — telemetry streams here live</TableCell></TableRow>
              )}
            </TableBody>
          </Table>
          <div className="flex items-center justify-center border-t p-3">
            {hasMore ? (
              <Button variant="outline" size="sm" onClick={loadMore} disabled={loadingMore}>
                {loadingMore ? "Loading…" : "Load older events"}
              </Button>
            ) : (
              <span className="font-mono text-xs text-muted-foreground">end of results</span>
            )}
          </div>
        </CardContent>
      </Card>

      <InfoSheet
        open={!!sel}
        onOpenChange={(o) => !o && setSel(null)}
        title={sel ? `${sel.category} · ${sel.action}` : ""}
        sub="event detail"
        badge={sel && <Sev s={sel.severity} />}
        fields={sel ? eventFields(sel) : []}
      />
    </div>
  );
}
