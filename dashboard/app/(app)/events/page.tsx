"use client";

import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sev, Chip } from "@/components/severity";
import { InfoSheet, type Field } from "@/components/info-sheet";
import { Inspect } from "@/components/inspect";
import { LineageTree } from "@/components/lineage-tree";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { useLiveList, useDebounced, respond } from "@/lib/use-data";
import { bytes, detail, shortTime } from "@/lib/format";
import type { Event } from "@/lib/types";
import { X, Skull, ListX, FileLock2, UserX } from "lucide-react";

const CATS = ["all", "process", "file", "network", "auth", "ssh", "usb", "package", "dlp", "system"];
const SEVS = ["all", "critical", "high", "medium", "low", "info"];

type Pending = { e: Event; type: string; label: string; target: Record<string, unknown>; desc: string };

export default function EventsPage() {
  const [cat, setCat] = useState("all");
  const [sev, setSev] = useState("all");
  const [q, setQ] = useState("");
  const [agentId, setAgentId] = useState("");
  const [user, setUser] = useState("");
  const [live, setLive] = useState(true);
  const [sel, setSel] = useState<Event | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);

  // Hydrate filters from the URL so pivots (host / user / category / search) deep-link here.
  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    if (p.get("category")) setCat(p.get("category")!);
    if (p.get("severity")) setSev(p.get("severity")!);
    if (p.get("q")) setQ(p.get("q")!);
    if (p.get("agent_id")) setAgentId(p.get("agent_id")!);
    if (p.get("user")) setUser(p.get("user")!);
  }, []);

  const dq = useDebounced(q, 300);
  const basePath = useMemo(() => {
    const p = new URLSearchParams();
    if (cat !== "all") p.set("category", cat);
    if (sev !== "all") p.set("severity", sev);
    if (dq) p.set("q", dq);
    if (agentId) p.set("agent_id", agentId);
    if (user) p.set("user", user);
    const qs = p.toString();
    return qs ? `events?${qs}` : "events";
  }, [cat, sev, dq, agentId, user]);

  const { items: events, loading, loadingMore, hasMore, connected, loadMore } =
    useLiveList<Event>(basePath, {
      pageSize: 100, liveMs: 2000, live,
      // real-time push prepends matching events instantly; disabled while a text/host/user
      // filter is active (server-side scope can't be replicated client-side), falling to poll.
      pushType: dq || agentId || user ? undefined : "event",
      pushFilter: (e) => (cat === "all" || e.category === cat) && (sev === "all" || e.severity === sev),
    });

  async function act(p: Pending) {
    const r = await respond({ type: p.type, agentId: p.e.agent_id, target: p.target, reason: `manual ${p.type} from event` });
    if (r.ok) toast.success(`${p.label} dispatched to ${p.e.hostname}`);
    else toast.error(r.error || `Action failed (HTTP ${r.status})`);
  }

  function pivotUser(u: string) { setUser(u); setSel(null); }
  function pivotSearch(s: string) { setQ(s); setSel(null); }

  function eventFields(e: Event): Field[] {
    const f: Field[] = [
      { label: "Time", value: new Date(e.ts).toLocaleString(), mono: true },
      { label: "Category", value: <Chip>{e.category}</Chip> },
      { label: "Action", value: e.action, mono: true },
      { label: "Host", value: e.hostname, mono: true },
      { label: "User", value: e.user ? <button className="hover:text-primary" onClick={() => pivotUser(e.user!)}>{e.user}</button> : undefined },
      { label: "Message", value: e.message, wrap: true },
    ];
    if (e.process) f.push(
      { label: "Process", value: `${e.process.name} (pid ${e.process.pid})`, mono: true },
      { label: "Process user", value: e.process.user ? `${e.process.user} (uid ${e.process.uid ?? 0})` : undefined, mono: true },
      { label: "Lineage", value: <LineageTree lineage={e.process.lineage || e.process.parent} />, wrap: true },
      { label: "Container", value: e.process.container, mono: true },
      { label: "Command", value: e.process.cmdline, mono: true, wrap: true },
    );
    if (e.file) f.push(
      { label: "File", value: e.file.path, mono: true, wrap: true },
      { label: "Operation", value: e.file.op },
      { label: "SHA-256", value: e.file.hash ? <button className="break-all text-left hover:text-primary" onClick={() => pivotSearch(e.file!.hash!)}>{e.file.hash}</button> : undefined, mono: true, wrap: true },
    );
    if (e.network) f.push(
      { label: "Domain", value: e.network.domain ? <button className="hover:text-primary" onClick={() => pivotSearch(e.network!.domain!)}>{e.network.domain}</button> : undefined, mono: true },
      { label: "Remote", value: e.network.remote, mono: true },
      { label: "Network category", value: e.network.category },
      { label: "Uploaded", value: bytes(e.network.bytes_out), mono: true },
      { label: "Downloaded", value: bytes(e.network.bytes_in), mono: true },
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

  // Context-aware response actions for the open event.
  function eventActions(e: Event): React.ReactNode {
    const btns: React.ReactNode[] = [];
    if (e.process?.pid) {
      btns.push(
        <Button key="kill" size="sm" variant="destructive" onClick={() => setPending({ e, type: "kill_process", label: "Kill process", target: { pid: e.process!.pid }, desc: `Send SIGKILL to pid ${e.process!.pid} (${e.process!.name}) on ${e.hostname}.` })}><Skull className="size-4" /> Kill process</Button>,
        <Button key="killtree" size="sm" variant="outline" onClick={() => setPending({ e, type: "kill_tree", label: "Kill process tree", target: { pid: e.process!.pid }, desc: `Kill pid ${e.process!.pid} and all descendants (cgroup-aware) on ${e.hostname}.` })}><ListX className="size-4" /> Kill tree</Button>,
      );
    }
    if (e.file?.path) {
      btns.push(
        <Button key="quar" size="sm" variant="outline" onClick={() => setPending({ e, type: "quarantine_file", label: "Quarantine file", target: { path: e.file!.path, hash: e.file!.hash }, desc: `Move ${e.file!.path} to quarantine (chmod 000, checksummed) on ${e.hostname}.` })}><FileLock2 className="size-4" /> Quarantine file</Button>,
      );
    }
    if (e.user && e.user !== "root") {
      btns.push(
        <Button key="disable" size="sm" variant="outline" onClick={() => setPending({ e, type: "disable_account", label: "Disable account", target: { user: e.user }, desc: `Disable login for ${e.user} on ${e.hostname}.` })}><UserX className="size-4" /> Disable {e.user}</Button>,
      );
    }
    return btns.length ? <div className="flex flex-wrap gap-2">{btns}</div> : null;
  }

  const activeFilters: { label: string; clear: () => void }[] = [];
  if (agentId) activeFilters.push({ label: `host ${agentId.slice(0, 12)}…`, clear: () => setAgentId("") });
  if (user) activeFilters.push({ label: `user ${user}`, clear: () => setUser("") });

  return (
    <div className="reveal space-y-4">
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
          aria-pressed={live}
          aria-label={live ? "Pause live tail" : "Resume live tail"}
          className={`inline-flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-sm font-medium transition-colors hover:bg-secondary/50 ${live && connected ? "border-[color-mix(in_oklch,var(--signal)_45%,transparent)] text-[var(--signal)]" : "text-muted-foreground"}`}
        >
          {live && connected ? <span className="live-dot size-2" /> : <span className="size-2 rounded-full bg-muted-foreground" />}
          {live ? "Live" : "Paused"}
        </button>
        <Chip>{events.length} loaded</Chip>
        {activeFilters.map((f) => (
          <button key={f.label} onClick={f.clear} className="inline-flex items-center gap-1 rounded-md border border-primary/40 bg-primary/[0.06] px-2 py-1 font-mono text-xs text-primary hover:bg-primary/10">
            {f.label} <X className="size-3" />
          </button>
        ))}
      </div>

      <Card className="panel overflow-hidden">
        <CardContent className="p-0">
          <Table aria-busy={loading || undefined}>
            <TableHeader>
              <TableRow><TableHead className="w-20">Time</TableHead><TableHead className="w-24">Severity</TableHead><TableHead className="w-28">Category</TableHead><TableHead>Host</TableHead><TableHead>User</TableHead><TableHead>Detail</TableHead><TableHead className="w-10" /></TableRow>
            </TableHeader>
            <TableBody>
              {events.map((e) => (
                <TableRow key={e.id} onClick={() => setSel(e)} className="group cursor-pointer">
                  <TableCell className="font-mono text-xs text-muted-foreground">{shortTime(e.ts)}</TableCell>
                  <TableCell><Sev s={e.severity} /></TableCell>
                  <TableCell className="text-muted-foreground"><span className="font-mono text-xs">{e.category}</span></TableCell>
                  <TableCell className="font-mono">{e.hostname}</TableCell>
                  <TableCell>{e.user || <span className="text-muted-foreground">—</span>}</TableCell>
                  <TableCell><span className="block max-w-[42rem] truncate font-mono text-xs text-muted-foreground">{detail(e)}</span></TableCell>
                  <TableCell onClick={(ev) => ev.stopPropagation()} className="text-right">
                    <span className="opacity-0 transition-opacity group-hover:opacity-100"><Inspect onClick={() => setSel(e)} /></span>
                  </TableCell>
                </TableRow>
              ))}
              {loading && events.length === 0 && Array.from({ length: 8 }).map((_, i) => (
                <TableRow key={`skeleton-${i}`}>
                  <TableCell><div className="shimmer h-4 w-16 rounded bg-muted" /></TableCell>
                  <TableCell><div className="shimmer h-4 w-16 rounded bg-muted" /></TableCell>
                  <TableCell><div className="shimmer h-4 w-20 rounded bg-muted" /></TableCell>
                  <TableCell><div className="shimmer h-4 w-28 rounded bg-muted" /></TableCell>
                  <TableCell><div className="shimmer h-4 w-24 rounded bg-muted" /></TableCell>
                  <TableCell><div className="shimmer h-4 w-40 rounded bg-muted" /></TableCell>
                  <TableCell />
                </TableRow>
              ))}
              {!loading && events.length === 0 && (
                <TableRow><TableCell colSpan={7} className="py-12 text-center text-sm text-muted-foreground">No events match your filters. Live telemetry will appear here as it streams in.</TableCell></TableRow>
              )}
            </TableBody>
          </Table>
          <div className="flex items-center justify-center border-t p-3">
            {hasMore ? (
              <Button variant="outline" size="sm" onClick={loadMore} disabled={loadingMore}>
                {loadingMore ? "Loading…" : "Load older events"}
              </Button>
            ) : (
              <span className="font-mono text-xs text-muted-foreground">End of results</span>
            )}
          </div>
        </CardContent>
      </Card>

      <InfoSheet
        open={!!sel}
        onOpenChange={(o) => !o && setSel(null)}
        title={sel ? `${sel.category} · ${sel.action}` : ""}
        sub="Event detail"
        badge={sel && <Sev s={sel.severity} />}
        fields={sel ? eventFields(sel) : []}
        footer={sel ? eventActions(sel) : null}
      />

      <ConfirmDialog
        open={!!pending}
        onOpenChange={(o) => !o && setPending(null)}
        title={pending ? `${pending.label} — ${pending.e.hostname}?` : ""}
        description={pending?.desc}
        confirmLabel={pending?.label}
        destructive
        onConfirm={() => { if (pending) act(pending); setPending(null); }}
      />
    </div>
  );
}
