"use client";

import { useRouter } from "next/navigation";
import {
  Area, AreaChart, Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Sev, Chip } from "@/components/severity";
import { Metric } from "@/components/metric";
import { MitreChips } from "@/components/mitre";
import { Inspect } from "@/components/inspect";
import { useData } from "@/lib/use-data";
import { ago, compact, sevColor } from "@/lib/format";
import type { Detection, Overview } from "@/lib/types";
import { Server, Radar, Activity, FileLock2, Inbox, WifiOff, RotateCw } from "lucide-react";

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

const tip = {
  background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 10,
  fontFamily: "var(--font-geist-mono)", fontSize: 12, color: "var(--popover-foreground)",
  boxShadow: "0 8px 24px -14px color-mix(in oklch, var(--foreground) 55%, transparent)",
};

function PanelTitle({ children, live }: { children: React.ReactNode; live?: boolean }) {
  return (
    <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
      {live && <span className="live-dot size-1.5" />}
      {children}
    </CardTitle>
  );
}

export default function OverviewPage() {
  const router = useRouter();
  const { data: ov, live, refetch } = useData<Overview>("stats/overview", 4000, "detection");
  // Open detections, severity-first then most-recent — surface the loudest thing first.
  const { data: detsRaw } = useData<Detection[]>("detections?status=open&limit=40", 4000, "detection");
  const dets = (detsRaw || [])
    .slice()
    .sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) || (b.ts > a.ts ? 1 : -1))
    .slice(0, 8);
  const c = ov?.counts || {};
  const timeline = (ov?.timeline || []).map((t) => ({ t: t.hour.slice(11, 16), count: t.count }));
  const spark = timeline.map((t) => t.count);
  const sevData = SEV_ORDER.map((name) => ({ name, value: ov?.severity?.[name] || 0 })).filter((d) => d.value > 0);
  const sevTotal = sevData.reduce((n, d) => n + d.value, 0);
  const catData = Object.entries(ov?.events_by_category || {}).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  const mitre = (ov?.top_mitre || []).map((m) => ({ name: m.tactic, value: m.count }));
  const lastIdx = timeline.length - 1;

  // one-line posture readout — the SOC "where do I look first" sentence
  const posture: string | null = ov ? buildPosture(c, ov) : null;

  return (
    <div className="space-y-5">
      {!live && !ov && (
        <div className="flex items-center justify-between gap-2 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-2.5 text-sm text-destructive">
          <span className="flex items-center gap-2"><WifiOff className="size-4" strokeWidth={1.75} /> Can&apos;t reach the server. Retrying…</span>
          <button onClick={refetch} className="inline-flex items-center gap-1.5 rounded-md border border-destructive/30 px-2 py-1 text-xs font-medium hover:bg-destructive/10">
            <RotateCw className="size-3.5" /> Retry now
          </button>
        </div>
      )}

      {!ov ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i} className="py-0"><CardContent className="p-5">
              <div className="shimmer h-3 w-24 rounded bg-muted" />
              <div className="shimmer mt-4 h-8 w-20 rounded bg-muted" />
            </CardContent></Card>
          ))}
        </div>
      ) : (
        <>
          <div className="reveal grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Metric label="Endpoints" value={c.agents_total ?? 0} icon={Server} accent="var(--signal)"
              sub={<span><span style={{ color: "var(--signal)" }}>{c.agents_online ?? 0} online</span>{(c.agents_isolated ?? 0) > 0 && <span className="text-destructive"> · {c.agents_isolated} isolated</span>}</span>} />
            <Metric label="Open detections" value={c.detections_open ?? 0} icon={Radar} accent="var(--sev-critical)"
              emphasize={(c.detections_critical ?? 0) > 0}
              sub={<span className="text-destructive">{c.detections_critical ?? 0} critical</span>} />
            <Metric label="Events · 24h" value={compact(c.events_24h ?? 0)} icon={Activity} accent="var(--signal)" spark={spark} sub="events ingested" />
            <Metric label="DLP · 24h" value={c.dlp_24h ?? 0} icon={FileLock2} accent="var(--signal)" sub={`${c.responses_total ?? 0} responses sent`} />
          </div>
          {posture && (
            <p className="reveal -mt-1 text-sm text-muted-foreground">{posture}</p>
          )}
        </>
      )}

      <div className="reveal grid gap-4 xl:grid-cols-3">
        <Card className="panel overflow-hidden xl:col-span-2">
          <CardHeader><PanelTitle live>Event volume · 24h</PanelTitle></CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={230}>
              <AreaChart data={timeline} margin={{ top: 6, right: 10, left: -18, bottom: 0 }}>
                <defs>
                  <linearGradient id="ev" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--signal)" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="var(--signal)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="t" stroke="var(--muted-foreground)" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                <YAxis stroke="var(--muted-foreground)" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} width={40} />
                <Tooltip contentStyle={tip} cursor={{ stroke: "var(--signal)", strokeOpacity: 0.3 }} />
                <Area type="monotone" dataKey="count" stroke="var(--signal)" strokeWidth={2.2} fill="url(#ev)"
                  isAnimationActive animationDuration={600}
                  dot={(p: { cx?: number; cy?: number; index?: number }) =>
                    p.index === lastIdx && p.cx != null
                      ? <circle key="head" cx={p.cx} cy={p.cy} r={4} fill="var(--signal)" stroke="var(--card)" strokeWidth={2} />
                      : <g key={p.index} />} />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="panel overflow-hidden">
          <CardHeader><PanelTitle>Detections by severity</PanelTitle></CardHeader>
          <CardContent>
            {sevData.length === 0 ? <Empty>No active detections</Empty> : (
              // Length-encoded bars in fixed critical→info order: preattentive and color-blind
              // safe (a pie/donut relies on color + arc area, which both fail here).
              <div className="space-y-2.5 py-2">
                {sevData.map((d) => (
                  <div key={d.name} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="inline-flex items-center gap-1.5 capitalize">
                        <span className="size-2 rounded-[3px]" style={{ background: sevColor(d.name) }} />{d.name}
                      </span>
                      <span className="font-mono tabular-nums text-muted-foreground">{d.value}</span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-muted">
                      <div className="h-full rounded-full" style={{ width: `${Math.max(3, (d.value / sevTotal) * 100)}%`, background: sevColor(d.name) }} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="reveal grid gap-4 lg:grid-cols-2">
        <Card className="panel overflow-hidden">
          <CardHeader><PanelTitle>Events by category</PanelTitle></CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={210}>
              <BarChart data={catData} layout="vertical" margin={{ left: 16, right: 16, top: 2, bottom: 2 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="name" stroke="var(--muted-foreground)" tick={{ fontSize: 11, fontFamily: "var(--font-geist-mono)" }} tickLine={false} axisLine={false} width={74} />
                <Tooltip contentStyle={tip} cursor={{ fill: "color-mix(in oklch, var(--foreground) 6%, transparent)" }} />
                <Bar dataKey="value" radius={[0, 5, 5, 0]} barSize={13} fill="var(--chart-2)" isAnimationActive animationDuration={600}
                  cursor="pointer" onClick={(d: { name?: string; payload?: { name?: string } }) => {
                    const name = d?.name ?? d?.payload?.name;
                    if (name) router.push(`/events?category=${encodeURIComponent(name)}`);
                  }} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
        <Card className="panel overflow-hidden">
          <CardHeader><PanelTitle>ATT&amp;CK tactics</PanelTitle></CardHeader>
          <CardContent>
            {mitre.length === 0 ? <Empty>No tactics observed</Empty> : (
              <ResponsiveContainer width="100%" height={210}>
                <BarChart data={mitre} layout="vertical" margin={{ left: 28, right: 16, top: 2, bottom: 2 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="name" stroke="var(--muted-foreground)" tick={{ fontSize: 10.5, fontFamily: "var(--font-geist-mono)" }} tickLine={false} axisLine={false} width={118} />
                  <Tooltip contentStyle={tip} cursor={{ fill: "color-mix(in oklch, var(--foreground) 6%, transparent)" }} />
                  <Bar dataKey="value" radius={[0, 5, 5, 0]} barSize={13} fill="var(--chart-1)" isAnimationActive animationDuration={600} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="panel overflow-hidden">
        <CardHeader><PanelTitle live>Priority detections</PanelTitle></CardHeader>
        <CardContent className="p-0">
          {!detsRaw ? (
            <div className="divide-y">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="flex items-center gap-3 px-5 py-3">
                  <div className="shimmer h-4 w-16 rounded bg-muted" />
                  <div className="shimmer h-4 w-40 rounded bg-muted" />
                  <div className="shimmer ml-auto h-4 w-12 rounded bg-muted" />
                </div>
              ))}
            </div>
          ) : dets.length === 0 ? <Empty>No open detections — fleet is clear</Empty> : (
            <div className="divide-y">
              {dets.map((d, i) => (
                <div key={d.id} role="button" tabIndex={0}
                  onClick={() => router.push(`/detections?id=${d.id}`)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      if (e.key === " ") e.preventDefault();
                      router.push(`/detections?id=${d.id}`);
                    }
                  }}
                  className={`group flex cursor-pointer items-center gap-3 border-l-2 px-5 text-sm transition-colors hover:bg-primary/[0.04] ${
                    i === 0 && d.severity === "critical"
                      ? "border-l-[var(--sev-critical)] bg-[color-mix(in_oklch,var(--sev-critical)_5%,transparent)] py-3"
                      : "border-l-transparent py-2.5 hover:border-l-primary"
                  }`}>
                  <Sev s={d.severity} />
                  <span className="font-mono">{d.rule_name}</span>
                  <span className="text-muted-foreground">{d.hostname}</span>
                  <div className="ml-auto flex items-center gap-2">
                    <MitreChips ids={d.mitre} max={2} />
                    <Chip>{d.engine}</Chip>
                    <span className="w-16 text-right text-xs text-muted-foreground">{ago(d.ts)}</span>
                    <span className="opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100">
                      <Inspect label="Open detection" onClick={() => router.push(`/detections?id=${d.id}`)} />
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function buildPosture(c: Record<string, number>, ov: Overview): string | null {
  const parts: string[] = [];
  const crit = c.detections_critical ?? 0;
  const open = c.detections_open ?? 0;
  if (crit > 0) parts.push(`${crit} critical detection${crit === 1 ? "" : "s"} need attention`);
  else if (open > 0) parts.push(`${open} open detection${open === 1 ? "" : "s"} in the queue`);
  else parts.push("No open detections");
  if ((c.agents_isolated ?? 0) > 0) parts.push(`${c.agents_isolated} host${c.agents_isolated === 1 ? "" : "s"} isolated`);
  const offline = (c.agents_total ?? 0) - (c.agents_online ?? 0);
  if (offline > 0) parts.push(`${offline} endpoint${offline === 1 ? "" : "s"} offline`);
  const topTactic = ov.top_mitre?.[0]?.tactic;
  if (topTactic) parts.push(`busiest tactic: ${topTactic}`);
  return parts.join(" · ") + ".";
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 py-12 text-center text-sm text-muted-foreground">
      <Inbox className="size-5 opacity-50" strokeWidth={1.75} />
      {children}
    </div>
  );
}
