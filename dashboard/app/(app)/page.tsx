"use client";

import {
  Area, AreaChart, Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Sev, Chip } from "@/components/severity";
import { useData } from "@/lib/use-data";
import { ago, compact, sevColor } from "@/lib/format";
import type { Detection, Overview } from "@/lib/types";
import { MonitorSmartphone, ShieldAlert, Activity, FileLock2 } from "lucide-react";

const tip = {
  background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 10,
  fontFamily: "var(--font-jetbrains)", fontSize: 12, color: "var(--popover-foreground)",
};

function Stat({ label, value, sub, icon: Icon }: { label: string; value: React.ReactNode; sub?: React.ReactNode; icon: any; accent?: string }) {
  return (
    <Card className="transition-colors hover:border-foreground/15">
      <CardContent className="p-5">
        <div className="flex items-center justify-between">
          <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">{label}</span>
          <Icon className="size-4 text-muted-foreground/70" strokeWidth={1.75} />
        </div>
        <div className="mt-3 font-mono text-[2rem] font-semibold leading-none tabular-nums">{value}</div>
        {sub && <div className="mt-2 text-xs text-muted-foreground">{sub}</div>}
      </CardContent>
    </Card>
  );
}

export default function OverviewPage() {
  const { data: ov } = useData<Overview>("stats/overview", 4000, "detection");
  const { data: dets } = useData<Detection[]>("detections?limit=8", 4000, "detection");
  const c = ov?.counts || {};
  const timeline = (ov?.timeline || []).map((t) => ({ t: t.hour.slice(11, 16), count: t.count }));
  const sevData = Object.entries(ov?.severity || {}).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value }));
  const catData = Object.entries(ov?.events_by_category || {}).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  const mitre = (ov?.top_mitre || []).map((m) => ({ name: m.tactic, value: m.count }));

  return (
    <div className="space-y-5">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Endpoints" value={c.agents_total ?? 0} icon={MonitorSmartphone}
          sub={<span><span style={{ color: "var(--chart-2)" }}>{c.agents_online ?? 0} online</span>{(c.agents_isolated ?? 0) > 0 && <span className="text-destructive"> · {c.agents_isolated} isolated</span>}</span>} />
        <Stat label="Open Detections" value={c.detections_open ?? 0} icon={ShieldAlert} accent="var(--sev-critical)"
          sub={<span className="text-destructive">{c.detections_critical ?? 0} critical</span>} />
        <Stat label="Events · 24h" value={compact(c.events_24h ?? 0)} icon={Activity} accent="var(--chart-2)" sub="telemetry ingested" />
        <Stat label="DLP · 24h" value={c.dlp_24h ?? 0} icon={FileLock2} accent="var(--chart-1)" sub={`${c.responses_total ?? 0} responses issued`} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader><CardTitle className="font-mono text-sm tracking-wide">EVENT VOLUME · 24h</CardTitle></CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={230}>
              <AreaChart data={timeline} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
                <defs>
                  <linearGradient id="ev" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="var(--primary)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="t" stroke="var(--muted-foreground)" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                <YAxis stroke="var(--muted-foreground)" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} width={40} />
                <Tooltip contentStyle={tip} cursor={{ stroke: "var(--primary)", strokeOpacity: 0.3 }} />
                <Area type="monotone" dataKey="count" stroke="var(--primary)" strokeWidth={2} fill="url(#ev)" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="font-mono text-sm tracking-wide">DETECTIONS BY SEVERITY</CardTitle></CardHeader>
          <CardContent>
            {sevData.length === 0 ? <Empty>no active detections</Empty> : (
              <>
                <ResponsiveContainer width="100%" height={170}>
                  <PieChart>
                    <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={78} paddingAngle={3} stroke="none">
                      {sevData.map((d) => <Cell key={d.name} fill={sevColor(d.name)} />)}
                    </Pie>
                    <Tooltip contentStyle={tip} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="mt-2 flex flex-wrap justify-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                  {sevData.map((d) => (
                    <span key={d.name} className="inline-flex items-center gap-1.5">
                      <span className="size-2 rounded-[2px]" style={{ background: sevColor(d.name) }} />{d.name} · {d.value}
                    </span>
                  ))}
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle className="font-mono text-sm tracking-wide">EVENTS BY DOMAIN</CardTitle></CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={210}>
              <BarChart data={catData} layout="vertical" margin={{ left: 16, right: 16, top: 2, bottom: 2 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="name" stroke="var(--muted-foreground)" tick={{ fontSize: 11, fontFamily: "var(--font-jetbrains)" }} tickLine={false} axisLine={false} width={74} />
                <Tooltip contentStyle={tip} cursor={{ fill: "color-mix(in oklch, var(--foreground) 6%, transparent)" }} />
                <Bar dataKey="value" radius={[0, 5, 5, 0]} barSize={13} fill="var(--chart-2)" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="font-mono text-sm tracking-wide">ATT&amp;CK TACTICS</CardTitle></CardHeader>
          <CardContent>
            {mitre.length === 0 ? <Empty>no tactics observed yet</Empty> : (
              <ResponsiveContainer width="100%" height={210}>
                <BarChart data={mitre} layout="vertical" margin={{ left: 28, right: 16, top: 2, bottom: 2 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="name" stroke="var(--muted-foreground)" tick={{ fontSize: 10.5, fontFamily: "var(--font-jetbrains)" }} tickLine={false} axisLine={false} width={118} />
                  <Tooltip contentStyle={tip} cursor={{ fill: "color-mix(in oklch, var(--foreground) 6%, transparent)" }} />
                  <Bar dataKey="value" radius={[0, 5, 5, 0]} barSize={13} fill="var(--chart-1)" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader><CardTitle className="font-mono text-sm tracking-wide">LATEST DETECTIONS</CardTitle></CardHeader>
        <CardContent className="p-0">
          {!dets || dets.length === 0 ? <Empty>awaiting telemetry…</Empty> : (
            <div className="divide-y">
              {dets.map((d) => (
                <div key={d.id} className="flex items-center gap-3 px-5 py-2.5 text-sm">
                  <Sev s={d.severity} />
                  <span className="font-mono">{d.rule_name}</span>
                  <span className="text-muted-foreground">{d.hostname}</span>
                  <div className="ml-auto flex items-center gap-2">
                    {(d.mitre || []).slice(0, 2).map((m) => <Chip key={m} color="var(--chart-1)">{m}</Chip>)}
                    <Chip>{d.engine}</Chip>
                    <span className="w-16 text-right text-xs text-muted-foreground">{ago(d.ts)}</span>
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

function Empty({ children }: { children: React.ReactNode }) {
  return <div className="py-12 text-center font-mono text-sm text-muted-foreground">{children}</div>;
}
