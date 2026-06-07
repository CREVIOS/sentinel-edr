"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { useTheme } from "next-themes";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useSession, signOut, authClient } from "@/lib/auth-client";
import { useData } from "@/lib/use-data";
import { compact } from "@/lib/format";
import type { Overview } from "@/lib/types";
import { TwoFactor } from "@/components/two-factor";
import {
  Activity, Cpu, Radio, Download, Copy, KeyRound, LogOut, Sun, Moon,
  ShieldCheck, Server, Loader2, CheckCircle2, AlertTriangle,
} from "lucide-react";

function copy(text: string, label: string) {
  navigator.clipboard.writeText(text).then(
    () => toast.success(`${label} copied`),
    () => toast.error("Copy failed"),
  );
}

async function download(kind: string, format: string, filename: string) {
  try {
    const res = await fetch(`/api/proxy/siem/export?kind=${kind}&format=${format}`, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
    toast.success(`Exported ${filename}`);
  } catch (e) {
    toast.error(`Export failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

function StatusBadge({ ok }: { ok: boolean }) {
  return ok ? (
    <Badge className="gap-1.5 border-transparent bg-[color-mix(in_oklch,var(--signal)_18%,transparent)] text-[var(--signal)]">
      <CheckCircle2 className="size-3.5" /> Operational
    </Badge>
  ) : (
    <Badge className="gap-1.5 border-transparent bg-[color-mix(in_oklch,var(--destructive)_18%,transparent)] text-destructive">
      <AlertTriangle className="size-3.5" /> Unreachable
    </Badge>
  );
}

function ActivityBadge({ active }: { active: boolean }) {
  return active ? (
    <Badge className="gap-1.5 border-transparent bg-[color-mix(in_oklch,var(--signal)_18%,transparent)] text-[var(--signal)]">
      <Activity className="size-3.5" /> Active
    </Badge>
  ) : (
    <Badge variant="secondary" className="gap-1.5 border-transparent text-muted-foreground">
      <Radio className="size-3.5" /> Idle
    </Badge>
  );
}

export default function SettingsPage() {
  const { data: session } = useSession();
  const { data: ov, live } = useData<Overview>("stats/overview", 6000, "detection");
  const c = ov?.counts || {};

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <Tabs defaultValue="system">
        <TabsList>
          <TabsTrigger value="system">System</TabsTrigger>
          <TabsTrigger value="account">Account</TabsTrigger>
          <TabsTrigger value="agents">Agents</TabsTrigger>
          <TabsTrigger value="siem">SIEM</TabsTrigger>
          <TabsTrigger value="appearance">Appearance</TabsTrigger>
        </TabsList>

        {/* SYSTEM */}
        <TabsContent value="system" className="space-y-4">
          <Card>
            <CardHeader><CardTitle className="text-sm font-medium text-muted-foreground">Service health</CardTitle><CardDescription>Live status of platform tiers</CardDescription></CardHeader>
            <CardContent className="grid gap-3 sm:grid-cols-2">
              {ov === undefined ? (
                Array.from({ length: 2 }).map((_, i) => (
                  <div key={i} className="shimmer h-[58px] rounded-lg bg-muted" />
                ))
              ) : (
                <>
                  <div className="flex items-center gap-3 rounded-lg border bg-secondary/30 p-3.5">
                    <Server className="size-4 text-muted-foreground" />
                    <span className="text-sm">Control plane</span>
                    <span className="ml-auto"><StatusBadge ok={live} /></span>
                  </div>
                  <div className="flex items-center gap-3 rounded-lg border bg-secondary/30 p-3.5">
                    <Radio className="size-4 text-muted-foreground" />
                    <span className="text-sm">Recent telemetry (24h)</span>
                    <span className="ml-auto"><ActivityBadge active={(c.events_24h ?? 0) > 0} /></span>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {ov === undefined ? (
              Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="shimmer h-[104px] rounded-xl bg-muted" />
              ))
            ) : (
              [
                { label: "Endpoints", value: c.agents_total ?? 0, sub: `${c.agents_online ?? 0} online`, icon: ShieldCheck },
                { label: "Events · 24h", value: compact(c.events_24h ?? 0), sub: "ingested", icon: Activity },
                { label: "Open detections", value: c.detections_open ?? 0, sub: `${c.detections_critical ?? 0} critical`, icon: AlertTriangle },
                { label: "Responses", value: c.responses_total ?? 0, sub: "issued", icon: Cpu },
              ].map((k) => (
                <Card key={k.label}><CardContent className="p-4">
                  <div className="flex items-center justify-between"><span className="text-xs font-medium text-muted-foreground">{k.label}</span><k.icon className="size-4 text-muted-foreground" /></div>
                  <div className="mt-2 font-mono text-2xl font-semibold tabular-nums">{k.value}</div>
                  <div className="mt-1 text-xs text-muted-foreground">{k.sub}</div>
                </CardContent></Card>
              ))
            )}
          </div>

          <Card>
            <CardHeader><CardTitle className="text-sm font-medium text-muted-foreground">Deployment</CardTitle></CardHeader>
            <CardContent>
              <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
                {[
                  ["Console", "Sentinel v1.0 · Next.js 16"],
                  ["Auth", "Better Auth · session cookie"],
                  ["Event store", "TimescaleDB hypertables · 90-day retention"],
                  ["Event bus", "NATS JetStream (durable)"],
                  ["Detection", "Sigma rules + behavioral correlator"],
                  ["Transport", "HTTPS + mTLS-ready · WebSocket control mesh"],
                ].map(([k, v]) => (
                  <div key={k} className="flex items-center justify-between gap-4 border-b pb-2 text-sm last:border-0">
                    <dt className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">{k}</dt>
                    <dd className="text-right">{v}</dd>
                  </div>
                ))}
              </dl>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ACCOUNT */}
        <TabsContent value="account" className="space-y-4">
          <Card>
            <CardHeader><CardTitle className="text-sm font-medium text-muted-foreground">Operator</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
                <Row k="Name" v={session?.user?.name || "—"} />
                <Row k="Email" v={<span className="font-mono">{session?.user?.email || "—"}</span>} />
                <Row k="Role" v={<Badge className="border-transparent bg-primary/15 text-primary">{(session?.user as { role?: string })?.role || "analyst"}</Badge>} />
                <Row k="Console" v="Sentinel v1.0" />
              </dl>
              <Separator />
              <Button variant="outline" onClick={() => signOut({ fetchOptions: { onSuccess: () => location.assign("/login") } })}>
                <LogOut className="size-4" /> Sign out
              </Button>
            </CardContent>
          </Card>
          <ChangePassword />
          <TwoFactor />
        </TabsContent>

        {/* AGENTS */}
        <TabsContent value="agents" className="space-y-4">
          <EnrollPanel />
        </TabsContent>

        {/* SIEM */}
        <TabsContent value="siem" className="space-y-4">
          <Card>
            <CardHeader><CardTitle className="text-sm font-medium text-muted-foreground">SIEM integration</CardTitle><CardDescription>Export normalized telemetry for Splunk / Elastic / QRadar.</CardDescription></CardHeader>
            <CardContent className="grid gap-2 sm:grid-cols-3">
              <Button variant="outline" className="justify-start font-mono" onClick={() => download("events", "cef", "sentinel-events.cef")}><Download className="size-4" /> Events · CEF</Button>
              <Button variant="outline" className="justify-start font-mono" onClick={() => download("events", "ecs", "sentinel-events-ecs.ndjson")}><Download className="size-4" /> Events · ECS</Button>
              <Button variant="outline" className="justify-start font-mono" onClick={() => download("detections", "cef", "sentinel-detections.cef")}><Download className="size-4" /> Detections · CEF</Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* APPEARANCE */}
        <TabsContent value="appearance" className="space-y-4">
          <ThemePicker />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b pb-2 text-sm last:border-0">
      <dt className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">{k}</dt>
      <dd className="text-right">{v}</dd>
    </div>
  );
}

function Code({ children }: { children: React.ReactNode }) {
  return <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px]">{children}</code>;
}

function EnrollPanel() {
  // The command auto-fills this console's own URL so it is copy-paste correct for this
  // deployment (origin is only available after mount, so it is read client-side).
  const [origin, setOrigin] = useState("");
  useEffect(() => setOrigin(window.location.origin), []);
  const server = origin || "https://<your-console>";

  const quick =
    `curl -fsSL ${server}/install-agent.sh | sudo \\\n` +
    `  SENTINEL_SERVER=${server} \\\n` +
    `  SENTINEL_ENROLL_TOKEN=<ENROLL_TOKEN> \\\n` +
    `  SENTINEL_REQUIRE_CHECKSUM=1 SENTINEL_REQUIRE_SIGNATURE=1 bash`;

  const docker =
    `docker run -d --name sentinel-agent --restart unless-stopped \\\n` +
    `  --pid host --cap-add NET_ADMIN \\\n` +
    `  -e SENTINEL_SERVER=${server} \\\n` +
    `  -e SENTINEL_ENROLL_TOKEN=<ENROLL_TOKEN> \\\n` +
    `  sentinel/agent:latest`;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium text-muted-foreground">Enroll an endpoint</CardTitle>
        <CardDescription>Run on a Linux host to install the agent and enroll it into the fleet.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <CommandBlock title="Quick install (Linux)" cmd={quick} />
        <CommandBlock title="Docker" cmd={docker} />
        <div className="space-y-2 text-xs leading-relaxed text-muted-foreground">
          <p>
            Replace <Code>&lt;ENROLL_TOKEN&gt;</Code> with the value of <Code>SENTINEL_ENROLL_TOKEN</Code> configured
            on the server. The same token enrolls any number of hosts; each agent is then issued its own per-host key.
          </p>
          <p>
            The installer is HTTPS-pinned and verifies the agent against a published SHA-256 and an Ed25519
            signature before installing. <Code>SENTINEL_REQUIRE_CHECKSUM=1</Code> and
            <Code>SENTINEL_REQUIRE_SIGNATURE=1</Code> fail closed if either is missing. It then installs and enables a
            hardened <Code>systemd</Code> service that restarts on crash and reboot.
          </p>
          <p>
            Manage with <Code>systemctl status sentinel-agent</Code>, follow logs with
            <Code>journalctl -u sentinel-agent -f</Code>, and enable mutual TLS via
            <Code>SENTINEL_AGENT_TLS_CA</Code> / <Code>_CERT</Code> / <Code>_KEY</Code>.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

function CommandBlock({ title, cmd }: { title: string; cmd: string }) {
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between">
        <span className="text-xs font-medium text-muted-foreground">{title}</span>
        <Button size="sm" variant="ghost" className="h-7 gap-1.5 text-xs" onClick={() => copy(cmd.replace(/\\\n\s*/g, " "), title + " command")}><Copy className="size-3.5" /> Copy</Button>
      </div>
      <pre className="overflow-x-auto rounded-lg border bg-secondary/40 p-3.5 font-mono text-xs leading-relaxed text-foreground">{cmd}</pre>
    </div>
  );
}

function ChangePassword() {
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (next.length < 8) { toast.error("New password must be ≥ 8 characters"); return; }
    setBusy(true);
    const { error } = await authClient.changePassword({ currentPassword: cur, newPassword: next, revokeOtherSessions: true });
    setBusy(false);
    if (error) toast.error(error.message || "Could not change password");
    else { toast.success("Password updated · other sessions revoked"); setCur(""); setNext(""); }
  }

  return (
    <Card>
      <CardHeader><CardTitle className="text-sm font-medium text-muted-foreground">Change password</CardTitle></CardHeader>
      <CardContent>
        <form onSubmit={submit} className="grid max-w-md gap-3">
          <div className="space-y-1.5">
            <Label htmlFor="cur" className="text-xs font-medium text-muted-foreground">Current</Label>
            <Input id="cur" type="password" value={cur} onChange={(e) => setCur(e.target.value)} required />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="np" className="text-xs font-medium text-muted-foreground">New (min 8)</Label>
            <Input id="np" type="password" value={next} onChange={(e) => setNext(e.target.value)} required />
          </div>
          <Button type="submit" className="w-fit" disabled={busy}>
            {busy ? <Loader2 className="size-4 animate-spin" /> : <KeyRound className="size-4" />} Update password
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function ThemePicker() {
  const { theme, setTheme } = useTheme();
  const opts = [
    { id: "dark", label: "Dark", icon: Moon, desc: "Low-light SOC default" },
    { id: "light", label: "Light", icon: Sun, desc: "Bright surfaces · high ambient light" },
    { id: "system", label: "System", icon: Activity, desc: "Match OS preference" },
  ];
  return (
    <Card>
      <CardHeader><CardTitle className="text-sm font-medium text-muted-foreground">Theme</CardTitle><CardDescription>Centralized color tokens; switches instantly.</CardDescription></CardHeader>
      <CardContent className="grid gap-3 sm:grid-cols-3">
        {opts.map((o) => {
          const active = theme === o.id;
          return (
            <button
              key={o.id}
              onClick={() => { setTheme(o.id); toast.success(`Theme: ${o.label}`); }}
              className={`rounded-xl border p-4 text-left transition ${active ? "border-primary bg-primary/5" : "hover:bg-secondary/40"}`}
            >
              <o.icon className="size-5 text-primary" />
              <div className="mt-2 text-sm font-medium">{o.label}</div>
              <div className="text-xs text-muted-foreground">{o.desc}</div>
            </button>
          );
        })}
      </CardContent>
    </Card>
  );
}
