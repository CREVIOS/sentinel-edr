"use client";

// Fleet-management controls for a single endpoint: hot-reload its collection policy
// (watch dirs / DLP / enforcement / interval / pause) and push a verified agent update.
// Both call admin-only server endpoints; failures surface as toasts.

import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { post } from "@/lib/use-data";
import type { Agent } from "@/lib/types";
import { ShieldCheck, ScanText, Pause, RefreshCw, DownloadCloud } from "lucide-react";

function Row({ icon, title, hint, children }: { icon: React.ReactNode; title: string; hint: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 py-1.5">
      <div className="flex items-start gap-2.5">
        <span className="mt-0.5 text-muted-foreground">{icon}</span>
        <div className="space-y-0.5">
          <div className="text-sm font-medium leading-none">{title}</div>
          <div className="text-xs text-muted-foreground">{hint}</div>
        </div>
      </div>
      {children}
    </div>
  );
}

export function PolicyPanel({ agent }: { agent: Agent }) {
  const [enforce, setEnforce] = useState(true);
  const [dlp, setDlp] = useState(true);
  const [paused, setPaused] = useState(false);
  const [intervalSec, setIntervalSec] = useState("5");
  const [watch, setWatch] = useState("");
  const [busy, setBusy] = useState(false);

  // self-update inputs
  const [ver, setVer] = useState("");
  const [url, setUrl] = useState("");
  const [sha, setSha] = useState("");
  const [upBusy, setUpBusy] = useState(false);

  async function pushPolicy() {
    const n = parseInt(intervalSec, 10);
    if (!Number.isFinite(n) || n < 1 || n > 3600) {
      toast.error("Interval must be 1–3600 seconds");
      return;
    }
    const body: Record<string, unknown> = { enforce, dlp_enabled: dlp, paused, interval: n, reason: "policy push from console" };
    const dirs = watch.split("\n").map((s) => s.trim()).filter((s) => s.startsWith("/"));
    if (dirs.length) body.watch = dirs;
    setBusy(true);
    try {
      const r = await post(`agents/${agent.id}/policy`, body);
      if (r.ok) toast.success(`Policy pushed to ${agent.hostname}`);
      else toast.error(`Policy push failed (${r.status})`);
    } catch {
      toast.error("Network error — not saved");
    } finally {
      setBusy(false);
    }
  }

  async function pushUpdate() {
    if (!ver.trim()) { toast.error("Enter a target version"); return; }
    if (!/^https:\/\//.test(url)) { toast.error("URL must be https"); return; }
    if (!/^[0-9a-fA-F]{64}$/.test(sha)) { toast.error("SHA-256 must be 64 hex chars"); return; }
    setUpBusy(true);
    try {
      const r = await post(`agents/${agent.id}/upgrade`, { version: ver.trim(), url: url.trim(), sha256: sha.trim(), reason: "upgrade from console" });
      if (r.ok) {
        const j = await r.json().catch(() => ({}));
        toast.success(j?.status === "up-to-date" ? `${agent.hostname} already on ${ver}` : `Update dispatched to ${agent.hostname}`);
      } else toast.error(`Upgrade failed (${r.status})`);
    } catch {
      toast.error("Network error — not saved");
    } finally {
      setUpBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <div>
        <div className="mb-1 text-sm font-medium text-muted-foreground">Collection policy</div>
        <Row icon={<ShieldCheck className="size-4" />} title="Enforcement" hint="Permit isolate / disable / quarantine / self-update">
          <Switch checked={enforce} onCheckedChange={setEnforce} />
        </Row>
        <Row icon={<ScanText className="size-4" />} title="DLP inspection" hint="Scan watched files for secrets / PII">
          <Switch checked={dlp} onCheckedChange={setDlp} />
        </Row>
        <Row icon={<Pause className="size-4" />} title="Pause telemetry" hint="Stop events; keep heartbeat (stays online)">
          <Switch checked={paused} onCheckedChange={setPaused} />
        </Row>
        <Row icon={<RefreshCw className="size-4" />} title="Interval" hint="Collection cadence in seconds (1–3600)">
          <Input value={intervalSec} onChange={(e) => setIntervalSec(e.target.value)} inputMode="numeric" className="h-8 w-20 text-right font-mono" />
        </Row>
        <div className="mt-2 space-y-1.5">
          <Label className="text-xs text-muted-foreground">Watch directories — one absolute path per line (blank = leave unchanged)</Label>
          <Textarea value={watch} onChange={(e) => setWatch(e.target.value)} rows={3} placeholder={"/etc\n/root\n/home"} className="font-mono text-xs" />
        </div>
        <Button size="sm" className="mt-2 w-full" disabled={busy} onClick={pushPolicy}>{busy ? "Pushing…" : "Push policy"}</Button>
      </div>

      <Separator />

      <div>
        <div className="mb-1 text-sm font-medium text-muted-foreground">Agent update</div>
        <div className="mb-2 text-xs text-muted-foreground">Current: <span className="font-mono">{agent.version || "unknown"}</span></div>
        <div className="grid grid-cols-1 gap-2">
          <Input value={ver} onChange={(e) => setVer(e.target.value)} placeholder="target version e.g. 0.4.0" className="h-8 font-mono text-xs" />
          <Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…/sentinel-agent-<arch>" className="h-8 font-mono text-xs" />
          <Input value={sha} onChange={(e) => setSha(e.target.value)} placeholder="sha256 (64 hex)" className="h-8 font-mono text-xs" />
        </div>
        <Button size="sm" variant="outline" className="mt-2 w-full" disabled={upBusy} onClick={pushUpdate}><DownloadCloud className="size-4" /> {upBusy ? "Dispatching…" : "Push update"}</Button>
      </div>
    </div>
  );
}
