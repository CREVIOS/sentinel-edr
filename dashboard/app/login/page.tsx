"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { signIn } from "@/lib/auth-client";
import { SentinelMark } from "@/components/logo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Loader2, ArrowRight, Radar, FileLock2, Crosshair } from "lucide-react";

const FEATURES = [
  { icon: Radar, title: "Endpoint EDR", desc: "Process, file, auth, USB & network telemetry in real time." },
  { icon: FileLock2, title: "Data Loss Prevention", desc: "Content classification with policy-based enforcement." },
  { icon: Crosshair, title: "Automated Response", desc: "Kill · isolate · disable · block — by rule or one click." },
];

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("admin@sentinel.local");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => { fetch("/api/bootstrap").catch(() => {}); }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    const { error } = await signIn.email({ email, password });
    setBusy(false);
    if (error) { setErr(error.message || "Authentication failed"); toast.error("Authentication failed"); }
    else { toast.success("Welcome back"); router.push("/"); }
  }

  return (
    <div className="grid h-dvh overflow-hidden lg:grid-cols-2">
      {/* Brand panel */}
      <aside className="relative hidden border-r bg-sidebar lg:flex lg:flex-col lg:justify-between lg:p-14">
        <div className="grid-veil pointer-events-none absolute inset-0 opacity-[0.4]" />
        <div className="relative flex items-center gap-3">
          <SentinelMark className="size-8 text-primary" />
          <div className="font-mono text-base font-semibold tracking-[0.32em]">SENTINEL</div>
        </div>

        <div className="relative max-w-md">
          <h2 className="text-balance text-[2.6rem] font-semibold leading-[1.08] tracking-tight">
            Linux endpoint security,<br />
            <span className="text-muted-foreground">end to end.</span>
          </h2>
          <p className="mt-5 font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">
            Monitor · Detect · Prevent · Respond
          </p>
          <div className="mt-10 space-y-5">
            {FEATURES.map((f) => (
              <div key={f.title} className="flex items-start gap-3.5">
                <f.icon className="mt-0.5 size-5 shrink-0 text-foreground/70" strokeWidth={1.5} />
                <div>
                  <div className="text-sm font-medium">{f.title}</div>
                  <div className="text-[13px] leading-relaxed text-muted-foreground">{f.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="relative font-mono text-[11px] tracking-wide text-muted-foreground">
          security operations console · v1.0
        </div>
      </aside>

      {/* Sign-in panel */}
      <main className="flex items-center justify-center p-6">
        <div className="w-full max-w-sm">
          <div className="mb-9 flex items-center gap-2.5 lg:hidden">
            <SentinelMark className="size-7 text-primary" />
            <span className="font-mono text-base font-semibold tracking-[0.3em]">SENTINEL</span>
          </div>

          <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
          <p className="mb-7 mt-1.5 text-sm text-muted-foreground">Authenticate to the command console.</p>

          <form onSubmit={submit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email" className="text-xs text-muted-foreground">Operator email</Label>
              <Input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus required />
            </div>
            <div className="space-y-2">
              <Label htmlFor="pw" className="text-xs text-muted-foreground">Passphrase</Label>
              <Input id="pw" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" required />
            </div>
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? <Loader2 className="size-4 animate-spin" /> : <>Sign in <ArrowRight className="size-4" /></>}
            </Button>
            {err && <p className="text-sm text-destructive">{err}</p>}
          </form>
          <p className="mt-7 font-mono text-[11px] text-muted-foreground">dev · admin@sentinel.local / sentinel-admin</p>
        </div>
      </main>
    </div>
  );
}
