"use client";

import { useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { toast } from "sonner";
import { authClient, useSession } from "@/lib/auth-client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { ShieldCheck, ShieldAlert, Loader2, Copy } from "lucide-react";

type Step = "idle" | "password" | "verify" | "disable";

export function TwoFactor() {
  const { data: session, refetch } = useSession();
  const enabled = Boolean((session?.user as { twoFactorEnabled?: boolean })?.twoFactorEnabled);

  const [step, setStep] = useState<Step>("idle");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [uri, setUri] = useState("");
  const [backup, setBackup] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  function reset() {
    setStep("idle"); setPassword(""); setCode(""); setUri(""); setBackup([]); setBusy(false);
  }

  async function startEnable(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    const { data, error } = await authClient.twoFactor.enable({ password });
    setBusy(false);
    if (error) { toast.error(error.message || "Incorrect password"); return; }
    setUri(data?.totpURI || "");
    setBackup(data?.backupCodes || []);
    setStep("verify");
  }

  async function verify(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    const { error } = await authClient.twoFactor.verifyTotp({ code });
    setBusy(false);
    if (error) { toast.error(error.message || "Invalid code"); return; }
    toast.success("Two-factor authentication enabled");
    reset(); refetch?.();
  }

  async function disable(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    const { error } = await authClient.twoFactor.disable({ password });
    setBusy(false);
    if (error) { toast.error(error.message || "Incorrect password"); return; }
    toast.success("Two-factor authentication disabled");
    reset(); refetch?.();
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <div>
            <CardTitle className="text-sm font-medium">Two-factor authentication</CardTitle>
            <CardDescription>Adds a one-time code from your authenticator app (TOTP) at sign-in.</CardDescription>
          </div>
          {enabled
            ? <Badge className="gap-1.5 border-transparent bg-[color-mix(in_oklch,var(--signal)_18%,transparent)] text-[var(--signal)]"><ShieldCheck className="size-3.5" strokeWidth={1.75} /> Enabled</Badge>
            : <Badge variant="outline" className="gap-1.5 text-muted-foreground"><ShieldAlert className="size-3.5" strokeWidth={1.75} /> Disabled</Badge>}
        </div>
      </CardHeader>
      <CardContent>
        {/* enabled → offer disable */}
        {enabled && step === "idle" && (
          <Button variant="outline" onClick={() => setStep("disable")}>Disable 2FA</Button>
        )}
        {enabled && step === "disable" && (
          <form onSubmit={disable} className="grid max-w-sm gap-3">
            <Label className="text-xs text-muted-foreground">Confirm password to disable</Label>
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            <div className="flex gap-2">
              <Button type="submit" variant="destructive" disabled={busy}>{busy ? <Loader2 className="size-4 animate-spin" strokeWidth={1.75} /> : "Disable"}</Button>
              <Button type="button" variant="ghost" onClick={reset}>Cancel</Button>
            </div>
          </form>
        )}

        {/* disabled → enable */}
        {!enabled && step === "idle" && (
          <Button onClick={() => setStep("password")}><ShieldCheck className="size-4" strokeWidth={1.75} /> Enable 2FA</Button>
        )}
        {!enabled && step === "password" && (
          <form onSubmit={startEnable} className="grid max-w-sm gap-3">
            <Label className="text-xs text-muted-foreground">Confirm your password to begin</Label>
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus required />
            <div className="flex gap-2">
              <Button type="submit" disabled={busy}>{busy ? <Loader2 className="size-4 animate-spin" strokeWidth={1.75} /> : "Continue"}</Button>
              <Button type="button" variant="ghost" onClick={reset}>Cancel</Button>
            </div>
          </form>
        )}
        {!enabled && step === "verify" && (
          <div className="grid gap-5 md:grid-cols-[auto_1fr]">
            <div className="space-y-2">
              <div className="rounded-lg bg-white p-3 w-fit">
                {uri ? <QRCodeSVG value={uri} size={168} /> : null}
              </div>
              <p className="max-w-[180px] text-xs text-muted-foreground">Scan with Google Authenticator, 1Password, Authy, etc.</p>
            </div>
            <div className="space-y-4">
              {backup.length > 0 && (
                <div>
                  <div className="mb-1 flex items-center justify-between">
                    <Label className="text-xs text-muted-foreground">Backup codes (store safely)</Label>
                    <Button size="sm" variant="ghost" className="h-7 gap-1.5 text-xs" onClick={() => { navigator.clipboard.writeText(backup.join("\n")); toast.success("Backup codes copied"); }}><Copy className="size-3.5" strokeWidth={1.75} /> Copy</Button>
                  </div>
                  <div className="grid grid-cols-2 gap-1 rounded-lg border bg-secondary/40 p-3 font-mono text-xs">
                    {backup.map((b) => <span key={b}>{b}</span>)}
                  </div>
                </div>
              )}
              <form onSubmit={verify} className="grid max-w-xs gap-2">
                <Label className="text-xs text-muted-foreground">Enter the 6-digit code to confirm</Label>
                <Input inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" required />
                <div className="flex gap-2">
                  <Button type="submit" disabled={busy}>{busy ? <Loader2 className="size-4 animate-spin" strokeWidth={1.75} /> : "Verify & enable"}</Button>
                  <Button type="button" variant="ghost" onClick={reset}>Cancel</Button>
                </div>
              </form>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
