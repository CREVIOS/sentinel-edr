import type { Severity } from "./types";

export function ago(ts: string): string {
  const s = Math.max(0, Math.floor((Date.now() - new Date(ts).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function shortTime(ts: string): string {
  return new Date(ts).toLocaleTimeString([], { hour12: false });
}

export function bytes(n?: number): string {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}

export function compact(n: number): string {
  if (n >= 1000) return (n / 1000).toFixed(1) + "k";
  return String(n);
}

export const SEV_VAR: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

export function sevColor(s: Severity | string): string {
  return SEV_VAR[s] || SEV_VAR.info;
}

export function detail(e: import("./types").Event): string {
  if (e.process?.cmdline) return e.process.cmdline;
  if (e.file?.path) return `${e.file.op || ""} ${e.file.path}`;
  if (e.network?.domain) return `${e.network.domain}${e.network.bytes_out ? " ↑" + bytes(e.network.bytes_out) : ""}`;
  if (e.usb) return `${e.usb.vendor || ""} ${e.usb.product || ""} ${e.usb.serial || ""}`.trim();
  if (e.auth) return `${e.auth.method || ""} from ${e.auth.source_ip || "local"} → ${e.auth.result || ""}`;
  if (e.dlp) return `${e.dlp.classifier} via ${e.dlp.channel}`;
  return e.message || "";
}
