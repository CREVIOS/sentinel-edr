import type { KeyboardEvent, ReactNode } from "react";
import type { Severity } from "./types";

/**
 * Props that make a non-button element (e.g. a clickable table row) operable by keyboard:
 * focusable, activatable with Enter/Space, and announced as a button to assistive tech.
 * Spread onto the element: `<tr {...rowClick(() => open(x))}>`.
 */
export function rowClick(onActivate: () => void) {
  return {
    role: "button" as const,
    tabIndex: 0,
    onClick: onActivate,
    onKeyDown: (e: KeyboardEvent) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        onActivate();
      }
    },
    style: { cursor: "pointer" as const },
  };
}

export function Sev({ s }: { s: Severity | string }) {
  const c = `sev sev-${s}`;
  return <span className={c}>{s}</span>;
}

export function StatusTag({ s }: { s: string }) {
  return (
    <span className={`status-tag st-${s}`}>
      <span className="d" />
      {s}
    </span>
  );
}

export function Stat({
  label,
  value,
  foot,
  crit,
  accent,
}: {
  label: string;
  value: ReactNode;
  foot?: ReactNode;
  crit?: boolean;
  accent?: string;
}) {
  return (
    <div className={`panel stat${crit ? " crit" : ""}`}>
      <span className="edge" style={accent ? { background: accent } : undefined} />
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {foot && <div className="foot">{foot}</div>}
    </div>
  );
}

export function Panel({
  title,
  sub,
  right,
  children,
  className,
}: {
  title?: string;
  sub?: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`panel ${className || ""}`}>
      {title && (
        <div className="panel-head">
          <h3>{title}</h3>
          {sub && <span className="sub">{sub}</span>}
          <span style={{ flex: 1 }} />
          {right}
        </div>
      )}
      <div className="panel-body">{children}</div>
    </div>
  );
}

export function Mitre({ ids }: { ids?: string[] | null }) {
  if (!ids || ids.length === 0) return <span className="dim">—</span>;
  return (
    <span className="mitre">
      {ids.map((t) => (
        <span key={t} className="chip violet">
          {t}
        </span>
      ))}
    </span>
  );
}

export function ago(ts: string): string {
  const d = new Date(ts).getTime();
  const s = Math.max(0, Math.floor((Date.now() - d) / 1000));
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
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}

export const CAT_ICON: Record<string, string> = {
  process: "▶",
  file: "✎",
  network: "◈",
  auth: "⚿",
  ssh: "⚿",
  usb: "⛁",
  package: "❒",
  dlp: "✦",
  system: "•",
};
