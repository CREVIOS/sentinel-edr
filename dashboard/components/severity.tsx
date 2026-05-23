import { Badge } from "@/components/ui/badge";
import { sevColor } from "@/lib/format";

export function Sev({ s }: { s: string }) {
  const c = sevColor(s);
  return (
    <Badge
      variant="outline"
      className="gap-1.5 font-mono text-[10px] uppercase tracking-wider"
      style={{
        color: c,
        borderColor: `color-mix(in oklch, ${c} 40%, transparent)`,
        background: `color-mix(in oklch, ${c} 12%, transparent)`,
      }}
    >
      <span className="size-1.5 rounded-[2px]" style={{ background: c }} />
      {s}
    </Badge>
  );
}

const STATUS_COLOR: Record<string, string> = {
  online: "var(--chart-2)",
  offline: "var(--sev-info)",
  isolated: "var(--sev-critical)",
};

export function StatusDot({ status }: { status: string }) {
  const c = STATUS_COLOR[status] || "var(--sev-info)";
  return (
    <span className="inline-flex items-center gap-2 font-mono text-xs">
      <span className="size-2 rounded-full" style={{ background: c, boxShadow: `0 0 8px ${c}` }} />
      {status}
    </span>
  );
}

export function Chip({ children, color }: { children: React.ReactNode; color?: string }) {
  return (
    <Badge
      variant="outline"
      className="font-mono text-[10px]"
      style={color ? { color, borderColor: `color-mix(in oklch, ${color} 40%, transparent)` } : undefined}
    >
      {children}
    </Badge>
  );
}
