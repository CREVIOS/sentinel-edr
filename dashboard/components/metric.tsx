"use client";

import { useEffect, useRef, useState, type ComponentType } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Sparkline } from "@/components/sparkline";
import { cn } from "@/lib/utils";

/** Ease-out count-up so live metrics animate to their new value instead of snapping. */
function useCountUp(target: number, ms = 650): number {
  const [v, setV] = useState(target);
  const from = useRef(target);
  useEffect(() => {
    const start = performance.now();
    const f = from.current;
    const delta = target - f;
    if (delta === 0) return;
    let raf = 0;
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / ms);
      const eased = 1 - Math.pow(1 - p, 3);
      setV(Math.round(f + delta * eased));
      if (p < 1) raf = requestAnimationFrame(tick);
      else from.current = target;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return v;
}

export function Metric({
  label,
  value,
  icon: Icon,
  accent = "var(--primary)",
  spark,
  sub,
  emphasize,
}: {
  label: string;
  value: number | string;
  icon?: ComponentType<{ className?: string; strokeWidth?: number; style?: React.CSSProperties }>;
  accent?: string;
  spark?: number[];
  sub?: React.ReactNode;
  emphasize?: boolean;
}) {
  const numeric = typeof value === "number" ? value : 0;
  const counted = useCountUp(numeric);
  return (
    <Card className={cn("panel overflow-hidden py-0", emphasize && "glow-primary")}>
      <CardContent className="relative p-5">
        {/* faint accent wash in the corner */}
        <div
          className="pointer-events-none absolute -right-8 -top-8 size-24 rounded-full opacity-[0.12] blur-2xl"
          style={{ background: accent }}
        />
        <div className="flex items-center justify-between">
          <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">{label}</span>
          {Icon && <Icon className="size-4 text-muted-foreground/80" strokeWidth={1.75} style={{ color: accent }} />}
        </div>
        <div className="mt-3 font-display text-[2.1rem] font-semibold leading-none tabular-nums">
          {typeof value === "number" ? counted.toLocaleString() : value}
        </div>
        {sub && <div className="mt-2 text-xs text-muted-foreground">{sub}</div>}
        {spark && spark.length > 1 && (
          <div className="-mx-1 mt-3">
            <Sparkline data={spark} color={accent} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}
