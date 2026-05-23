"use client";

import { useEffect, useState } from "react";
import { useData } from "@/lib/use-data";
import type { Overview } from "@/lib/types";

export function LiveStatus() {
  const { live } = useData<Overview>("stats/overview", 5000);
  const [now, setNow] = useState("");
  useEffect(() => {
    const t = setInterval(() => setNow(new Date().toISOString().slice(11, 19)), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <div className="flex items-center gap-3">
      <span
        className="inline-flex items-center gap-2 rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-muted-foreground"
      >
        <span
          className="size-2 rounded-full"
          style={{
            background: live ? "var(--chart-2)" : "var(--sev-info)",
            boxShadow: live ? "0 0 8px var(--chart-2)" : "none",
            animation: live ? "pulse 1.8s infinite" : "none",
          }}
        />
        {live ? "Live" : "Offline"}
      </span>
      <span className="hidden font-mono text-xs text-muted-foreground sm:inline">{now} UTC</span>
    </div>
  );
}
