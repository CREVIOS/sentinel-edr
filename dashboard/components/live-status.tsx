"use client";

import { useEffect, useState } from "react";
import { Eye } from "lucide-react";
import { useStreamStatus } from "@/lib/use-stream";

export function LiveStatus() {
  // True push-channel status: lit when the SSE relay to the control plane is connected.
  const live = useStreamStatus();
  const [now, setNow] = useState("");
  useEffect(() => {
    const t = setInterval(() => setNow(new Date().toISOString().slice(11, 19)), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <div className="flex items-center gap-3">
      <span
        className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors ${
          live
            ? "border-[color-mix(in_oklch,var(--signal)_45%,transparent)] text-[var(--signal)]"
            : "text-muted-foreground"
        }`}
      >
        {live ? (
          <span className="live-dot size-2" />
        ) : (
          <span className="size-2 rounded-full bg-[var(--sev-info)]" />
        )}
        {live ? "Watching" : "Offline"}
      </span>
      <span className="hidden items-center gap-1.5 font-mono text-xs text-muted-foreground sm:inline-flex">
        <Eye className="size-3.5 opacity-70" />
        {now} UTC
      </span>
    </div>
  );
}
