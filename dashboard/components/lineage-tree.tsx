"use client";

import { CornerDownRight } from "lucide-react";

/**
 * Renders a process ancestry chain (pid1→…→self, "A→B→C") as an indented tree so analysts
 * can read the execution lineage at a glance. The last node (the acting process) is
 * highlighted. This is the process-tree reconstruction an EDR console needs for triage.
 */
export function LineageTree({ lineage }: { lineage?: string }) {
  if (!lineage) return <span className="text-muted-foreground">—</span>;
  const nodes = lineage.split("→").map((s) => s.trim()).filter(Boolean);
  if (nodes.length === 0) return <span className="text-muted-foreground">—</span>;
  return (
    <div className="space-y-0.5 font-mono text-xs">
      {nodes.map((n, i) => {
        const last = i === nodes.length - 1;
        return (
          <div key={i} className="flex items-center" style={{ paddingLeft: `${i * 14}px` }}>
            {i > 0 && <CornerDownRight className="mr-1 size-3 shrink-0 text-muted-foreground/60" />}
            <span
              className={
                last
                  ? "rounded bg-primary/15 px-1.5 py-0.5 font-semibold text-primary"
                  : "text-muted-foreground"
              }
            >
              {n}
            </span>
          </div>
        );
      })}
    </div>
  );
}
