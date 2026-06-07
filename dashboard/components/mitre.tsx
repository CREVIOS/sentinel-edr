"use client";

// ATT&CK presentation: named technique chips (T1059 → "Command & Scripting", linked to the
// ATT&CK page) and a kill-chain strip that lights the stages an incident has traversed.

import * as React from "react";
import { Badge } from "@/components/ui/badge";
import { TACTICS, TACTIC_SHORT, techniqueName, techniqueTactic, attackUrl, tacticsFromTechniques } from "@/lib/mitre";

/** Technique id chips with name tooltip + deep link. */
export function MitreChips({ ids, max }: { ids?: string[]; max?: number }) {
  const list = ids || [];
  if (list.length === 0) return <span className="text-muted-foreground">—</span>;
  const shown = max ? list.slice(0, max) : list;
  return (
    <div className="flex flex-wrap gap-1">
      {shown.map((id) => (
        <a
          key={id}
          href={attackUrl(id)}
          target="_blank"
          rel="noreferrer"
          title={`${id} · ${techniqueName(id)}${techniqueTactic(id) ? ` (${techniqueTactic(id)})` : ""}`}
          onClick={(e) => e.stopPropagation()}
          className="inline-flex"
        >
          <Badge
            variant="outline"
            className="gap-1 font-mono text-[10px] transition-colors hover:border-[color-mix(in_oklch,var(--signal)_55%,transparent)]"
            style={{
              color: "color-mix(in oklch, var(--signal) 58%, var(--foreground))",
              borderColor: "color-mix(in oklch, var(--signal) 40%, transparent)",
            }}
          >
            {id}
            <span className="hidden font-sans text-muted-foreground sm:inline">{techniqueName(id)}</span>
          </Badge>
        </a>
      ))}
      {max && list.length > max && <Badge variant="outline" className="font-mono text-[10px]">+{list.length - max}</Badge>}
    </div>
  );
}

/**
 * Horizontal kill-chain. Stages the incident touched (derived from its technique ids and/or
 * an explicit tactic) are lit; the rest are dimmed — a one-glance read of attack progression.
 */
export function KillChainStrip({ ids, tactic }: { ids?: string[]; tactic?: string }) {
  const observed = React.useMemo(() => {
    const set = new Set(tacticsFromTechniques(ids || []));
    if (tactic) {
      // tolerate the server's free-form tactic string by matching against known names
      const match = TACTICS.find((t) => t.toLowerCase() === tactic.toLowerCase());
      if (match) set.add(match);
    }
    return set;
  }, [ids, tactic]);

  if (observed.size === 0) return null;

  // Show a compact window: from the first observed stage to the last, plus a little context.
  const firstIdx = TACTICS.findIndex((t) => observed.has(t));
  const lastIdx = TACTICS.length - 1 - [...TACTICS].reverse().findIndex((t) => observed.has(t));
  const start = Math.max(0, firstIdx - 1);
  const end = Math.min(TACTICS.length, lastIdx + 2);
  const window = TACTICS.slice(start, end);

  return (
    <div className="flex flex-wrap items-center gap-1" aria-label="ATT&CK kill chain progress">
      {window.map((t, i) => {
        const hot = observed.has(t);
        return (
          <React.Fragment key={t}>
            {i > 0 && <span className="text-muted-foreground/40" aria-hidden>›</span>}
            <span
              title={t}
              className={`rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide transition-colors ${
                hot
                  ? "bg-[color-mix(in_oklch,var(--signal)_18%,transparent)] font-semibold text-[var(--signal)]"
                  : "text-muted-foreground/60"
              }`}
            >
              {TACTIC_SHORT[t]}
            </span>
          </React.Fragment>
        );
      })}
    </div>
  );
}
