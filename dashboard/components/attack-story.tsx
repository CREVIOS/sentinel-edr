"use client";

// Attack-story: the EDR investigation surface. Given an agent + the event ids a detection
// fired on, it pulls that host's recent telemetry, reconstructs the process lineage of the
// triggering events, and lays the surrounding activity on a chronological timeline with the
// linked events highlighted. Every node and row pivots into the full event detail. This is
// the "show the right thing first, the rest one click away" investigation view.

import * as React from "react";
import { Sev, Chip } from "@/components/severity";
import { LineageTree } from "@/components/lineage-tree";
import { useData } from "@/lib/use-data";
import { detail, shortTime } from "@/lib/format";
import type { Event } from "@/lib/types";
import { GitBranch, ListTree, Loader2 } from "lucide-react";

export function AttackStory({
  agentId,
  eventIds,
  onSelectEvent,
  limit = 120,
}: {
  agentId?: string;
  eventIds?: string[];
  onSelectEvent?: (e: Event) => void;
  limit?: number;
}) {
  // Poll slowly — this lives inside a drawer; the host's recent activity is the substrate
  // for both the lineage and the timeline. (listEvents has no by-id filter, so we scope by
  // host and highlight the linked ids client-side.)
  const { data, live } = useData<Event[]>(
    agentId ? `events?agent_id=${encodeURIComponent(agentId)}&limit=${limit}` : "events?agent_id=__none__&limit=1",
    8000,
  );
  const linked = React.useMemo(() => new Set(eventIds || []), [eventIds]);
  const events = data || [];

  if (!agentId) {
    return <p className="text-sm text-muted-foreground">No endpoint associated with this finding.</p>;
  }
  if (!data && !live) {
    return (
      <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
        <Loader2 className="size-4 animate-spin" /> Reconstructing activity…
      </div>
    );
  }

  // Lineage from the linked (triggering) events first; fall back to the most severe event.
  const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const withLineage = events.filter((e) => e.process?.lineage || e.process?.parent);
  const linkedWithLineage = withLineage.filter((e) => linked.has(e.id));
  const lineageSrc = (linkedWithLineage.length ? linkedWithLineage : withLineage)
    .sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0))
    .slice(0, 3);

  // Timeline ascending (oldest → newest) so it reads as a narrative.
  const timeline = [...events].sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return (
    <div className="space-y-5">
      {lineageSrc.length > 0 && (
        <section className="space-y-2">
          <h4 className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
            <GitBranch className="size-3.5" /> Process lineage
          </h4>
          <div className="space-y-3 rounded-lg border bg-muted/20 p-3">
            {lineageSrc.map((e) => (
              <div key={e.id} className="space-y-1">
                <LineageTree lineage={e.process?.lineage || e.process?.parent} />
                {e.process?.cmdline && (
                  <button
                    onClick={() => onSelectEvent?.(e)}
                    className="block max-w-full truncate text-left font-mono text-[11px] text-muted-foreground hover:text-foreground"
                    title={e.process.cmdline}
                  >
                    $ {e.process.cmdline}
                  </button>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="space-y-2">
        <h4 className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
          <ListTree className="size-3.5" /> Activity timeline
          <span className="ml-auto normal-case tracking-normal opacity-70">{timeline.length} events · oldest → newest</span>
        </h4>
        {timeline.length === 0 ? (
          <p className="px-1 py-4 text-sm text-muted-foreground">No recent telemetry for this host.</p>
        ) : (
          <ol className="relative ml-1.5 space-y-0.5 border-l pl-3">
            {timeline.map((e) => {
              const hot = linked.has(e.id);
              return (
                <li key={e.id}>
                  <button
                    onClick={() => onSelectEvent?.(e)}
                    className={`group -ml-[1.05rem] flex w-[calc(100%+1.05rem)] items-center gap-2 rounded-md py-1 pl-[1.05rem] pr-2 text-left text-xs transition-colors hover:bg-primary/[0.06] ${
                      hot ? "bg-primary/[0.06]" : ""
                    }`}
                  >
                    <span
                      className={`-ml-[1.42rem] size-2 shrink-0 rounded-full ring-2 ring-card ${hot ? "bg-[var(--sev-critical)]" : "bg-muted-foreground/50"}`}
                      aria-hidden
                    />
                    <span className="w-16 shrink-0 font-mono text-[11px] text-muted-foreground">{shortTime(e.ts)}</span>
                    <Sev s={e.severity} />
                    <Chip>{e.category}</Chip>
                    <span className="min-w-0 flex-1 truncate font-mono text-muted-foreground group-hover:text-foreground" title={detail(e)}>
                      {detail(e)}
                    </span>
                    {hot && <span className="shrink-0 font-mono text-[10px] uppercase tracking-wide text-primary">linked</span>}
                  </button>
                </li>
              );
            })}
          </ol>
        )}
        <p className="px-1 pt-1 text-[11px] text-muted-foreground">Live · scoped to this host</p>
      </section>
    </div>
  );
}
