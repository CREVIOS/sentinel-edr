"use client";

// Deterministic, no-model incident summary: a plain-language narrative assembled from fields
// the finding already carries, plus the concrete next-step actions an analyst would take —
// each wired straight to the response handler. A strong v1 of the "AI summary + recommended
// actions" pattern every enterprise console now ships; swap the narrative for a generated one
// later behind the same component.

import * as React from "react";
import { Button } from "@/components/ui/button";
import { techniqueName } from "@/lib/mitre";
import { Sparkles, ShieldOff, UserX, Crosshair, FolderPlus } from "lucide-react";

export interface IncidentLike {
  severity: string;
  hostname?: string;
  agentId?: string;
  user?: string;
  ruleName?: string;
  summary?: string;
  engine?: string;
  tactic?: string;
  mitre?: string[];
  detectionCount?: number;
  eventCount?: number;
}

export type Recommendation =
  | { kind: "isolate"; label: string; destructive: true }
  | { kind: "disable_account"; label: string; user: string; destructive: true }
  | { kind: "escalate"; label: string };

function narrative(x: IncidentLike): string {
  const parts: string[] = [];
  const sev = x.severity ? x.severity[0].toUpperCase() + x.severity.slice(1) : "A";
  const what = x.ruleName ? `“${x.ruleName}”` : "activity";
  parts.push(`${sev}-severity ${what}${x.hostname ? ` on ${x.hostname}` : ""}${x.user ? ` attributed to ${x.user}` : ""}.`);
  if (x.summary) parts.push(x.summary.endsWith(".") ? x.summary : `${x.summary}.`);
  const techs = (x.mitre || []).map(techniqueName);
  if (techs.length) parts.push(`Maps to ${techs.slice(0, 4).join(", ")}${techs.length > 4 ? `, +${techs.length - 4} more` : ""}.`);
  if (x.tactic) parts.push(`Kill-chain stage: ${x.tactic}.`);
  if (x.detectionCount) parts.push(`Correlates ${x.detectionCount} detection${x.detectionCount === 1 ? "" : "s"}.`);
  if (x.engine) parts.push(`Surfaced by the ${x.engine} engine.`);
  return parts.join(" ");
}

export function IncidentSummary({
  incident,
  onRecommend,
}: {
  incident: IncidentLike;
  onRecommend?: (r: Recommendation) => void;
}) {
  const recs: Recommendation[] = [];
  if (incident.hostname || incident.agentId) {
    recs.push({ kind: "isolate", label: `Isolate ${incident.hostname || "host"}`, destructive: true });
  }
  if (incident.user && incident.user !== "root") {
    recs.push({ kind: "disable_account", label: `Disable ${incident.user}`, user: incident.user, destructive: true });
  }
  recs.push({ kind: "escalate", label: "Escalate to case" });

  const icon = (r: Recommendation) =>
    r.kind === "isolate" ? <ShieldOff className="size-4" /> :
    r.kind === "disable_account" ? <UserX className="size-4" /> :
    r.kind === "escalate" ? <FolderPlus className="size-4" /> : <Crosshair className="size-4" />;

  return (
    <div className="rounded-lg border bg-muted/20 p-3">
      <h4 className="mb-1.5 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
        <Sparkles className="size-3.5 text-[var(--signal)]" /> Summary
      </h4>
      <p className="text-sm leading-relaxed">{narrative(incident)}</p>
      {onRecommend && recs.length > 0 && (
        <>
          <div className="mt-3 mb-1.5 font-mono text-[11px] uppercase tracking-wide text-muted-foreground">Recommended actions</div>
          <div className="flex flex-wrap gap-2">
            {recs.map((r, i) => (
              <Button
                key={i}
                size="sm"
                variant="outline"
                className={"destructive" in r && r.destructive ? "border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive" : ""}
                onClick={() => onRecommend(r)}
              >
                {icon(r)} {r.label}
              </Button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
