"use client";

// LLM-assisted triage: asks the Go server (POST detections/{id}/triage → Claude) for a
// decision-ready summary, assessment, and recommended actions. Sibling to IncidentSummary
// (the deterministic narrative) — this is the generated one. Gracefully degrades when the
// server has no ANTHROPIC_API_KEY (501 → a plain "not configured" line).

import * as React from "react";
import { Button } from "@/components/ui/button";
import { postJSON } from "@/lib/use-data";
import type { TriageResult } from "@/lib/types";
import { Sparkles, Loader2 } from "lucide-react";

export function AiTriage({ detectionId }: { detectionId: string }) {
  const [result, setResult] = React.useState<TriageResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);

  // reset when a different detection opens
  React.useEffect(() => {
    setResult(null);
    setErr(null);
    setLoading(false);
  }, [detectionId]);

  async function run() {
    setLoading(true);
    setErr(null);
    const r = await postJSON(`detections/${detectionId}/triage`, {});
    setLoading(false);
    if (r.ok) setResult(r.data as TriageResult);
    else setErr(r.error || `Triage failed (HTTP ${r.status})`);
  }

  const conf = (result?.confidence || "").toLowerCase();
  const confColor =
    conf === "high" ? "var(--signal)" : conf === "medium" ? "var(--sev-low)" : "var(--muted-foreground)";

  return (
    <div className="rounded-lg border bg-muted/20 p-3">
      <div className="mb-1.5 flex items-center gap-2">
        <h4 className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
          <Sparkles className="size-3.5 text-[var(--signal)]" /> AI Triage
        </h4>
        {!result && (
          <Button size="sm" variant="outline" className="ml-auto h-7" disabled={loading} onClick={run}>
            {loading ? (
              <>
                <Loader2 className="size-3.5 animate-spin" /> Analyzing…
              </>
            ) : (
              "Analyze"
            )}
          </Button>
        )}
      </div>

      {err && <p className="text-sm text-muted-foreground">{err}</p>}
      {!result && !err && !loading && (
        <p className="text-xs text-muted-foreground">Summarize this detection and suggest next actions.</p>
      )}

      {result && (
        <div className="space-y-2.5">
          <div className="flex flex-wrap items-center gap-2 text-[11px]">
            <span className="rounded border px-2 py-0.5 font-mono text-muted-foreground">{result.model || "claude"}</span>
            {result.confidence && (
              <span className="rounded border px-2 py-0.5 font-mono" style={{ color: confColor, borderColor: confColor }}>
                {result.confidence} confidence
              </span>
            )}
            {result.cached && <span className="rounded border px-2 py-0.5 font-mono text-muted-foreground">cached</span>}
          </div>

          <p className="text-sm leading-relaxed">{result.summary}</p>

          {result.assessment && (
            <>
              <div className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">Assessment</div>
              <p className="text-sm leading-relaxed text-muted-foreground">{result.assessment}</p>
            </>
          )}

          {result.recommended_actions && result.recommended_actions.length > 0 && (
            <>
              <div className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">Recommended actions</div>
              <ol className="list-decimal space-y-0.5 pl-5 text-sm">
                {result.recommended_actions.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ol>
            </>
          )}

          <p className="text-[10.5px] text-muted-foreground">AI-generated · verify before acting</p>
        </div>
      )}
    </div>
  );
}
