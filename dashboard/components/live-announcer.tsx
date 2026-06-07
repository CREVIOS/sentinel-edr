"use client";

// A single app-level ARIA live region so streaming updates (new criticals, connection
// drops, bulk-action results) are announced to screen readers without flooding them.
// Two pre-mounted regions: polite (queued) and assertive (interrupts) per WAI-ARIA. A
// tiny module-level pub/sub lets any component or the data layer call announce() without
// prop-drilling. Visually hidden; never affects layout.

import * as React from "react";
import { useStream } from "@/lib/use-stream";
import type { Detection } from "@/lib/types";

type Politeness = "polite" | "assertive";
type Listener = (msg: string, level: Politeness) => void;

const listeners = new Set<Listener>();

/** Announce a message to assistive tech. assertive interrupts; polite queues. */
export function announce(msg: string, opts?: { assertive?: boolean }) {
  const level: Politeness = opts?.assertive ? "assertive" : "polite";
  listeners.forEach((l) => l(msg, level));
}

export function LiveAnnouncer() {
  const [polite, setPolite] = React.useState("");
  const [assertive, setAssertive] = React.useState("");

  React.useEffect(() => {
    const l: Listener = (msg, level) => {
      // Toggle to empty first so repeated identical messages still re-announce.
      if (level === "assertive") {
        setAssertive("");
        requestAnimationFrame(() => setAssertive(msg));
      } else {
        setPolite("");
        requestAnimationFrame(() => setPolite(msg));
      }
    };
    listeners.add(l);
    return () => {
      listeners.delete(l);
    };
  }, []);

  return (
    <>
      <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">
        {polite}
      </div>
      <div className="sr-only" role="alert" aria-live="assertive" aria-atomic="true">
        {assertive}
      </div>
    </>
  );
}

/**
 * App-level subscriber that voices newly-arrived high-priority detections to assistive tech.
 * Mounted once in the app layout — a new critical is exactly the event a SOC analyst must not
 * miss, and it would otherwise arrive silently for screen-reader users.
 */
export function DetectionAnnouncer() {
  useStream("detection", (raw) => {
    const d = raw as Detection;
    if (!d || !d.severity) return;
    if (d.severity === "critical" || d.severity === "high") {
      announce(
        `New ${d.severity} detection: ${d.rule_name || "rule"} on ${d.hostname || "a host"}`,
        { assertive: d.severity === "critical" },
      );
    }
  });
  return null;
}
