"use client";

import { usePathname } from "next/navigation";

// Single source of truth for the human title + one-line descriptor of each route.
// Keeps the header honest about where the operator is, with no decorative eyebrow.
const ROUTES: Record<string, { title: string; desc: string }> = {
  "/": { title: "Overview", desc: "Live security posture across the fleet" },
  "/endpoints": { title: "Endpoints", desc: "Enrolled Linux hosts and their status" },
  "/events": { title: "Events", desc: "Real-time endpoint telemetry" },
  "/detections": { title: "Detections", desc: "Triggered rules and behavioral alerts" },
  "/cases": { title: "Cases", desc: "Investigations and incident tracking" },
  "/dlp": { title: "Data Loss Prevention", desc: "Sensitive-data policy and incidents" },
  "/internet": { title: "Network", desc: "Outbound connections and domains" },
  "/responses": { title: "Response", desc: "Containment actions and history" },
  "/rules": { title: "Rules", desc: "Detection rule catalog" },
  "/settings": { title: "Settings", desc: "Integrations, SIEM export and account" },
};

export function PageTitle() {
  const pathname = usePathname();
  const match =
    ROUTES[pathname] ??
    ROUTES[Object.keys(ROUTES).find((r) => r !== "/" && pathname.startsWith(r)) ?? "/"];

  return (
    <div className="min-w-0 leading-tight">
      <h1 className="truncate text-sm font-medium tracking-tight">{match.title}</h1>
      <p className="hidden truncate text-xs text-muted-foreground sm:block">{match.desc}</p>
    </div>
  );
}
