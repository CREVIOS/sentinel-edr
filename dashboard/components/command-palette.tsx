"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator,
} from "@/components/ui/command";
import {
  LayoutDashboard, Radar, Activity, Server, FileLock2,
  Globe, Crosshair, ScrollText, Settings, FolderKanban, Eye, Search,
} from "lucide-react";
import { useData } from "@/lib/use-data";
import type { Agent, Detection } from "@/lib/types";

// Mirror the sidebar exactly — same labels, same icons — so navigation is predictable.
const NAV = [
  { label: "Overview", href: "/", icon: LayoutDashboard },
  { label: "Endpoints", href: "/endpoints", icon: Server },
  { label: "Events", href: "/events", icon: Activity },
  { label: "Network", href: "/internet", icon: Globe },
  { label: "Detections", href: "/detections", icon: Radar },
  { label: "Cases", href: "/cases", icon: FolderKanban },
  { label: "Data Loss", href: "/dlp", icon: FileLock2 },
  { label: "Response", href: "/responses", icon: Crosshair },
  { label: "Rules", href: "/rules", icon: ScrollText },
  { label: "Settings", href: "/settings", icon: Settings },
];

/** Live entity results — mounted only while the palette is open, so it doesn't poll idle. */
function EntityResults({ go }: { go: (href: string) => void }) {
  const { data: agents } = useData<Agent[]>("agents", 15000);
  const { data: dets } = useData<Detection[]>("detections?limit=50", 15000);
  return (
    <>
      {(agents?.length ?? 0) > 0 && (
        <CommandGroup heading="Endpoints">
          {agents!.slice(0, 8).map((a) => (
            <CommandItem key={a.id} value={`host ${a.hostname} ${a.ip}`} onSelect={() => go(`/events?agent_id=${encodeURIComponent(a.id)}`)}>
              <Server className="size-4 text-muted-foreground" />
              <span className="font-mono">{a.hostname}</span>
              <span className="ml-auto text-xs text-muted-foreground">{a.status}</span>
            </CommandItem>
          ))}
        </CommandGroup>
      )}
      {(dets?.length ?? 0) > 0 && (
        <CommandGroup heading="Detections">
          {dets!.slice(0, 8).map((d) => (
            <CommandItem key={d.id} value={`detection ${d.rule_name} ${d.hostname} ${d.severity}`} onSelect={() => go(`/detections?id=${d.id}`)}>
              <Radar className="size-4 text-muted-foreground" />
              <span className="font-mono">{d.rule_name}</span>
              <span className="ml-auto text-xs text-muted-foreground">{d.hostname}</span>
            </CommandItem>
          ))}
        </CommandGroup>
      )}
    </>
  );
}

/**
 * ⌘K / Ctrl-K command palette for fast SOC navigation + entity search. Renders its own
 * trigger button so it can be mounted directly in a server component.
 */
export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const go = (href: string) => { setOpen(false); router.push(href); };

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-2 rounded-md border bg-muted/40 px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-muted"
      >
        <Search className="size-3.5" />
        <span className="hidden md:inline">Search hosts, detections…</span>
        <kbd className="ml-2 hidden rounded border bg-background px-1.5 py-0.5 font-mono text-[10px] md:inline">⌘K</kbd>
      </button>
      <CommandDialog open={open} onOpenChange={setOpen}>
        <CommandInput placeholder="Search hosts, detections, or jump to a page…" />
        <CommandList>
          <CommandEmpty>No matches.</CommandEmpty>
          <CommandGroup heading="Navigate">
            {NAV.map((n) => (
              <CommandItem key={n.href} value={n.label} onSelect={() => go(n.href)}>
                <n.icon className="size-4 text-muted-foreground" />
                {n.label}
              </CommandItem>
            ))}
            <CommandItem value="live events" keywords={["live", "events", "stream", "tail"]} onSelect={() => go("/events")}>
              <Eye className="size-4 text-[var(--signal)]" />
              Live event stream
            </CommandItem>
          </CommandGroup>
          <CommandSeparator />
          {open && <EntityResults go={go} />}
        </CommandList>
      </CommandDialog>
    </>
  );
}
