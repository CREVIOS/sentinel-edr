"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator,
} from "@/components/ui/command";
import {
  LayoutDashboard, ShieldAlert, Activity, MonitorSmartphone, FileLock2,
  Globe, Crosshair, ScrollText, Settings, Eye, Search,
} from "lucide-react";

const NAV = [
  { label: "Overview", href: "/", icon: LayoutDashboard },
  { label: "Detections", href: "/detections", icon: ShieldAlert },
  { label: "Events", href: "/events", icon: Activity },
  { label: "Endpoints", href: "/endpoints", icon: MonitorSmartphone },
  { label: "DLP", href: "/dlp", icon: FileLock2 },
  { label: "Internet", href: "/internet", icon: Globe },
  { label: "Responses", href: "/responses", icon: Crosshair },
  { label: "Rules", href: "/rules", icon: ScrollText },
  { label: "Settings", href: "/settings", icon: Settings },
];

/**
 * ⌘K / Ctrl-K command palette for fast SOC navigation. Renders its own trigger button so it
 * can be mounted directly in a server component (no function props across the RSC boundary).
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
        className="hidden items-center gap-2 rounded-md border bg-muted/40 px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-muted md:inline-flex"
      >
        <Search className="size-3.5" />
        <span>Jump to…</span>
        <kbd className="ml-2 rounded border bg-background px-1.5 py-0.5 font-mono text-[10px]">⌘K</kbd>
      </button>
      <CommandDialog open={open} onOpenChange={setOpen}>
        <CommandInput placeholder="Jump to a console…" />
        <CommandList>
          <CommandEmpty>No matches.</CommandEmpty>
          <CommandGroup heading="Navigate">
            {NAV.map((n) => (
              <CommandItem key={n.href} value={n.label} onSelect={() => go(n.href)}>
                <n.icon className="size-4 text-muted-foreground" />
                {n.label}
              </CommandItem>
            ))}
          </CommandGroup>
          <CommandSeparator />
          <CommandGroup heading="Watch">
            <CommandItem value="live events" onSelect={() => go("/events")}>
              <Eye className="size-4 text-[var(--signal)]" />
              Live event stream
            </CommandItem>
          </CommandGroup>
        </CommandList>
      </CommandDialog>
    </>
  );
}
