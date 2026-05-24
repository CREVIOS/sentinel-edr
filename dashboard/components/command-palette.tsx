"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator,
} from "@/components/ui/command";
import {
  LayoutDashboard, ShieldAlert, Activity, MonitorSmartphone, FileLock2,
  Globe, Crosshair, ScrollText, Settings, Eye,
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

/** ⌘K / Ctrl-K command palette for fast SOC navigation. Mounted once in the app shell. */
export function CommandPalette({ trigger }: { trigger?: (open: () => void) => React.ReactNode }) {
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
      {trigger?.(() => setOpen(true))}
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
