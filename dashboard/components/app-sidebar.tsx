"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  LayoutDashboard, Server, Activity, Globe, Radar, FolderKanban,
  FileLock2, Crosshair, ScrollText, Settings, LogOut, ChevronsUpDown,
} from "lucide-react";
import { SentinelMark } from "@/components/logo";
import { signOut } from "@/lib/auth-client";
import {
  Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupLabel,
  SidebarHeader, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarRail,
} from "@/components/ui/sidebar";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";

// Grouped by the product's verbs — Monitor, Detect, Respond — so the nav reads as the
// security workflow, not an arbitrary list. Icons avoid the shield/lock cliche where a
// more literal glyph is clearer (Server = Linux host, Radar = active detection).
const NAV = [
  {
    label: "Monitor",
    items: [
      { href: "/", title: "Overview", icon: LayoutDashboard },
      { href: "/endpoints", title: "Endpoints", icon: Server },
      { href: "/events", title: "Events", icon: Activity },
      { href: "/internet", title: "Network", icon: Globe },
    ],
  },
  {
    label: "Detect",
    items: [
      { href: "/detections", title: "Detections", icon: Radar },
      { href: "/cases", title: "Cases", icon: FolderKanban },
      { href: "/dlp", title: "Data Loss", icon: FileLock2 },
    ],
  },
  {
    label: "Respond",
    items: [
      { href: "/responses", title: "Response", icon: Crosshair },
      { href: "/rules", title: "Rules", icon: ScrollText },
    ],
  },
  {
    label: "System",
    items: [
      { href: "/settings", title: "Settings", icon: Settings },
    ],
  },
];

export function AppSidebar({ user }: { user: { name?: string; email?: string } }) {
  const pathname = usePathname();
  const router = useRouter();
  const initials = (user.name || user.email || "OP").slice(0, 2).toUpperCase();

  return (
    <Sidebar collapsible="icon" variant="inset">
      <SidebarHeader>
        <div className="flex items-center gap-2.5 px-1.5 py-1.5">
          <SentinelMark className="size-7 text-primary" />
          <div className="grid group-data-[collapsible=icon]:hidden">
            <span className="font-mono text-sm font-semibold tracking-[0.2em] leading-none">SENTINEL</span>
            <span className="mt-1 text-[10px] text-muted-foreground">EDR &amp; DLP</span>
          </div>
        </div>
      </SidebarHeader>

      <SidebarContent>
        {NAV.map((group) => (
          <SidebarGroup key={group.label}>
            <SidebarGroupLabel className="text-[11px] font-medium text-muted-foreground">{group.label}</SidebarGroupLabel>
            <SidebarMenu>
              {group.items.map((item) => {
                const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
                return (
                  <SidebarMenuItem key={item.href}>
                    <SidebarMenuButton asChild isActive={active} tooltip={item.title}>
                      <Link href={item.href}>
                        <item.icon strokeWidth={1.75} />
                        <span>{item.title}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroup>
        ))}
      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <SidebarMenuButton size="lg" className="data-[state=open]:bg-sidebar-accent">
                  <Avatar className="size-8 rounded-lg">
                    <AvatarFallback className="rounded-lg bg-primary/12 text-xs font-semibold text-primary">
                      {initials}
                    </AvatarFallback>
                  </Avatar>
                  <div className="grid flex-1 text-left text-sm leading-tight group-data-[collapsible=icon]:hidden">
                    <span className="truncate font-medium">{user.name || "Operator"}</span>
                    <span className="truncate text-xs text-muted-foreground">{user.email}</span>
                  </div>
                  <ChevronsUpDown className="ml-auto size-4 group-data-[collapsible=icon]:hidden" />
                </SidebarMenuButton>
              </DropdownMenuTrigger>
              <DropdownMenuContent side="top" align="start" className="w-56">
                <DropdownMenuLabel className="font-mono text-xs">{user.email}</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={() => signOut({ fetchOptions: { onSuccess: () => router.push("/login") } })}
                >
                  <LogOut className="size-4" /> Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
