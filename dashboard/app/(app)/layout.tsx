import { redirect } from "next/navigation";
import { headers } from "next/headers";
import { auth } from "@/lib/auth";
import { AppSidebar } from "@/components/app-sidebar";
import { LiveStatus } from "@/components/live-status";
import { ThemeToggle } from "@/components/theme-toggle";
import { CommandPalette } from "@/components/command-palette";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { Separator } from "@/components/ui/separator";
import { Search } from "lucide-react";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  return (
    <SidebarProvider>
      <AppSidebar user={session.user} />
      <SidebarInset>
        <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-3 border-b bg-background/70 px-4 backdrop-blur">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mr-1 !h-5" />
          <div className="leading-tight">
            <div className="text-[10px] uppercase tracking-[0.25em] text-muted-foreground">Security Operations Center</div>
            <div className="font-mono text-sm">Command Console</div>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <CommandPalette
              trigger={(openPalette) => (
                <button
                  onClick={openPalette}
                  className="hidden items-center gap-2 rounded-md border bg-muted/40 px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-muted md:inline-flex"
                >
                  <Search className="size-3.5" />
                  <span>Jump to…</span>
                  <kbd className="ml-2 rounded border bg-background px-1.5 py-0.5 font-mono text-[10px]">⌘K</kbd>
                </button>
              )}
            />
            <LiveStatus />
            <Separator orientation="vertical" className="!h-5" />
            <ThemeToggle />
          </div>
        </header>
        <div className="min-h-[calc(100dvh-3.5rem)] p-4 md:p-6">{children}</div>
      </SidebarInset>
    </SidebarProvider>
  );
}
