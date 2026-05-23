"use client";

import { useState } from "react";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { StatusDot, Chip } from "@/components/severity";
import { InfoSheet, type Field } from "@/components/info-sheet";
import { useData, post } from "@/lib/use-data";
import { ago } from "@/lib/format";
import type { Agent } from "@/lib/types";
import { MoreHorizontal, ShieldOff, ShieldCheck, Usb, CloudOff } from "lucide-react";

export default function EndpointsPage() {
  const { data: agents } = useData<Agent[]>("agents", 5000);
  const [sel, setSel] = useState<Agent | null>(null);

  async function act(a: Agent, type: string, label: string) {
    const r = await post("respond", { type, agent_id: a.id, reason: `manual ${type} from console` });
    if (r.ok) toast.success(`${label} dispatched to ${a.hostname}`);
    else toast.error(`Action failed (${r.status})`);
  }

  function fields(a: Agent): Field[] {
    return [
      { label: "Agent ID", value: a.id, mono: true, wrap: true },
      { label: "Status", value: <StatusDot status={a.status} /> },
      { label: "OS", value: a.os },
      { label: "Kernel", value: a.kernel, mono: true },
      { label: "Arch", value: <Chip>{a.arch}</Chip> },
      { label: "IP", value: a.ip, mono: true },
      { label: "MAC", value: a.mac, mono: true },
      { label: "Version", value: a.version, mono: true },
      { label: "Labels", value: <div className="flex flex-wrap gap-1">{(a.labels || []).map((l) => <Chip key={l} color="var(--primary)">{l}</Chip>)}</div> },
      { label: "Events", value: a.event_count?.toLocaleString?.(), mono: true },
      { label: "Enrolled", value: new Date(a.enrolled_at).toLocaleString(), mono: true },
      { label: "Last Seen", value: `${ago(a.last_seen)} · ${new Date(a.last_seen).toLocaleString()}`, mono: true, wrap: true },
    ];
  }

  return (
    <>
      <Card>
        <CardHeader><CardTitle className="font-mono text-sm tracking-wide">ENDPOINT FLEET · {agents?.length ?? 0} enrolled</CardTitle></CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Status</TableHead><TableHead>Hostname</TableHead><TableHead>OS / Kernel</TableHead>
                <TableHead>IP</TableHead><TableHead>MAC</TableHead><TableHead>Arch</TableHead>
                <TableHead className="text-right">Events</TableHead><TableHead>Last Seen</TableHead><TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {(agents || []).map((a) => (
                <TableRow key={a.id} onClick={() => setSel(a)} className="cursor-pointer">
                  <TableCell><StatusDot status={a.status} /></TableCell>
                  <TableCell className="font-mono">{a.hostname}</TableCell>
                  <TableCell className="text-muted-foreground">{a.os} <span className="opacity-60">{a.kernel}</span></TableCell>
                  <TableCell className="font-mono">{a.ip || "—"}</TableCell>
                  <TableCell className="font-mono text-muted-foreground">{a.mac || "—"}</TableCell>
                  <TableCell><Chip>{a.arch || "—"}</Chip></TableCell>
                  <TableCell className="text-right font-mono tabular-nums">{a.event_count?.toLocaleString?.() ?? a.event_count}</TableCell>
                  <TableCell className="text-muted-foreground">{ago(a.last_seen)}</TableCell>
                  <TableCell onClick={(e) => e.stopPropagation()}>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" className="size-8"><MoreHorizontal className="size-4" /></Button></DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        {a.status !== "isolated"
                          ? <DropdownMenuItem variant="destructive" onClick={() => act(a, "isolate", "Isolate")}><ShieldOff className="size-4" /> Isolate endpoint</DropdownMenuItem>
                          : <DropdownMenuItem onClick={() => act(a, "unisolate", "Lift isolation")}><ShieldCheck className="size-4" /> Lift isolation</DropdownMenuItem>}
                        <DropdownMenuItem onClick={() => act(a, "block_usb", "Block USB")}><Usb className="size-4" /> Block USB</DropdownMenuItem>
                        <DropdownMenuItem onClick={() => act(a, "block_upload", "Block uploads")}><CloudOff className="size-4" /> Block uploads</DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
              {(!agents || agents.length === 0) && (
                <TableRow><TableCell colSpan={9} className="py-12 text-center font-mono text-sm text-muted-foreground">no endpoints enrolled</TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <InfoSheet
        open={!!sel}
        onOpenChange={(o) => !o && setSel(null)}
        title={sel?.hostname || ""}
        sub={sel ? `endpoint · ${sel.status}` : ""}
        badge={sel && <StatusDot status={sel.status} />}
        fields={sel ? fields(sel) : []}
      >
        {sel && (
          <div className="flex flex-wrap gap-2">
            {sel.status !== "isolated"
              ? <Button size="sm" variant="destructive" onClick={() => act(sel, "isolate", "Isolate")}><ShieldOff className="size-4" /> Isolate</Button>
              : <Button size="sm" onClick={() => act(sel, "unisolate", "Lift isolation")}><ShieldCheck className="size-4" /> Lift isolation</Button>}
            <Button size="sm" variant="outline" onClick={() => act(sel, "block_usb", "Block USB")}><Usb className="size-4" /> Block USB</Button>
            <Button size="sm" variant="outline" onClick={() => act(sel, "block_upload", "Block uploads")}><CloudOff className="size-4" /> Block uploads</Button>
          </div>
        )}
      </InfoSheet>
    </>
  );
}
