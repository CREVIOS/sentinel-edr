"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Chip } from "@/components/severity";
import { useData } from "@/lib/use-data";
import { ago } from "@/lib/format";
import type { ResponseAction } from "@/lib/types";

const LABEL: Record<string, string> = {
  kill_process: "Kill Process", isolate: "Isolate Endpoint", unisolate: "Lift Isolation",
  disable_account: "Disable Account", block_upload: "Block Upload", block_usb: "Block USB",
};

function statusColor(s: string) {
  return s === "completed" ? "var(--chart-2)" : s === "failed" ? "var(--sev-critical)" : s === "pending" ? "var(--sev-medium)" : "var(--muted-foreground)";
}

function StatMini({ label, value, accent }: { label: string; value: React.ReactNode; accent?: string }) {
  return (
    <Card className="transition-colors hover:border-foreground/15">
      <CardContent className="p-5">
        <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
        <div className="mt-3 font-mono text-[2rem] font-semibold leading-none tabular-nums">{value}</div>
      </CardContent>
    </Card>
  );
}

export default function ResponsesPage() {
  const { data: responses } = useData<ResponseAction[]>("responses", 3000, "response");
  const r = responses || [];
  const auto = r.filter((x) => x.automated).length;
  const done = r.filter((x) => x.status === "completed").length;
  const failed = r.filter((x) => x.status === "failed").length;

  return (
    <div className="space-y-5">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatMini label="Total Responses" value={r.length} />
        <StatMini label="Automated" value={auto} accent="var(--chart-2)" />
        <StatMini label="Completed" value={done} accent="var(--chart-3)" />
        <StatMini label="Failed" value={failed} accent="var(--sev-critical)" />
      </div>
      <Card>
        <CardHeader><CardTitle className="font-mono text-sm tracking-wide">RESPONSE ACTIONS · Monitor → Detect → Prevent → Respond</CardTitle></CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader><TableRow><TableHead>Time</TableHead><TableHead>Action</TableHead><TableHead>Target</TableHead><TableHead>Host</TableHead><TableHead>Source</TableHead><TableHead>By</TableHead><TableHead>Status</TableHead><TableHead>Result</TableHead></TableRow></TableHeader>
            <TableBody>
              {r.map((x) => (
                <TableRow key={x.id}>
                  <TableCell className="font-mono text-xs text-muted-foreground">{ago(x.ts)}</TableCell>
                  <TableCell className="font-mono">{LABEL[x.type] || x.type}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{Object.entries(x.target || {}).map(([k, v]) => `${k}=${v}`).join(" ") || "—"}</TableCell>
                  <TableCell>{x.hostname}</TableCell>
                  <TableCell>{x.automated ? <Chip color="var(--chart-2)">auto</Chip> : <Chip>manual</Chip>}</TableCell>
                  <TableCell className="text-muted-foreground">{x.issued_by}</TableCell>
                  <TableCell><Chip color={statusColor(x.status)}>{x.status}</Chip></TableCell>
                  <TableCell className="max-w-[20rem] truncate text-xs text-muted-foreground" title={x.result}>{x.result}</TableCell>
                </TableRow>
              ))}
              {r.length === 0 && <TableRow><TableCell colSpan={8} className="py-12 text-center font-mono text-sm text-muted-foreground">no response actions yet</TableCell></TableRow>}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
