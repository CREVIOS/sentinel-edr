import { useMemo, useState } from "react";
import { SearchInput, Segmented, matchText } from "../filters";
import { useStore } from "../store";
import { Panel, Stat, ago } from "../ui";

const TYPE_LABEL: Record<string, string> = {
  kill_process: "Kill Process",
  isolate: "Isolate Endpoint",
  unisolate: "Lift Isolation",
  disable_account: "Disable Account",
  block_upload: "Block Upload",
  block_usb: "Block USB",
};

export default function Responses() {
  const { responses } = useStore();
  const [q, setQ] = useState("");
  const [src, setSrc] = useState("all");
  const auto = responses.filter((r) => r.automated).length;
  const done = responses.filter((r) => r.status === "completed").length;
  const failed = responses.filter((r) => r.status === "failed").length;

  const rows = useMemo(
    () =>
      responses.filter(
        (r) =>
          (src === "all" || (src === "auto" ? r.automated : !r.automated)) &&
          matchText(q, r.hostname, r.type, TYPE_LABEL[r.type], r.issued_by, r.reason, r.result, targetStr(r.target))
      ),
    [responses, q, src]
  );

  return (
    <div className="grid" style={{ gap: 18 }}>
      <div className="grid cols-4">
        <Stat label="Total Responses" value={responses.length} accent="#c6ff3a" foot={<span>this session</span>} />
        <Stat label="Automated" value={auto} accent="#34e3d4" foot={<span>rule-triggered</span>} />
        <Stat label="Completed" value={done} foot={<span>acknowledged by agent</span>} />
        <Stat label="Failed" value={failed} crit={failed > 0} foot={<span>need attention</span>} />
      </div>

      <div className="toolbar">
        <Segmented
          value={src}
          onChange={setSrc}
          options={[
            { value: "all", label: "All", count: responses.length },
            { value: "auto", label: "Automated", count: auto },
            { value: "manual", label: "Manual", count: responses.length - auto },
          ]}
        />
        <SearchInput value={q} onChange={setQ} placeholder="Filter by host, action, issuer, result…" width={300} />
        <span style={{ flex: 1 }} />
        <span className="chip">{rows.length} shown</span>
      </div>

      <Panel title="RESPONSE ACTIONS" sub="Monitor → Detect → Prevent → Respond">
        <div className="table-wrap scroll">
          <table className="table">
            <thead>
              <tr><th>Time</th><th>Action</th><th>Target</th><th>Host</th><th>Source</th><th>Issued By</th><th>Status</th><th>Result</th></tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className="row-enter">
                  <td className="mono dim">{ago(r.ts)}</td>
                  <td className="mono">{TYPE_LABEL[r.type] || r.type}</td>
                  <td className="mono dim">{targetStr(r.target)}</td>
                  <td>{r.hostname}</td>
                  <td>{r.automated ? <span className="chip lime">auto</span> : <span className="chip">manual</span>}</td>
                  <td className="dim">{r.issued_by}</td>
                  <td><RespStatus s={r.status} /></td>
                  <td className="dim" style={{ maxWidth: 280, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title={r.result}>{r.result}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && <div className="empty">{responses.length === 0 ? "no response actions yet" : "no actions match this filter"}</div>}
        </div>
      </Panel>
    </div>
  );
}

function targetStr(t: Record<string, unknown>): string {
  if (!t) return "—";
  return Object.entries(t).map(([k, v]) => `${k}=${v}`).join(" ") || "—";
}

function RespStatus({ s }: { s: string }) {
  const color =
    s === "completed" ? "var(--signal)" : s === "failed" ? "var(--crit)" : s === "pending" ? "var(--med)" : "var(--ink-dim)";
  return <span className="chip" style={{ color, borderColor: color }}>{s}</span>;
}
