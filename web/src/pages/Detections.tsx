import { useMemo, useState } from "react";
import { api, getRole } from "../api";
import { ConfirmButton, Copyable, Drawer, KV } from "../components";
import { SearchInput, matchText } from "../filters";
import { useStore } from "../store";
import type { Detection } from "../types";
import { Mitre, Panel, Sev, ago } from "../ui";

export default function Detections() {
  const { detections, events, pushToast, refreshDetections } = useStore();
  const [status, setStatus] = useState("");
  const [sev, setSev] = useState("");
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<Detection | null>(null);
  const canAct = getRole() === "admin" || getRole() === "analyst";

  const rows = useMemo(
    () =>
      detections.filter(
        (d) =>
          (!status || d.status === status) &&
          (!sev || d.severity === sev) &&
          matchText(q, d.hostname, d.user, d.rule_name, d.rule_id, d.summary, d.tactic, d.engine)
      ),
    [detections, status, sev, q]
  );

  const relatedPid = (d: Detection): number | undefined => {
    const id = d.event_ids?.[0];
    const ev = events.find((e) => e.id === id);
    return ev?.process?.pid;
  };

  const setStat = async (d: Detection, s: string) => {
    try {
      await api.setDetectionStatus(d.id, s);
      pushToast(`detection ${s}`);
      refreshDetections();
      setSel((cur) => (cur ? { ...cur, status: s as any } : cur));
    } catch (e) {
      pushToast(`failed: ${e}`, true);
    }
  };

  const respond = async (d: Detection, type: string, target?: Record<string, unknown>) => {
    try {
      await api.respond({ type, agent_id: d.agent_id, target, reason: `from detection ${d.rule_id}`, detection_id: d.id });
      pushToast(`${type} dispatched to ${d.hostname}`);
    } catch (e) {
      pushToast(`action failed: ${e}`, true);
    }
  };

  return (
    <>
      <div className="toolbar">
        <SearchInput value={q} onChange={setQ} placeholder="Filter by host, user, rule, tactic…" width={300} />
        <select className="input" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="closed">Closed</option>
        </select>
        <select className="input" value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="">All Severities</option>
          {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{s.toUpperCase()}</option>)}
        </select>
        <span style={{ flex: 1 }} />
        <span className="chip">{rows.length} detections</span>
      </div>

      <Panel title="THREAT DETECTIONS" sub="Sigma · behavioral · DLP">
        <div className="table-wrap scroll">
          <table className="table">
            <thead>
              <tr>
                <th>Sev</th><th>Detection</th><th>Host</th><th>User</th><th>Tactic</th><th>ATT&CK</th><th>Engine</th><th>Status</th><th>When</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => (
                <tr key={d.id} className="row-enter" onClick={() => setSel(d)} style={{ cursor: "pointer" }}>
                  <td><Sev s={d.severity} /></td>
                  <td className="mono">{d.rule_name}</td>
                  <td>{d.hostname}</td>
                  <td>{d.user || <span className="dim">—</span>}</td>
                  <td className="dim">{d.tactic || "—"}</td>
                  <td><Mitre ids={d.mitre} /></td>
                  <td><span className="chip">{d.engine}</span></td>
                  <td><StatusPill s={d.status} /></td>
                  <td className="dim">{ago(d.ts)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && <div className="empty">no detections — run the agent scenario to generate threats</div>}
        </div>
      </Panel>

      {sel && (
        <Drawer
          title={sel.rule_name}
          sub={`${sel.severity} · ${sel.engine} engine`}
          onClose={() => setSel(null)}
          foot={
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button className="btn btn-sm" onClick={() => setStat(sel, "acknowledged")}>Acknowledge</button>
              <button className="btn btn-sm" onClick={() => setStat(sel, "closed")}>Close</button>
              {canAct && (
                <>
                  {relatedPid(sel) && (
                    <ConfirmButton className="btn btn-danger btn-sm" confirmLabel={`Kill ${relatedPid(sel)}`} onConfirm={() => respond(sel, "kill_process", { pid: relatedPid(sel) })}>Kill PID {relatedPid(sel)}</ConfirmButton>
                  )}
                  <ConfirmButton className="btn btn-danger btn-sm" confirmLabel="Isolate" onConfirm={() => respond(sel, "isolate")}>Isolate Host</ConfirmButton>
                  {sel.user && <ConfirmButton className="btn btn-sm" confirmLabel={`Disable ${sel.user}`} onConfirm={() => respond(sel, "disable_account", { user: sel.user })}>Disable {sel.user}</ConfirmButton>}
                </>
              )}
            </div>
          }
        >
          <KV
            items={[
              ["Rule", <span className="mono">{sel.rule_id}</span>],
              ["Severity", <Sev s={sel.severity} />],
              ["Summary", sel.summary],
              ["Host", <span className="mono">{sel.hostname}</span>],
              ["User", sel.user],
              ["Tactic", sel.tactic],
              ["ATT&CK", <Mitre ids={sel.mitre} />],
              ["Engine", <span className="chip">{sel.engine}</span>],
              ["Status", <StatusPill s={sel.status} />],
              ["Assigned", sel.assigned_to],
              ["Detected", new Date(sel.ts).toLocaleString()],
              ["Events", <span className="mono dim">{(sel.event_ids || []).join(", ")}</span>],
            ]}
          />
        </Drawer>
      )}
    </>
  );
}

function StatusPill({ s }: { s: string }) {
  const color = s === "open" ? "var(--high)" : s === "acknowledged" ? "var(--low)" : "var(--ink-faint)";
  return <span className="chip" style={{ color, borderColor: color }}>{s}</span>;
}
