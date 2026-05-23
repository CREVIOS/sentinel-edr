import { useState } from "react";
import { api, getRole } from "../api";
import { Drawer, KV } from "../components";
import { useStore } from "../store";
import type { Agent } from "../types";
import { Panel, StatusTag, ago } from "../ui";

export default function Endpoints() {
  const { agents, pushToast, refreshAgents } = useStore();
  const [sel, setSel] = useState<Agent | null>(null);
  const canAct = getRole() === "admin" || getRole() === "analyst";

  const act = async (a: Agent, type: string) => {
    try {
      await api.respond({ type, agent_id: a.id, reason: `manual ${type} from console` });
      pushToast(`${type} dispatched to ${a.hostname}`);
      refreshAgents();
    } catch (e) {
      pushToast(`action failed: ${e}`, true);
    }
  };

  return (
    <>
      <Panel title="ENDPOINT FLEET" sub={`${agents.length} enrolled`}>
        {agents.length === 0 ? (
          <div className="empty">no endpoints enrolled — start an agent to enroll</div>
        ) : (
          <div className="table-wrap scroll">
            <table className="table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Hostname</th>
                  <th>OS / Kernel</th>
                  <th>IP</th>
                  <th>MAC</th>
                  <th>Arch</th>
                  <th>Events</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((a) => (
                  <tr key={a.id} onClick={() => setSel(a)} style={{ cursor: "pointer" }}>
                    <td><StatusTag s={a.status} /></td>
                    <td className="mono">{a.hostname}</td>
                    <td>{a.os || "—"} <span className="dim">{a.kernel}</span></td>
                    <td className="mono">{a.ip || "—"}</td>
                    <td className="mono dim">{a.mac || "—"}</td>
                    <td><span className="chip">{a.arch || "—"}</span></td>
                    <td className="mono">{a.event_count?.toLocaleString?.() ?? a.event_count}</td>
                    <td className="dim">{ago(a.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {sel && (
        <Drawer
          title={sel.hostname}
          sub={`endpoint · ${sel.status}`}
          onClose={() => setSel(null)}
          foot={
            canAct && (
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                {sel.status !== "isolated" ? (
                  <button className="btn btn-danger" onClick={() => act(sel, "isolate")}>⊘ Isolate Endpoint</button>
                ) : (
                  <button className="btn btn-primary" onClick={() => act(sel, "unisolate")}>↺ Lift Isolation</button>
                )}
                <button className="btn" onClick={() => act(sel, "block_usb")}>⛁ Block USB</button>
                <button className="btn" onClick={() => act(sel, "block_upload")}>◈ Block Uploads</button>
              </div>
            )
          }
        >
          <KV
            items={[
              ["Agent ID", <span className="mono">{sel.id}</span>],
              ["Status", <StatusTag s={sel.status} />],
              ["Operating System", sel.os],
              ["Kernel", <span className="mono">{sel.kernel}</span>],
              ["Architecture", <span className="chip">{sel.arch}</span>],
              ["IP Address", <span className="mono">{sel.ip}</span>],
              ["MAC Address", <span className="mono">{sel.mac}</span>],
              ["Agent Version", sel.version],
              ["Labels", (sel.labels || []).map((l) => <span key={l} className="chip lime" style={{ marginRight: 5 }}>{l}</span>)],
              ["Events Reported", sel.event_count?.toLocaleString?.()],
              ["Enrolled", new Date(sel.enrolled_at).toLocaleString()],
              ["Last Seen", `${ago(sel.last_seen)} (${new Date(sel.last_seen).toLocaleString()})`],
            ]}
          />
        </Drawer>
      )}
    </>
  );
}
