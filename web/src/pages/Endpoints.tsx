import { useMemo, useState } from "react";
import { api, getRole } from "../api";
import { ConfirmButton, Copyable, Drawer, KV } from "../components";
import { SearchInput, Segmented, SortHeader, matchText, useTableSort } from "../filters";
import { useStore } from "../store";
import type { Agent } from "../types";
import { Panel, StatusTag, ago, rowClick } from "../ui";

export default function Endpoints() {
  const { agents, pushToast, refreshAgents } = useStore();
  const [sel, setSel] = useState<Agent | null>(null);
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("all");
  const { sortKey, dir, toggle, sort } = useTableSort<Agent>("hostname", 1);
  const canAct = getRole() === "admin" || getRole() === "analyst";

  const counts = useMemo(() => {
    const c = { all: agents.length, online: 0, offline: 0, isolated: 0 } as Record<string, number>;
    agents.forEach((a) => (c[a.status] = (c[a.status] || 0) + 1));
    return c;
  }, [agents]);

  const rows = useMemo(() => {
    let r = agents;
    if (status !== "all") r = r.filter((a) => a.status === status);
    r = r.filter((a) =>
      matchText(q, a.hostname, a.ip, a.mac, a.os, a.kernel, a.arch, a.id, (a.labels || []).join(" "))
    );
    return sort(r, (a, k) =>
      k === "last_seen" ? new Date(a.last_seen).getTime() : k === "event_count" ? a.event_count : (a as any)[k]
    );
  }, [agents, q, status, sortKey, dir]);

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
      <div className="toolbar">
        <Segmented
          value={status}
          onChange={setStatus}
          options={[
            { value: "all", label: "All", count: counts.all },
            { value: "online", label: "Online", count: counts.online, dot: "st-online" },
            { value: "offline", label: "Offline", count: counts.offline, dot: "st-offline" },
            { value: "isolated", label: "Isolated", count: counts.isolated, dot: "st-isolated" },
          ]}
        />
        <SearchInput value={q} onChange={setQ} placeholder="Filter by host, IP, MAC, OS, arch, label…" width={320} />
        <span style={{ flex: 1 }} />
        <span className="chip lime">{rows.length} shown</span>
      </div>

      <Panel title="ENDPOINT FLEET" sub={`${agents.length} enrolled · ${counts.online} online`}>
        {agents.length === 0 ? (
          <div className="empty">no endpoints enrolled — start an agent to enroll</div>
        ) : (
          <div className="table-wrap scroll">
            <table className="table">
              <thead>
                <tr>
                  <SortHeader k="status" label="Status" sortKey={sortKey} dir={dir} onSort={toggle} />
                  <SortHeader k="hostname" label="Hostname" sortKey={sortKey} dir={dir} onSort={toggle} />
                  <SortHeader k="os" label="OS / Kernel" sortKey={sortKey} dir={dir} onSort={toggle} />
                  <SortHeader k="ip" label="IP" sortKey={sortKey} dir={dir} onSort={toggle} />
                  <SortHeader k="mac" label="MAC" sortKey={sortKey} dir={dir} onSort={toggle} />
                  <th>Arch</th>
                  <SortHeader k="event_count" label="Events" sortKey={sortKey} dir={dir} onSort={toggle} align="right" />
                  <SortHeader k="last_seen" label="Last Seen" sortKey={sortKey} dir={dir} onSort={toggle} />
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.id} {...rowClick(() => setSel(a))}>
                    <td><StatusTag s={a.status} /></td>
                    <td className="mono">{hl(a.hostname, q)}</td>
                    <td>{a.os || "—"} <span className="dim">{a.kernel}</span></td>
                    <td className="mono">{hl(a.ip || "—", q)}</td>
                    <td className="mono dim">{hl(a.mac || "—", q)}</td>
                    <td><span className="chip">{a.arch || "—"}</span></td>
                    <td className="mono" style={{ textAlign: "right" }}>{a.event_count?.toLocaleString?.() ?? a.event_count}</td>
                    <td className="dim">{ago(a.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {rows.length === 0 && <div className="empty">no endpoints match this filter</div>}
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
                  <ConfirmButton className="btn btn-danger" confirmLabel="Isolate" onConfirm={() => act(sel, "isolate")}>⊘ Isolate Endpoint</ConfirmButton>
                ) : (
                  <button className="btn btn-primary" onClick={() => act(sel, "unisolate")}>↺ Lift Isolation</button>
                )}
                <ConfirmButton className="btn" confirmLabel="Block USB" onConfirm={() => act(sel, "block_usb")}>⛁ Block USB</ConfirmButton>
                <ConfirmButton className="btn" confirmLabel="Block Uploads" onConfirm={() => act(sel, "block_upload")}>◈ Block Uploads</ConfirmButton>
              </div>
            )
          }
        >
          <KV
            items={[
              ["Agent ID", <Copyable text={sel.id}><span className="mono">{sel.id}</span></Copyable>],
              ["Status", <StatusTag s={sel.status} />],
              ["Operating System", sel.os],
              ["Kernel", <span className="mono">{sel.kernel}</span>],
              ["Architecture", <span className="chip">{sel.arch}</span>],
              ["IP Address", <Copyable text={sel.ip}><span className="mono">{sel.ip}</span></Copyable>],
              ["MAC Address", <Copyable text={sel.mac}><span className="mono">{sel.mac}</span></Copyable>],
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

/** Highlight the matched substring in a cell so the filter hit is obvious. */
function hl(text: string, q: string) {
  if (!q) return text;
  const i = text.toLowerCase().indexOf(q.toLowerCase());
  if (i < 0) return text;
  return (
    <>
      {text.slice(0, i)}
      <mark className="hl">{text.slice(i, i + q.length)}</mark>
      {text.slice(i + q.length)}
    </>
  );
}
