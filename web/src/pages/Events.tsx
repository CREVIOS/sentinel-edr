import { useMemo, useState } from "react";
import { Drawer, KV } from "../components";
import { ProcessTree } from "../ProcessTree";
import { useStore } from "../store";
import type { Event } from "../types";
import { CAT_ICON, Panel, Sev, bytes, rowClick, shortTime } from "../ui";

const CATS = ["", "process", "file", "network", "auth", "ssh", "usb", "package", "dlp", "system"];
const SEVS = ["", "critical", "high", "medium", "low", "info"];

export function EventDrawer({ e, onClose }: { e: Event; onClose: () => void }) {
  const { events } = useStore();
  const items: [string, any][] = [
    ["Time", new Date(e.ts).toLocaleString()],
    ["Severity", <Sev s={e.severity} />],
    ["Host", <span className="mono">{e.hostname}</span>],
    ["User", e.user],
    ["Message", e.message],
  ];
  if (e.process) {
    items.push(
      ["Process", <span className="mono">{e.process.name} (pid {e.process.pid})</span>],
      ["Parent", e.process.parent],
      ["Command", <span className="cmd" style={{ whiteSpace: "normal" }}>{e.process.cmdline}</span>]
    );
  }
  if (e.file) {
    items.push(
      ["File", <span className="mono">{e.file.path}</span>],
      ["Operation", e.file.op],
      ["SHA-256", <span className="mono dim">{e.file.hash}</span>]
    );
  }
  if (e.network) {
    items.push(
      ["Domain", e.network.domain],
      ["Remote", <span className="mono">{e.network.remote}</span>],
      ["Category", e.network.category],
      ["Bytes", `↑ ${bytes(e.network.bytes_out)} · ↓ ${bytes(e.network.bytes_in)}`]
    );
  }
  if (e.usb) {
    items.push(["Device", `${e.usb.vendor} ${e.usb.product}`], ["Serial", <span className="mono">{e.usb.serial}</span>]);
  }
  if (e.auth) {
    items.push(["Method", e.auth.method], ["Source IP", <span className="mono">{e.auth.source_ip}</span>], ["Result", e.auth.result]);
  }
  if (e.dlp) {
    items.push(
      ["Classifier", e.dlp.classifier],
      ["Channel", e.dlp.channel],
      ["Sample", <span className="mono">{e.dlp.sample}</span>],
      ["Verdict", e.dlp.verdict]
    );
  }
  return (
    <Drawer title={`${e.category} · ${e.action}`} sub="event detail" onClose={onClose}>
      <KV items={items} />
      {e.process?.pid ? (
        <div style={{ marginTop: 18 }}>
          <ProcessTree event={e} events={events} />
        </div>
      ) : null}
    </Drawer>
  );
}

function detail(e: Event): string {
  if (e.process?.cmdline) return e.process.cmdline;
  if (e.file?.path) return `${e.file.op || ""} ${e.file.path}`;
  if (e.network?.domain) return `${e.network.domain} ${e.network.bytes_out ? "↑" + bytes(e.network.bytes_out) : ""}`;
  if (e.usb) return `${e.usb.vendor || ""} ${e.usb.product || ""} ${e.usb.serial || ""}`.trim();
  if (e.auth) return `${e.auth.method || ""} from ${e.auth.source_ip || "local"} → ${e.auth.result || ""}`;
  if (e.dlp) return `${e.dlp.classifier} via ${e.dlp.channel}`;
  return e.message || "";
}

export default function Events() {
  const { events } = useStore();
  const [cat, setCat] = useState("");
  const [sev, setSev] = useState("");
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<Event | null>(null);

  const rows = useMemo(() => {
    return events.filter((e) => {
      if (cat && e.category !== cat) return false;
      if (sev && e.severity !== sev) return false;
      if (q) {
        const blob = `${e.message} ${detail(e)} ${e.user} ${e.hostname}`.toLowerCase();
        if (!blob.includes(q.toLowerCase())) return false;
      }
      return true;
    });
  }, [events, cat, sev, q]);

  return (
    <>
      <div className="toolbar">
        <input className="input" placeholder="Search command, path, domain, user…" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 300 }} />
        <select className="input" value={cat} onChange={(e) => setCat(e.target.value)}>
          {CATS.map((c) => <option key={c} value={c}>{c ? c.toUpperCase() : "All Categories"}</option>)}
        </select>
        <select className="input" value={sev} onChange={(e) => setSev(e.target.value)}>
          {SEVS.map((s) => <option key={s} value={s}>{s ? s.toUpperCase() : "All Severities"}</option>)}
        </select>
        <span className="chip lime">{rows.length} shown · live</span>
      </div>

      <Panel title="EVENT STREAM" sub="real-time endpoint telemetry">
        <div className="table-wrap scroll">
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Sev</th>
                <th>Cat</th>
                <th>Host</th>
                <th>User</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, 250).map((e) => (
                <tr key={e.id} className="row-enter" {...rowClick(() => setSel(e))}>
                  <td className="mono dim">{shortTime(e.ts)}</td>
                  <td><Sev s={e.severity} /></td>
                  <td title={e.category}>{CAT_ICON[e.category] || "•"} <span className="dim">{e.action}</span></td>
                  <td className="mono">{e.hostname}</td>
                  <td>{e.user || <span className="dim">—</span>}</td>
                  <td><span className="cmd">{detail(e)}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && <div className="empty">no events match — telemetry will stream here live</div>}
        </div>
      </Panel>

      {sel && <EventDrawer e={sel} onClose={() => setSel(null)} />}
    </>
  );
}
