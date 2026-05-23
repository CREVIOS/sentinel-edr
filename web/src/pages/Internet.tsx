import { useMemo } from "react";
import { useStore } from "../store";
import { Panel, Stat, ago, bytes } from "../ui";

export default function Internet() {
  const { events } = useStore();
  const net = useMemo(() => events.filter((e) => e.category === "network" && e.network), [events]);

  const topDomains = useMemo(() => {
    const m: Record<string, { hits: number; out: number; cat: string }> = {};
    net.forEach((e) => {
      const d = e.network!.domain || e.network!.remote || "unknown";
      if (!m[d]) m[d] = { hits: 0, out: 0, cat: e.network!.category || "web" };
      m[d].hits++;
      m[d].out += e.network!.bytes_out || 0;
    });
    return Object.entries(m).sort((a, b) => b[1].out - a[1].out).slice(0, 12);
  }, [net]);

  const totalOut = net.reduce((s, e) => s + (e.network!.bytes_out || 0), 0);
  const cloud = net.filter((e) => e.network!.category === "cloud_storage").length;
  const webmail = net.filter((e) => e.network!.category === "webmail").length;

  return (
    <div className="grid" style={{ gap: 18 }}>
      <div className="grid cols-4">
        <Stat label="Connections" value={net.length} accent="#34e3d4" foot={<span>live session</span>} />
        <Stat label="Data Uploaded" value={bytes(totalOut)} accent="#c6ff3a" foot={<span>outbound total</span>} />
        <Stat label="Cloud Storage" value={cloud} accent="#8b7bff" foot={<span>uploads observed</span>} />
        <Stat label="Webmail" value={webmail} foot={<span>sessions</span>} />
      </div>

      <Panel title="TOP DESTINATIONS" sub="by upload volume">
        <table className="table">
          <thead><tr><th>Domain</th><th>Category</th><th>Connections</th><th>Uploaded</th></tr></thead>
          <tbody>
            {topDomains.map(([d, v]) => (
              <tr key={d}>
                <td className="mono">{d}</td>
                <td><span className="chip cyan">{v.cat}</span></td>
                <td className="mono">{v.hits}</td>
                <td className="mono">{bytes(v.out)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {topDomains.length === 0 && <div className="empty">no internet activity captured yet</div>}
      </Panel>

      <Panel title="WEB ACTIVITY" sub="recent connections">
        <div className="table-wrap scroll">
          <table className="table">
            <thead><tr><th>Time</th><th>Host</th><th>User</th><th>Domain</th><th>Category</th><th>↑ Out</th><th>↓ In</th><th></th></tr></thead>
            <tbody>
              {net.slice(0, 150).map((e) => (
                <tr key={e.id} className="row-enter">
                  <td className="mono dim">{ago(e.ts)}</td>
                  <td>{e.hostname}</td>
                  <td>{e.user || <span className="dim">—</span>}</td>
                  <td className="mono">{e.network!.domain || e.network!.remote}</td>
                  <td><span className="chip">{e.network!.category || "web"}</span></td>
                  <td className="mono">{bytes(e.network!.bytes_out)}</td>
                  <td className="mono dim">{bytes(e.network!.bytes_in)}</td>
                  <td>{e.network!.blocked && <span className="chip" style={{ color: "var(--crit)", borderColor: "var(--crit)" }}>blocked</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
