import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useStore } from "../store";
import { Mitre, Panel, Sev, Stat, ago } from "../ui";

const SEV_COLORS: Record<string, string> = {
  critical: "#ff3b54",
  high: "#ff8a3d",
  medium: "#ffd23d",
  low: "#46a6ff",
  info: "#6b7686",
};

const tip = {
  background: "#0f141d",
  border: "1px solid rgba(140,170,210,0.28)",
  borderRadius: 10,
  fontFamily: "var(--mono)",
  fontSize: 12,
  color: "#e8edf5",
};

export default function Overview() {
  const { overview, detections } = useStore();
  const c = overview?.counts || {};
  const timeline = (overview?.timeline || []).map((t) => ({
    t: t.hour.slice(11, 16),
    count: t.count,
  }));
  const sevData = Object.entries(overview?.severity || {})
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));
  const catData = Object.entries(overview?.events_by_category || {})
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);
  const mitreData = (overview?.top_mitre || []).map((m) => ({ name: m.tactic, value: m.count }));
  const recent = detections.slice(0, 8);

  return (
    <div className="grid" style={{ gap: 18 }}>
      <div className="grid cols-4">
        <div className="reveal d1">
          <Stat
            label="Endpoints"
            value={c.agents_total ?? 0}
            foot={
              <>
                <span style={{ color: "var(--signal)" }}>{c.agents_online ?? 0} online</span>
                {(c.agents_isolated ?? 0) > 0 && <span style={{ color: "var(--crit)" }}>· {c.agents_isolated} isolated</span>}
              </>
            }
          />
        </div>
        <div className="reveal d2">
          <Stat
            label="Open Detections"
            value={c.detections_open ?? 0}
            crit={(c.detections_critical ?? 0) > 0}
            foot={<span style={{ color: "var(--crit)" }}>{c.detections_critical ?? 0} critical</span>}
          />
        </div>
        <div className="reveal d3">
          <Stat label="Events · 24h" value={fmt(c.events_24h ?? 0)} accent="#34e3d4" foot={<span>telemetry ingested</span>} />
        </div>
        <div className="reveal d4">
          <Stat label="DLP Incidents · 24h" value={c.dlp_24h ?? 0} accent="#8b7bff" foot={<span>{c.responses_total ?? 0} responses issued</span>} />
        </div>
      </div>

      <div className="grid cols-3">
        <div className="span-2 reveal d2">
          <Panel title="EVENT VOLUME" sub="last 24 hours">
            <ResponsiveContainer width="100%" height={240}>
              <AreaChart data={timeline} margin={{ top: 6, right: 6, left: -18, bottom: 0 }}>
                <defs>
                  <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#c6ff3a" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#c6ff3a" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="t" stroke="#5f6c82" tick={{ fontSize: 10, fontFamily: "var(--mono)" }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                <YAxis stroke="#5f6c82" tick={{ fontSize: 10, fontFamily: "var(--mono)" }} tickLine={false} axisLine={false} width={42} />
                <Tooltip contentStyle={tip} cursor={{ stroke: "#c6ff3a", strokeOpacity: 0.3 }} />
                <Area type="monotone" dataKey="count" stroke="#c6ff3a" strokeWidth={2} fill="url(#g)" />
              </AreaChart>
            </ResponsiveContainer>
          </Panel>
        </div>
        <div className="reveal d3">
          <Panel title="DETECTIONS BY SEVERITY" sub="active">
            {sevData.length === 0 ? (
              <div className="empty">no active detections</div>
            ) : (
              <>
                <ResponsiveContainer width="100%" height={180}>
                  <PieChart>
                    <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={52} outerRadius={80} paddingAngle={3} stroke="none">
                      {sevData.map((d) => (
                        <Cell key={d.name} fill={SEV_COLORS[d.name] || "#6b7686"} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={tip} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="legend" style={{ justifyContent: "center", marginTop: 6 }}>
                  {sevData.map((d) => (
                    <span key={d.name}>
                      <i style={{ background: SEV_COLORS[d.name] }} />
                      {d.name} · {d.value}
                    </span>
                  ))}
                </div>
              </>
            )}
          </Panel>
        </div>
      </div>

      <div className="grid cols-2">
        <div className="reveal d3">
          <Panel title="EVENTS BY DOMAIN" sub="24h by category">
            <ResponsiveContainer width="100%" height={210}>
              <BarChart data={catData} layout="vertical" margin={{ left: 18, right: 16, top: 4, bottom: 4 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="name" stroke="#9aa7bb" tick={{ fontSize: 11, fontFamily: "var(--mono)" }} tickLine={false} axisLine={false} width={78} />
                <Tooltip contentStyle={tip} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
                <Bar dataKey="value" radius={[0, 5, 5, 0]} barSize={14} fill="#34e3d4" />
              </BarChart>
            </ResponsiveContainer>
          </Panel>
        </div>
        <div className="reveal d4">
          <Panel title="ATT&CK TACTICS" sub="most observed">
            {mitreData.length === 0 ? (
              <div className="empty">no tactics observed yet</div>
            ) : (
              <ResponsiveContainer width="100%" height={210}>
                <BarChart data={mitreData} layout="vertical" margin={{ left: 30, right: 16, top: 4, bottom: 4 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="name" stroke="#9aa7bb" tick={{ fontSize: 10.5, fontFamily: "var(--mono)" }} tickLine={false} axisLine={false} width={120} />
                  <Tooltip contentStyle={tip} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
                  <Bar dataKey="value" radius={[0, 5, 5, 0]} barSize={14} fill="#8b7bff" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </Panel>
        </div>
      </div>

      <div className="reveal d5">
        <Panel title="LATEST DETECTIONS" sub="real-time">
          {recent.length === 0 ? (
            <div className="empty">awaiting telemetry…</div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Detection</th>
                  <th>Host</th>
                  <th>ATT&CK</th>
                  <th>Engine</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((d) => (
                  <tr key={d.id}>
                    <td><Sev s={d.severity} /></td>
                    <td className="mono">{d.rule_name}</td>
                    <td>{d.hostname}</td>
                    <td><Mitre ids={d.mitre} /></td>
                    <td><span className="chip">{d.engine}</span></td>
                    <td className="dim">{ago(d.ts)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>
    </div>
  );
}

function fmt(n: number): string {
  if (n >= 1000) return (n / 1000).toFixed(1) + "k";
  return String(n);
}
