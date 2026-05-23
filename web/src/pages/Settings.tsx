import { getRole, getToken, getUser } from "../api";
import { useStore } from "../store";
import { Panel } from "../ui";

export default function Settings() {
  const { pushToast } = useStore();

  const download = async (kind: string, format: string, filename: string) => {
    try {
      const res = await fetch(`/api/v1/siem/export?kind=${kind}&format=${format}`, {
        headers: getToken() ? { Authorization: `Bearer ${getToken()}` } : {},
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      pushToast(`exported ${filename}`);
    } catch (e) {
      pushToast(`export failed: ${e}`, true);
    }
  };

  return (
    <div className="grid cols-2" style={{ gap: 18 }}>
      <Panel title="SIEM INTEGRATION" sub="forward to Splunk · Elastic · QRadar">
        <p style={{ color: "var(--ink-dim)", fontSize: 13, marginTop: 0 }}>
          Export normalized telemetry in standard formats for cross-source correlation in your enterprise SIEM.
        </p>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <button className="btn" onClick={() => download("events", "cef", "sentinel-events.cef")}>↧ Events — ArcSight CEF (syslog)</button>
          <button className="btn" onClick={() => download("events", "ecs", "sentinel-events-ecs.ndjson")}>↧ Events — Elastic Common Schema (ECS)</button>
          <button className="btn" onClick={() => download("detections", "cef", "sentinel-detections.cef")}>↧ Detections — ArcSight CEF</button>
        </div>
        <p style={{ color: "var(--ink-faint)", fontSize: 11, marginTop: 16, fontFamily: "var(--mono)" }}>
          Production forwarders should run from the exported CEF/ECS stream or a dedicated syslog/Kafka worker.
        </p>
      </Panel>

      <Panel title="SESSION" sub="current operator">
        <dl className="kv">
          <dt>Operator</dt><dd>{getUser()}</dd>
          <dt>Role</dt><dd><span className="chip lime">{getRole()}</span></dd>
          <dt>Console</dt><dd>Sentinel v1.0</dd>
          <dt>Auth</dt><dd>JWT · HS256 · 12h</dd>
        </dl>
      </Panel>

      <Panel title="PLATFORM ARCHITECTURE" sub="how it scales" className="span-2">
        <div className="grid cols-3" style={{ gap: 14 }}>
          <ArchCard title="Ingest Tier" body="Stateless Go API behind a load balancer. Validates per-agent HMAC, publishes to NATS JetStream. Scale horizontally." />
          <ArchCard title="Processing Tier" body="Workers consume the durable bus: Sigma detection, DLP content inspection, behavioral correlation, auto-response." />
          <ArchCard title="Storage Tier" body="TimescaleDB hypertables — time-partitioned, compressed, 90-day retention. Built for billions of events." />
          <ArchCard title="Endpoint Agent" body="Rust. Low-overhead collectors, local DLP, AES-256-GCM offline spool that replays on reconnect." />
          <ArchCard title="Control Mesh" body="NATS core routes containment commands to the gateway holding each agent's WebSocket. mTLS-ready." />
          <ArchCard title="Response" body="Kill process · isolate endpoint · disable account · block upload/USB — automated or analyst-issued." />
        </div>
      </Panel>
    </div>
  );
}

function ArchCard({ title, body }: { title: string; body: string }) {
  return (
    <div style={{ background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 10, padding: 16 }}>
      <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--signal)", letterSpacing: "0.08em", marginBottom: 8 }}>{title}</div>
      <div style={{ fontSize: 12.5, color: "var(--ink-dim)", lineHeight: 1.55 }}>{body}</div>
    </div>
  );
}
