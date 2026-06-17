import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { SearchInput, matchText } from "../filters";
import { useStore } from "../store";
import { Panel, Sev, Stat, ago } from "../ui";

export default function Dlp() {
  const { events } = useStore();
  const [q, setQ] = useState("");
  const [classifiers, setClassifiers] = useState<{ name: string; label: string; severity: string }[]>([]);
  const [policies, setPolicies] = useState<{ Classifier: string; Channel: string; Verdict: string }[]>([]);

  useEffect(() => {
    api.dlpClassifiers().then(setClassifiers).catch(() => {});
    api.dlpPolicies().then(setPolicies).catch(() => {});
  }, []);

  const allDlp = useMemo(() => events.filter((e) => e.category === "dlp" || e.dlp), [events]);
  const dlpEvents = useMemo(
    () => allDlp.filter((e) => matchText(q, e.hostname, e.user, e.dlp?.classifier, e.dlp?.channel, e.dlp?.sample, e.dlp?.verdict)),
    [allDlp, q]
  );
  const byClass = useMemo(() => {
    const m: Record<string, number> = {};
    allDlp.forEach((e) => {
      const c = e.dlp?.classifier || "unknown";
      m[c] = (m[c] || 0) + 1;
    });
    return m;
  }, [allDlp]);
  const blocked = allDlp.filter((e) => e.dlp?.verdict === "block").length;

  return (
    <div className="grid" style={{ gap: 18 }}>
      <div className="grid cols-4">
        <Stat label="DLP Incidents" value={allDlp.length} accent="#8b7bff" foot={<span>live session</span>} />
        <Stat label="Blocked Transfers" value={blocked} crit={blocked > 0} foot={<span>policy enforced</span>} />
        <Stat label="Classifiers" value={classifiers.length} accent="#34e3d4" foot={<span>active patterns</span>} />
        <Stat label="Policies" value={policies.length} accent="#c6ff3a" foot={<span>channel rules</span>} />
      </div>

      <Panel
        title="DLP INCIDENTS"
        sub="sensitive data movement"
        right={<SearchInput value={q} onChange={setQ} placeholder="Filter by host, user, classifier, channel…" width={300} />}
      >
        <div className="table-wrap scroll">
          <table className="table">
            <thead>
              <tr><th>Sev</th><th>Classifier</th><th>Channel</th><th>Host</th><th>User</th><th>Sample</th><th>Verdict</th><th>When</th></tr>
            </thead>
            <tbody>
              {dlpEvents.map((e) => (
                <tr key={e.id} className="row-enter">
                  <td><Sev s={e.severity} /></td>
                  <td className="mono">{e.dlp?.classifier}</td>
                  <td><span className="chip">{e.dlp?.channel}</span></td>
                  <td>{e.hostname}</td>
                  <td>{e.user || <span className="dim">—</span>}</td>
                  <td className="mono dim">{e.dlp?.sample}</td>
                  <td><Verdict v={e.dlp?.verdict} /></td>
                  <td className="dim">{ago(e.ts)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {dlpEvents.length === 0 && <div className="empty">no DLP incidents in this session</div>}
        </div>
      </Panel>

      <div className="grid cols-2">
        <Panel title="CLASSIFIERS" sub="content patterns">
          <table className="table">
            <thead><tr><th>Name</th><th>Detects</th><th>Severity</th><th>Hits</th></tr></thead>
            <tbody>
              {classifiers.map((c) => (
                <tr key={c.name}>
                  <td className="mono">{c.name}</td>
                  <td>{c.label}</td>
                  <td><Sev s={c.severity} /></td>
                  <td className="mono">{byClass[c.name] || 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
        <Panel title="ENFORCEMENT POLICIES" sub="classifier × channel → verdict">
          <table className="table">
            <thead><tr><th>Classifier</th><th>Channel</th><th>Verdict</th></tr></thead>
            <tbody>
              {policies.map((p, i) => (
                <tr key={i}>
                  <td className="mono">{p.Classifier}</td>
                  <td><span className="chip">{p.Channel}</span></td>
                  <td><Verdict v={p.Verdict} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
    </div>
  );
}

function Verdict({ v }: { v?: string }) {
  if (!v) return <span className="dim">—</span>;
  const color = v === "block" ? "var(--crit)" : v === "alert" ? "var(--high)" : "var(--ink-dim)";
  return <span className="chip" style={{ color, borderColor: color }}>{v}</span>;
}
