import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { Rule } from "../types";
import { Mitre, Panel, Sev, Stat } from "../ui";

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [q, setQ] = useState("");
  useEffect(() => {
    api.rules().then((r) => setRules(r || [])).catch(() => {});
  }, []);

  const rows = useMemo(
    () => rules.filter((r) => !q || `${r.Title} ${r.ID} ${r.Tactic} ${(r.MITRE || []).join(" ")}`.toLowerCase().includes(q.toLowerCase())),
    [rules, q]
  );
  const withResp = rules.filter((r) => r.AutoRespond).length;
  const tactics = new Set(rules.map((r) => r.Tactic).filter(Boolean)).size;

  return (
    <div className="grid" style={{ gap: 18 }}>
      <div className="grid cols-4">
        <Stat label="Detection Rules" value={rules.length} accent="#c6ff3a" foot={<span>Sigma-style</span>} />
        <Stat label="ATT&CK Tactics" value={tactics} accent="#8b7bff" foot={<span>covered</span>} />
        <Stat label="Auto-Response" value={withResp} accent="#34e3d4" foot={<span>rules with actions</span>} />
        <Stat label="Behavioral" value={4} foot={<span>correlation rules</span>} />
      </div>

      <div className="toolbar">
        <input className="input" placeholder="Search rules, tactics, technique IDs…" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 320 }} />
        <span className="chip">{rows.length} rules</span>
      </div>

      <Panel title="DETECTION RULE CATALOG" sub="log-source agnostic · MITRE ATT&CK mapped">
        <div className="table-wrap scroll">
          <table className="table">
            <thead>
              <tr><th>Sev</th><th>Rule</th><th>Category</th><th>Tactic</th><th>ATT&CK</th><th>Auto-Response</th></tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.ID}>
                  <td><Sev s={r.Severity} /></td>
                  <td>
                    <div className="mono">{r.Title}</div>
                    <div className="dim" style={{ fontSize: 11 }}>{r.ID}</div>
                  </td>
                  <td><span className="chip">{r.Category}</span></td>
                  <td className="dim">{r.Tactic || "—"}</td>
                  <td><Mitre ids={r.MITRE} /></td>
                  <td>{r.AutoRespond ? <span className="chip lime">{r.AutoRespond}</span> : <span className="dim">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
