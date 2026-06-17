import { useEffect, useMemo, useState } from "react";
import { api, getRole, getUser } from "../api";
import { Drawer } from "../components";
import { SearchInput, Segmented, matchText } from "../filters";
import { useStore } from "../store";
import type { Case, CaseDetail } from "../types";
import { Mitre, Panel, Sev, ago, rowClick } from "../ui";

const STATUS_COLOR: Record<string, string> = {
  open: "var(--high)",
  investigating: "var(--low)",
  contained: "var(--cyan)",
  closed: "var(--ink-faint)",
};

function CaseStatusPill({ s }: { s: string }) {
  const c = STATUS_COLOR[s] || "var(--ink-dim)";
  return <span className="chip" style={{ color: c, borderColor: c }}>{s}</span>;
}

export default function Cases() {
  const { cases, pushToast, refreshCases } = useStore();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("all");
  const [sel, setSel] = useState<Case | null>(null);
  const canAct = getRole() === "admin" || getRole() === "analyst";

  const counts = useMemo(() => {
    const c = { all: cases.length, open: 0, investigating: 0, contained: 0, closed: 0 } as Record<string, number>;
    cases.forEach((k) => (c[k.status] = (c[k.status] || 0) + 1));
    return c;
  }, [cases]);

  const rows = useMemo(() => {
    let r = cases;
    if (status !== "all") r = r.filter((c) => c.status === status);
    return r.filter((c) => matchText(q, c.title, c.hostname, c.assigned_to, c.severity, (c.mitre || []).join(" ")));
  }, [cases, q, status]);

  return (
    <>
      <div className="toolbar">
        <Segmented
          value={status}
          onChange={setStatus}
          options={[
            { value: "all", label: "All", count: counts.all },
            { value: "open", label: "Open", count: counts.open },
            { value: "investigating", label: "Investigating", count: counts.investigating },
            { value: "contained", label: "Contained", count: counts.contained },
            { value: "closed", label: "Closed", count: counts.closed },
          ]}
        />
        <SearchInput value={q} onChange={setQ} placeholder="Filter by title, host, assignee, ATT&CK…" width={300} />
        <span style={{ flex: 1 }} />
        <span className="chip">{rows.length} cases</span>
      </div>

      <Panel title="INCIDENT CASES" sub="correlated detections → investigations">
        {cases.length === 0 ? (
          <div className="empty">no cases yet — correlated detections open cases automatically</div>
        ) : (
          <div className="table-wrap scroll">
            <table className="table">
              <thead>
                <tr>
                  <th>Sev</th><th>Title</th><th>Host</th><th>Status</th><th>Detections</th><th>ATT&CK</th><th>Assigned</th><th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((c) => (
                  <tr key={c.id} className="row-enter" {...rowClick(() => setSel(c))}>
                    <td><Sev s={c.severity} /></td>
                    <td className="mono">{c.title}</td>
                    <td>{c.hostname || <span className="dim">—</span>}</td>
                    <td><CaseStatusPill s={c.status} /></td>
                    <td className="mono"><span className="chip">{c.detection_ids?.length ?? 0}</span></td>
                    <td><Mitre ids={c.mitre} /></td>
                    <td className="dim">{c.assigned_to || "—"}</td>
                    <td className="dim">{ago(c.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {rows.length === 0 && <div className="empty">no cases match this filter</div>}
          </div>
        )}
      </Panel>

      {sel && (
        <CaseDrawer
          id={sel.id}
          canAct={canAct}
          onClose={() => setSel(null)}
          onChanged={refreshCases}
          notify={pushToast}
        />
      )}
    </>
  );
}

function CaseDrawer({
  id,
  canAct,
  onClose,
  onChanged,
  notify,
}: {
  id: string;
  canAct: boolean;
  onClose: () => void;
  onChanged: () => void;
  notify: (t: string, crit?: boolean) => void;
}) {
  const [c, setC] = useState<CaseDetail | null>(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () => api.caseDetail(id).then(setC).catch(() => {});
  useEffect(() => {
    load();
  }, [id]);

  const update = async (body: { status?: string; assigned_to?: string }) => {
    setBusy(true);
    try {
      await api.updateCase(id, body);
      await load();
      onChanged();
      notify("case updated");
    } catch (e) {
      notify(`update failed: ${e}`, true);
    } finally {
      setBusy(false);
    }
  };

  const submitNote = async () => {
    if (!note.trim()) return;
    setBusy(true);
    try {
      await api.addCaseNote(id, note.trim());
      setNote("");
      await load();
      onChanged();
    } catch (e) {
      notify(`note failed: ${e}`, true);
    } finally {
      setBusy(false);
    }
  };

  // Build a chronological incident timeline: case opened + member detections + analyst notes.
  const timeline = useMemo(() => {
    if (!c) return [];
    const items: { ts: string; kind: string; label: string; sev?: string }[] = [
      { ts: c.created_at, kind: "open", label: `Case opened${c.created_by ? ` by ${c.created_by}` : ""}` },
    ];
    (c.detections || []).forEach((d) =>
      items.push({ ts: d.ts, kind: "detection", label: `${d.rule_name} (${d.engine})`, sev: d.severity })
    );
    (c.notes || []).forEach((n) => items.push({ ts: n.ts, kind: "note", label: `${n.author}: ${n.body}` }));
    return items.sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
  }, [c]);

  return (
    <Drawer
      title={c?.title || "case"}
      sub={c ? `case · ${c.status} · ${c.severity}` : "loading…"}
      onClose={onClose}
      foot={
        canAct && c ? (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button className="btn btn-sm" disabled={busy} onClick={() => update({ assigned_to: getUser() || "me" })}>Assign to me</button>
            {c.status !== "investigating" && <button className="btn btn-sm" disabled={busy} onClick={() => update({ status: "investigating" })}>Investigating</button>}
            {c.status !== "contained" && <button className="btn btn-sm" disabled={busy} onClick={() => update({ status: "contained" })}>Contained</button>}
            {c.status !== "closed" && <button className="btn btn-sm" disabled={busy} onClick={() => update({ status: "closed" })}>Close</button>}
            {c.status === "closed" && <button className="btn btn-sm" disabled={busy} onClick={() => update({ status: "open" })}>Reopen</button>}
          </div>
        ) : undefined
      }
    >
      {!c ? (
        <div className="empty">loading case…</div>
      ) : (
        <div className="grid" style={{ gap: 18 }}>
          <div className="case-meta">
            <span><CaseStatusPill s={c.status} /></span>
            <span><Sev s={c.severity} /></span>
            {c.hostname && <span className="chip">{c.hostname}</span>}
            {c.assigned_to && <span className="chip cyan">@{c.assigned_to}</span>}
            <span className="dim" style={{ fontSize: 11 }}>opened {ago(c.created_at)}</span>
          </div>
          {c.mitre && c.mitre.length > 0 && (
            <div>
              <div className="page-kicker" style={{ marginBottom: 6 }}>ATT&CK Techniques</div>
              <Mitre ids={c.mitre} />
            </div>
          )}

          <div>
            <div className="page-kicker" style={{ marginBottom: 8 }}>Incident Timeline · {timeline.length} events</div>
            <ul className="timeline">
              {timeline.map((t, i) => (
                <li key={i} className={`tl-item tl-${t.kind}`}>
                  <span className="tl-dot" />
                  <span className="tl-time mono dim">{new Date(t.ts).toLocaleString()}</span>
                  <span className="tl-label">
                    {t.sev && <Sev s={t.sev} />} {t.label}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <div className="page-kicker" style={{ marginBottom: 8 }}>Add Note</div>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                className="input"
                style={{ flex: 1 }}
                placeholder="Investigation note…"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && submitNote()}
                disabled={!canAct || busy}
              />
              <button className="btn btn-primary btn-sm" disabled={!canAct || busy || !note.trim()} onClick={submitNote}>Add</button>
            </div>
          </div>
        </div>
      )}
    </Drawer>
  );
}
