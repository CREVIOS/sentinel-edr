import type { ReactNode } from "react";

export function Drawer({ title, sub, onClose, children, foot }: { title: string; sub?: string; onClose: () => void; children: ReactNode; foot?: ReactNode }) {
  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <div className="drawer scroll">
        <div className="drawer-head">
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ flex: 1 }}>
              {sub && <div className="page-kicker">{sub}</div>}
              <h2 style={{ margin: "2px 0 0", fontFamily: "var(--mono)", fontSize: 17 }}>{title}</h2>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={onClose}>✕ Close</button>
          </div>
        </div>
        <div className="drawer-body">{children}</div>
        {foot && <div className="drawer-body" style={{ borderTop: "1px solid var(--line)", position: "sticky", bottom: 0, background: "var(--panel-solid)" }}>{foot}</div>}
      </div>
    </>
  );
}

export function KV({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([k, v], i) => (
        <div style={{ display: "contents" }} key={i}>
          <dt>{k}</dt>
          <dd>{v ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}
