import { useEffect, useState, type ReactNode } from "react";

export function Drawer({ title, sub, onClose, children, foot }: { title: string; sub?: string; onClose: () => void; children: ReactNode; foot?: ReactNode }) {
  // Esc closes the drawer — expected behavior, and keeps the panel keyboard-dismissable.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
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

/**
 * Two-step confirm for destructive/irreversible actions (isolate, kill, disable…).
 * First click arms a "✓ Confirm / Cancel" pair; auto-disarms after 3s so a stray
 * arm doesn't linger. No modal plumbing — inline and fast.
 */
export function ConfirmButton({
  children,
  onConfirm,
  className,
  confirmLabel = "Confirm",
}: {
  children: ReactNode;
  onConfirm: () => void;
  className?: string;
  confirmLabel?: string;
}) {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const t = setTimeout(() => setArmed(false), 3000);
    return () => clearTimeout(t);
  }, [armed]);
  if (armed) {
    return (
      <span style={{ display: "inline-flex", gap: 6 }}>
        <button
          className={className || "btn btn-danger btn-sm"}
          onClick={() => {
            setArmed(false);
            onConfirm();
          }}
        >
          ✓ {confirmLabel}
        </button>
        <button className="btn btn-ghost btn-sm" onClick={() => setArmed(false)}>
          Cancel
        </button>
      </span>
    );
  }
  return (
    <button className={className} onClick={() => setArmed(true)}>
      {children}
    </button>
  );
}

/** Click-to-copy wrapper for IDs, IPs, MACs, hashes. Stops row-click propagation. */
export function Copyable({ text, children }: { text?: string; children?: ReactNode }) {
  const [done, setDone] = useState(false);
  if (!text) return <>{children ?? "—"}</>;
  return (
    <span
      className="copyable"
      title="Click to copy"
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard?.writeText(text).then(
          () => {
            setDone(true);
            setTimeout(() => setDone(false), 1200);
          },
          () => {}
        );
      }}
    >
      {children ?? text}
      <span className="copy-ico">{done ? "✓" : "⧉"}</span>
    </span>
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
