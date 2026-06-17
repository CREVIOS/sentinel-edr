import { useEffect, useState, type ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { clearSession, getRole, getUser } from "./api";
import { useStore } from "./store";

const NAV = [
  { to: "/", icon: "◎", label: "Overview", section: "Operations" },
  { to: "/endpoints", icon: "⛂", label: "Endpoints" },
  { to: "/events", icon: "≡", label: "Event Stream" },
  { to: "/detections", icon: "⚠", label: "Detections", section: "Threat" },
  { to: "/dlp", icon: "✦", label: "Data Loss (DLP)" },
  { to: "/internet", icon: "◈", label: "Internet / Web" },
  { to: "/responses", icon: "⊘", label: "Response", section: "Control" },
  { to: "/rules", icon: "❖", label: "Detection Rules" },
  { to: "/settings", icon: "⚙", label: "SIEM / Settings" },
];

export default function Layout({ children, onLogout }: { children: ReactNode; onLogout: () => void }) {
  const { connected, detections, toasts, dismissToast } = useStore();
  const openCrit = detections.filter((d) => d.status === "open" && (d.severity === "critical" || d.severity === "high")).length;
  const user = getUser() || "operator";
  const role = getRole() || "viewer";
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  // Press "/" anywhere (outside a field) to jump to the page's filter box.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      const el = e.target as HTMLElement;
      if (el && /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName)) return;
      const box = document.querySelector<HTMLInputElement>(".content .search-input, .content input.input");
      if (box) {
        e.preventDefault();
        box.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <>
      <div className="app-bg" />
      <div className="shell">
        <aside className="sidebar scroll">
          <div className="brand">
            <div className="brand-mark">S</div>
            <div>
              <div className="brand-name">SENTINEL</div>
              <div className="brand-sub">EDR · DLP</div>
            </div>
          </div>
          {NAV.map((n) => (
            <div key={n.to}>
              {n.section && <div className="nav-section">{n.section}</div>}
              <NavLink to={n.to} end={n.to === "/"} className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}>
                <span className="ico">{n.icon}</span>
                {n.label}
                {n.to === "/detections" && openCrit > 0 && <span className="nav-badge">{openCrit}</span>}
              </NavLink>
            </div>
          ))}
          <div className="sidebar-foot">
            v1.0 · {connected ? "stream live" : "reconnecting…"}
          </div>
        </aside>

        <main className="main scroll">
          <Topbar now={now} connected={connected} user={user} role={role} onLogout={onLogout} />
          <div className="content">{children}</div>
        </main>
      </div>

      <div className="toasts">
        {toasts.map((t) => (
          <div key={t.id} className={`toast${t.crit ? " crit" : ""}`}>
            <span className="dot on" />
            <span style={{ flex: 1 }}>{t.text}</span>
            <button className="toast-close" onClick={() => dismissToast(t.id)} title="Dismiss" aria-label="Dismiss">
              ✕
            </button>
          </div>
        ))}
      </div>
    </>
  );
}

function Topbar({
  now,
  connected,
  user,
  role,
  onLogout,
}: {
  now: Date;
  connected: boolean;
  user: string;
  role: string;
  onLogout: () => void;
}) {
  return (
    <div className="topbar">
      <div>
        <div className="page-kicker">Security Operations Center</div>
        <h1 className="page-title">Command Console</h1>
      </div>
      <div className="topbar-spacer" />
      <span className="live-pill">
        <span className={`dot${connected ? " on" : ""}`} />
        {connected ? "Live" : "Offline"}
      </span>
      <span className="clock">{now.toISOString().slice(11, 19)} UTC</span>
      <div className="user-chip">
        <div className="avatar">{user.slice(0, 1).toUpperCase()}</div>
        <div>
          <div style={{ color: "var(--ink)" }}>{user}</div>
          <div style={{ fontSize: 10, color: "var(--ink-faint)", fontFamily: "var(--mono)", textTransform: "uppercase", letterSpacing: "0.12em" }}>{role}</div>
        </div>
        <button
          className="btn btn-ghost btn-sm"
          style={{ marginLeft: 8 }}
          onClick={() => {
            clearSession();
            onLogout();
          }}
        >
          Exit
        </button>
      </div>
    </div>
  );
}
