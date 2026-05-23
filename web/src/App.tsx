import { useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { api, getUser, setSession } from "./api";
import { StoreProvider } from "./store";
import Layout from "./Layout";
import Overview from "./pages/Overview";
import Endpoints from "./pages/Endpoints";
import Events from "./pages/Events";
import Detections from "./pages/Detections";
import Dlp from "./pages/Dlp";
import Internet from "./pages/Internet";
import Responses from "./pages/Responses";
import Rules from "./pages/Rules";
import Settings from "./pages/Settings";

export default function App() {
  const [authed, setAuthed] = useState(!!getUser());
  if (!authed) return <Login onAuthed={() => setAuthed(true)} />;
  return (
    <StoreProvider>
      <Layout onLogout={() => setAuthed(false)}>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/endpoints" element={<Endpoints />} />
          <Route path="/events" element={<Events />} />
          <Route path="/detections" element={<Detections />} />
          <Route path="/dlp" element={<Dlp />} />
          <Route path="/internet" element={<Internet />} />
          <Route path="/responses" element={<Responses />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </Layout>
    </StoreProvider>
  );
}

function Login({ onAuthed }: { onAuthed: () => void }) {
  const [u, setU] = useState("admin");
  const [p, setP] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const r = await api.login(u, p);
      setSession(r.token, r.user, r.role);
      onAuthed();
    } catch {
      setErr("Authentication failed. Check credentials.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="app-bg" />
      <div className="login-wrap">
        <div className="panel login-card">
          <div className="brand" style={{ padding: 0 }}>
            <div className="brand-mark">S</div>
            <div>
              <div className="brand-name">SENTINEL</div>
              <div className="brand-sub">EDR · DLP · XDR</div>
            </div>
          </div>
          <h1>Operator Sign-In</h1>
          <p>Linux Endpoint Monitoring &amp; Response Console</p>
          <form onSubmit={submit}>
            <div className="field">
              <label>Operator</label>
              <input className="input" value={u} onChange={(e) => setU(e.target.value)} autoFocus />
            </div>
            <div className="field">
              <label>Passphrase</label>
              <input
                className="input"
                type="password"
                value={p}
                onChange={(e) => setP(e.target.value)}
                placeholder="••••••••"
              />
            </div>
            <button className="btn btn-primary" style={{ width: "100%", justifyContent: "center", marginTop: 8 }} disabled={busy}>
              {busy ? "Authenticating…" : "Enter Console →"}
            </button>
            {err && <div className="login-err">{err}</div>}
          </form>
        </div>
      </div>
    </>
  );
}

export { getUser };
