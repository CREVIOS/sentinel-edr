import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "./api";
import type { Agent, Detection, Event, Overview, ResponseAction } from "./types";
import { useLiveFeed } from "./ws";

interface Toast {
  id: string;
  text: string;
  crit?: boolean;
}

interface StoreState {
  connected: boolean;
  overview?: Overview;
  agents: Agent[];
  events: Event[];
  detections: Detection[];
  responses: ResponseAction[];
  toasts: Toast[];
  refreshOverview: () => void;
  refreshAgents: () => void;
  refreshDetections: () => void;
  refreshResponses: () => void;
  pushToast: (text: string, crit?: boolean) => void;
}

const Ctx = createContext<StoreState>(null as any);
export const useStore = () => useContext(Ctx);

const CAP = 400;

export function StoreProvider({ children }: { children: ReactNode }) {
  const [overview, setOverview] = useState<Overview>();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [responses, setResponses] = useState<ResponseAction[]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const seenDet = useRef<Set<string>>(new Set());

  const refreshOverview = () => api.overview().then(setOverview).catch(() => {});
  const refreshAgents = () => api.agents().then((a) => setAgents(a || [])).catch(() => {});
  const refreshDetections = () =>
    api.detections({ limit: "200" }).then((d) => setDetections(d || [])).catch(() => {});
  const refreshResponses = () => api.responses().then((r) => setResponses(r || [])).catch(() => {});

  const pushToast = (text: string, crit?: boolean) => {
    const id = Math.random().toString(36).slice(2);
    setToasts((t) => [...t, { id, text, crit }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 6000);
  };

  useEffect(() => {
    refreshOverview();
    refreshAgents();
    refreshDetections();
    refreshResponses();
    api.events({ limit: "200" }).then((e) => setEvents(e || [])).catch(() => {});
    const t = setInterval(() => {
      refreshOverview();
      refreshAgents();
    }, 8000);
    return () => clearInterval(t);
  }, []);

  const connected = useLiveFeed((m) => {
    if (m.type === "event") {
      setEvents((prev) => [m.data as Event, ...prev].slice(0, CAP));
    } else if (m.type === "detection") {
      const d = m.data as Detection;
      setDetections((prev) => {
        const without = prev.filter((x) => x.id !== d.id);
        return [d, ...without].slice(0, CAP);
      });
      if (!seenDet.current.has(d.id) && d.status === "open") {
        seenDet.current.add(d.id);
        if (d.severity === "critical" || d.severity === "high") {
          pushToast(`${d.severity.toUpperCase()} · ${d.rule_name} @ ${d.hostname}`, d.severity === "critical");
        }
      }
    } else if (m.type === "response") {
      const r = m.data as ResponseAction;
      setResponses((prev) => [r, ...prev.filter((x) => x.id !== r.id)].slice(0, CAP));
      if (r.status === "completed") pushToast(`Response ${r.type} → ${r.hostname}: done`);
    } else if (m.type === "agent") {
      const a = m.data as Agent;
      setAgents((prev) => {
        const without = prev.filter((x) => x.id !== a.id);
        return [...without, a].sort((x, y) => x.hostname.localeCompare(y.hostname));
      });
    }
  });

  const value: StoreState = {
    connected,
    overview,
    agents,
    events,
    detections,
    responses,
    toasts,
    refreshOverview,
    refreshAgents,
    refreshDetections,
    refreshResponses,
    pushToast,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
