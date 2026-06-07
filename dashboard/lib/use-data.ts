"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { subscribe } from "./use-stream";

/** Numeric timestamp for safe ordering (RFC3339 strings → ms; NaN-safe). */
function tsNum(s?: string): number {
  if (!s) return 0;
  const n = Date.parse(s);
  return Number.isNaN(n) ? 0 : n;
}

export interface DataState<T> {
  data: T | undefined;
  live: boolean;
  /** populated on the last failed fetch: distinguishes 403 (permission) / network / parse */
  error?: { status: number; kind: "forbidden" | "unauthorized" | "network" | "server" } | null;
  refetch: () => void;
}

/**
 * Poll a BFF endpoint (relative to /api/proxy/) on an interval for near-real-time data.
 * When `revalidateOn` is set (a stream type like "detection"|"agent"|"response"), an inbound
 * push triggers an immediate (debounced) refetch — instant updates with the poll as a safety
 * net. With push wired the interval can be relaxed (it only backstops missed pushes).
 *
 * Hardening over the naive version: a typed error (so the UI can tell 403 from a network
 * drop), an equality short-circuit (static panels don't re-render every tick), and polling
 * that pauses while the tab is hidden (a backgrounded SOC wall display stops hammering the
 * API and resumes instantly on focus).
 */
export function useData<T>(
  path: string,
  intervalMs = 4000,
  revalidateOn?: string,
): DataState<T> {
  const [data, setData] = useState<T>();
  const [live, setLive] = useState(false);
  const [error, setError] = useState<DataState<T>["error"]>(null);
  const path0 = useRef(path);
  path0.current = path;
  const last = useRef<string>("");
  const tickRef = useRef<() => void>(() => {});

  useEffect(() => {
    let on = true;
    let debounce: ReturnType<typeof setTimeout> | null = null;
    const tick = async () => {
      try {
        const r = await fetch(`/api/proxy/${path0.current}`, { cache: "no-store" });
        if (!r.ok) {
          const kind =
            r.status === 403 ? "forbidden" : r.status === 401 ? "unauthorized" : "server";
          if (on) { setLive(false); setError({ status: r.status, kind }); }
          return;
        }
        const text = await r.text();
        if (!on) return;
        setLive(true);
        setError(null);
        // Skip the state update (and the re-render it triggers) when nothing changed.
        if (text === last.current) return;
        last.current = text;
        try { setData(JSON.parse(text) as T); } catch { /* keep prior data on parse glitch */ }
      } catch {
        if (on) { setLive(false); setError({ status: 0, kind: "network" }); }
      }
    };
    tickRef.current = tick;
    tick();
    const id = setInterval(() => {
      if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
      tick();
    }, intervalMs);
    // refetch immediately when the tab is refocused (cheap; data may be stale)
    const onVis = () => { if (document.visibilityState === "visible") tick(); };
    document.addEventListener("visibilitychange", onVis);
    const unsub = revalidateOn
      ? subscribe(revalidateOn, () => {
          if (debounce) return; // coalesce bursts into one refetch
          debounce = setTimeout(() => { debounce = null; tick(); }, 250);
        })
      : undefined;
    return () => {
      on = false;
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVis);
      if (debounce) clearTimeout(debounce);
      unsub?.();
    };
  }, [path, intervalMs, revalidateOn]);

  const refetch = useCallback(() => tickRef.current(), []);
  return { data, live, error, refetch };
}

interface HasIdTs { id: string; ts: string }

/**
 * Live, paginated list for high-volume logs.
 *  - initial load fetches the newest `pageSize`
 *  - live tail polls only rows newer than the newest seen (`since` cursor → tiny payloads)
 *  - loadMore pages backwards with `offset` (keyset-style on a time-ordered index)
 * basePath may already contain a query string (filters); cursor/limit params are appended.
 */
export function useLiveList<T extends HasIdTs>(
  basePath: string,
  opts: {
    pageSize?: number; liveMs?: number; live?: boolean; cap?: number;
    /** stream type to prepend in real time (e.g. "event"); poll stays as a safety net */
    pushType?: string;
    /** keep only pushes matching this page's filter (push carries the whole fleet) */
    pushFilter?: (x: T) => boolean;
  } = {},
) {
  const { pageSize = 100, liveMs = 2000, live: liveEnabled = true, cap = 2000, pushType, pushFilter } = opts;
  const [items, setItems] = useState<T[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<boolean>(false);
  const seen = useRef<Set<string>>(new Set());
  const newest = useRef<string>("");

  const url = (extra: string) => `/api/proxy/${basePath}${basePath.includes("?") ? "&" : "?"}${extra}`;

  // reset whenever the query (filters/search) changes
  useEffect(() => {
    let on = true;
    seen.current = new Set();
    newest.current = "";
    setItems([]);
    setHasMore(true);
    setLoading(true);
    (async () => {
      try {
        const r = await fetch(url(`limit=${pageSize}`), { cache: "no-store" });
        const j: T[] = await r.json();
        if (!on) return;
        const rows = j || [];
        rows.forEach((x) => seen.current.add(x.id));
        if (rows.length) newest.current = rows[0].ts;
        setItems(rows);
        setHasMore(rows.length >= pageSize);
        setConnected(true);
        setError(false);
      } catch {
        if (on) { setConnected(false); setError(true); }
      } finally {
        if (on) setLoading(false);
      }
    })();
    return () => { on = false; };
  }, [basePath, pageSize]);

  // live tail: pull only rows newer than the newest we have
  useEffect(() => {
    if (!liveEnabled) return;
    let on = true;
    const tick = async () => {
      if (!newest.current) return;
      if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
      try {
        const r = await fetch(url(`since=${encodeURIComponent(newest.current)}&limit=300`), { cache: "no-store" });
        const j: T[] = await r.json();
        if (!on) return;
        const fresh = (j || []).filter((x) => !seen.current.has(x.id));
        setConnected(true);
        setError(false);
        if (fresh.length) {
          fresh.forEach((x) => seen.current.add(x.id));
          if (tsNum(fresh[0].ts) > tsNum(newest.current)) newest.current = fresh[0].ts;
          setItems((prev) => [...fresh, ...prev].slice(0, cap));
        }
      } catch {
        if (on) { setConnected(false); setError(true); }
      }
    };
    const id = setInterval(tick, liveMs);
    return () => { on = false; clearInterval(id); };
  }, [basePath, liveEnabled, liveMs, cap]);

  // real-time push: prepend matching rows as the server broadcasts them (no poll latency)
  const filt = useRef(pushFilter);
  filt.current = pushFilter;
  useEffect(() => {
    if (!liveEnabled || !pushType) return;
    return subscribe(pushType, (raw) => {
      const x = raw as T;
      if (!x || !x.id || seen.current.has(x.id)) return;
      if (filt.current && !filt.current(x)) return;
      seen.current.add(x.id);
      if (tsNum(x.ts) > tsNum(newest.current)) newest.current = x.ts;
      setItems((prev) => [x, ...prev].slice(0, cap));
      setConnected(true);
    });
  }, [basePath, liveEnabled, pushType, cap]);

  const loadMore = async () => {
    setLoadingMore(true);
    try {
      const r = await fetch(url(`limit=${pageSize}&offset=${items.length}`), { cache: "no-store" });
      const j: T[] = await r.json();
      const rows = (j || []).filter((x) => !seen.current.has(x.id));
      rows.forEach((x) => seen.current.add(x.id));
      setItems((prev) => [...prev, ...rows]);
      if ((j || []).length < pageSize) setHasMore(false);
    } catch {
      setError(true);
    } finally {
      setLoadingMore(false);
    }
  };

  return { items, loading, loadingMore, hasMore, connected, error, loadMore };
}

/** Debounce any fast-changing value (e.g. a search box) to avoid query spam. */
export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return v;
}

export async function post(path: string, body: unknown): Promise<Response> {
  return fetch(`/api/proxy/${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function del(path: string): Promise<Response> {
  return fetch(`/api/proxy/${path}`, { method: "DELETE" });
}

export interface ActionResult {
  ok: boolean;
  status: number;
  /** server error text on failure (the BFF returns "forbidden: analyst role required" etc.) */
  error?: string;
  /** parsed JSON body on success, if any */
  data?: unknown;
}

/** POST that reads the response body so callers can surface a precise, consistent toast. */
export async function postJSON(path: string, body: unknown): Promise<ActionResult> {
  try {
    const r = await post(path, body);
    if (!r.ok) {
      const text = await r.text().catch(() => "");
      return { ok: false, status: r.status, error: text || `HTTP ${r.status}` };
    }
    const data = await r.json().catch(() => undefined);
    return { ok: true, status: r.status, data };
  } catch {
    return { ok: false, status: 0, error: "Network error — the console could not reach the server" };
  }
}

/**
 * Issue a containment / response action against an agent. Centralizes the payload shape
 * (type, agent_id, target, reason, detection_id) the Go control plane expects so every
 * call site — detections, events, endpoints, bulk bars — stays consistent.
 */
export function respond(args: {
  type: string;
  agentId: string;
  target?: Record<string, unknown>;
  reason?: string;
  detectionId?: string;
}): Promise<ActionResult> {
  return postJSON("respond", {
    type: args.type,
    agent_id: args.agentId,
    target: args.target ?? {},
    reason: args.reason ?? `manual ${args.type} from console`,
    detection_id: args.detectionId,
  });
}
