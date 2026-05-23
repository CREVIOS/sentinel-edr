"use client";
import { useEffect, useRef, useState } from "react";

/** Poll a BFF endpoint (relative to /api/proxy/) on an interval for near-real-time data. */
export function useData<T>(path: string, intervalMs = 4000): { data: T | undefined; live: boolean } {
  const [data, setData] = useState<T>();
  const [live, setLive] = useState(false);
  const path0 = useRef(path);
  path0.current = path;

  useEffect(() => {
    let on = true;
    const tick = async () => {
      try {
        const r = await fetch(`/api/proxy/${path0.current}`, { cache: "no-store" });
        if (!r.ok) throw new Error();
        const j = await r.json();
        if (on) { setData(j); setLive(true); }
      } catch {
        if (on) setLive(false);
      }
    };
    tick();
    const id = setInterval(tick, intervalMs);
    return () => { on = false; clearInterval(id); };
  }, [path, intervalMs]);

  return { data, live };
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
  opts: { pageSize?: number; liveMs?: number; live?: boolean; cap?: number } = {},
) {
  const { pageSize = 100, liveMs = 2000, live: liveEnabled = true, cap = 2000 } = opts;
  const [items, setItems] = useState<T[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const [connected, setConnected] = useState(false);
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
      } catch {
        if (on) setConnected(false);
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
      try {
        const r = await fetch(url(`since=${encodeURIComponent(newest.current)}&limit=300`), { cache: "no-store" });
        const j: T[] = await r.json();
        if (!on) return;
        const fresh = (j || []).filter((x) => !seen.current.has(x.id));
        setConnected(true);
        if (fresh.length) {
          fresh.forEach((x) => seen.current.add(x.id));
          newest.current = fresh[0].ts > newest.current ? fresh[0].ts : newest.current;
          setItems((prev) => [...fresh, ...prev].slice(0, cap));
        }
      } catch {
        if (on) setConnected(false);
      }
    };
    const id = setInterval(tick, liveMs);
    return () => { on = false; clearInterval(id); };
  }, [basePath, liveEnabled, liveMs, cap]);

  const loadMore = async () => {
    setLoadingMore(true);
    try {
      const r = await fetch(url(`limit=${pageSize}&offset=${items.length}`), { cache: "no-store" });
      const j: T[] = await r.json();
      const rows = (j || []).filter((x) => !seen.current.has(x.id));
      rows.forEach((x) => seen.current.add(x.id));
      setItems((prev) => [...prev, ...rows]);
      if ((j || []).length < pageSize) setHasMore(false);
    } finally {
      setLoadingMore(false);
    }
  };

  return { items, loading, loadingMore, hasMore, connected, loadMore };
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
