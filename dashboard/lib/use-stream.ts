"use client";
import { useEffect, useRef, useState } from "react";

// Single shared EventSource for the whole app (browsers cap concurrent connections per host,
// and one push channel is enough). Components subscribe to a message `type`; the relay at
// /api/stream forwards Go broadcasts as {type,data}. EventSource auto-reconnects on drop.

type Handler = (data: unknown) => void;

let es: EventSource | null = null;
let refs = 0;
const handlers = new Map<string, Set<Handler>>();
const statusCbs = new Set<(c: boolean) => void>();
let connected = false;

function setConnected(c: boolean) {
  if (c === connected) return;
  connected = c;
  statusCbs.forEach((cb) => cb(c));
}

function ensure() {
  if (es) return;
  es = new EventSource("/api/stream");
  es.onopen = () => setConnected(true);
  es.onerror = () => setConnected(false); // EventSource retries automatically
  es.onmessage = (e) => {
    let msg: { type?: string; data?: unknown };
    try { msg = JSON.parse(e.data); } catch { return; }
    if (!msg.type) return;
    handlers.get(msg.type)?.forEach((h) => h(msg.data));
    handlers.get("*")?.forEach((h) => h(msg));
  };
}

function teardown() {
  if (refs > 0 || !es) return;
  es.close();
  es = null;
  setConnected(false);
}

/** Subscribe to a broadcast `type` ("event"|"detection"|"agent"|"response", or "*"). */
export function subscribe(type: string, handler: Handler): () => void {
  refs++;
  ensure();
  if (!handlers.has(type)) handlers.set(type, new Set());
  handlers.get(type)!.add(handler);
  return () => {
    handlers.get(type)?.delete(handler);
    refs--;
    // defer so a remount in the same tick doesn't churn the connection
    setTimeout(teardown, 0);
  };
}

/** React hook wrapper around subscribe(); `onData` may change without resubscribing. */
export function useStream(type: string, onData: Handler) {
  const cb = useRef(onData);
  cb.current = onData;
  useEffect(() => subscribe(type, (d) => cb.current(d)), [type]);
}

/** Live connection status of the shared stream (for a LIVE indicator). */
export function useStreamStatus(): boolean {
  const [c, setC] = useState(connected);
  useEffect(() => {
    statusCbs.add(setC);
    setC(connected);
    ensure(); // make sure the channel is open even if no list subscribed yet
    refs++;
    return () => { statusCbs.delete(setC); refs--; setTimeout(teardown, 0); };
  }, []);
  return c;
}
