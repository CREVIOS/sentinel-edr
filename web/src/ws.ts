// Live event/detection/response/agent stream over WebSocket, with auto-reconnect.

import { useEffect, useRef, useState } from "react";
import { getToken } from "./api";

export interface LiveMessage {
  type: "event" | "detection" | "response" | "agent" | "stats";
  data: any;
}

export function useLiveFeed(onMessage: (m: LiveMessage) => void) {
  const [connected, setConnected] = useState(false);
  const cb = useRef(onMessage);
  cb.current = onMessage;

  useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;
    let retry: ReturnType<typeof setTimeout>;

    const connect = () => {
      const token = getToken();
      const proto = location.protocol === "https:" ? "wss" : "ws";
      // During the current session the token can ride in the subprotocol header; after
      // reloads the server authenticates the HTTP-only session cookie on the WS handshake.
      ws = token
        ? new WebSocket(`${proto}://${location.host}/ws`, ["bearer", token])
        : new WebSocket(`${proto}://${location.host}/ws`);
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!closed) retry = setTimeout(connect, 2000);
      };
      ws.onerror = () => ws?.close();
      ws.onmessage = (e) => {
        try {
          cb.current(JSON.parse(e.data) as LiveMessage);
        } catch {
          /* ignore malformed frames */
        }
      };
    };
    connect();
    return () => {
      closed = true;
      clearTimeout(retry);
      ws?.close();
    };
  }, []);

  return connected;
}
