import { auth } from "@/lib/auth";
import { goToken } from "@/lib/go";
import { headers } from "next/headers";

// Server-Sent-Events relay for live push. The browser opens a session-gated EventSource to
// this route (same-origin, allowed by CSP connect-src 'self'); the route authenticates the
// Better Auth session, mints a short-lived Go JWT, and subscribes to the Go control-plane
// console WebSocket (ws://server:8080/ws) over the internal network. Each broadcast
// ({type,data}) is forwarded to the browser as one SSE message. The JWT never leaves the
// server, so the browser holds no Go credential.
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return new Response("unauthorized", { status: 401 });

  const token = await goToken();
  const wsURL = (process.env.GO_API || "http://server:8080").replace(/^http/, "ws") + "/ws";

  const encoder = new TextEncoder();
  let ws: WebSocket | null = null;
  let ping: ReturnType<typeof setInterval> | null = null;

  const stream = new ReadableStream({
    start(controller) {
      const send = (s: string) => {
        try { controller.enqueue(encoder.encode(s)); } catch { /* closed */ }
      };
      // Initial comment + retry hint so EventSource reconnects quickly on drop.
      send(": connected\nretry: 3000\n\n");

      // Token carried in the WebSocket subprotocol (["bearer", <jwt>]) — same scheme the Go
      // consoleWS handler expects; keeps it out of the URL.
      ws = new WebSocket(wsURL, ["bearer", token]);
      ws.onmessage = (e) => send(`data: ${typeof e.data === "string" ? e.data : ""}\n\n`);
      ws.onclose = () => { cleanup(); try { controller.close(); } catch { /* already closed */ } };
      ws.onerror = () => { try { ws?.close(); } catch { /* noop */ } };

      // Heartbeat keeps the SSE connection (and any proxy idle timer) alive.
      ping = setInterval(() => send(": ping\n\n"), 25000);
    },
    cancel() { cleanup(); },
  });

  function cleanup() {
    if (ping) { clearInterval(ping); ping = null; }
    try { ws?.close(); } catch { /* noop */ }
    ws = null;
  }

  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no", // disable proxy buffering for SSE
    },
  });
}
