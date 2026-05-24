import { auth } from "@/lib/auth";
import { goFetch } from "@/lib/go";
import { headers } from "next/headers";
import { NextRequest } from "next/server";

// The BFF proxies to the Go API with a service (admin) token, so the Go RBAC layer never
// sees the real operator — authorization MUST be enforced HERE against the Better Auth
// session role. Because Go always sees the admin token, this layer encodes the *full*
// per-endpoint role map (not a blanket viewer-for-GET rule): e.g. SIEM bulk export and all
// writes require analyst+. Without this every console user would inherit admin rights.
const RANK: Record<string, number> = { viewer: 1, analyst: 2, admin: 3 };

// GET endpoints that require more than viewer. Matched against the joined path.
const GET_MIN_ROLE: { re: RegExp; role: string }[] = [
  { re: /^siem\//, role: "analyst" }, // bulk CEF/ECS export of all events+detections
];

// POST/writes always require analyst+ (respond, status changes, exports).
const WRITE_MIN_ROLE = "analyst";

// Only allow simple path segments — blocks "..", encoded traversal, and any attempt to reach
// non-/api/v1 Go routes (/metrics, /readyz, /healthz) by path manipulation.
const SEGMENT = /^[A-Za-z0-9_-]+$/;

async function operatorRole(): Promise<string | null> {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return null;
  return ((session.user as { role?: string }).role || "viewer").toLowerCase();
}

function allowed(role: string | null, min: string): boolean {
  return role != null && (RANK[role] || 0) >= (RANK[min] || 99);
}

function validPath(path: string[]): boolean {
  return path.length > 0 && path.every((s) => SEGMENT.test(s));
}

function getMinRole(path: string[]): string {
  const p = path.join("/");
  for (const r of GET_MIN_ROLE) if (r.re.test(p)) return r.role;
  return "viewer";
}

function passthrough(r: Response): Response {
  return new Response(r.body, {
    status: r.status,
    headers: { "content-type": r.headers.get("content-type") || "application/json" },
  });
}

export async function GET(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  if (!validPath(path)) return new Response("bad request", { status: 400 });
  const role = await operatorRole();
  if (!role) return new Response("unauthorized", { status: 401 });
  const min = getMinRole(path);
  if (!allowed(role, min)) return new Response(`forbidden: ${min} role required`, { status: 403 });
  const url = `/api/v1/${path.join("/")}${req.nextUrl.search}`;
  return passthrough(await goFetch(url));
}

export async function POST(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  if (!validPath(path)) return new Response("bad request", { status: 400 });
  const role = await operatorRole();
  if (!role) return new Response("unauthorized", { status: 401 });
  if (!allowed(role, WRITE_MIN_ROLE)) return new Response(`forbidden: ${WRITE_MIN_ROLE} role required`, { status: 403 });
  const url = `/api/v1/${path.join("/")}${req.nextUrl.search}`;
  const body = await req.text();
  return passthrough(await goFetch(url, { method: "POST", body }));
}
