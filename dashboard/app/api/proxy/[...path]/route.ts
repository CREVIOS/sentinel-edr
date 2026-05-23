import { auth } from "@/lib/auth";
import { goFetch } from "@/lib/go";
import { headers } from "next/headers";
import { NextRequest } from "next/server";

// The BFF proxies to the Go API with a service (admin) token, so the Go RBAC layer never
// sees the real operator. Authorization is therefore enforced HERE against the Better Auth
// session role: reads need any authenticated operator (viewer+), writes (POST = respond /
// status changes / exports) need analyst+. Without this every console user would inherit the
// service account's admin rights.
const RANK: Record<string, number> = { viewer: 1, analyst: 2, admin: 3 };

async function operatorRole(): Promise<string | null> {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return null;
  return ((session.user as { role?: string }).role || "viewer").toLowerCase();
}

function allowed(role: string | null, min: string): boolean {
  return role != null && (RANK[role] || 0) >= RANK[min];
}

function passthrough(r: Response): Response {
  return new Response(r.body, {
    status: r.status,
    headers: { "content-type": r.headers.get("content-type") || "application/json" },
  });
}

export async function GET(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const role = await operatorRole();
  if (!allowed(role, "viewer")) return new Response("unauthorized", { status: 401 });
  const { path } = await ctx.params;
  const url = `/api/v1/${path.join("/")}${req.nextUrl.search}`;
  return passthrough(await goFetch(url));
}

export async function POST(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const role = await operatorRole();
  if (!role) return new Response("unauthorized", { status: 401 });
  if (!allowed(role, "analyst")) return new Response("forbidden: analyst role required", { status: 403 });
  const { path } = await ctx.params;
  const url = `/api/v1/${path.join("/")}${req.nextUrl.search}`;
  const body = await req.text();
  return passthrough(await goFetch(url, { method: "POST", body }));
}
