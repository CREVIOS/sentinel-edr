// Backend-for-frontend bridge to the Go control plane. The Next server holds the Go
// service credential and mints a short-lived Go JWT, caching it; the browser only ever
// talks to Next (authorized by a Better Auth session).
import "server-only";

let cached: { token: string; exp: number } | null = null;

export async function goToken(): Promise<string> {
  if (cached && cached.exp > Date.now()) return cached.token;
  const res = await fetch(`${process.env.GO_API}/api/v1/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: process.env.GO_ADMIN_USER,
      password: process.env.GO_ADMIN_PASS,
    }),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`go login failed: ${res.status}`);
  const j = (await res.json()) as { token: string };
  cached = { token: j.token, exp: Date.now() + 11 * 60 * 60 * 1000 };
  return j.token;
}

export async function goFetch(path: string, init?: RequestInit): Promise<Response> {
  const token = await goToken();
  return fetch(`${process.env.GO_API}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
      Authorization: `Bearer ${token}`,
    },
    cache: "no-store",
  });
}
