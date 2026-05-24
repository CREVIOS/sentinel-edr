import { NextRequest, NextResponse } from "next/server";

// Next 16 renamed `middleware` → `proxy`. Two jobs:
//   1. Block PUBLIC self-registration (sign-in/session/sign-out still work). Defence-in-depth
//      alongside auth.ts `disableSignUp`.
//   2. Emit a per-request nonce Content-Security-Policy so script-src needs no 'unsafe-inline'
//      — Next injects this nonce into its own <script> tags when it sees it on the request CSP
//      header. 'strict-dynamic' lets those trusted scripts load the chunk graph.
export function proxy(req: NextRequest) {
  if (req.method === "POST" && req.nextUrl.pathname.startsWith("/api/auth/sign-up")) {
    return NextResponse.json({ error: "self-registration disabled" }, { status: 403 });
  }

  // Web Crypto (Edge runtime has no Buffer); base64 nonce.
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const nonce = btoa(String.fromCharCode(...bytes));

  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    "style-src 'self' 'unsafe-inline'", // Next/Tailwind inject some inline styles
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "object-src 'none'",
    "form-action 'self'",
  ].join("; ");

  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("content-security-policy", csp);

  const res = NextResponse.next({ request: { headers: requestHeaders } });
  res.headers.set("content-security-policy", csp);
  return res;
}

export const config = {
  // Run on auth (for the signup block) and on document routes (for the nonce CSP), but skip
  // static assets, the image optimizer, and prefetches.
  matcher: [
    {
      source: "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|txt|sh)$).*)",
      missing: [{ type: "header", key: "purpose", value: "prefetch" }],
    },
  ],
};
