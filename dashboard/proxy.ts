import { NextRequest, NextResponse } from "next/server";

// Next 16 renamed `middleware` → `proxy`. Jobs:
//   1. Block PUBLIC self-registration (sign-in/session/sign-out still work). Defence-in-depth
//      alongside auth.ts `disableSignUp`.
//   2. Set a Content-Security-Policy in production.
//
// NOTE: a per-request nonce + 'strict-dynamic' was tried but Next 16 (standalone output) does
// NOT propagate the nonce onto its emitted <script> chunk tags, so strict-dynamic blocked the
// entire app. We therefore use a static policy: script chunks are same-origin ('self') and the
// small Next bootstrap inline scripts need 'unsafe-inline'. CSP is production-only — dev needs
// eval()/inline for HMR + next-themes.
export function proxy(req: NextRequest) {
  if (req.method === "POST" && req.nextUrl.pathname.startsWith("/api/auth/sign-up")) {
    return NextResponse.json({ error: "self-registration disabled" }, { status: 403 });
  }

  const res = NextResponse.next();
  if (process.env.NODE_ENV === "production") {
    res.headers.set(
      "content-security-policy",
      [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob:",
        "font-src 'self' data:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "object-src 'none'",
        "form-action 'self'",
      ].join("; "),
    );
  }
  return res;
}

export const config = {
  matcher: [
    {
      source: "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|txt|sh)$).*)",
      missing: [{ type: "header", key: "purpose", value: "prefetch" }],
    },
  ],
};
