import { NextRequest, NextResponse } from "next/server";

// Block PUBLIC self-registration. Accounts are provisioned only by the server-side bootstrap
// (auth.api.signUpEmail — a direct function call that does NOT pass through this proxy).
// This stops anyone who can reach the console from registering an account, while sign-in /
// session / sign-out endpoints keep working. (Next 16 renamed `middleware` → `proxy`.)
export function proxy(req: NextRequest) {
  if (req.method === "POST" && req.nextUrl.pathname.startsWith("/api/auth/sign-up")) {
    return NextResponse.json({ error: "self-registration disabled" }, { status: 403 });
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/api/auth/:path*"],
};
