import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins";
import { Pool } from "pg";

// Better Auth owns console authentication (email + password), persisting its own tables
// in the same Postgres instance as the platform. The Next BFF authorizes every Go API
// call against a Better Auth session — the browser never holds Go credentials.
export const auth = betterAuth({
  database: new Pool({ connectionString: process.env.DATABASE_URL }),
  secret: process.env.BETTER_AUTH_SECRET,
  baseURL: process.env.BETTER_AUTH_URL || "http://localhost:3000",
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 12,
    // No public self-registration. Operators are provisioned by an admin (seed script /
    // invite), never by anyone who can reach the console. Defence-in-depth alongside the
    // middleware block in proxy.ts.
    disableSignUp: true,
  },
  // Brute-force protection on the public auth surface (sign-in/2FA), keyed per client IP by
  // Better Auth. Stricter than the default for credential endpoints.
  rateLimit: {
    enabled: true,
    window: 60,
    max: 60,
    customRules: {
      "/sign-in/email": { window: 60, max: 8 },
      "/two-factor/verify-totp": { window: 60, max: 8 },
      "/two-factor/enable": { window: 60, max: 5 },
    },
  },
  session: {
    expiresIn: 60 * 60 * 12, // 12h
    cookieCache: { enabled: true, maxAge: 60 * 5 },
  },
  user: {
    additionalFields: {
      // Least privilege by default; elevate operators explicitly.
      role: { type: "string", required: false, defaultValue: "viewer", input: false },
    },
  },
  plugins: [
    // TOTP two-factor (authenticator app) + backup codes. Operators self-enable in Settings.
    twoFactor({ issuer: "Sentinel" }),
  ],
});

export type Session = typeof auth.$Infer.Session;
