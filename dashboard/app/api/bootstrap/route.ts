import { auth } from "@/lib/auth";
import { Pool } from "pg";

// One-time seed of the bootstrap admin operator.
// - Requires SEED_ADMIN_PASS (no default-password fallback).
// - Idempotent: if the account exists, just ensures it has the admin role.
// - Reports real failures (does not mask DB/auth errors as success).
export async function GET() {
  const email = process.env.SEED_ADMIN_EMAIL || "admin@sentinel.local";
  const password = process.env.SEED_ADMIN_PASS;
  if (!password) {
    return Response.json(
      { ok: false, error: "seeding disabled: set SEED_ADMIN_PASS" },
      { status: 400 },
    );
  }

  // Create the account (ignore "already exists"; surface any other error).
  let created = false;
  try {
    await auth.api.signUpEmail({ body: { email, password, name: "Administrator" } });
    created = true;
  } catch (e) {
    const msg = String((e as Error)?.message || e).toLowerCase();
    const exists = msg.includes("exist") || msg.includes("already") || msg.includes("unique");
    if (!exists) {
      console.error("bootstrap signUp failed:", e);
      return Response.json({ ok: false, error: "bootstrap failed" }, { status: 500 });
    }
  }

  // Ensure the bootstrap account has the admin role (default role is viewer).
  try {
    const pool = new Pool({ connectionString: process.env.DATABASE_URL });
    await pool.query(`UPDATE "user" SET role = 'admin' WHERE email = $1`, [email]);
    await pool.end();
  } catch (e) {
    console.error("bootstrap role grant failed:", e);
    return Response.json({ ok: false, error: "role grant failed" }, { status: 500 });
  }

  return Response.json({ ok: true, created, admin: email });
}
