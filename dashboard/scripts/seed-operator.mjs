// Seed or elevate a console operator. Public sign-up is disabled at runtime (auth.ts
// disableSignUp + proxy.ts), so operators are provisioned here by an admin. This uses its own
// Better Auth instance (same DB + secret) which does not set disableSignUp, then sets the
// role directly.
//
// Run from deploy/app2 against the live stack:
//   docker run --rm --network sentinel_internal \
//     -e DATABASE_URL="$(docker inspect sentinel-dashboard --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^DATABASE_URL=//p')" \
//     -e BETTER_AUTH_SECRET="$(docker inspect sentinel-dashboard --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^BETTER_AUTH_SECRET=//p')" \
//     -e OP_EMAIL=new.operator@example.com -e OP_PASS='a-strong-passphrase' -e OP_ROLE=analyst \
//     -v "$PWD/../../dashboard":/app -w /app node:22-bookworm-slim \
//     bash -c "corepack enable && pnpm install --frozen-lockfile >/dev/null 2>&1; node scripts/seed-operator.mjs"
import { betterAuth } from "better-auth";
import { Pool } from "pg";

const email = process.env.OP_EMAIL;
const password = process.env.OP_PASS;
const role = (process.env.OP_ROLE || "viewer").toLowerCase();
if (!email || !password) {
  console.error("set OP_EMAIL and OP_PASS (and optionally OP_ROLE=viewer|analyst|admin)");
  process.exit(1);
}
if (!["viewer", "analyst", "admin"].includes(role)) {
  console.error(`invalid OP_ROLE: ${role}`);
  process.exit(1);
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const auth = betterAuth({
  database: pool,
  secret: process.env.BETTER_AUTH_SECRET,
  emailAndPassword: { enabled: true, minPasswordLength: 12 },
});

try {
  await auth.api.signUpEmail({ body: { email, password, name: email.split("@")[0] } });
  console.log("created:", email);
} catch (e) {
  const m = String(e?.message || e).toLowerCase();
  if (m.includes("exist") || m.includes("already") || m.includes("unique")) {
    console.log("exists (password unchanged):", email);
  } else {
    console.error("signup failed:", e);
    await pool.end();
    process.exit(1);
  }
}

await pool.query(`UPDATE "user" SET role = $2 WHERE email = $1`, [email, role]);
console.log("role set:", role);
await pool.end();
