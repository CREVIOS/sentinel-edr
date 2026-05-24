"use client";
import { createAuthClient } from "better-auth/react";
import { twoFactorClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: typeof window !== "undefined" ? window.location.origin : process.env.BETTER_AUTH_URL,
  plugins: [twoFactorClient()],
});

export const { signIn, signOut, signUp, useSession, twoFactor } = authClient;
