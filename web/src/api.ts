// Thin API client. All URLs are relative so the same build works behind the Vite dev
// proxy and when served from the Go server in production.

import type { Agent, Case, CaseDetail, Detection, Event, Overview, ResponseAction, Rule, TriageResult } from "./types";

const USER_KEY = "sentinel_user";
const ROLE_KEY = "sentinel_role";
let sessionToken: string | null = null;

export function getToken(): string | null {
  return sessionToken;
}
export function getUser(): string | null {
  return sessionStorage.getItem(USER_KEY);
}
export function getRole(): string | null {
  return sessionStorage.getItem(ROLE_KEY);
}
export function setSession(token: string, user: string, role: string) {
  sessionToken = token;
  sessionStorage.setItem(USER_KEY, user);
  sessionStorage.setItem(ROLE_KEY, role);
}
export function clearSession() {
  sessionToken = null;
  sessionStorage.removeItem(USER_KEY);
  sessionStorage.removeItem(ROLE_KEY);
  fetch("/api/v1/logout", { method: "POST" }).catch(() => {});
}

async function req<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(opts.headers as Record<string, string>),
  };
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401) {
    clearSession();
    if (!path.endsWith("/login")) window.location.reload();
    throw new Error("unauthorized");
  }
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  const ct = res.headers.get("content-type") || "";
  return (ct.includes("json") ? res.json() : res.text()) as Promise<T>;
}

export const api = {
  async login(username: string, password: string) {
    return req<{ token: string; role: string; user: string }>("/api/v1/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
  },
  overview: () => req<Overview>("/api/v1/stats/overview"),
  agents: () => req<Agent[]>("/api/v1/agents"),
  agent: (id: string) => req<Agent>(`/api/v1/agents/${id}`),
  events: (q: Record<string, string> = {}) =>
    req<Event[]>("/api/v1/events?" + new URLSearchParams(q).toString()),
  detections: (q: Record<string, string> = {}) =>
    req<Detection[]>("/api/v1/detections?" + new URLSearchParams(q).toString()),
  responses: () => req<ResponseAction[]>("/api/v1/responses"),
  rules: () => req<Rule[]>("/api/v1/rules"),
  dlpPolicies: () => req<{ Classifier: string; Channel: string; Verdict: string }[]>("/api/v1/dlp/policies"),
  dlpClassifiers: () => req<{ name: string; label: string; severity: string }[]>("/api/v1/dlp/classifiers"),
  setDetectionStatus: (id: string, status: string) =>
    req<Detection>(`/api/v1/detections/${id}/status`, {
      method: "POST",
      body: JSON.stringify({ status }),
    }),
  triageDetection: (id: string) =>
    req<TriageResult>(`/api/v1/detections/${id}/triage`, { method: "POST" }),
  respond: (body: {
    type: string;
    agent_id: string;
    target?: Record<string, unknown>;
    reason?: string;
    detection_id?: string;
  }) =>
    req<ResponseAction>("/api/v1/respond", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  cases: (q: Record<string, string> = {}) =>
    req<Case[]>("/api/v1/cases?" + new URLSearchParams(q).toString()),
  caseDetail: (id: string) => req<CaseDetail>(`/api/v1/cases/${id}`),
  createCase: (body: { title: string; severity?: string; agent_id?: string; hostname?: string; detection_ids?: string[] }) =>
    req<Case>("/api/v1/cases", { method: "POST", body: JSON.stringify(body) }),
  updateCase: (id: string, body: { status?: string; assigned_to?: string; title?: string }) =>
    req<Case>(`/api/v1/cases/${id}`, { method: "POST", body: JSON.stringify(body) }),
  addCaseNote: (id: string, body: string) =>
    req<Case>(`/api/v1/cases/${id}/notes`, { method: "POST", body: JSON.stringify({ body }) }),
};
