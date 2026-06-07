// Canonical labels for every response verb the Go control plane accepts (model.ResponseType).
// One source of truth so the Responses log, action menus, bulk bars and incident-summary
// recommendations all read the same human label instead of raw snake_case.

export const RESPONSE_LABELS: Record<string, string> = {
  kill_process: "Kill process",
  kill_tree: "Kill process tree",
  isolate: "Isolate endpoint",
  unisolate: "Lift isolation",
  disable_account: "Disable account",
  block_upload: "Block uploads",
  unblock_upload: "Lift upload block",
  block_usb: "Block USB",
  unblock_usb: "Lift USB block",
  freeze: "Freeze processes",
  unfreeze: "Unfreeze processes",
  quarantine_file: "Quarantine file",
  live_triage: "Live triage",
  update_policy: "Update policy",
  self_update: "Agent self-update",
};

export function responseLabel(t: string): string {
  return RESPONSE_LABELS[t] || t.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

/** Verbs that change host state irreversibly enough to warrant a confirmation step. */
export const DESTRUCTIVE_RESPONSES = new Set([
  "kill_process",
  "kill_tree",
  "isolate",
  "disable_account",
  "freeze",
  "quarantine_file",
]);
