// MITRE ATT&CK enrichment — a static, offline lookup so bare technique IDs (T1059) render
// as named, tactic-mapped chips and a kill-chain strip. Curated for the Linux EDR surface
// the rule pack covers; unknown IDs degrade gracefully to the raw id. No network, no deps.

export interface Technique {
  name: string;
  /** primary ATT&CK tactic (kill-chain stage) this technique belongs to */
  tactic: Tactic;
}

export type Tactic =
  | "Reconnaissance"
  | "Resource Development"
  | "Initial Access"
  | "Execution"
  | "Persistence"
  | "Privilege Escalation"
  | "Defense Evasion"
  | "Credential Access"
  | "Discovery"
  | "Lateral Movement"
  | "Collection"
  | "Command and Control"
  | "Exfiltration"
  | "Impact";

// Ordered kill chain (left → right) for the progress strip.
export const TACTICS: Tactic[] = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

// Short tactic labels for compact strips.
export const TACTIC_SHORT: Record<Tactic, string> = {
  Reconnaissance: "Recon",
  "Resource Development": "ResDev",
  "Initial Access": "Access",
  Execution: "Exec",
  Persistence: "Persist",
  "Privilege Escalation": "PrivEsc",
  "Defense Evasion": "Evasion",
  "Credential Access": "Creds",
  Discovery: "Discovery",
  "Lateral Movement": "Lateral",
  Collection: "Collect",
  "Command and Control": "C2",
  Exfiltration: "Exfil",
  Impact: "Impact",
};

// Curated technique table. Covers the techniques the Sentinel rule pack and behavioral
// correlators emit, plus common Linux-adjacent ones. Sub-technique ids (T1059.004) resolve
// to their parent if not listed explicitly.
const TECHNIQUES: Record<string, Technique> = {
  T1595: { name: "Active Scanning", tactic: "Reconnaissance" },
  T1190: { name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  T1133: { name: "External Remote Services", tactic: "Initial Access" },
  T1078: { name: "Valid Accounts", tactic: "Initial Access" },
  T1200: { name: "Hardware Additions", tactic: "Initial Access" },
  T1059: { name: "Command & Scripting Interpreter", tactic: "Execution" },
  "T1059.004": { name: "Unix Shell", tactic: "Execution" },
  T1203: { name: "Exploitation for Client Execution", tactic: "Execution" },
  T1106: { name: "Native API", tactic: "Execution" },
  T1053: { name: "Scheduled Task/Job", tactic: "Execution" },
  "T1053.003": { name: "Cron", tactic: "Persistence" },
  T1204: { name: "User Execution", tactic: "Execution" },
  T1547: { name: "Boot/Logon Autostart Execution", tactic: "Persistence" },
  T1543: { name: "Create or Modify System Process", tactic: "Persistence" },
  "T1543.002": { name: "Systemd Service", tactic: "Persistence" },
  T1546: { name: "Event Triggered Execution", tactic: "Persistence" },
  "T1546.004": { name: "Unix Shell Config Modification", tactic: "Persistence" },
  T1037: { name: "Boot/Logon Initialization Scripts", tactic: "Persistence" },
  T1136: { name: "Create Account", tactic: "Persistence" },
  T1098: { name: "Account Manipulation", tactic: "Persistence" },
  "T1098.004": { name: "SSH Authorized Keys", tactic: "Persistence" },
  T1505: { name: "Server Software Component", tactic: "Persistence" },
  "T1505.003": { name: "Web Shell", tactic: "Persistence" },
  T1574: { name: "Hijack Execution Flow", tactic: "Persistence" },
  "T1574.006": { name: "Dynamic Linker Hijacking", tactic: "Persistence" },
  T1548: { name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  "T1548.003": { name: "Sudo and Sudo Caching", tactic: "Privilege Escalation" },
  T1068: { name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
  T1055: { name: "Process Injection", tactic: "Defense Evasion" },
  T1070: { name: "Indicator Removal", tactic: "Defense Evasion" },
  "T1070.002": { name: "Clear Linux/Mac System Logs", tactic: "Defense Evasion" },
  "T1070.004": { name: "File Deletion", tactic: "Defense Evasion" },
  T1027: { name: "Obfuscated Files or Information", tactic: "Defense Evasion" },
  T1140: { name: "Deobfuscate/Decode Files", tactic: "Defense Evasion" },
  T1014: { name: "Rootkit", tactic: "Defense Evasion" },
  T1562: { name: "Impair Defenses", tactic: "Defense Evasion" },
  "T1562.001": { name: "Disable or Modify Tools", tactic: "Defense Evasion" },
  T1222: { name: "File and Directory Permissions Modification", tactic: "Defense Evasion" },
  T1564: { name: "Hide Artifacts", tactic: "Defense Evasion" },
  T1610: { name: "Deploy Container", tactic: "Defense Evasion" },
  T1611: { name: "Escape to Host", tactic: "Privilege Escalation" },
  T1110: { name: "Brute Force", tactic: "Credential Access" },
  T1003: { name: "OS Credential Dumping", tactic: "Credential Access" },
  "T1003.008": { name: "/etc/passwd and /etc/shadow", tactic: "Credential Access" },
  T1552: { name: "Unsecured Credentials", tactic: "Credential Access" },
  "T1552.001": { name: "Credentials In Files", tactic: "Credential Access" },
  "T1552.004": { name: "Private Keys", tactic: "Credential Access" },
  T1555: { name: "Credentials from Password Stores", tactic: "Credential Access" },
  T1056: { name: "Input Capture", tactic: "Credential Access" },
  T1082: { name: "System Information Discovery", tactic: "Discovery" },
  T1083: { name: "File and Directory Discovery", tactic: "Discovery" },
  T1057: { name: "Process Discovery", tactic: "Discovery" },
  T1018: { name: "Remote System Discovery", tactic: "Discovery" },
  T1046: { name: "Network Service Discovery", tactic: "Discovery" },
  T1033: { name: "System Owner/User Discovery", tactic: "Discovery" },
  T1087: { name: "Account Discovery", tactic: "Discovery" },
  T1518: { name: "Software Discovery", tactic: "Discovery" },
  T1021: { name: "Remote Services", tactic: "Lateral Movement" },
  "T1021.004": { name: "SSH", tactic: "Lateral Movement" },
  T1563: { name: "Remote Service Session Hijacking", tactic: "Lateral Movement" },
  T1560: { name: "Archive Collected Data", tactic: "Collection" },
  T1005: { name: "Data from Local System", tactic: "Collection" },
  T1039: { name: "Data from Network Shared Drive", tactic: "Collection" },
  T1071: { name: "Application Layer Protocol", tactic: "Command and Control" },
  "T1071.001": { name: "Web Protocols", tactic: "Command and Control" },
  T1090: { name: "Proxy", tactic: "Command and Control" },
  T1095: { name: "Non-Application Layer Protocol", tactic: "Command and Control" },
  T1571: { name: "Non-Standard Port", tactic: "Command and Control" },
  T1572: { name: "Protocol Tunneling", tactic: "Command and Control" },
  T1573: { name: "Encrypted Channel", tactic: "Command and Control" },
  T1105: { name: "Ingress Tool Transfer", tactic: "Command and Control" },
  T1219: { name: "Remote Access Software", tactic: "Command and Control" },
  T1041: { name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
  T1048: { name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
  T1567: { name: "Exfiltration Over Web Service", tactic: "Exfiltration" },
  "T1567.002": { name: "Exfiltration to Cloud Storage", tactic: "Exfiltration" },
  T1052: { name: "Exfiltration Over Physical Medium", tactic: "Exfiltration" },
  "T1052.001": { name: "Exfiltration over USB", tactic: "Exfiltration" },
  T1030: { name: "Data Transfer Size Limits", tactic: "Exfiltration" },
  T1486: { name: "Data Encrypted for Impact", tactic: "Impact" },
  T1490: { name: "Inhibit System Recovery", tactic: "Impact" },
  T1489: { name: "Service Stop", tactic: "Impact" },
  T1496: { name: "Resource Hijacking", tactic: "Impact" },
  T1529: { name: "System Shutdown/Reboot", tactic: "Impact" },
};

/** Resolve a technique id (or sub-technique) to its curated entry, falling back to parent. */
export function technique(id: string): Technique | undefined {
  const key = id.trim().toUpperCase();
  if (TECHNIQUES[key]) return TECHNIQUES[key];
  const parent = key.split(".")[0];
  return TECHNIQUES[parent];
}

export function techniqueName(id: string): string {
  return technique(id)?.name ?? id;
}

export function techniqueTactic(id: string): Tactic | undefined {
  return technique(id)?.tactic;
}

/** Canonical ATT&CK reference URL for a technique id. */
export function attackUrl(id: string): string {
  const k = id.trim().toUpperCase();
  const [base, sub] = k.split(".");
  return sub ? `https://attack.mitre.org/techniques/${base}/${sub}/` : `https://attack.mitre.org/techniques/${base}/`;
}

/** Distinct, kill-chain-ordered tactics observed across a set of technique ids. */
export function tacticsFromTechniques(ids: string[]): Tactic[] {
  const set = new Set<Tactic>();
  for (const id of ids) {
    const t = techniqueTactic(id);
    if (t) set.add(t);
  }
  return TACTICS.filter((t) => set.has(t));
}
