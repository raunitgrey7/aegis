// Shared color maps and small formatting helpers.

import type { Severity } from "./types";

export const SEVERITY_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#64748b",
  none: "#64748b",
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

// Full kill chain, ordered.
export const PHASES: { id: string; label: string }[] = [
  { id: "reconnaissance", label: "Recon" },
  { id: "initial_access", label: "Initial Access" },
  { id: "execution", label: "Execution" },
  { id: "persistence", label: "Persistence" },
  { id: "privilege_escalation", label: "Priv Esc" },
  { id: "defense_evasion", label: "Defense Evasion" },
  { id: "credential_access", label: "Cred Access" },
  { id: "discovery", label: "Discovery" },
  { id: "lateral_movement", label: "Lateral Movement" },
  { id: "collection", label: "Collection" },
  { id: "command_and_control", label: "C2" },
  { id: "exfiltration", label: "Exfiltration" },
  { id: "impact", label: "Impact" },
];

export const PHASE_LABEL: Record<string, string> = Object.fromEntries(
  PHASES.map((p) => [p.id, p.label]),
);

// A perceptually-ordered ramp for kill-chain phases (cool → hot).
export const PHASE_COLOR: Record<string, string> = {
  reconnaissance: "#38bdf8",
  initial_access: "#22d3ee",
  execution: "#2dd4bf",
  persistence: "#a3e635",
  privilege_escalation: "#facc15",
  defense_evasion: "#fbbf24",
  credential_access: "#fb923c",
  discovery: "#60a5fa",
  lateral_movement: "#f97316",
  collection: "#f472b6",
  command_and_control: "#f43f5e",
  exfiltration: "#ef4444",
  impact: "#dc2626",
};

export const NODE_COLOR: Record<string, string> = {
  user: "#22d3ee",
  host: "#60a5fa",
  process: "#a3e635",
  file: "#c084fc",
  ip: "#f97316",
  domain: "#fb923c",
  ioc: "#ef4444",
  service: "#2dd4bf",
};

export const NODE_LABEL: Record<string, string> = {
  user: "Identity",
  host: "Host",
  process: "Process",
  file: "File",
  ip: "IP",
  domain: "Domain",
  ioc: "Threat Indicator",
  service: "Service",
};

export function riskColor(risk: number): string {
  if (risk >= 85) return "#ef4444";
  if (risk >= 65) return "#f97316";
  if (risk >= 40) return "#eab308";
  if (risk >= 20) return "#3b82f6";
  return "#64748b";
}

export function severityColor(sev: string): string {
  return SEVERITY_COLOR[sev] ?? "#64748b";
}

export function threatLevelColor(level: string): string {
  switch (level) {
    case "CRITICAL":
      return "#ef4444";
    case "HIGH":
      return "#f97316";
    case "ELEVATED":
      return "#eab308";
    default:
      return "#34d399";
  }
}

export function fmtNum(n: number | undefined | null): string {
  if (n === undefined || n === null) return "—";
  return n.toLocaleString("en-US");
}

export function fmtBytes(n: number | null | undefined): string {
  if (!n) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("en-GB", {
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

export function fmtAgo(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso).getTime();
  const s = Math.round((Date.now() - d) / 1000);
  if (Number.isNaN(s)) return "—";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}
