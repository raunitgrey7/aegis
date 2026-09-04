// Aegis API client. Reads NEXT_PUBLIC_API_URL (default http://localhost:8000/api).

import type {
  CopilotResponse,
  Incident,
  IncidentSummary,
  InvestigationReport,
  Me,
  MitreCoverage,
  Overview,
  RuleInfo,
  ThreatMapResponse,
  TokenResponse,
} from "./types";

/* ---- response hardening -------------------------------------------------
 * Whatever a client's backend returns (older versions, partial data, nulls
 * from odd telemetry), pages must always receive well-formed shapes. These
 * helpers fill defaults so a missing array or a null number can never take
 * down a render tree. */

function arr<T>(v: unknown): T[] {
  return Array.isArray(v) ? (v as T[]) : [];
}

function num(v: unknown, fallback = 0): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function rec<T>(v: unknown): Record<string, T> {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, T>) : {};
}

function normalizeOverview(o: Overview): Overview {
  return {
    ...o,
    threat_level: o.threat_level ?? "LOW",
    active_incidents: num(o.active_incidents),
    critical: num(o.critical),
    high: num(o.high),
    suspicious_users: num(o.suspicious_users),
    affected_hosts: num(o.affected_hosts),
    events_ingested: num(o.events_ingested),
    detections: num(o.detections),
    graph: { nodes: 0, edges: 0, by_kind: {}, ...rec(o.graph) } as Overview["graph"],
    threat_intel: {
      ips: 0, domains: 0, hashes: 0, urls: 0, cidrs: 0,
      ...rec<number>(o.threat_intel),
    } as Overview["threat_intel"],
    detector: rec(o.detector) as Overview["detector"],
    top_incidents: arr(o.top_incidents).map((t) => ({
      ...(t as object),
      risk: num((t as { risk?: unknown }).risk),
      hosts: arr((t as { hosts?: unknown }).hosts),
      users: arr((t as { users?: unknown }).users),
      phases: arr((t as { phases?: unknown }).phases),
    })) as Overview["top_incidents"],
    severity_distribution: rec<number>(o.severity_distribution),
    phase_distribution: arr(o.phase_distribution),
    tactic_coverage: arr(o.tactic_coverage),
  };
}

function normalizeIncident(i: Incident): Incident {
  return {
    ...i,
    title: i.title || i.incident_id || "Untitled incident",
    risk_score: Math.min(100, Math.max(0, num(i.risk_score))),
    confidence: Math.min(1, Math.max(0, num(i.confidence))),
    affected_users: arr(i.affected_users),
    affected_hosts: arr(i.affected_hosts),
    external_ips: arr(i.external_ips),
    domains: arr(i.domains),
    techniques: arr(i.techniques),
    phases: arr(i.phases),
    detections: arr(i.detections).map((d) => ({
      ...(d as object),
      techniques: arr((d as { techniques?: unknown }).techniques),
      evidence_event_ids: arr((d as { evidence_event_ids?: unknown }).evidence_event_ids),
      entities: rec((d as { entities?: unknown }).entities),
      details: rec((d as { details?: unknown }).details),
    })) as Incident["detections"],
    event_ids: arr(i.event_ids),
    events: arr(i.events),
    critical_path: arr(i.critical_path),
    tags: arr(i.tags),
    graph: {
      nodes: arr(i.graph?.nodes).map((n) => ({
        ...(n as object),
        attributes: rec((n as { attributes?: unknown }).attributes),
        evidence_event_ids: arr((n as { evidence_event_ids?: unknown }).evidence_event_ids),
      })),
      edges: arr(i.graph?.edges),
    } as Incident["graph"],
    score_breakdown: rec<number>(i.score_breakdown),
    summary: i.summary ?? "",
  };
}

function normalizeReport(r: InvestigationReport): InvestigationReport {
  return {
    ...r,
    attack_narrative: r.attack_narrative ?? r.summary ?? "",
    affected_users: arr(r.affected_users),
    affected_hosts: arr(r.affected_hosts),
    external_ips: arr(r.external_ips),
    phases_present: arr(r.phases_present),
    techniques: arr(r.techniques),
    timeline: arr(r.timeline),
    agent_findings: arr(r.agent_findings),
    recommended_actions: arr(r.recommended_actions),
    injection_warnings: arr(r.injection_warnings),
  };
}

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") || "http://localhost:8000/api";

const TOKEN_KEY = "aegis_token";
const ROLE_KEY = "aegis_role";
const USER_KEY = "aegis_user";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function getRole(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(ROLE_KEY);
  } catch {
    return null;
  }
}

export function getUsername(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(USER_KEY);
  } catch {
    return null;
  }
}

export function setSession(token: string, role: string, username: string) {
  try {
    window.localStorage.setItem(TOKEN_KEY, token);
    window.localStorage.setItem(ROLE_KEY, role);
    window.localStorage.setItem(USER_KEY, username);
  } catch {
    /* ignore */
  }
}

export function clearSession() {
  try {
    window.localStorage.removeItem(TOKEN_KEY);
    window.localStorage.removeItem(ROLE_KEY);
    window.localStorage.removeItem(USER_KEY);
  } catch {
    /* ignore */
  }
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  auth = true,
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (auth) {
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  } catch {
    throw new ApiError(0, "Backend unavailable — is the Aegis API running on :8000?");
  }
  if (res.status === 401 && auth) {
    // token expired / invalid
    if (typeof window !== "undefined") {
      clearSession();
      if (!window.location.pathname.startsWith("/login")) {
        window.location.href = "/login";
      }
    }
    throw new ApiError(401, "Session expired");
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  base: API_BASE,

  async login(username: string, password: string): Promise<TokenResponse> {
    return request<TokenResponse>(
      "/auth/login",
      { method: "POST", body: JSON.stringify({ username, password }) },
      false,
    );
  },

  me: () => request<Me>("/auth/me"),
  overview: () => request<Overview>("/overview").then(normalizeOverview),

  incidents: (params?: { severity?: string; status?: string; limit?: number }) => {
    const q = new URLSearchParams();
    if (params?.severity) q.set("severity", params.severity);
    if (params?.status) q.set("status", params.status);
    if (params?.limit) q.set("limit", String(params.limit));
    const qs = q.toString();
    return request<{ count: number; incidents: IncidentSummary[] }>(
      `/incidents${qs ? `?${qs}` : ""}`,
    ).then((r) => ({
      count: num(r?.count),
      incidents: arr<IncidentSummary>(r?.incidents).map((i) => ({
        ...i,
        title: i.title || i.incident_id || "Untitled incident",
        risk_score: Math.min(100, Math.max(0, num(i.risk_score))),
        confidence: Math.min(1, Math.max(0, num(i.confidence))),
        affected_users: arr<string>(i.affected_users),
        affected_hosts: arr<string>(i.affected_hosts),
        external_ips: arr<string>(i.external_ips),
        techniques: arr<string>(i.techniques),
        phases: arr<string>(i.phases),
        tags: arr<string>(i.tags),
        detection_count: num(i.detection_count),
      })),
    }));
  },

  incident: (id: string) =>
    request<Incident>(`/incidents/${encodeURIComponent(id)}`).then(normalizeIncident),

  setStatus: (id: string, status: string) =>
    request<{ incident_id: string; status: string }>(`/incidents/${id}/status`, {
      method: "POST",
      body: JSON.stringify({ status }),
    }),

  investigate: (id: string) =>
    request<InvestigationReport>(`/incidents/${encodeURIComponent(id)}/investigate`, {
      method: "POST",
    }).then(normalizeReport),

  copilot: (id: string, question: string) =>
    request<CopilotResponse>(`/incidents/${encodeURIComponent(id)}/copilot`, {
      method: "POST",
      body: JSON.stringify({ question }),
    }),

  threatMap: () =>
    request<ThreatMapResponse>("/graph/threat-map").then((r) => ({
      nodes: arr<ThreatMapResponse["nodes"][number]>(r?.nodes).map((n) => ({
        ...n,
        risk: num(n.risk),
        country: n.country ?? null,
        hosts: arr<string>(n.hosts),
      })),
      origins: arr<ThreatMapResponse["origins"][number]>(r?.origins).map((o) => ({
        ...o,
        incidents: num(o.incidents),
        max_risk: num(o.max_risk),
        users: arr<string>(o.users),
      })),
      hq: { country: r?.hq?.country || "IN" },
    })),
  rules: () => request<{ count: number; rules: RuleInfo[] }>("/rules"),
  mitreCoverage: () => request<MitreCoverage>("/mitre/coverage"),

  simulate: (scenario: string) =>
    request<{
      scenario: string;
      name: string;
      events: number;
      detections: number;
      new_incidents: string[];
      expected_techniques: string[];
    }>("/simulate", { method: "POST", body: JSON.stringify({ scenario }) }),

  health: () =>
    request<{ status: string; events: number; incidents: number; llm: boolean }>(
      "/healthz",
      {},
      false,
    ),
};
