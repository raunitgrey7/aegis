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
  ThreatMapNode,
  TokenResponse,
} from "./types";

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
  overview: () => request<Overview>("/overview"),

  incidents: (params?: { severity?: string; status?: string; limit?: number }) => {
    const q = new URLSearchParams();
    if (params?.severity) q.set("severity", params.severity);
    if (params?.status) q.set("status", params.status);
    if (params?.limit) q.set("limit", String(params.limit));
    const qs = q.toString();
    return request<{ count: number; incidents: IncidentSummary[] }>(
      `/incidents${qs ? `?${qs}` : ""}`,
    );
  },

  incident: (id: string) => request<Incident>(`/incidents/${id}`),

  setStatus: (id: string, status: string) =>
    request<{ incident_id: string; status: string }>(`/incidents/${id}/status`, {
      method: "POST",
      body: JSON.stringify({ status }),
    }),

  investigate: (id: string) =>
    request<InvestigationReport>(`/incidents/${id}/investigate`, { method: "POST" }),

  copilot: (id: string, question: string) =>
    request<CopilotResponse>(`/incidents/${id}/copilot`, {
      method: "POST",
      body: JSON.stringify({ question }),
    }),

  threatMap: () => request<{ nodes: ThreatMapNode[] }>("/graph/threat-map"),
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
