"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft,
  Bot,
  CheckCircle2,
  ChevronRight,
  ExternalLink,
  Fingerprint,
  Loader,
  Network,
  ScrollText,
  Send,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
  Waypoints,
} from "lucide-react";
import { api, ApiError } from "@/lib/api";
import type {
  CopilotResponse,
  GraphNode,
  Incident,
  InvestigationReport,
} from "@/lib/types";
import {
  fmtBytes,
  fmtTime,
  NODE_COLOR,
  PHASE_COLOR,
  PHASE_LABEL,
  PHASES,
  riskColor,
  severityColor,
} from "@/lib/theme";
import {
  Chip,
  Confidence,
  ErrorState,
  Loading,
  Panel,
  SeverityBadge,
} from "@/components/ui";
import { AttackGraph } from "@/components/AttackGraph";

type Tab = "graph" | "timeline" | "investigation" | "copilot";

export default function IncidentDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const id = params.id;
  const [inc, setInc] = useState<Incident | null>(null);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<Tab>("graph");

  useEffect(() => {
    (async () => {
      try {
        setInc(await api.incident(id));
        setError("");
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) return;
        setError(err instanceof Error ? err.message : "Failed to load incident");
      }
    })();
  }, [id]);

  if (error) return <ErrorState message={error} />;
  if (!inc) return <Loading label="Loading incident…" rows={8} />;

  const TABS: { id: Tab; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { id: "graph", label: "Attack Graph", icon: Waypoints },
    { id: "timeline", label: "Timeline", icon: ScrollText },
    { id: "investigation", label: "AI Investigation", icon: Sparkles },
    { id: "copilot", label: "Copilot", icon: Bot },
  ];

  return (
    <div className="space-y-5 rise">
      <button
        onClick={() => router.push("/incidents")}
        className="flex cursor-pointer items-center gap-1.5 text-sm text-[var(--fg-dim)] transition hover:text-[var(--fg)]"
      >
        <ArrowLeft className="h-4 w-4" /> All incidents
      </button>

      {/* Header */}
      <div className="panel p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            <RiskGauge value={inc.risk_score} />
            <div>
              <div className="flex items-center gap-2">
                <span className="mono text-sm font-semibold text-[var(--accent)]">
                  {inc.incident_id}
                </span>
                <SeverityBadge severity={inc.severity} small />
                <StatusPill incident={inc} onChange={(s) => setInc({ ...inc, status: s })} />
              </div>
              <h1 className="mt-1.5 max-w-2xl text-lg font-bold leading-snug text-[var(--fg)]">
                {inc.title}
              </h1>
              <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[var(--fg-dim)]">
                <Confidence value={inc.confidence} />
                <span>·</span>
                <span className="mono">{inc.detections.length} detections</span>
                <span>·</span>
                <span className="mono">{inc.event_ids.length} events</span>
                <span>·</span>
                <span>{fmtTime(inc.first_event_at)} → {fmtTime(inc.last_event_at)}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Entity chips */}
        <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
          <EntityGroup label="Affected identities" color={NODE_COLOR.user} items={inc.affected_users} />
          <EntityGroup label="Affected hosts" color={NODE_COLOR.host} items={inc.affected_hosts} />
          <EntityGroup
            label="External destinations"
            color={NODE_COLOR.ip}
            items={[...inc.external_ips, ...inc.domains]}
          />
        </div>

        {/* Kill chain stepper */}
        <div className="mt-5">
          <PhaseStepper present={inc.phases.filter((p) => p.present).map((p) => p.phase)} />
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[var(--border)]">
        {TABS.map((t) => {
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex cursor-pointer items-center gap-2 border-b-2 px-4 py-2.5 text-sm transition ${
                active
                  ? "border-[var(--accent)] font-medium text-[var(--fg)]"
                  : "border-transparent text-[var(--fg-dim)] hover:text-[var(--fg-muted)]"
              }`}
            >
              <t.icon className="h-4 w-4" />
              {t.label}
            </button>
          );
        })}
      </div>

      {tab === "graph" && <GraphTab inc={inc} />}
      {tab === "timeline" && <TimelineTab inc={inc} />}
      {tab === "investigation" && <InvestigationTab id={id} />}
      {tab === "copilot" && <CopilotTab id={id} />}
    </div>
  );
}

/* ------------------------------------------------------------------ Risk gauge */
function RiskGauge({ value }: { value: number }) {
  const color = riskColor(value);
  const r = 30;
  const c = 2 * Math.PI * r;
  const off = c * (1 - value / 100);
  return (
    <div className="relative flex h-[72px] w-[72px] shrink-0 items-center justify-center">
      <svg width="72" height="72" className="-rotate-90">
        <circle cx="36" cy="36" r={r} fill="none" stroke="rgba(148,173,204,0.12)" strokeWidth="6" />
        <circle
          cx="36"
          cy="36"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={off}
          style={{ filter: `drop-shadow(0 0 5px ${color}88)`, transition: "stroke-dashoffset 0.6s" }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-lg font-bold tabular-nums" style={{ color }}>
          {Math.round(value)}
        </span>
        <span className="mono text-[8px] uppercase tracking-wider text-[var(--fg-dim)]">risk</span>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ Status pill */
const STATUSES = ["open", "investigating", "contained", "resolved", "false_positive"];
function StatusPill({ incident, onChange }: { incident: Incident; onChange: (s: string) => void }) {
  const [busy, setBusy] = useState(false);
  async function update(s: string) {
    setBusy(true);
    try {
      await api.setStatus(incident.incident_id, s);
      onChange(s);
    } catch {
      /* role or network */
    } finally {
      setBusy(false);
    }
  }
  return (
    <select
      value={incident.status}
      disabled={busy}
      onChange={(e) => update(e.target.value)}
      className="mono cursor-pointer rounded-md border border-[var(--border)] bg-[var(--panel)] px-2 py-0.5 text-[10px] uppercase tracking-wider text-[var(--fg-muted)] outline-none hover:border-[var(--accent)]/40"
    >
      {STATUSES.map((s) => (
        <option key={s} value={s}>
          {s.replace(/_/g, " ")}
        </option>
      ))}
    </select>
  );
}

function EntityGroup({ label, color, items }: { label: string; color: string; items: string[] }) {
  return (
    <div className="panel-flat p-3">
      <div className="mb-2 text-[10px] uppercase tracking-wider text-[var(--fg-dim)]">{label}</div>
      <div className="flex flex-wrap gap-1.5">
        {items.length ? (
          items.slice(0, 8).map((i) => (
            <Chip key={i} color={color}>
              {i}
            </Chip>
          ))
        ) : (
          <span className="text-xs text-[var(--fg-dim)]">none</span>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ Phase stepper */
function PhaseStepper({ present }: { present: string[] }) {
  const set = new Set(present);
  const active = PHASES.filter((p) => set.has(p.id));
  const relevant = active.length ? active : PHASES.slice(0, 6);
  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <span className="text-[10px] uppercase tracking-wider text-[var(--fg-dim)]">
          Kill-chain progression
        </span>
        <span className="mono text-[10px] text-[var(--fg-dim)]">
          {present.length} / 13 phases
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-1">
        {PHASES.map((p, i) => {
          const on = set.has(p.id);
          const color = PHASE_COLOR[p.id];
          return (
            <div key={p.id} className="flex items-center">
              <div
                className="flex items-center gap-1.5 rounded-md px-2 py-1 text-[10px] transition"
                style={{
                  background: on ? `${color}1a` : "transparent",
                  border: `1px solid ${on ? `${color}55` : "var(--border)"}`,
                  color: on ? color : "var(--fg-dim)",
                }}
                title={p.id}
              >
                {on && <CheckCircle2 className="h-3 w-3" />}
                {p.label}
              </div>
              {i < PHASES.length - 1 && (
                <ChevronRight className="h-3 w-3 shrink-0 text-[var(--fg-dim)]/40" />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ Graph tab */
function GraphTab({ inc }: { inc: Incident }) {
  const [sel, setSel] = useState<GraphNode | null>(null);
  const eventsById = useMemo(
    () => Object.fromEntries(inc.events.map((e) => [e.event_id, e])),
    [inc.events],
  );
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_320px]">
      <AttackGraph
        graph={inc.graph}
        criticalPath={inc.critical_path}
        onSelect={setSel}
        selectedId={sel?.id}
      />
      <Panel title={sel ? "Node evidence" : "Attack graph"} subtitle={sel ? sel.label : "click a node to inspect"}>
        {!sel ? (
          <div className="space-y-3 text-sm text-[var(--fg-muted)]">
            <p>
              Nodes are laid out left→right along the intrusion: identity → host → process → file →
              destination → threat indicator. Edges are colored by kill-chain phase; the animated path
              is the reconstructed attack spine.
            </p>
            <div className="grid grid-cols-2 gap-2 pt-1">
              {Object.entries(NODE_COLOR).map(([k, c]) => (
                <div key={k} className="flex items-center gap-2 text-xs">
                  <span className="h-2.5 w-2.5 rounded" style={{ background: c }} />
                  <span className="capitalize text-[var(--fg-muted)]">{k}</span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <span
                className="rounded-md px-2 py-0.5 text-[10px] font-medium uppercase"
                style={{
                  color: NODE_COLOR[sel.type],
                  background: `${NODE_COLOR[sel.type]}18`,
                }}
              >
                {sel.type}
              </span>
              {sel.risk > 0 && (
                <span className="mono text-xs" style={{ color: riskColor(sel.risk) }}>
                  risk {Math.round(sel.risk)}
                </span>
              )}
            </div>
            <div className="mono break-all text-xs text-[var(--fg)]">{sel.label}</div>

            {Object.keys(sel.attributes).length > 0 && (
              <div className="space-y-1 border-t border-[var(--border)] pt-2">
                {Object.entries(sel.attributes)
                  .filter(([, v]) => v !== null && v !== "" && typeof v !== "object")
                  .slice(0, 10)
                  .map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-2 text-xs">
                      <span className="text-[var(--fg-dim)]">{k}</span>
                      <span className="mono max-w-[60%] truncate text-right text-[var(--fg-muted)]">
                        {String(v)}
                      </span>
                    </div>
                  ))}
              </div>
            )}

            <div className="border-t border-[var(--border)] pt-2">
              <div className="mb-1.5 text-[10px] uppercase tracking-wider text-[var(--fg-dim)]">
                Evidence ({sel.evidence_event_ids.length})
              </div>
              <div className="max-h-56 space-y-1.5 overflow-y-auto">
                {sel.evidence_event_ids.slice(0, 20).map((eid) => {
                  const ev = eventsById[eid];
                  return (
                    <div key={eid} className="rounded-md bg-[var(--panel)] p-2 text-[11px]">
                      <div className="mono text-[9px] text-[var(--accent)]">{eid}</div>
                      <div className="mono mt-0.5 break-all text-[var(--fg-muted)]">
                        {ev ? summarize(ev) : "—"}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}

/* ------------------------------------------------------------------ Timeline tab */
function TimelineTab({ inc }: { inc: Incident }) {
  const detByEvent = useMemo(() => {
    const m: Record<string, { phase: string | null; techs: string[] }> = {};
    for (const d of inc.detections) {
      for (const eid of d.evidence_event_ids) {
        const cur = m[eid] ?? { phase: d.phase, techs: [] };
        cur.phase = cur.phase ?? d.phase;
        cur.techs = [...new Set([...cur.techs, ...d.techniques])];
        m[eid] = cur;
      }
    }
    return m;
  }, [inc.detections]);

  const events = [...inc.events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
  );

  return (
    <Panel title="Evidence timeline" subtitle={`${events.length} normalized events`}>
      <div className="relative space-y-0 pl-4">
        <div className="absolute bottom-2 left-[7px] top-2 w-px bg-[var(--border)]" />
        {events.map((e) => {
          const det = detByEvent[e.event_id];
          const color = det?.phase ? PHASE_COLOR[det.phase] : "#5c6b80";
          return (
            <div key={e.event_id} className="relative flex gap-3 py-2">
              <div
                className="absolute -left-4 top-3.5 h-2.5 w-2.5 rounded-full border-2"
                style={{
                  borderColor: color,
                  background: det ? color : "var(--panel)",
                  boxShadow: det ? `0 0 8px ${color}88` : "none",
                }}
              />
              <div className="mono w-16 shrink-0 pt-1 text-[10px] text-[var(--fg-dim)]">
                {fmtHM(e.timestamp)}
              </div>
              <div
                className={`min-w-0 flex-1 rounded-lg border p-2.5 ${
                  det ? "border-[var(--border-strong)]" : "border-[var(--border)]"
                }`}
                style={{ background: det ? "var(--panel-2)" : "transparent" }}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="mono text-[10px] text-[var(--fg-dim)]">{e.event_type}</span>
                  {det?.phase && (
                    <Chip color={PHASE_COLOR[det.phase]}>{PHASE_LABEL[det.phase] ?? det.phase}</Chip>
                  )}
                  {det?.techs.slice(0, 3).map((t) => (
                    <Chip key={t}>{t}</Chip>
                  ))}
                </div>
                <div className="mono mt-1 break-all text-[11px] text-[var(--fg-muted)]">
                  {summarize(e)}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

/* ------------------------------------------------------------------ Investigation tab */
function InvestigationTab({ id }: { id: string }) {
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const run = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setReport(await api.investigate(id));
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setError("Investigations require an analyst or admin role.");
      } else if (!(err instanceof ApiError && err.status === 401)) {
        setError(err instanceof Error ? err.message : "Investigation failed");
      }
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    run();
  }, [run]);

  if (loading) return <Loading label="Running AI investigation — planning, agents, synthesis…" rows={6} />;
  if (error) return <ErrorState message={error} />;
  if (!report) return null;

  return (
    <div className="space-y-4">
      {/* Two-gate verification banner — reference integrity + semantic claim check. No "trust me" badge. */}
      <div className="flex flex-wrap items-center gap-3">
        {(() => {
          const g = report.grounding;
          const cv = report.claim_verification;
          const refOk = g?.grounded ?? true;
          const semOk = cv?.verified ?? true;
          return (
            <>
              <div
                className="flex items-center gap-2 rounded-lg px-3 py-2"
                style={{
                  background: refOk ? "#34d39914" : "#f9731614",
                  border: `1px solid ${refOk ? "#34d39944" : "#f9731644"}`,
                }}
              >
                <ShieldCheck className="h-4 w-4" style={{ color: refOk ? "#34d399" : "#f97316" }} />
                <span className="text-xs font-medium" style={{ color: refOk ? "#34d399" : "#f97316" }}>
                  Citations resolve to real events
                </span>
                <span className="mono text-[10px] text-[var(--fg-dim)]">
                  {g?.evidence_cited ?? 0} cited · {(g?.fabricated_ids?.length ?? 0)} fabricated
                </span>
              </div>
              <div
                className="flex items-center gap-2 rounded-lg px-3 py-2"
                style={{
                  background: semOk ? "#22d3ee14" : "#f9731614",
                  border: `1px solid ${semOk ? "#22d3ee44" : "#f9731644"}`,
                }}
              >
                <ShieldCheck className="h-4 w-4" style={{ color: semOk ? "#22d3ee" : "#f97316" }} />
                <span className="text-xs font-medium" style={{ color: semOk ? "#22d3ee" : "#f97316" }}>
                  Claims consistent with detections
                </span>
                <span className="mono text-[10px] text-[var(--fg-dim)]">
                  {cv?.supported ?? 0}/{cv?.total ?? 0} entity/technique/phase claims
                </span>
              </div>
            </>
          );
        })()}
        <Chip color={report.llm_used ? "#22d3ee" : "#8a99ad"}>
          {report.llm_used ? `LLM: ${report.model}` : "Deterministic synthesizer"}
        </Chip>
        <Chip>{report.latency_ms} ms</Chip>
      </div>

      {report.injection_warnings.length > 0 && (
        <div
          className="flex items-start gap-3 rounded-lg p-3"
          style={{ background: "#eab30814", border: "1px solid #eab30844" }}
        >
          <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-[var(--medium)]" />
          <div className="text-xs">
            <div className="font-medium text-[var(--medium)]">
              Prompt-injection content detected in telemetry
            </div>
            <div className="mt-0.5 text-[var(--fg-muted)]">
              {report.injection_warnings.length} field(s) contained directive-like text. Aegis treats
              all telemetry as untrusted data — it never reaches the model as instructions.
            </div>
          </div>
        </div>
      )}

      {/* Narrative */}
      <Panel title="Attack narrative">
        <div className="space-y-3 text-sm leading-relaxed text-[var(--fg-muted)]">
          {report.attack_narrative.split("\n\n").map((para, i) => (
            <p key={i}>{para}</p>
          ))}
        </div>
        {report.verification?.not_verified && (
          <p className="mt-3 border-t border-[var(--border)] pt-3 text-xs text-[var(--fg-dim)]">
            <span className="font-medium text-[var(--fg-muted)]">Not machine-verified:</span>{" "}
            {report.verification.not_verified}
          </p>
        )}
        {report.claim_verification && report.claim_verification.unsupported > 0 && (
          <div className="mt-3 rounded-lg border border-[#f9731644] bg-[#f9731610] p-3">
            <div className="mb-1 text-xs font-medium text-[#f97316]">
              {report.claim_verification.unsupported} narrative claim(s) not supported by detections — reverted to rule-derived text
            </div>
            <div className="mono text-[10px] text-[var(--fg-dim)]">
              {report.claim_verification.unsupported_claims.map((c) => `${c.kind}:${c.value}`).join(" · ")}
            </div>
          </div>
        )}
      </Panel>

      {/* Agent findings */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {report.agent_findings.map((f) => (
          <div key={f.agent} className="panel p-4">
            <div className="mb-2 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AgentIcon agent={f.agent} />
                <span className="text-sm font-semibold capitalize text-[var(--fg)]">
                  {f.agent} agent
                </span>
              </div>
              <span className="mono text-[10px] text-[var(--fg-dim)]">
                conf {Math.round(f.confidence * 100)}%
              </span>
            </div>
            <div className="text-sm font-medium text-[var(--accent)]">{f.headline}</div>
            <p className="mt-1 text-xs leading-relaxed text-[var(--fg-muted)]">{f.detail}</p>
            {f.evidence_event_ids.length > 0 && (
              <div className="mono mt-2 text-[9px] text-[var(--fg-dim)]">
                {f.evidence_event_ids.length} evidence event(s)
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Recommended actions */}
        <Panel title="Recommended actions" subtitle="prioritized response playbook">
          <ol className="space-y-2">
            {report.recommended_actions.map((a, i) => (
              <li key={i} className="flex gap-3 text-sm">
                <span className="mono flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[var(--accent)]/12 text-[10px] font-bold text-[var(--accent)]">
                  {i + 1}
                </span>
                <span className="text-[var(--fg-muted)]">{a}</span>
              </li>
            ))}
          </ol>
        </Panel>

        {/* MITRE techniques */}
        <Panel title="MITRE ATT&CK techniques" subtitle={`${report.techniques.length} mapped`}>
          <div className="flex flex-wrap gap-2">
            {report.techniques.map((t) => (
              <a
                key={t.id}
                href={t.url ?? "#"}
                target="_blank"
                rel="noreferrer"
                className="group flex items-center gap-1.5 rounded-md border border-[var(--border)] bg-[var(--panel)] px-2.5 py-1.5 text-xs transition hover:border-[var(--accent)]/40"
              >
                <span className="mono font-semibold text-[var(--accent)]">{t.id}</span>
                <span className="text-[var(--fg-muted)]">{t.name}</span>
                <ExternalLink className="h-3 w-3 text-[var(--fg-dim)] opacity-0 transition group-hover:opacity-100" />
              </a>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}

function AgentIcon({ agent }: { agent: string }) {
  const map: Record<string, React.ComponentType<{ className?: string }>> = {
    identity: Fingerprint,
    process: ScrollText,
    network: Network,
    file: ScrollText,
  };
  const Icon = map[agent] ?? Sparkles;
  return (
    <div className="flex h-7 w-7 items-center justify-center rounded-md bg-[var(--accent)]/12 text-[var(--accent)]">
      <Icon className="h-3.5 w-3.5" />
    </div>
  );
}

/* ------------------------------------------------------------------ Copilot tab */
function CopilotTab({ id }: { id: string }) {
  const [messages, setMessages] = useState<
    { q: string; res?: CopilotResponse; error?: string }[]
  >([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);

  const SUGGESTIONS = [
    "Why is this host suspicious?",
    "What external IPs did it connect to?",
    "What happened before the compromise?",
    "Which processes were executed?",
  ];

  async function ask(q: string) {
    if (!q.trim() || busy) return;
    setBusy(true);
    setInput("");
    setMessages((m) => [...m, { q }]);
    try {
      const res = await api.copilot(id, q);
      setMessages((m) => m.map((msg, i) => (i === m.length - 1 ? { ...msg, res } : msg)));
    } catch (err) {
      const message =
        err instanceof ApiError && err.status === 403
          ? "Copilot requires an analyst or admin role."
          : err instanceof Error
            ? err.message
            : "Query failed";
      setMessages((m) => m.map((msg, i) => (i === m.length - 1 ? { ...msg, error: message } : msg)));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title="Investigation Copilot" subtitle="every answer cites the evidence it used">
      <div className="space-y-4">
        {messages.length === 0 && (
          <div className="rounded-lg border border-dashed border-[var(--border)] p-6 text-center">
            <Bot className="mx-auto h-6 w-6 text-[var(--accent)]" />
            <p className="mt-2 text-sm text-[var(--fg-muted)]">
              Ask about this incident. The copilot answers strictly from incident evidence.
            </p>
            <div className="mt-3 flex flex-wrap justify-center gap-2">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => ask(s)}
                  className="cursor-pointer rounded-full border border-[var(--border)] bg-[var(--panel)] px-3 py-1.5 text-xs text-[var(--fg-muted)] transition hover:border-[var(--accent)]/40 hover:text-[var(--fg)]"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="space-y-4">
          {messages.map((m, i) => (
            <div key={i} className="space-y-2">
              <div className="flex justify-end">
                <div className="max-w-[80%] rounded-2xl rounded-br-sm bg-[var(--accent)]/12 px-3.5 py-2 text-sm text-[var(--fg)]">
                  {m.q}
                </div>
              </div>
              {m.res && (
                <div className="max-w-[85%] space-y-2">
                  <div className="rounded-2xl rounded-bl-sm border border-[var(--border)] bg-[var(--panel-2)] px-3.5 py-2.5 text-sm text-[var(--fg-muted)]">
                    {m.res.answer}
                  </div>
                  <div className="flex items-center gap-2">
                    <span
                      className="flex items-center gap-1 text-[10px]"
                      style={{ color: m.res.grounding.grounded ? "#34d399" : "#f97316" }}
                    >
                      <ShieldCheck className="h-3 w-3" />
                      {m.res.grounding.grounded ? "grounded" : "ungrounded"}
                    </span>
                    <span className="mono text-[10px] text-[var(--fg-dim)]">
                      {m.res.evidence.length} evidence · {m.res.llm_used ? "LLM" : "deterministic"}
                    </span>
                  </div>
                  {m.res.evidence.length > 0 && (
                    <div className="space-y-1">
                      {m.res.evidence.slice(0, 5).map((e) => (
                        <div
                          key={e.event_id}
                          className="rounded-md bg-[var(--panel)] px-2.5 py-1.5 text-[11px]"
                        >
                          <span className="mono text-[9px] text-[var(--accent)]">{e.event_id}</span>
                          <span className="mono ml-2 text-[var(--fg-muted)]">{e.summary}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
              {m.error && (
                <div className="text-xs text-[var(--critical)]">{m.error}</div>
              )}
            </div>
          ))}
          {busy && (
            <div className="flex items-center gap-2 text-xs text-[var(--fg-dim)]">
              <Loader className="h-3.5 w-3.5 animate-spin" /> searching evidence…
            </div>
          )}
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            ask(input);
          }}
          className="flex gap-2"
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about this incident…"
            className="flex-1 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3.5 py-2.5 text-sm text-[var(--fg)] outline-none transition focus:border-[var(--accent)]/50"
          />
          <button
            type="submit"
            disabled={busy || !input.trim()}
            className="flex cursor-pointer items-center gap-1.5 rounded-lg bg-[var(--accent)] px-4 py-2.5 text-sm font-semibold text-[#04141a] transition hover:brightness-110 disabled:opacity-50"
          >
            <Send className="h-4 w-4" />
          </button>
        </form>
      </div>
    </Panel>
  );
}

/* ------------------------------------------------------------------ helpers */
function fmtHM(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return iso;
  }
}

function summarize(e: {
  event_type: string;
  action: string;
  user?: string | null;
  host?: string | null;
  process_name?: string | null;
  command_line?: string | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  domain?: string | null;
  file_path?: string | null;
  bytes_out?: number | null;
}): string {
  const parts: string[] = [e.action];
  if (e.user) parts.push(`user=${e.user}`);
  if (e.host) parts.push(`host=${e.host}`);
  if (e.process_name) parts.push(`proc=${e.process_name}`);
  if (e.dst_ip) parts.push(`dst=${e.dst_ip}${e.dst_port ? `:${e.dst_port}` : ""}`);
  if (e.domain) parts.push(`domain=${e.domain}`);
  if (e.file_path) parts.push(`file=${e.file_path.split(/[\\/]/).pop()}`);
  if (e.bytes_out) parts.push(`out=${fmtBytes(e.bytes_out)}`);
  if (e.command_line) parts.push(`» ${e.command_line.slice(0, 80)}`);
  return parts.join("  ");
}
