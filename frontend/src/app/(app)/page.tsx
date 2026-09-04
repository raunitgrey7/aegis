"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Activity,
  Cpu,
  Database,
  Globe,
  Play,
  RefreshCw,
  ShieldAlert,
  Users,
  Zap,
} from "lucide-react";
import { api, ApiError, getRole } from "@/lib/api";
import type { Overview } from "@/lib/types";
import { fmtNum, riskColor, severityColor, threatLevelColor } from "@/lib/theme";
import { Chip, ErrorState, LiveBadge, Loading, Panel, RiskMeter, SeverityBadge } from "@/components/ui";
import { PhaseBar, SeverityDonut, TacticCoverage } from "@/components/charts/Charts";

const SCENARIOS = [
  ["A", "Brute force"],
  ["B", "Suspicious login"],
  ["C", "Malicious execution"],
  ["D", "Privilege escalation"],
  ["E", "Lateral movement"],
  ["F", "Ransomware"],
  ["G", "DNS tunneling"],
  ["H", "Data exfiltration"],
];

export default function OverviewPage() {
  const router = useRouter();
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState("");
  const [simulating, setSimulating] = useState(false);
  const [role, setRole] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);

  const load = useCallback(async () => {
    try {
      const ov = await api.overview();
      setData(ov);
      setUpdatedAt(new Date());
      setError("");
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : "Failed to load");
    }
  }, []);

  useEffect(() => {
    setRole(getRole());
    load();
    const t = setInterval(() => {
      if (document.visibilityState === "visible") load();
    }, 30_000);
    return () => clearInterval(t);
  }, [load]);

  async function simulate(sid: string) {
    setSimulating(true);
    try {
      await api.simulate(sid);
      await load();
    } catch {
      /* ignore, likely role */
    } finally {
      setSimulating(false);
    }
  }

  if (error) return <ErrorState message={error} />;
  if (!data) return <Loading label="Loading threat overview…" rows={6} />;

  const tlColor = threatLevelColor(data.threat_level);
  const ti = data.threat_intel;
  const iocTotal = ti.ips + ti.domains + ti.hashes + ti.urls;

  return (
    <div className="space-y-6 rise">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--fg)]">
            Security Overview
          </h1>
          <p className="mt-1 text-sm text-[var(--fg-dim)]">
            Live posture across the monitored estate ·{" "}
            <span className="mono">{fmtNum(data.events_ingested)}</span> events ingested
          </p>
        </div>
        <div className="flex items-center gap-2">
          <LiveBadge updatedAt={updatedAt} intervalLabel="30s" />
          {role === "admin" && (
            <div className="relative">
              <select
                onChange={(e) => e.target.value && simulate(e.target.value)}
                disabled={simulating}
                defaultValue=""
                className="cursor-pointer appearance-none rounded-lg border border-[var(--border)] bg-[var(--panel)] py-2 pl-8 pr-8 text-sm text-[var(--fg)] outline-none transition hover:border-[var(--accent)]/40 focus:border-[var(--accent)]/50"
              >
                <option value="" disabled>
                  {simulating ? "Simulating…" : "Simulate attack"}
                </option>
                {SCENARIOS.map(([id, name]) => (
                  <option key={id} value={id}>
                    {id} — {name}
                  </option>
                ))}
              </select>
              <Play className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--accent)]" />
            </div>
          )}
          <button
            onClick={load}
            className="flex cursor-pointer items-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-2 text-sm text-[var(--fg-muted)] transition hover:border-[var(--accent)]/40 hover:text-[var(--fg)]"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <div className="panel relative overflow-hidden p-4">
          <div
            className="absolute inset-x-0 top-0 h-1"
            style={{ background: tlColor, boxShadow: `0 0 16px ${tlColor}` }}
          />
          <div className="text-xs uppercase tracking-wider text-[var(--fg-dim)]">Threat Level</div>
          <div className="mt-2 flex items-center gap-2">
            <ShieldAlert className="h-6 w-6" style={{ color: tlColor }} />
            <span className="text-2xl font-bold" style={{ color: tlColor }}>
              {data.threat_level}
            </span>
          </div>
        </div>
        <Kpi label="Active Incidents" value={data.active_incidents} icon={Activity} accent="#22d3ee" />
        <Kpi label="Critical" value={data.critical} icon={ShieldAlert} accent="#ef4444" />
        <Kpi label="Suspicious Users" value={data.suspicious_users} icon={Users} accent="#f97316" />
        <Kpi label="Affected Hosts" value={data.affected_hosts} icon={Globe} accent="#3b82f6" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel title="Incidents by Severity">
          <SeverityDonut data={data.severity_distribution} />
        </Panel>
        <Panel title="Kill-Chain Phase Activity" subtitle="incidents touching each phase">
          <PhaseBar data={data.phase_distribution} />
        </Panel>
        <Panel title="MITRE ATT&CK Tactic Coverage" subtitle="observed techniques by tactic">
          {data.tactic_coverage.some((t) => t.count > 0) ? (
            <TacticCoverage data={data.tactic_coverage} />
          ) : (
            <div className="flex h-[200px] items-center justify-center text-xs text-[var(--fg-dim)]">
              No techniques observed yet
            </div>
          )}
        </Panel>
      </div>

      {/* Top incidents + stat rail */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel
          title="Priority Incidents"
          subtitle="ranked by risk score"
          className="lg:col-span-2"
        >
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-[11px] uppercase tracking-wider text-[var(--fg-dim)]">
                  <th className="pb-2 pr-3 font-medium">ID</th>
                  <th className="pb-2 pr-3 font-medium">Incident</th>
                  <th className="pb-2 pr-3 font-medium">Severity</th>
                  <th className="pb-2 pr-3 font-medium">Risk</th>
                  <th className="pb-2 font-medium">Phases</th>
                </tr>
              </thead>
              <tbody>
                {data.top_incidents.map((inc) => (
                  <tr
                    key={inc.incident_id}
                    onClick={() => router.push(`/incidents/${inc.incident_id}`)}
                    className="cursor-pointer border-b border-[var(--border)]/50 transition hover:bg-white/[0.03]"
                  >
                    <td className="py-2.5 pr-3">
                      <span className="mono text-xs text-[var(--accent)]">{inc.incident_id}</span>
                    </td>
                    <td className="max-w-[280px] py-2.5 pr-3">
                      <div className="truncate text-[var(--fg)]">{inc.title}</div>
                      <div className="mono mt-0.5 text-[10px] text-[var(--fg-dim)]">
                        {inc.hosts.slice(0, 2).join(", ")}
                        {inc.users.length ? ` · ${inc.users.slice(0, 2).join(", ")}` : ""}
                      </div>
                    </td>
                    <td className="py-2.5 pr-3">
                      <SeverityBadge severity={inc.severity} small />
                    </td>
                    <td className="py-2.5 pr-3">
                      <RiskMeter value={inc.risk} width={80} />
                    </td>
                    <td className="py-2.5">
                      <span className="mono text-xs" style={{ color: riskColor(inc.risk) }}>
                        {inc.phases.length}
                      </span>
                      <span className="text-[10px] text-[var(--fg-dim)]"> / 13</span>
                    </td>
                  </tr>
                ))}
                {!data.top_incidents.length && (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-sm text-[var(--fg-dim)]">
                      No incidents — the estate is quiet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>

        <div className="space-y-4">
          <Panel title="Pipeline">
            <div className="space-y-3">
              <StatRow icon={Zap} label="Events ingested" value={fmtNum(data.events_ingested)} />
              <StatRow icon={Activity} label="Detections raised" value={fmtNum(data.detections)} />
              <StatRow
                icon={Cpu}
                label="Detector latency"
                value={`${data.detector.avg_latency_us?.toFixed(0) ?? "—"} µs/ev`}
              />
              <StatRow icon={Cpu} label="Rules loaded" value={fmtNum(data.detector.rules_loaded)} />
            </div>
          </Panel>
          <Panel title="Knowledge Graph & Intel">
            <div className="space-y-3">
              <StatRow
                icon={Database}
                label="Graph nodes"
                value={fmtNum(data.graph.nodes)}
                sub={`${fmtNum(data.graph.edges)} edges`}
              />
              <StatRow
                icon={ShieldAlert}
                label="Threat indicators"
                value={fmtNum(iocTotal)}
                sub={`${fmtNum(ti.ips)} IP · ${fmtNum(ti.domains)} dom · ${fmtNum(ti.cidrs)} CIDR`}
              />
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}

function Kpi({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: number;
  icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }>;
  accent: string;
}) {
  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between">
        <div className="text-xs uppercase tracking-wider text-[var(--fg-dim)]">{label}</div>
        <Icon className="h-4 w-4" style={{ color: accent }} />
      </div>
      <div className="mt-2 text-3xl font-bold tabular-nums" style={{ color: accent }}>
        {value}
      </div>
    </div>
  );
}

function StatRow({
  icon: Icon,
  label,
  value,
  sub,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  sub?: string;
}) {
  return (
    <div className="flex items-center gap-3">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--elevated)] text-[var(--fg-muted)]">
        <Icon className="h-4 w-4" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-xs text-[var(--fg-muted)]">{label}</div>
        {sub && <div className="mono text-[10px] text-[var(--fg-dim)]">{sub}</div>}
      </div>
      <div className="mono text-sm font-semibold text-[var(--fg)]">{value}</div>
    </div>
  );
}
