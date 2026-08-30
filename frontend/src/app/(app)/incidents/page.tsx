"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ChevronRight, Filter } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import type { IncidentSummary } from "@/lib/types";
import { PHASE_LABEL } from "@/lib/theme";
import { Chip, Confidence, ErrorState, Loading, RiskMeter, SeverityBadge } from "@/components/ui";

const SEVERITIES = ["critical", "high", "medium", "low"];
const STATUSES = ["open", "investigating", "contained", "resolved"];

export default function IncidentsPage() {
  const router = useRouter();
  const [incidents, setIncidents] = useState<IncidentSummary[] | null>(null);
  const [error, setError] = useState("");
  const [severity, setSeverity] = useState<string>("");
  const [status, setStatus] = useState<string>("");

  const load = useCallback(async () => {
    try {
      const res = await api.incidents({
        severity: severity || undefined,
        status: status || undefined,
        limit: 200,
      });
      setIncidents(res.incidents);
      setError("");
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : "Failed to load incidents");
    }
  }, [severity, status]);

  useEffect(() => {
    load();
  }, [load]);

  if (error) return <ErrorState message={error} />;

  return (
    <div className="space-y-5 rise">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--fg)]">Incidents</h1>
          <p className="mt-1 text-sm text-[var(--fg-dim)]">
            Correlated attack stories, ranked by risk.{" "}
            {incidents && <span className="mono">{incidents.length} shown</span>}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-[var(--fg-dim)]" />
          <FilterSelect value={severity} onChange={setSeverity} placeholder="All severities" options={SEVERITIES} />
          <FilterSelect value={status} onChange={setStatus} placeholder="All statuses" options={STATUSES} />
        </div>
      </div>

      {!incidents ? (
        <Loading label="Loading incidents…" rows={8} />
      ) : incidents.length === 0 ? (
        <div className="panel-flat p-12 text-center text-sm text-[var(--fg-dim)]">
          No incidents match these filters.
        </div>
      ) : (
        <div className="space-y-2.5">
          {incidents.map((inc) => (
            <button
              key={inc.incident_id}
              onClick={() => router.push(`/incidents/${inc.incident_id}`)}
              className="group flex w-full cursor-pointer items-center gap-4 rounded-xl border border-[var(--border)] bg-[var(--panel)] p-4 text-left transition hover:border-[var(--accent)]/30 hover:bg-[var(--panel-2)]"
            >
              <div className="flex w-24 shrink-0 flex-col gap-1">
                <span className="mono text-xs font-semibold text-[var(--accent)]">
                  {inc.incident_id}
                </span>
                <SeverityBadge severity={inc.severity} small />
              </div>

              <div className="min-w-0 flex-1">
                <div className="truncate font-medium text-[var(--fg)]">{inc.title}</div>
                <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                  {inc.phases.slice(0, 6).map((p) => (
                    <Chip key={p}>{PHASE_LABEL[p] ?? p}</Chip>
                  ))}
                  {inc.phases.length > 6 && (
                    <span className="text-[10px] text-[var(--fg-dim)]">+{inc.phases.length - 6}</span>
                  )}
                </div>
                <div className="mono mt-1.5 text-[10px] text-[var(--fg-dim)]">
                  {inc.affected_hosts.slice(0, 3).join(", ")}
                  {inc.affected_users.length > 0 && ` · ${inc.affected_users.slice(0, 2).join(", ")}`}
                  {inc.external_ips.length > 0 && ` · ${inc.external_ips.length} ext IP`}
                </div>
              </div>

              <div className="hidden w-40 shrink-0 flex-col items-end gap-1.5 sm:flex">
                <RiskMeter value={inc.risk_score} width={110} />
                <div className="flex items-center gap-2">
                  <Confidence value={inc.confidence} />
                  <span className="mono text-[10px] text-[var(--fg-dim)]">
                    {inc.detection_count} det · {inc.techniques.length} tech
                  </span>
                </div>
              </div>

              <ChevronRight className="h-5 w-5 shrink-0 text-[var(--fg-dim)] transition group-hover:translate-x-0.5 group-hover:text-[var(--accent)]" />
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function FilterSelect({
  value,
  onChange,
  placeholder,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  options: string[];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="cursor-pointer rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-2 text-sm capitalize text-[var(--fg-muted)] outline-none transition hover:border-[var(--accent)]/40 focus:border-[var(--accent)]/50"
    >
      <option value="">{placeholder}</option>
      {options.map((o) => (
        <option key={o} value={o} className="capitalize">
          {o}
        </option>
      ))}
    </select>
  );
}
