"use client";

import { useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import type { RuleInfo } from "@/lib/types";
import { PHASE_COLOR, PHASE_LABEL } from "@/lib/theme";
import { Chip, ErrorState, Loading, Panel, SeverityBadge } from "@/components/ui";

const KIND_COLOR: Record<string, string> = {
  match: "#22d3ee",
  threshold: "#a3e635",
  sequence: "#c084fc",
  anomaly: "#fb923c",
  threat_intel: "#ef4444",
};

export default function RulesPage() {
  const [rules, setRules] = useState<RuleInfo[] | null>(null);
  const [error, setError] = useState("");
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const res = await api.rules();
        setRules(res.rules);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) return;
        setError(err instanceof Error ? err.message : "Failed to load rules");
      }
    })();
  }, []);

  const filtered = useMemo(() => {
    if (!rules) return [];
    return rules.filter((r) => {
      if (kind && r.kind !== kind) return false;
      if (!q) return true;
      const hay = `${r.id} ${r.title} ${r.techniques.join(" ")} ${r.phase ?? ""}`.toLowerCase();
      return hay.includes(q.toLowerCase());
    });
  }, [rules, q, kind]);

  if (error) return <ErrorState message={error} />;
  if (!rules) return <Loading label="Loading detection rules…" rows={8} />;

  const kinds = [...new Set(rules.map((r) => r.kind))];

  return (
    <div className="space-y-5 rise">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--fg)]">Detection Rules</h1>
          <p className="mt-1 text-sm text-[var(--fg-dim)]">
            {rules.length} deterministic rules — match, threshold, sequence & behavioral chains.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--fg-dim)]" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search rules…"
              className="w-56 rounded-lg border border-[var(--border)] bg-[var(--panel)] py-2 pl-8 pr-3 text-sm text-[var(--fg)] outline-none focus:border-[var(--accent)]/50"
            />
          </div>
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value)}
            className="cursor-pointer rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-2 text-sm capitalize text-[var(--fg-muted)] outline-none hover:border-[var(--accent)]/40"
          >
            <option value="">All kinds</option>
            {kinds.map((k) => (
              <option key={k} value={k} className="capitalize">
                {k}
              </option>
            ))}
          </select>
        </div>
      </div>

      <Panel className="!p-0">
        <div className="divide-y divide-[var(--border)]">
          {filtered.map((r) => (
            <div key={r.id} className="flex items-start gap-4 p-4 transition hover:bg-white/[0.02]">
              <div className="w-28 shrink-0">
                <div className="mono text-xs font-semibold text-[var(--accent)]">{r.id}</div>
                <div className="mt-1">
                  <SeverityBadge severity={r.severity} small />
                </div>
              </div>
              <div className="min-w-0 flex-1">
                <div className="font-medium text-[var(--fg)]">{r.title}</div>
                {r.description && (
                  <p className="mt-0.5 line-clamp-2 text-xs text-[var(--fg-dim)]">{r.description}</p>
                )}
                <div className="mt-2 flex flex-wrap items-center gap-1.5">
                  <Chip color={KIND_COLOR[r.kind]}>{r.kind}</Chip>
                  {r.phase && <Chip color={PHASE_COLOR[r.phase]}>{PHASE_LABEL[r.phase] ?? r.phase}</Chip>}
                  {r.techniques.slice(0, 4).map((t) => (
                    <Chip key={t}>{t}</Chip>
                  ))}
                </div>
              </div>
              <div className="shrink-0 text-right">
                <div className="mono text-sm font-semibold text-[var(--fg)]">score {r.score}</div>
                {r.fired > 0 && (
                  <div className="mono mt-1 text-[10px] text-[var(--ok)]">fired {r.fired}×</div>
                )}
              </div>
            </div>
          ))}
          {filtered.length === 0 && (
            <div className="p-8 text-center text-sm text-[var(--fg-dim)]">No rules match.</div>
          )}
        </div>
      </Panel>
    </div>
  );
}
