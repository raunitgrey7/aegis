"use client";

import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { MitreCoverage } from "@/lib/types";
import { ErrorState, Loading, Panel } from "@/components/ui";

export default function CoveragePage() {
  const [cov, setCov] = useState<MitreCoverage | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      try {
        setCov(await api.mitreCoverage());
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) return;
        setError(err instanceof Error ? err.message : "Failed to load coverage");
      }
    })();
  }, []);

  if (error) return <ErrorState message={error} />;
  if (!cov) return <Loading label="Loading ATT&CK coverage…" rows={6} />;

  const pct = Math.round((cov.techniques_covered / cov.techniques_total) * 100);
  const tactics = Object.entries(cov.tactics).filter(([, t]) => t.total > 0);

  return (
    <div className="space-y-5 rise">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--fg)]">
            MITRE ATT&CK Coverage
          </h1>
          <p className="mt-1 text-sm text-[var(--fg-dim)]">
            Techniques the Aegis detection rules cover, per tactic.
          </p>
        </div>
        <div className="panel flex items-center gap-4 px-5 py-3">
          <div>
            <div className="text-2xl font-bold text-[var(--accent)]">
              {cov.techniques_covered}
              <span className="text-base text-[var(--fg-dim)]">/{cov.techniques_total}</span>
            </div>
            <div className="mono text-[10px] uppercase tracking-wider text-[var(--fg-dim)]">
              techniques covered
            </div>
          </div>
          <div className="h-10 w-px bg-[var(--border)]" />
          <div className="text-2xl font-bold text-[var(--ok)]">{pct}%</div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {tactics.map(([id, t]) => {
          const tpct = Math.round((t.covered / t.total) * 100);
          return (
            <Panel key={id} className="!p-4">
              <div className="mb-3 flex items-center justify-between">
                <span className="text-sm font-semibold text-[var(--fg)]">{t.label}</span>
                <span className="mono text-[11px] text-[var(--fg-dim)]">
                  {t.covered}/{t.total}
                </span>
              </div>
              <div className="mb-3 h-1.5 overflow-hidden rounded-full bg-white/5">
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${tpct}%`,
                    background: tpct > 66 ? "#34d399" : tpct > 33 ? "#eab308" : "#f97316",
                  }}
                />
              </div>
              <div className="flex flex-wrap gap-1.5">
                {t.techniques.map((tech) => (
                  <span
                    key={tech.id}
                    title={`${tech.id} ${tech.name}${tech.covered ? " — covered" : ""}`}
                    className="mono rounded px-1.5 py-0.5 text-[10px] transition"
                    style={{
                      color: tech.covered ? "#22d3ee" : "var(--fg-dim)",
                      background: tech.covered ? "#22d3ee14" : "transparent",
                      border: `1px solid ${tech.covered ? "#22d3ee44" : "var(--border)"}`,
                    }}
                  >
                    {tech.id}
                  </span>
                ))}
              </div>
            </Panel>
          );
        })}
      </div>
    </div>
  );
}
