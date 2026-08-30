"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Bug, Globe, Radar, Waypoints } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import type { ThreatMapNode } from "@/lib/types";
import { riskColor } from "@/lib/theme";
import { Chip, ErrorState, Loading, Panel } from "@/components/ui";

export default function ThreatMapPage() {
  const router = useRouter();
  const [nodes, setNodes] = useState<ThreatMapNode[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const res = await api.threatMap();
        setNodes(res.nodes.sort((a, b) => b.risk - a.risk));
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) return;
        setError(err instanceof Error ? err.message : "Failed to load threat map");
      }
    })();
  }, []);

  if (error) return <ErrorState message={error} />;
  if (!nodes) return <Loading label="Loading external threat map…" rows={6} />;

  const malicious = nodes.filter((n) => n.known_malicious);
  const ips = nodes.filter((n) => n.type === "ip");
  const domains = nodes.filter((n) => n.type === "domain");

  return (
    <div className="space-y-5 rise">
      <div>
        <h1 className="text-xl font-bold tracking-tight text-[var(--fg)]">Threat Map</h1>
        <p className="mt-1 text-sm text-[var(--fg-dim)]">
          External destinations touched by incident activity, enriched with threat intelligence.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="External nodes" value={nodes.length} icon={Radar} color="#22d3ee" />
        <Stat label="Known malicious" value={malicious.length} icon={Bug} color="#ef4444" />
        <Stat label="IP addresses" value={ips.length} icon={Globe} color="#f97316" />
        <Stat label="Domains" value={domains.length} icon={Waypoints} color="#fb923c" />
      </div>

      <Panel title="External destinations" subtitle="red = matched threat intelligence · sorted by risk">
        {nodes.length === 0 ? (
          <div className="p-8 text-center text-sm text-[var(--fg-dim)]">
            No external destinations in current incidents.
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {nodes.map((n) => (
              <button
                key={`${n.type}:${n.value}`}
                onClick={() => router.push(`/incidents/${n.incident}`)}
                className="group cursor-pointer rounded-xl border bg-[var(--panel)] p-3.5 text-left transition hover:bg-[var(--panel-2)]"
                style={{
                  borderColor: n.known_malicious ? "#ef444455" : "var(--border)",
                  boxShadow: n.known_malicious ? "0 0 18px -8px #ef4444" : "none",
                }}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <div
                      className="flex h-8 w-8 items-center justify-center rounded-lg"
                      style={{
                        background: n.known_malicious ? "#ef444418" : "#f9731618",
                        color: n.known_malicious ? "#ef4444" : "#f97316",
                      }}
                    >
                      {n.type === "domain" ? (
                        <Waypoints className="h-4 w-4" />
                      ) : (
                        <Globe className="h-4 w-4" />
                      )}
                    </div>
                    <div>
                      <div className="mono text-xs font-medium text-[var(--fg)]">{n.value}</div>
                      <div className="mono text-[9px] uppercase tracking-wide text-[var(--fg-dim)]">
                        {n.type}
                      </div>
                    </div>
                  </div>
                  <span
                    className="mono rounded px-1.5 py-0.5 text-[10px] font-bold"
                    style={{ color: riskColor(n.risk), background: `${riskColor(n.risk)}18` }}
                  >
                    {Math.round(n.risk)}
                  </span>
                </div>
                {n.known_malicious && n.threat && (
                  <div className="mt-2">
                    <Chip color="#ef4444">
                      <Bug className="h-3 w-3" /> {n.threat}
                    </Chip>
                  </div>
                )}
                <div className="mono mt-2 flex items-center justify-between text-[10px] text-[var(--fg-dim)]">
                  <span>{n.hosts.slice(0, 2).join(", ")}</span>
                  <span className="text-[var(--accent)]">{n.incident} →</span>
                </div>
              </button>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}

function Stat({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: number;
  icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }>;
  color: string;
}) {
  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-[var(--fg-dim)]">{label}</span>
        <Icon className="h-4 w-4" style={{ color }} />
      </div>
      <div className="mt-2 text-2xl font-bold" style={{ color }}>
        {value}
      </div>
    </div>
  );
}
