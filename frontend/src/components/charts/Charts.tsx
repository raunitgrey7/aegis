"use client";

import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { PHASE_COLOR, SEVERITY_COLOR } from "@/lib/theme";

const AXIS = { stroke: "#5c6b80", fontSize: 11, fontFamily: "var(--font-mono)" };

function TipBox({
  active,
  payload,
  label,
  unit,
}: {
  active?: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  payload?: any[];
  label?: string;
  unit?: string;
}) {
  if (!active || !payload?.length) return null;
  const p = payload[0];
  return (
    <div className="panel-flat px-2.5 py-1.5 text-xs shadow-xl">
      <div className="font-medium text-[var(--fg)]">{p.payload.label ?? label}</div>
      <div className="mono text-[var(--accent)]">
        {p.value}
        {unit ? ` ${unit}` : ""}
      </div>
    </div>
  );
}

export function SeverityDonut({ data }: { data: Record<string, number> }) {
  const rows = Object.entries(data ?? {})
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: k, label: k, value: v, color: SEVERITY_COLOR[k] ?? "#64748b" }));
  const total = rows.reduce((a, r) => a + r.value, 0);
  if (!total) return <EmptyChart />;
  return (
    <div className="relative h-[220px]">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={rows}
            dataKey="value"
            nameKey="label"
            innerRadius={62}
            outerRadius={92}
            paddingAngle={2}
            stroke="none"
          >
            {rows.map((r) => (
              <Cell key={r.name} fill={r.color} />
            ))}
          </Pie>
          <Tooltip content={<TipBox unit="incidents" />} />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <div className="text-2xl font-bold text-[var(--fg)]">{total}</div>
        <div className="mono text-[10px] uppercase tracking-wider text-[var(--fg-dim)]">
          incidents
        </div>
      </div>
      <div className="mt-2 flex flex-wrap justify-center gap-x-4 gap-y-1">
        {rows.map((r) => (
          <div key={r.name} className="flex items-center gap-1.5 text-[11px]">
            <span className="h-2 w-2 rounded-full" style={{ background: r.color }} />
            <span className="capitalize text-[var(--fg-muted)]">{r.name}</span>
            <span className="mono text-[var(--fg-dim)]">{r.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function PhaseBar({ data }: { data: { phase: string; label: string; count: number }[] }) {
  if (!data?.length) return <EmptyChart />;
  return (
    <div className="h-[240px]">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
          <XAxis type="number" {...AXIS} allowDecimals={false} axisLine={false} tickLine={false} />
          <YAxis
            type="category"
            dataKey="label"
            {...AXIS}
            width={110}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip content={<TipBox unit="incidents" />} cursor={{ fill: "rgba(148,173,204,0.05)" }} />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={14}>
            {data.map((d) => (
              <Cell key={d.phase} fill={PHASE_COLOR[d.phase] ?? "#22d3ee"} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function TacticCoverage({
  data,
}: {
  data: { tactic: string; label: string; count: number }[];
}) {
  const rows = (data ?? []).filter((d) => d.count > 0);
  if (!rows.length) return <EmptyChart />;
  const max = Math.max(...rows.map((d) => d.count));
  return (
    <div className="space-y-2">
      {rows.map((d) => (
        <div key={d.tactic} className="flex items-center gap-3">
          <div className="w-28 shrink-0 truncate text-right text-[11px] text-[var(--fg-muted)]">
            {d.label}
          </div>
          <div className="h-3 flex-1 overflow-hidden rounded-sm bg-white/5">
            <div
              className="h-full rounded-sm"
              style={{
                width: `${(d.count / max) * 100}%`,
                background: `linear-gradient(90deg, ${PHASE_COLOR[d.tactic] ?? "#22d3ee"}, ${
                  PHASE_COLOR[d.tactic] ?? "#22d3ee"
                }bb)`,
              }}
            />
          </div>
          <div className="mono w-6 text-right text-[11px] text-[var(--fg-dim)]">{d.count}</div>
        </div>
      ))}
    </div>
  );
}

function EmptyChart() {
  return (
    <div className="flex h-[200px] items-center justify-center text-xs text-[var(--fg-dim)]">
      No data yet
    </div>
  );
}
