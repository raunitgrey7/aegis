"use client";

// 3D threat globe: night-lights earth with topographic relief, animated arcs from
// observed login-origin countries to the estate HQ, and attributed indicator points.
// Rendered client-side only (three.js); the page shows a skeleton until mounted.

import { useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import type { ThreatMapNode, ThreatOrigin } from "@/lib/types";
import { countryCoords, countryName } from "@/lib/countries";
import { riskColor } from "@/lib/theme";

// next/dynamic does not forward refs, so wrap the globe and pass the ref as a prop.
const Globe = dynamic(
  () =>
    import("react-globe.gl").then((m) => {
      const G = m.default;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const Wrapper = ({ globeRef, ...props }: { globeRef?: React.MutableRefObject<any> } & Record<string, unknown>) => (
        <G ref={globeRef} {...props} />
      );
      Wrapper.displayName = "GlobeWrapper";
      return Wrapper;
    }),
  { ssr: false, loading: () => <GlobeSkeleton /> },
);

function GlobeSkeleton() {
  return (
    <div className="flex h-[440px] items-center justify-center">
      <div className="flex flex-col items-center gap-3">
        <div className="skeleton h-40 w-40 rounded-full" />
        <span className="mono text-[10px] uppercase tracking-widest text-[var(--fg-dim)]">
          rendering globe…
        </span>
      </div>
    </div>
  );
}

interface ArcDatum {
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
  color: string;
  label: string;
}

interface PointDatum {
  lat: number;
  lng: number;
  color: string;
  radius: number;
  altitude: number;
  label: string;
  incident: string;
}

interface RingDatum {
  lat: number;
  lng: number;
  color: string;
  maxR: number;
}

export function ThreatGlobe({
  nodes,
  origins,
  hq,
  onSelectIncident,
}: {
  nodes: ThreatMapNode[];
  origins: ThreatOrigin[];
  hq: { country: string };
  onSelectIncident?: (incidentId: string) => void;
}) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState<{ w: number; h: number }>({ w: 0, h: 440 });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const globeRef = useRef<any>(undefined);

  // responsive width
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const measure = () => setSize({ w: el.clientWidth, h: 440 });
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const hqPos = countryCoords(hq.country) ?? { name: hq.country, lat: 20.6, lng: 79.0 };

  const { arcs, points, rings, unplaced } = useMemo(() => {
    const arcs: ArcDatum[] = [];
    const points: PointDatum[] = [];
    const rings: RingDatum[] = [];
    let unplaced = 0;

    // HQ marker
    points.push({
      lat: hqPos.lat,
      lng: hqPos.lng,
      color: "#22d3ee",
      radius: 0.55,
      altitude: 0.012,
      label: `HQ — monitored estate (${countryName(hq.country)})`,
      incident: "",
    });
    rings.push({ lat: hqPos.lat, lng: hqPos.lng, color: "#22d3ee", maxR: 4.5 });

    // Login origins observed in incident evidence → arcs into HQ
    for (const o of origins) {
      const c = countryCoords(o.country);
      if (!c) {
        unplaced++;
        continue;
      }
      const color = riskColor(o.max_risk);
      arcs.push({
        startLat: c.lat,
        startLng: c.lng,
        endLat: hqPos.lat,
        endLng: hqPos.lng,
        color,
        label: `${countryName(o.country)} → HQ · ${o.incidents} incident${o.incidents === 1 ? "" : "s"}${o.users.length ? ` · ${o.users.slice(0, 3).join(", ")}` : ""}`,
      });
      rings.push({ lat: c.lat, lng: c.lng, color, maxR: 3 });
    }

    // Feed-attributed external infrastructure → points (deduped per country+value)
    for (const n of nodes) {
      const c = countryCoords(n.country);
      if (!c) {
        if (n.known_malicious) unplaced++;
        continue;
      }
      // jitter within ~1.5° so multiple indicators in one country stay distinguishable;
      // deterministic per value so the layout is stable across refreshes
      let hsh = 0;
      for (let i = 0; i < n.value.length; i++) hsh = (hsh * 31 + n.value.charCodeAt(i)) | 0;
      const jLat = ((hsh % 100) / 100 - 0.5) * 3;
      const jLng = (((hsh >> 7) % 100) / 100 - 0.5) * 3;
      points.push({
        lat: c.lat + jLat,
        lng: c.lng + jLng,
        color: n.known_malicious ? "#ef4444" : "#f97316",
        radius: n.known_malicious ? 0.45 : 0.3,
        altitude: 0.01,
        label: `${n.value}${n.threat ? ` · ${n.threat}` : ""} · ${countryName(n.country)} · risk ${Math.round(n.risk)}`,
        incident: n.incident,
      });
      if (n.known_malicious) rings.push({ lat: c.lat + jLat, lng: c.lng + jLng, color: "#ef4444", maxR: 2.2 });
    }
    return { arcs, points, rings, unplaced };
  }, [nodes, origins, hqPos.lat, hqPos.lng, hq.country]);

  // aim the camera between HQ and the hottest origin once the globe mounts
  useEffect(() => {
    const g = globeRef.current;
    if (!g || !size.w) return;
    const t = setTimeout(() => {
      try {
        g.pointOfView({ lat: hqPos.lat + 8, lng: hqPos.lng + 12, altitude: 2.1 }, 900);
        const controls = g.controls?.();
        if (controls) {
          controls.autoRotate = true;
          controls.autoRotateSpeed = 0.55;
          controls.enableZoom = true;
          controls.minDistance = 140;
        }
      } catch {
        /* controls not ready — cosmetic only */
      }
    }, 300);
    return () => clearTimeout(t);
  }, [size.w, hqPos.lat, hqPos.lng]);

  return (
    <div ref={wrapRef} className="relative overflow-hidden rounded-xl" style={{ minHeight: 440 }}>
      {size.w > 0 && (
        <Globe
          globeRef={globeRef}
          width={size.w}
          height={size.h}
          backgroundColor="rgba(0,0,0,0)"
          globeImageUrl="/globe/earth-night.jpg"
          bumpImageUrl="/globe/earth-topology.png"
          atmosphereColor="#22d3ee"
          atmosphereAltitude={0.18}
          arcsData={arcs}
          arcColor={(d: object) => (d as ArcDatum).color}
          arcLabel={(d: object) => (d as ArcDatum).label}
          arcAltitudeAutoScale={0.4}
          arcStroke={0.55}
          arcDashLength={0.45}
          arcDashGap={0.25}
          arcDashAnimateTime={2200}
          pointsData={points}
          pointLat={(d: object) => (d as PointDatum).lat}
          pointLng={(d: object) => (d as PointDatum).lng}
          pointColor={(d: object) => (d as PointDatum).color}
          pointRadius={(d: object) => (d as PointDatum).radius}
          pointAltitude={(d: object) => (d as PointDatum).altitude}
          pointLabel={(d: object) => (d as PointDatum).label}
          onPointClick={(d: object) => {
            const p = d as PointDatum;
            if (p.incident && onSelectIncident) onSelectIncident(p.incident);
          }}
          ringsData={rings}
          ringLat={(d: object) => (d as RingDatum).lat}
          ringLng={(d: object) => (d as RingDatum).lng}
          ringColor={(d: object) => (d as RingDatum).color}
          ringMaxRadius={(d: object) => (d as RingDatum).maxR}
          ringPropagationSpeed={1.2}
          ringRepeatPeriod={1600}
        />
      )}

      {/* legend */}
      <div className="pointer-events-none absolute bottom-3 left-3 space-y-1 rounded-lg border border-[var(--border)] bg-[var(--panel)]/80 px-3 py-2 backdrop-blur">
        <LegendRow color="#22d3ee" label={`HQ · ${countryName(hq.country)}`} />
        <LegendRow color="#ef4444" label="known-malicious infrastructure" />
        <LegendRow color="#f97316" label="external destination (attributed)" />
        <LegendRow color="#eab308" label="arc = login origin seen in incidents" arc />
        {unplaced > 0 && (
          <div className="mono pt-0.5 text-[9px] text-[var(--fg-dim)]">
            +{unplaced} unattributed (no country data) — listed below
          </div>
        )}
      </div>
    </div>
  );
}

function LegendRow({ color, label, arc }: { color: string; label: string; arc?: boolean }) {
  return (
    <div className="flex items-center gap-2 text-[10px] text-[var(--fg-muted)]">
      {arc ? (
        <span className="h-0.5 w-3 rounded-full" style={{ background: color }} />
      ) : (
        <span className="h-2 w-2 rounded-full" style={{ background: color }} />
      )}
      {label}
    </div>
  );
}
