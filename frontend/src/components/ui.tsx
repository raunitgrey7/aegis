"use client";

import Link from "next/link";
import clsx from "clsx";
import { severityColor } from "@/lib/theme";

/* ---- Link that plays nicely with typed routes -------------------------- */
export function NavLink(props: {
  href: string;
  className?: string;
  children: React.ReactNode;
  title?: string;
}) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (
    <Link href={props.href as any} className={props.className} title={props.title}>
      {props.children}
    </Link>
  );
}

/* ---- Panel -------------------------------------------------------------- */
export function Panel({
  children,
  className,
  title,
  subtitle,
  right,
}: {
  children: React.ReactNode;
  className?: string;
  title?: string;
  subtitle?: string;
  right?: React.ReactNode;
}) {
  return (
    <section className={clsx("panel p-4 sm:p-5", className)}>
      {(title || right) && (
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            {title && (
              <h3 className="text-sm font-semibold tracking-wide text-[var(--fg)]">{title}</h3>
            )}
            {subtitle && <p className="mt-0.5 text-xs text-[var(--fg-dim)]">{subtitle}</p>}
          </div>
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

/* ---- Severity badge ----------------------------------------------------- */
export function SeverityBadge({ severity, small }: { severity: string; small?: boolean }) {
  const c = severityColor(severity);
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-full font-semibold uppercase tracking-wider",
        small ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-1 text-[11px]",
      )}
      style={{ color: c, background: `${c}1a`, border: `1px solid ${c}44` }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />
      {severity}
    </span>
  );
}

/* ---- Chip --------------------------------------------------------------- */
export function Chip({
  children,
  color,
  className,
  title,
}: {
  children: React.ReactNode;
  color?: string;
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={clsx(
        "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium",
        className,
      )}
      style={
        color
          ? { color, background: `${color}14`, border: `1px solid ${color}33` }
          : {
              color: "var(--fg-muted)",
              background: "rgba(148,173,204,0.06)",
              border: "1px solid var(--border)",
            }
      }
    >
      {children}
    </span>
  );
}

/* ---- Risk meter --------------------------------------------------------- */
export function RiskMeter({ value, width = 120 }: { value: number; width?: number }) {
  const color =
    value >= 85 ? "#ef4444" : value >= 65 ? "#f97316" : value >= 40 ? "#eab308" : "#3b82f6";
  return (
    <div className="flex items-center gap-2">
      <div
        className="h-1.5 overflow-hidden rounded-full bg-white/5"
        style={{ width }}
      >
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${value}%`, background: color, boxShadow: `0 0 8px ${color}66` }}
        />
      </div>
      <span className="mono w-9 text-right text-xs font-semibold" style={{ color }}>
        {Math.round(value)}
      </span>
    </div>
  );
}

/* ---- Loading / error / empty ------------------------------------------- */
export function Loading({ label = "Loading…", rows = 4 }: { label?: string; rows?: number }) {
  return (
    <div className="space-y-3">
      <p className="text-xs text-[var(--fg-dim)]">{label}</p>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="skeleton h-10 rounded-lg" />
      ))}
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  const offline = message.toLowerCase().includes("unavailable");
  return (
    <div className="panel-flat flex flex-col items-center justify-center gap-2 p-8 text-center">
      <div
        className="flex h-11 w-11 items-center justify-center rounded-full"
        style={{ background: "#ef444418", border: "1px solid #ef444444" }}
      >
        <span className="text-lg text-[var(--critical)]">!</span>
      </div>
      <p className="text-sm font-medium text-[var(--fg)]">
        {offline ? "Backend unavailable" : "Something went wrong"}
      </p>
      <p className="max-w-md text-xs text-[var(--fg-dim)]">{message}</p>
      {offline && (
        <p className="mono mt-1 text-[11px] text-[var(--fg-dim)]">
          start it with: <span className="text-[var(--accent)]">make run</span> or{" "}
          <span className="text-[var(--accent)]">docker compose up</span>
        </p>
      )}
    </div>
  );
}

export function Empty({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center rounded-lg border border-dashed border-[var(--border)] p-8 text-sm text-[var(--fg-dim)]">
      {label}
    </div>
  );
}

/* ---- Confidence pill ---------------------------------------------------- */
export function Confidence({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  return (
    <span className="mono text-xs text-[var(--fg-muted)]">
      <span className="text-[var(--fg-dim)]">conf</span> {pct}%
    </span>
  );
}
