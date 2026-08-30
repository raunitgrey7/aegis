"use client";

import { usePathname, useRouter } from "next/navigation";
import clsx from "clsx";
import {
  Activity,
  LayoutDashboard,
  LogOut,
  Radar,
  ScrollText,
  ShieldAlert,
  Waypoints,
} from "lucide-react";
import { NavLink } from "./ui";
import { logout, useAuth } from "@/lib/auth";

const NAV = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/incidents", label: "Incidents", icon: ShieldAlert },
  { href: "/threat-map", label: "Threat Map", icon: Radar },
  { href: "/coverage", label: "ATT&CK Coverage", icon: Waypoints },
  { href: "/rules", label: "Detections", icon: ScrollText },
];

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { session, ready } = useAuth();

  if (!ready) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="flex items-center gap-3 text-[var(--fg-dim)]">
          <Activity className="h-5 w-5 animate-pulse text-[var(--accent)]" />
          <span className="mono text-sm">initializing console…</span>
        </div>
      </div>
    );
  }

  const isActive = (href: string) =>
    href === "/" ? pathname === "/" : pathname.startsWith(href);

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="hidden w-60 shrink-0 flex-col border-r border-[var(--border)] bg-[var(--panel)]/60 backdrop-blur md:flex">
        <div className="flex h-16 items-center gap-2.5 border-b border-[var(--border)] px-5">
          <div className="relative flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--accent)]/12 glow-accent">
            <ShieldAlert className="h-4.5 w-4.5 text-[var(--accent)]" />
          </div>
          <div className="leading-tight">
            <div className="text-[15px] font-bold tracking-tight text-gradient">AEGIS</div>
            <div className="mono text-[9px] uppercase tracking-[0.2em] text-[var(--fg-dim)]">
              Threat Console
            </div>
          </div>
        </div>

        <nav className="flex-1 space-y-1 p-3">
          {NAV.map((item) => {
            const active = isActive(item.href);
            const Icon = item.icon;
            return (
              <NavLink
                key={item.href}
                href={item.href}
                className={clsx(
                  "group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-all",
                  active
                    ? "bg-[var(--accent)]/10 font-medium text-[var(--fg)]"
                    : "text-[var(--fg-muted)] hover:bg-white/[0.04] hover:text-[var(--fg)]",
                )}
              >
                <Icon
                  className={clsx(
                    "h-4.5 w-4.5 transition-colors",
                    active ? "text-[var(--accent)]" : "text-[var(--fg-dim)] group-hover:text-[var(--fg-muted)]",
                  )}
                />
                {item.label}
                {active && (
                  <span className="ml-auto h-1.5 w-1.5 rounded-full bg-[var(--accent)] pulse" />
                )}
              </NavLink>
            );
          })}
        </nav>

        <div className="border-t border-[var(--border)] p-3">
          <div className="flex items-center gap-3 rounded-lg px-3 py-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-[var(--elevated)] text-xs font-bold uppercase text-[var(--accent)]">
              {session?.username?.[0] ?? "u"}
            </div>
            <div className="min-w-0 flex-1 leading-tight">
              <div className="truncate text-sm font-medium text-[var(--fg)]">
                {session?.username}
              </div>
              <div className="mono text-[10px] uppercase tracking-wider text-[var(--fg-dim)]">
                {session?.role}
              </div>
            </div>
            <button
              onClick={() => logout(router)}
              title="Sign out"
              className="cursor-pointer rounded-md p-1.5 text-[var(--fg-dim)] transition-colors hover:bg-white/5 hover:text-[var(--critical)]"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Mobile top bar */}
        <div className="flex items-center gap-3 border-b border-[var(--border)] bg-[var(--panel)]/70 px-4 py-3 backdrop-blur md:hidden">
          <ShieldAlert className="h-5 w-5 text-[var(--accent)]" />
          <span className="text-sm font-bold tracking-tight">AEGIS</span>
          <div className="ml-auto flex gap-1">
            {NAV.map((item) => (
              <NavLink
                key={item.href}
                href={item.href}
                className={clsx(
                  "rounded-md p-2",
                  isActive(item.href) ? "text-[var(--accent)]" : "text-[var(--fg-dim)]",
                )}
                title={item.label}
              >
                <item.icon className="h-4.5 w-4.5" />
              </NavLink>
            ))}
            <button
              onClick={() => logout(router)}
              className="rounded-md p-2 text-[var(--fg-dim)]"
            >
              <LogOut className="h-4.5 w-4.5" />
            </button>
          </div>
        </div>

        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto max-w-[1600px] px-4 py-6 sm:px-6 lg:px-8">{children}</div>
        </main>
      </div>
    </div>
  );
}
