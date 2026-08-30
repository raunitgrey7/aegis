"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, Loader, ShieldAlert } from "lucide-react";
import { api, getToken, setSession } from "@/lib/api";

const DEMO = [
  { u: "admin", p: "admin", role: "Admin", desc: "full control + simulator" },
  { u: "analyst", p: "analyst", role: "Analyst", desc: "investigate + copilot" },
  { u: "viewer", p: "viewer", role: "Viewer", desc: "read-only" },
];

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("analyst");
  const [password, setPassword] = useState("analyst");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (getToken()) router.replace("/");
  }, [router]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await api.login(username, password);
      setSession(res.access_token, res.role, username);
      router.replace("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
      setLoading(false);
    }
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      {/* Brand panel */}
      <div className="relative hidden overflow-hidden border-r border-[var(--border)] lg:block">
        <div className="grid-fade absolute inset-0 opacity-60" />
        <div
          className="absolute inset-0"
          style={{
            background:
              "radial-gradient(700px 400px at 30% 20%, rgba(34,211,238,0.12), transparent 60%)",
          }}
        />
        <div className="relative flex h-full flex-col justify-between p-12">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[var(--accent)]/12 glow-accent">
              <ShieldAlert className="h-5 w-5 text-[var(--accent)]" />
            </div>
            <div>
              <div className="text-xl font-bold tracking-tight text-gradient">AEGIS</div>
              <div className="mono text-[10px] uppercase tracking-[0.25em] text-[var(--fg-dim)]">
                Threat Intelligence Platform
              </div>
            </div>
          </div>

          <div className="max-w-md">
            <h1 className="text-3xl font-bold leading-tight text-[var(--fg)]">
              See the whole attack,
              <br />
              <span className="text-[var(--accent)]">not scattered alerts.</span>
            </h1>
            <p className="mt-4 text-sm leading-relaxed text-[var(--fg-muted)]">
              Aegis ingests security telemetry, detects malicious behavior deterministically,
              reconstructs the attack chain into a graph, and produces evidence-grounded
              investigations — no black-box detection, no API keys.
            </p>
            <div className="mt-8 grid grid-cols-3 gap-3">
              {[
                ["Detection", "rules + stats + intel"],
                ["Correlation", "attack-graph"],
                ["Investigation", "grounded AI"],
              ].map(([t, s]) => (
                <div key={t} className="panel-flat p-3">
                  <div className="text-xs font-semibold text-[var(--fg)]">{t}</div>
                  <div className="mono mt-1 text-[10px] text-[var(--fg-dim)]">{s}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="mono text-[11px] text-[var(--fg-dim)]">
            MITRE ATT&CK · kill-chain reconstruction · self-hosted
          </div>
        </div>
      </div>

      {/* Login form */}
      <div className="flex items-center justify-center p-6">
        <div className="w-full max-w-sm rise">
          <div className="mb-8 lg:hidden">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-6 w-6 text-[var(--accent)]" />
              <span className="text-lg font-bold tracking-tight text-gradient">AEGIS</span>
            </div>
          </div>

          <h2 className="text-xl font-semibold text-[var(--fg)]">Sign in to the console</h2>
          <p className="mt-1 text-sm text-[var(--fg-dim)]">
            Use a demo account below or enter credentials.
          </p>

          <form onSubmit={submit} className="mt-6 space-y-4">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-[var(--fg-muted)]">
                Username
              </label>
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3.5 py-2.5 text-sm text-[var(--fg)] outline-none transition focus:border-[var(--accent)]/50 focus:ring-2 focus:ring-[var(--accent)]/20"
                autoComplete="username"
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-[var(--fg-muted)]">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3.5 py-2.5 text-sm text-[var(--fg)] outline-none transition focus:border-[var(--accent)]/50 focus:ring-2 focus:ring-[var(--accent)]/20"
                autoComplete="current-password"
              />
            </div>

            {error && (
              <div
                className="rounded-lg px-3 py-2 text-xs"
                style={{ background: "#ef444414", border: "1px solid #ef444444", color: "#fca5a5" }}
              >
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="group flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg bg-[var(--accent)] px-4 py-2.5 text-sm font-semibold text-[#04141a] transition hover:brightness-110 disabled:opacity-60"
            >
              {loading ? (
                <Loader className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  Sign in
                  <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
                </>
              )}
            </button>
          </form>

          <div className="mt-6">
            <div className="mb-2 text-[11px] uppercase tracking-wider text-[var(--fg-dim)]">
              Demo accounts
            </div>
            <div className="space-y-2">
              {DEMO.map((d) => (
                <button
                  key={d.u}
                  onClick={() => {
                    setUsername(d.u);
                    setPassword(d.p);
                  }}
                  className="flex w-full cursor-pointer items-center justify-between rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-2 text-left transition hover:border-[var(--accent)]/40 hover:bg-[var(--elevated)]"
                >
                  <div>
                    <div className="text-sm font-medium text-[var(--fg)]">{d.role}</div>
                    <div className="mono text-[10px] text-[var(--fg-dim)]">
                      {d.u} / {d.p} — {d.desc}
                    </div>
                  </div>
                  <ArrowRight className="h-4 w-4 text-[var(--fg-dim)]" />
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
