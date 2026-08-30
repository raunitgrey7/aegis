"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { clearSession, getRole, getToken, getUsername } from "./api";

export interface Session {
  token: string;
  role: string;
  username: string;
}

// Guard hook: returns the session, or redirects to /login if absent.
export function useAuth(): { session: Session | null; ready: boolean } {
  const router = useRouter();
  const [session, setSession] = useState<Session | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const token = getToken();
    const role = getRole();
    const username = getUsername();
    if (!token) {
      router.replace("/login");
      return;
    }
    setSession({ token, role: role ?? "viewer", username: username ?? "user" });
    setReady(true);
  }, [router]);

  return { session, ready };
}

export function logout(router: ReturnType<typeof useRouter>) {
  clearSession();
  router.replace("/login");
}

export function roleAtLeast(role: string | undefined, min: "viewer" | "analyst" | "admin"): boolean {
  const rank: Record<string, number> = { viewer: 10, analyst: 20, admin: 30, ingestor: 5 };
  return (rank[role ?? "viewer"] ?? 0) >= rank[min];
}
