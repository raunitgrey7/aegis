import type { NextConfig } from "next";
import path from "node:path";

// In dev, proxy /api/* to the backend so the browser can use same-origin calls.
// The API client prefers NEXT_PUBLIC_API_URL when set (used in docker/prod).
const BACKEND = process.env.AEGIS_BACKEND_URL ?? "http://localhost:8000";

const nextConfig: NextConfig = {
  // Emit a self-contained server bundle for the Docker image only (set NEXT_OUTPUT=standalone).
  // On Vercel we leave this unset — Vercel manages its own build output/tracing.
  output: process.env.NEXT_OUTPUT === "standalone" ? "standalone" : undefined,
  // Pin the workspace root so Next doesn't pick up a stray lockfile in the home directory.
  turbopack: {
    root: path.resolve(__dirname),
  },
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${BACKEND}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
