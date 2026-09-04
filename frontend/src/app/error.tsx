"use client"; // Error boundaries must be Client Components

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { RefreshCw, ShieldAlert } from "lucide-react";

export default function ErrorPage({
  error,
  retry,
}: {
  error: Error & { digest?: string };
  retry: () => void;
}) {
  const router = useRouter();
  useEffect(() => {
    console.error("[aegis-ui] uncaught render error:", error);
  }, [error]);

  return (
    <div className="flex min-h-[60vh] items-center justify-center p-6">
      <div className="panel-flat max-w-md p-8 text-center">
        <div
          className="mx-auto flex h-12 w-12 items-center justify-center rounded-full"
          style={{ background: "#ef444418", border: "1px solid #ef444444" }}
        >
          <ShieldAlert className="h-5 w-5 text-[var(--critical)]" />
        </div>
        <h2 className="mt-3 text-sm font-semibold text-[var(--fg)]">
          This view hit an unexpected error
        </h2>
        <p className="mt-1.5 text-xs leading-relaxed text-[var(--fg-dim)]">
          The rest of the console is unaffected. The error has been logged to the browser console;
          retrying re-fetches this view from the API.
        </p>
        {error?.digest && (
          <p className="mono mt-2 text-[10px] text-[var(--fg-dim)]">digest: {error.digest}</p>
        )}
        <div className="mt-4 flex justify-center gap-2">
          <button
            onClick={() => retry()}
            className="flex cursor-pointer items-center gap-2 rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-[#04141a] transition hover:brightness-110"
          >
            <RefreshCw className="h-4 w-4" /> Try again
          </button>
          <button
            onClick={() => router.push("/")}
            className="cursor-pointer rounded-lg border border-[var(--border)] bg-[var(--panel)] px-4 py-2 text-sm text-[var(--fg-muted)] transition hover:text-[var(--fg)]"
          >
            Back to overview
          </button>
        </div>
      </div>
    </div>
  );
}
