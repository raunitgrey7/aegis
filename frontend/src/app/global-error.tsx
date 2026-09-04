"use client"; // Global error boundary — replaces the root layout when it crashes

export default function GlobalError({
  error,
  retry,
}: {
  error: Error & { digest?: string };
  retry: () => void;
}) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#070b12",
          color: "#e5edf5",
          fontFamily: "system-ui, sans-serif",
        }}
      >
        <div style={{ textAlign: "center", maxWidth: 420, padding: 24 }}>
          <div style={{ fontSize: 28, marginBottom: 8 }}>🛡️</div>
          <h2 style={{ fontSize: 16, margin: 0 }}>Aegis console failed to render</h2>
          <p style={{ fontSize: 12, color: "#8a99ad", lineHeight: 1.6, marginTop: 8 }}>
            Something went wrong at the application root.
            {error?.digest ? ` (digest: ${error.digest})` : ""}
          </p>
          <button
            onClick={() => retry()}
            style={{
              marginTop: 16,
              cursor: "pointer",
              background: "#22d3ee",
              color: "#04141a",
              border: "none",
              borderRadius: 8,
              padding: "10px 20px",
              fontWeight: 600,
              fontSize: 13,
            }}
          >
            Reload console
          </button>
        </div>
      </body>
    </html>
  );
}
