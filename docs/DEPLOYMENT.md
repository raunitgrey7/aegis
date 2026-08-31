# Deploying Aegis (Hugging Face backend + Vercel frontend)

The public demo runs the **API on a Hugging Face Docker Space** and the **Next.js UI on Vercel**. The
frontend proxies `/api/*` to the Space via a Next.js rewrite, so the browser makes same-origin calls and
there is no CORS to configure.

```
Browser ──▶ Vercel (Next.js UI)  ──/api/* rewrite──▶  HF Space (FastAPI API, :7860)
```

## 1. Backend → Hugging Face Space

Prereqs: a free HF account and a **write** token (https://huggingface.co/settings/tokens).

```bash
export HF_TOKEN=hf_xxxxxxxx          # write token
export HF_USER=<your-hf-username>
bash deploy/hf-space/push.sh
```

This creates/updates the Space `HF_USER/aegis-api`, uploads `backend/` + `simulator/` with the Space
Dockerfile, and HF builds the image. When the build finishes the API is live at:

- Space page: `https://huggingface.co/spaces/<HF_USER>/aegis-api`
- API base: `https://<HF_USER>-aegis-api.hf.space`  (docs at `/docs`, health at `/api/healthz`)

The Space seeds the demo environment on boot and runs with the local LLM disabled (deterministic
narrative), so it needs no GPU and runs on the free CPU tier.

## 2. Frontend → Vercel

Prereqs: the Vercel CLI (`npm i -g vercel`) and a login (`vercel login`) or a token.

```bash
cd frontend
vercel link            # or: vercel --yes to auto-create the project
# Point the rewrite at the Space and use the same-origin proxy path:
vercel env add AEGIS_BACKEND_URL production      # value: https://<HF_USER>-aegis-api.hf.space
vercel env add NEXT_PUBLIC_API_URL production    # value: /api
vercel deploy --prod --yes
```

`next.config.ts` reads `AEGIS_BACKEND_URL` and rewrites `/api/:path*` to `${AEGIS_BACKEND_URL}/api/:path*`.
The client reads `NEXT_PUBLIC_API_URL=/api`, so every call is same-origin and Vercel proxies it to the Space.

After deploy, open the Vercel URL and log in with `analyst` / `analyst`.

## Notes
- **CORS:** not needed with the proxy. If you instead point `NEXT_PUBLIC_API_URL` directly at the Space
  URL, set `AEGIS_CORS_ORIGINS` on the Space to include your Vercel origin (the Space Dockerfile defaults
  to `["*"]` with credentialed CORS disabled, which also works for a public demo).
- **State:** the API keeps incidents in memory and reseeds on restart; HF Spaces sleep when idle and wake
  on the next request (first load after sleep is slower). This is expected for a demo deployment.
- **Secrets:** change `AEGIS_JWT_SECRET` and the demo passwords via Space/Vercel env vars for anything
  beyond a public demo.
