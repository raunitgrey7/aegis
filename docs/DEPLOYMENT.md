# Deploying Aegis

**Live demo:** frontend https://aegis-ochre-eight.vercel.app · backend https://aegis-api-henna.vercel.app/docs

The current live demo runs **both tiers on Vercel** (the frontend as a Next.js app, the FastAPI backend
as a Python function via Fluid Compute) — see **Option B** below. HuggingFace Docker Spaces now require a
paid PRO plan, so the original HF-backend path (**Option A**) is kept for reference but needs HF PRO.

## Option B — backend on Vercel (free, what the live demo uses)

The FastAPI backend is packaged as a self-contained Vercel Python project in `deploy/vercel-backend/`.

```bash
bash deploy/vercel-backend/build.sh          # copies aegis + aegis_sim into the project
cd deploy/vercel-backend
vercel link --yes --project aegis-api
printf 'false'  | vercel env add AEGIS_LLM_ENABLED  production
printf '["*"]'  | vercel env add AEGIS_CORS_ORIGINS production
vercel deploy --prod --yes                   # -> https://<project>.vercel.app  (use the production alias)
```

Then deploy the frontend pointing at that backend:

```bash
cd frontend
vercel link --yes --project aegis
printf 'https://aegis-api-henna.vercel.app' | vercel env add AEGIS_BACKEND_URL   production
printf '/api'                                | vercel env add NEXT_PUBLIC_API_URL production
vercel deploy --prod --yes
```

`next.config.ts` rewrites `/api/:path*` to `${AEGIS_BACKEND_URL}/api/:path*`, and the client uses
`NEXT_PUBLIC_API_URL=/api`, so every call is same-origin and Vercel proxies it to the backend (no CORS).
Note: Vercel's protected preview URLs 302; use the **production alias** (public) for the demo.

---

# Deploying Aegis (Hugging Face backend + Vercel frontend) — Option A (needs HF PRO)

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
