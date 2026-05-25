# AttackLens — MITRE ATT&CK Auto-Mapper

AI-powered MITRE ATT&CK mapping platform. Paste logs, attack names, IOCs, or natural-language incident descriptions; get back mapped techniques, kill chain, Sigma/SPL/KQL detection rules, and a printable analyst report.

---

## Quick Decision: Where will you run it?

| | Local development | Netlify (or any static host) |
|---|---|---|
| Best for | Building, testing, demos on your machine | Sharing a live URL, interviewing |
| Storage | Your browser's localStorage | Your browser's localStorage |
| API key location | `.env` file on your machine | Netlify environment variable |
| Setup time | ~3 minutes | ~5 minutes |

**Storage note:** analyses persist in the browser you use to access the site. They follow the **browser**, not the user. Clearing site data wipes them. For a multi-user / multi-device setup, see the "Production hardening" section at the bottom.

---

## A. Local development (recommended for first run)

Requirements: Node.js 18+ and an Anthropic API key (https://console.anthropic.com).

```bash
# 1. Install dependencies
npm install

# 2. Configure your API key
cp .env.example .env
# Edit .env, paste your sk-ant-... key on the ANTHROPIC_API_KEY line

# 3. Run frontend (port 5173) + LLM proxy (port 8787) together
npm run dev
```

Open **http://localhost:5173**.

---

## B. Deploy to Netlify

### Step 1 — Push to a Git repo

```bash
git init
git add .
git commit -m "Initial AttackLens deploy"
git remote add origin https://github.com/YOU/attacklens.git
git push -u origin main
```

(If you don't have a GitHub account, you can also drag-and-drop the `dist/` folder
after running `npm run build` — but the Git workflow gets you continuous deployment.)

### Step 2 — Connect the repo to Netlify

1. Go to https://app.netlify.com
2. Click **Add new site → Import an existing project**
3. Pick your Git provider, authorize, choose the AttackLens repo
4. Netlify auto-detects the build settings from `netlify.toml`. **Don't change them.**
5. **Before clicking Deploy**, click **Add environment variables** and add:
   - Key: `ANTHROPIC_API_KEY`
   - Value: your `sk-ant-...` key
6. Click **Deploy site**

### Step 3 — Verify

After ~1 minute the build completes. Click the generated URL. Try a quick-start sample.

### If you already deployed and got the 404 HTML error

That happened because your initial deploy was missing the serverless function and the env var. The fix:

1. Make sure these files exist in your repo:
   - `netlify.toml` (in the project root)
   - `netlify/functions/llm.js`
2. In Netlify → **Site settings → Environment variables**, add `ANTHROPIC_API_KEY`.
3. Trigger a re-deploy: **Deploys → Trigger deploy → Deploy site**.
4. Confirm the function exists: **Functions** tab in Netlify should list `llm`.

---

## How it works

### Local dev
```
Browser  ──fetch──▶  Vite dev server (5173)  ──proxy──▶  Node server (8787)  ──fetch──▶  Anthropic API
   │
   └── localStorage (analyses, tags, notes — all in the browser)
```

### Netlify (production)
```
Browser  ──fetch──▶  Netlify CDN (HTML/JS/CSS)
          ──fetch /api/llm──▶  Netlify Function (llm.js)  ──fetch──▶  Anthropic API
   │
   └── localStorage (analyses, tags, notes — all in the browser)
```

In both cases, the Anthropic API key never reaches the browser. It only lives on the server (Node locally, the serverless function on Netlify).

---

## File layout

```
attacklens-app/
├── README.md                          ← you are here
├── package.json
├── netlify.toml                       ← Netlify build + routing config
├── vite.config.js
├── tailwind.config.js
├── postcss.config.js
├── index.html
├── .env.example                       ← copy to .env for local dev
├── .gitignore
├── netlify/
│   └── functions/
│       └── llm.js                     ← serverless function (production /api/llm)
├── server/
│   └── proxy.mjs                      ← local Node server (dev /api/llm)
└── src/
    ├── main.jsx
    ├── index.css
    └── AttackLensApp.jsx              ← the entire app
```

---

## Troubleshooting

**"API 404: <!DOCTYPE html>..."** (you hit this earlier)
The serverless function isn't deployed or isn't matching `/api/llm`. Fix:
1. Verify `netlify/functions/llm.js` exists in your repo.
2. Verify `netlify.toml` is at the project root.
3. In Netlify, click **Functions** — `llm` should be listed.
4. If it's missing, re-deploy.

**"ANTHROPIC_API_KEY not configured"**
- Locally: check that `.env` exists at the project root with `ANTHROPIC_API_KEY=sk-ant-...`. Restart `npm run dev`.
- On Netlify: Site settings → Environment variables → add `ANTHROPIC_API_KEY`. Re-deploy.

**"API error 529: Overloaded"**
Anthropic's API is at capacity. The app retries automatically with exponential backoff (up to 6 attempts). If it still fails, wait 30–60 seconds.

**"Browser storage is full"**
localStorage typically caps at 5–10 MB per origin. Delete old analyses (History tab → trash icon) to free space.

**Port 5173 or 8787 already in use**
Edit `vite.config.js` (frontend port) or set `ATTACKLENS_PORT` env var (backend port).

---

## Privacy / data handling

- **Your analyses stay in your browser.** Nothing is stored on Netlify or any database. Clearing site data wipes them.
- **Your prompts (logs, descriptions) are sent to Anthropic** for the LLM call. Review Anthropic's data usage policy if you intend to paste sensitive production data.
- **Your API key lives only on the server.** It's never embedded in the deployed frontend bundle.

---

## Production hardening (optional, if you go beyond a personal demo)

The current setup is great for local use, interviews, and personal projects. For a multi-user production deployment:

1. **Real storage:** swap localStorage for Netlify Blobs, Supabase, or Postgres. The architecture doc has schema suggestions.
2. **Auth:** put Netlify Identity, Auth0, or Clerk in front of `/api/*` routes.
3. **Rate limiting:** add a per-IP token bucket to the serverless function to prevent API key abuse.
4. **Audit logging:** the architecture doc has a Postgres `audit_log` table design.

---

Built with React + Vite + Tailwind. Backend is one zero-dep file (local) or one serverless function (Netlify).
