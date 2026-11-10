# Playbook 02 — Config / Secrets / robots.txt / security.txt / API deny-by-default

**Audience:** Indie Hackers shipping Web / JAMstack / small APIs  
**Output style:** 🔴 critical · 🟡 improve · 🟢 ok — plus Copy-Paste fixes  
**Defense only** — stop leaks and tighten defaults; no attack recipes.  
**Local checks:** each rule lists an optional `rg_pattern` you may run with local `rg` on a tree you are authorized to review. This repository does not ship a scanner or an ignore-file.

---

## Checklist

| Check | Look for |
|-------|----------|
| `.env` not public | `.env`, `.env.local`, `.env.production` never under web root / never in git |
| Config leak | No `config.json` / `secrets.*` / private keys served as static files |
| robots.txt type | `/robots.txt` returns `text/plain` (not SPA `index.html`) |
| security.txt type | `/.well-known/security.txt` returns `text/plain` (not SPA shell) |
| Static before SPA | CDN/edge serves real files **before** SPA fallback rewrite |
| API deny-by-default | Unknown routes/methods → uniform 404/405; no stack traces |
| Authz on API | Document allowed methods/routes; require auth where needed |

*Example pattern: SPA hosts that rewrite everything to `index.html` often accidentally serve HTML for `/robots.txt` and `/.well-known/security.txt`. Fix by placing static files at the edge **before** the fallback.*

---

---

## Deterministic probes (RULE_ID + rg_pattern)

Defense-detection only — find committed / shipped secret smells; never print secret values in findings.

## RULE_ID: SEC-ENV-COMMITTED
- **Trigger:** `.env` / `.dev.vars` / secret-shaped files appear tracked or under publish dir.
- **rg_pattern:** `^\.env$|\.env\.(local|production|development)|\.dev\.vars|secrets\.`
- **scan_note:** When using local `rg`, you may skip `.env` / `.env.*` to reduce noise; still flag those files if they are git-tracked or inside `dist/`.
- **Risk_1L:** Live keys in VCS or static host.

## RULE_ID: SEC-HARDCODED-SECRET
- **Trigger:** Source literals look like API keys / private PEM / session defaults.
- **rg_pattern:** `SESSION_SECRET|API_KEY|sk_live|sk-[a-zA-Z0-9]{10,}|BEGIN (RSA |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16}|dev-insecure`
- **scan_note:** Skip `*.pem` / `*.key` / `**/secrets/` paths; report only first-party source hits.
- **Risk_1L:** Forged auth or cloud account takeover if value is real.

## RULE_ID: SEC-VITE-PUBLIC-LEAK
- **Trigger:** `VITE_*` (or similar) names that embed secrets into the client bundle.
- **rg_pattern:** `VITE_.*SECRET|VITE_.*KEY|VITE_.*TOKEN|import\.meta\.env\.VITE_`
- **Risk_1L:** Anything `VITE_`-prefixed ships to browsers.

## RULE_ID: SEC-CLIENT-SECRET-BUNDLE
- **Trigger:** Client/bundled JS contains wrangler secret names or Discord client secret assignments.
- **rg_pattern:** `DISCORD_CLIENT_SECRET|wrangler secret|client_secret\s*[:=]|SESSION_SECRET\s*[:=]\s*["'][^"']+["']`
- **Risk_1L:** Server secrets baked into SPA / Tauri frontend.

---

## Traffic-light examples

### 🔴 Critical — `.env` or secrets reachable + SPA HTML for security.txt

```
Findings:
🔴 /.env (or similar) returns 200 with KEY=... content — remove from publish dir; rotate keys
🔴 /.well-known/security.txt returns text/html (SPA shell) — deploy real text/plain file before SPA fallback
🟡 /robots.txt also HTML — same static-before-fallback fix
🟡 /api/<unknown> returns 500 with stack trace — uniform 404/405, no internals
```

### 🟡 Improve — files OK, API still allow-any

```
Findings:
🟢 robots.txt and security.txt are text/plain
🟢 .env not in deploy artifact
🟡 API default permission is allow-any / open CORS — switch to deny-by-default + authz
🟡 Error bodies still echo exception messages — use generic client errors
```

### 🟢 OK

```
Findings:
🟢 No secrets in static publish dir; .gitignore covers .env*
🟢 robots.txt + security.txt are real text/plain at edge
🟢 API: allowlisted routes/methods only; unknown → 404/405
🟢 Auth required on non-public endpoints; no stack traces to clients
```

---

## Copy-Paste fixes

### 1) Keep secrets out of the publish tree

`.gitignore` (minimum):

```gitignore
.env
.env.*
!.env.example
*.pem
*.key
secrets/
config.local.json
```

`.env.example` (safe template only):

```bash
# Copy to .env and fill locally — never commit .env
DATABASE_URL=
API_KEY=
OPENAI_API_KEY=
```

Pre-deploy guard (bash, run in CI or before `wrangler pages deploy` / `netlify deploy`):

```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-./dist}"
if find "$ROOT" -type f \( -name '.env' -o -name '.env.*' -o -name '*.pem' -o -name 'id_rsa' \) | grep -q .; then
  echo "REFUSE: secret-like files under $ROOT"
  find "$ROOT" -type f \( -name '.env' -o -name '.env.*' -o -name '*.pem' -o -name 'id_rsa' \)
  exit 1
fi
echo "OK: no obvious secret files in $ROOT"
```

### 2) Serve real `robots.txt` and `security.txt` (SPA-safe)

**Cloudflare Pages / static `_routes` idea:** put files in `public/`:

```txt
# public/robots.txt
User-agent: *
Allow: /
Sitemap: https://example.com/sitemap.xml
```

```txt
# public/.well-known/security.txt
Contact: mailto:security@example.com
Expires: 2027-12-31T23:59:59.000Z
Preferred-Languages: en, zh
Canonical: https://example.com/.well-known/security.txt
```

**nginx** — static files before SPA fallback:

```nginx
location = /robots.txt {
    add_header Content-Type text/plain;
    alias /var/www/site/robots.txt;
}
location = /.well-known/security.txt {
    add_header Content-Type text/plain;
    alias /var/www/site/.well-known/security.txt;
}
# SPA fallback last
location / {
    try_files $uri $uri/ /index.html;
}
```

**Netlify `public/_redirects` / headers:** ensure `/robots.txt` and `/.well-known/*` are not force-rewritten to `/index.html`. Ship the files under `public/`.

**Cloudflare Pages `_redirects`:** avoid a catch-all that overrides well-known paths; place the files in the build output root.

### 3) Deny-by-default API (Node / Express-style sketch)

```js
// routes must be explicitly registered; unknown paths → uniform 404
import express from "express";
const app = express();

const ALLOWED = new Map([
  ["GET /api/health", true],
  ["GET /api/me", true],
  ["POST /api/chat", true],
]);

app.use("/api", (req, res, next) => {
  const key = `${req.method} ${req.path}`;
  // If you mount at /api, path is relative to mount
  const rel = `${req.method} /api${req.path === "/" ? "" : req.path}`;
  if (!ALLOWED.has(rel) && !ALLOWED.has(key)) {
    return res.status(404).json({ error: "not_found" });
  }
  next();
});

app.get("/api/health", (_req, res) => res.json({ ok: true }));

// Authz example for private routes
function requireUser(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "unauthorized" });
  next();
}
app.get("/api/me", requireUser, (req, res) => res.json({ id: req.user.id }));

// No stack traces to clients
app.use((err, _req, res, _next) => {
  console.error(err); // server logs only
  res.status(500).json({ error: "internal_error" });
});
```

### 4) Cloudflare Worker — method allowlist + generic errors

```js
const ALLOW = {
  "GET /api/health": true,
  "POST /api/chat": true,
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const key = `${request.method} ${url.pathname}`;
    if (url.pathname.startsWith("/api/") && !ALLOW[key]) {
      return Response.json({ error: "not_found" }, { status: 404 });
    }
    try {
      // ... route handlers ...
      return Response.json({ error: "not_found" }, { status: 404 });
    } catch (e) {
      console.error(e);
      return Response.json({ error: "internal_error" }, { status: 500 });
    }
  },
};
```

---

## Rollout tips

1. Rotate any key that ever sat in a public artifact — assume compromised.
2. Add a CI grep for `AKIA`, `sk-`, `BEGIN PRIVATE KEY`, `api_key` in the publish dir.
3. Document every public API route in one markdown table; anything else is 404.
4. `security.txt` `Expires` must be a future date; refresh yearly.

---

*Pre-launch Check · playbook 02 · defense-only*
