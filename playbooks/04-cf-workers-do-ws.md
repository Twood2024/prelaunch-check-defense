# Playbook 04 — CF Workers / Durable Objects / WebSocket

**Audience:** Indie apps on Cloudflare Workers + DO rooms + WS  
**Output:** findings → `schemas/finding-report.schema.json`  
**Defense only** — hardening; no exploit recipes.  
**Budget:** keep each rule short (~this file ＜2000 tokens).  
**Local checks:** each rule lists an optional `rg_pattern` you may run with local `rg` on a tree you are authorized to review. This repository does not ship a scanner or an ignore-file.

OAuth / PKCE / session cookies are in playbook 05. Tauri / Wails WebView and game-integrity rules are in playbook 06.

---

## RULE_ID: CFWS-MOCK-OFF
- **Trigger:** Public host still exposes `/auth/mock` or `mockAvailable: true` in `/auth/status`.
- **Risk_1L:** Anyone can mint a production session without Discord.
- **rg_pattern:** `mockAvailable|/auth/mock|ALLOW_MOCK_AUTH`
- **Fix_Snippet:**
```ts
function mockAuthAllowed(env, request) {
  if (env.ALLOW_MOCK_AUTH === "1") return true;
  if (env.ALLOW_MOCK_AUTH === "0") return false;
  const h = new URL(request.url).hostname;
  return h === "127.0.0.1" || h === "localhost" || h === "[::1]";
}
// status.mockAvailable = mockAuthAllowed(...); /auth/mock → 403 when false
```
- **Verify:** `curl -s https://HOST/auth/status` → `mockAvailable:false`; `curl -sI https://HOST/auth/mock` → 403.

---

## RULE_ID: CFWS-NO-QUERY-TOKEN
- **Trigger:** Redirects or `/auth/me` accept long-lived `?token=`.
- **Risk_1L:** Session leaks via history, Referer, CDN/proxy logs.
- **rg_pattern:** `token=|searchParams\.get\(["']token|query\.get\(["']token|redirectWithToken`
- **Fix_Snippet:**
```ts
// Redirect with short-lived HMAC code only: /index.html?code=...
// POST /auth/exchange { code } → session token
// GET /auth/me: Authorization Bearer only; if url has token → 400 query_token_rejected
```
- **Verify:** `curl -s 'https://HOST/auth/me?token=x'` → 400; exchange path returns token in JSON body only.

---

## RULE_ID: CFWS-CORS-ALLOWLIST
- **Trigger:** `Access-Control-Allow-Origin: *` on auth or private APIs (incl. OPTIONS).
- **Risk_1L:** Any origin can read auth responses in the browser.
- **rg_pattern:** `Access-Control-Allow-Origin.*\*|ACAO|corsHeaders|corsPairs`
- **Fix_Snippet:**
```ts
function corsHeadersFor(env, request) {
  const h = new Headers();
  const origin = request.headers.get("Origin") || "";
  const allow = String(env.CLIENT_ORIGIN || "").split(",").map(s => s.trim()).filter(Boolean);
  if (origin && allow.includes(origin)) {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Vary", "Origin");
  }
  // unmatched: omit ACAO — never set *; OPTIONS uses same helper
  return h;
}
```
- **Verify:** `curl -sI -H 'Origin: https://evil.example' https://HOST/auth/status` → no `*`; allowlisted Origin reflected.

---

## RULE_ID: CFWS-ROOM-CSPRNG
- **Trigger:** Client-chosen short room codes or default `TEST01` in prod UI / server default.
- **Risk_1L:** Room enumeration / join guessing.
- **rg_pattern:** `TEST01|DEFAULT_ROOM_CODE|generateRoomCode|getRandomValues.*[Rr]oom`
- **Fix_Snippet:**
```ts
// POST /room/create → crypto.getRandomValues → Crockford-ish 8+ chars
// /ws without ?room= → 400 room_required; UI does not prefill TEST01
```
- **Verify:** `curl -sX POST https://HOST/room/create` → unique `roomCode`; UI empty by default.

---

## RULE_ID: CFWS-KICK-OLD-WS
- **Trigger:** Same `userId` can hold multiple open WS seats.
- **Risk_1L:** Duplicate votes / presence / game integrity break.
- **rg_pattern:** `close\(4000|replaced by newer|kick.*[Ww][Ss]|dedupe.*peer|same userId`
- **Fix_Snippet:**
```ts
// On join: if peer id already mapped → close old socket (e.g. 4000) then bind new
// listPeers dedupe by id
```
- **Verify:** Two joins same session id → only one peer in roster.

---

## RULE_ID: CFWS-NO-SECRET-FALLBACK
- **Trigger:** Source contains hardcoded `SESSION_SECRET` / `dev-insecure-…` fallback.
- **Risk_1L:** Forged sessions if prod ships without wrangler secret.
- **rg_pattern:** `dev-insecure|SESSION_SECRET\s*[=:]\s*["']|sessionSecret\(\)|requireSessionSecret`
- **scan_note:** Skip `.env` / `.dev.vars` / `*.pem` hits; flag only committed source defaults.
- **Fix_Snippet:**
```ts
function requireSessionSecret(env) {
  const s = env.SESSION_SECRET?.trim();
  if (!s) throw new Error("SESSION_SECRET required");
  return s;
}
// local only via .dev.vars — never commit; no inline default string
```
- **Verify:** `rg -n 'dev-insecure|SESSION_SECRET\s*[=:]\s*"' src` empty; missing secret refuses mint/join.

---

## RULE_ID: CFWS-WORKERS-DEV-HEADERS
- **Trigger:** Custom domain ships CSP/HSTS/XFO/nosniff/Referrer/Permissions-Policy but `*.workers.dev` HTML/auth responses omit the same set.
- **Risk_1L:** Dual-entry policy gap; users on workers.dev get weaker browser defenses for the same auth/WS surface.
- **rg_pattern:** `securityHeaders|withSecurity|Content-Security-Policy|workers\.dev`
- **Fix_Snippet:**
```ts
function securityHeaders() {
  return {
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'; ...",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  };
}
// Apply via withSecurity() on HTML, JSON auth, and error pages (workers.dev + custom domain).
// Prefer first-party host for OAuth redirect_uri + CSP connect-src.
```
- **Verify:** `curl -sI https://PROJECT.workers.dev/` and custom host both show CSP (or workers.dev 301s to custom domain).

---

*OAuth PKCE / session join / CSRF content-type coverage (incl. `text/ping`) → playbook 05 `OAUTH-CSRF-CTYPE`. Tauri CSP / host-only start / UNICAST / rate limits / webview origin + IPC frame + WS origin allowlist (`TAURI-WS-ORIGIN`) → playbook 06.*
