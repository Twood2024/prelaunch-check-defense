# Playbook 05 — OAuth PKCE / Session / redirect_uri

**Audience:** Discord (or similar) OAuth on Workers + SPA / Tauri return  
**Output:** finding-report JSON  
**Defense only.** File budget ＜~1500 tokens.  
**Local checks:** each rule lists an optional `rg_pattern` you may run with local `rg` on a tree you are authorized to review. This repository does not ship a scanner or an ignore-file.

---

## RULE_ID: OAUTH-PKCE-S256
- **Trigger:** Authorize URL lacks `code_challenge` / `code_challenge_method=S256`, or callback omits `code_verifier`.
- **Risk_1L:** Stolen auth code can be redeemed by another client.
- **rg_pattern:** `code_challenge|code_challenge_method|S256|pkceChallengeS256|code_verifier`
- **Fix_Snippet:**
```ts
const verifier = randomB64Url(32);
const challenge = await pkceChallengeS256(verifier); // SHA-256 → base64url
authorize.searchParams.set("code_challenge", challenge);
authorize.searchParams.set("code_challenge_method", "S256");
// store verifier inside signed state (or server store); token exchange sends code_verifier
```
- **Verify:** `curl -sI 'https://HOST/auth/discord?return_origin=https://ALLOWLISTED'` Location contains `code_challenge` + `S256`.

---

## RULE_ID: OAUTH-STATE-HMAC
- **Trigger:** `state` is plain `btoa({origin})` with no HMAC / expiry / nonce.
- **Risk_1L:** CSRF / login CSRF; forged return_origin if allowlist weak.
- **rg_pattern:** `mintOAuthState|verifyOAuthState|invalid_or_expired_state|btoa\(\{.*origin|HMAC.*state`
- **Fix_Snippet:**
```ts
// state payload: { o: returnOrigin, n: nonce, exp, v: code_verifier }
// mac = HMAC-SHA256(SESSION_SECRET, body); wire = base64url(body) + "." + mac
// callback: verify mac + exp + CLIENT_ORIGIN allowlist; else invalid_or_expired_state
```
- **Verify:** Tampered state → 400 `invalid_or_expired_state`; expired state rejected.

---

## RULE_ID: OAUTH-VERIFY-SESSION-JOIN
- **Trigger:** WS/API join trusts client `discordUser` / nickname as authoritative id.
- **Risk_1L:** Impersonation; bypass Discord login.
- **rg_pattern:** `verifySession|sessionToken required|discordUser|guestFromNickname|msg\.discordUser`
- **scan_note:** Defense detection of trust-client-join smells; not an exploit recipe.
- **Fix_Snippet:**
```ts
const claims = await verifySession(msg.sessionToken, requireSessionSecret(env));
if (!claims) return error("sessionToken required");
const peer = { id: claims.sub, nickname: claims.name }; // claims only
// do not set id from msg.discordUser
```
- **Verify:** Join without token fails; join with token + fake discordUser still uses claims.sub.

---

## RULE_ID: OAUTH-REDIRECT-URI
- **Trigger:** Discord app redirect list missing prod callback, or `PUBLIC_BASE_URL` / return_origin not allowlisted.
- **Risk_1L:** Login fails or tokens return to unexpected origin.
- **rg_pattern:** `redirect_uri|CLIENT_ORIGIN|return_origin|PUBLIC_BASE_URL|/auth/callback`
- **Fix_Snippet:**
```
# Discord Portal Redirects (exact):
https://YOUR_HOST/auth/callback
# Keep localhost only for dev:
http://127.0.0.1:8787/auth/callback
# Worker: CLIENT_ORIGIN allowlist includes SPA + http://tauri.localhost
# redirect_uri in authorize = `${PUBLIC_BASE_URL}/auth/callback`
```
- **Verify:** Authorize `redirect_uri` matches Portal; unlisted `return_origin` rejected / falls back to first allowlist entry (document behavior).

---

## RULE_ID: OAUTH-CALLBACK-ESCAPE
- **Trigger:** Callback error HTML embeds raw `error=` or upstream body.
- **Risk_1L:** Reflected XSS on auth host.
- **rg_pattern:** `escapeHtml|errorPage|authErrorPage|<pre>\$\{|dangerouslySetInnerHTML`
- **Fix_Snippet:**
```ts
function escapeHtml(s: string) {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
// errorPage(fixedCode, escapeHtml(detail?)) — never nest raw tokenRes.text()
```
- **Verify:** `error=<script>` appears escaped or as fixed code only.

---

## RULE_ID: OAUTH-STATE-BIND
- **Trigger:** OAuth `state` / `nonce` / PKCE `code_verifier` sits in a cookie (or client storage) that is not bound to the current login session and provider, or is not cleared after the callback.
- **Risk_1L:** Login-CSRF or a stolen callback code can be redeemed under another session/provider.
- **rg_pattern:** `code_verifier|oauth.?state|pkce|nonce|Set-Cookie.*state|clearCookie|providerId`
- **Fix_Snippet:**
```ts
// Mint state cookie: { sid, provider, n, exp, v: verifier } + HMAC
// HttpOnly; Secure; SameSite=Lax; path=/auth
// Callback: verify mac+exp; require cookie.sid === session && cookie.provider === expected
// Then delete the cookie (single use)
```
- **Verify:** Callback with a state cookie from another provider or session is rejected; after success the state cookie is gone.

---

## RULE_ID: OAUTH-CSRF-CTYPE
- **Trigger:** CSRF gate (e.g. Hono `csrf()`) only Origin-checks typical form content-types and skips other credentialed POSTs (including Chromium `text/ping`).
- **Risk_1L:** State-changing requests can bypass the CSRF Origin check.
- **rg_pattern:** `csrf\(|text/ping|Sec-Fetch-Site|content-type.*Origin`
- **Fix_Snippet:**
```ts
// Treat any credentialed mutating method as CSRF-sensitive, not only form types.
// Check Origin or Sec-Fetch-Site (same-origin / same-site) on POST/PUT/PATCH/DELETE
// including Content-Type text/ping; or require a CSRF token / custom header.
// Hono: upgrade to ≥ 4.13.16 if you rely on csrf(); still review non-form types.
```
- **Verify:** Credentialed POST with `Content-Type: text/ping` is accepted only when Origin/Sec-Fetch-Site (or a CSRF token) passes; cross-site is rejected. Workers stacks: also playbook 04.

---

## RULE_ID: OAUTH-COOKIE-HDR
- **Trigger:** Session/auth cookies set via `NextResponse.cookies.set()` (or similar) are also copied onto a JS-readable response header such as `x-middleware-set-cookie`.
- **Risk_1L:** `HttpOnly` on `Set-Cookie` does not stop same-origin script from reading the twin header.
- **rg_pattern:** `x-middleware-set-cookie|NextResponse\.cookies\.set|Set-Cookie`
- **Fix_Snippet:**
```ts
// Set session cookies only via Set-Cookie (HttpOnly; Secure; SameSite).
// Do not serialize cookie values into any custom / framework header JS can read.
// Next.js Edge: use patched next 16.4.5 / 15.5.29 or later.
```
- **Verify:** `curl -sI` on the Edge route that sets the session cookie shows `Set-Cookie` with HttpOnly and no cookie value on other headers (incl. `x-middleware-set-cookie`). Also playbook 01 checklist.
