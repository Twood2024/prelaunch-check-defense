# Playbook 01 — Headers / CSP / HSTS / Clickjacking / CORS

**Audience:** Indie Hackers shipping Web apps (Pages, nginx, Cloudflare, static hosts)  
**Output style:** 🔴 critical · 🟡 improve · 🟢 ok — plus Copy-Paste fixes  
**Defense only** — hardening patches; no attack recipes.  
**Local checks:** each rule lists an optional `rg_pattern` you may run with local `rg` on a tree you are authorized to review. This repository does not ship a scanner or an ignore-file.

---

## Checklist (scan your responses)

| Check | Look for |
|-------|----------|
| CSP present | `Content-Security-Policy` (or Report-Only while tuning) |
| CSP quality | Prefer nonces/hashes; avoid `unsafe-inline` / `unsafe-eval` when feasible |
| HSTS | `Strict-Transport-Security: max-age=31536000; includeSubDomains` (add `preload` only after HTTPS inventory) |
| Clickjacking | `X-Frame-Options: DENY` **and/or** CSP `frame-ancestors 'none'` |
| MIME sniff | `X-Content-Type-Options: nosniff` |
| Referrer | `Referrer-Policy: strict-origin-when-cross-origin` |
| Permissions | `Permissions-Policy` locking camera/mic/geo if unused |
| CORS ACAO | Never `Access-Control-Allow-Origin: *` on credentialed / private APIs; allowlist origins |
| CORS origin bind | Exact origins (scheme+host+port). Subdomain wildcards need a leading-dot label boundary (`host == "example.com"` or `host.endsWith(".example.com")`). Never trailing `*` on a host prefix, never `origin.startsWith(allowed)`. Desktop webview lists: playbook 06 `TAURI-ORIGIN-BOUND`. |
| Cookie header isolation | Do not copy `Set-Cookie` / session values onto JS-readable response headers (e.g. `x-middleware-set-cookie`). `HttpOnly` is not enough if a twin header is readable. Session details: playbook 05 `OAUTH-COOKIE-HDR`. |

*Example pattern notes (hardening targets, not live probes): sites that ship HTML without CSP/HSTS/XFO, or APIs that echo `ACAO: *`, match the same checklist Indie Hackers hit on Pages / Cloudflare / nginx.*

---

---

## Deterministic probes (RULE_ID + rg_pattern)

Machine-readable defense signals for pre-scan (additive to the human checklist above).

## RULE_ID: HDR-CSP-PRESENT
- **Trigger:** Responses / static config lack `Content-Security-Policy` (and no Report-Only while tuning).
- **rg_pattern:** `Content-Security-Policy|content-security-policy|http-equiv=["']Content-Security-Policy`
- **Risk_1L:** XSS / script injection has no browser policy brake.

## RULE_ID: HDR-HSTS
- **Trigger:** No `Strict-Transport-Security` on HTTPS hosts.
- **rg_pattern:** `Strict-Transport-Security|max-age=31536000`
- **Risk_1L:** Downgrade / cookie stripping on first visit after HTTP.

## RULE_ID: HDR-XFO-FRAME
- **Trigger:** Missing `X-Frame-Options` and CSP `frame-ancestors`.
- **rg_pattern:** `X-Frame-Options|frame-ancestors`
- **Risk_1L:** Clickjacking / UI redress.

## RULE_ID: HDR-NOSNIFF
- **Trigger:** Missing `X-Content-Type-Options: nosniff`.
- **rg_pattern:** `X-Content-Type-Options|nosniff`
- **Risk_1L:** MIME sniffing turns attacker-controlled content into script.

## RULE_ID: HDR-REFERRER
- **Trigger:** Missing `Referrer-Policy`.
- **rg_pattern:** `Referrer-Policy|strict-origin-when-cross-origin`
- **Risk_1L:** Token/URL leakage via Referer on cross-origin navigations.

## RULE_ID: HDR-PERMISSIONS
- **Trigger:** Missing `Permissions-Policy` while camera/mic/geo unused or over-broad.
- **rg_pattern:** `Permissions-Policy|Feature-Policy`
- **Risk_1L:** Unexpected device API access from embedded/third-party script.

## RULE_ID: HDR-CORS-ACAO
- **Trigger:** `Access-Control-Allow-Origin: *` on private / credentialed APIs.
- **rg_pattern:** `Access-Control-Allow-Origin\s*:\s*\*|Access-Control-Allow-Origin:\s*\*`
- **Risk_1L:** Any origin can read private API responses in the browser.

## RULE_ID: HDR-CORS-SUFFIX
- **Trigger:** CORS / origin allowlist uses trailing `*`, `origin.startsWith(...)`, or a host suffix without a leading-dot label boundary.
- **rg_pattern:** `AllowOrigins|allowedOrigins|allowed_origins|BindingsAllowedOrigins|origin\.startsWith|Access-Control-Allow-Origin.*\*`
- **Risk_1L:** A look-alike origin can pass the allowlist and read credentialed responses. Desktop webview lists: playbook 06 `TAURI-ORIGIN-BOUND`.

---

## Traffic-light examples

### 🔴 Critical — missing CSP + missing HSTS + ACAO wildcard on API

```
Findings:
🔴 Content-Security-Policy: missing
🔴 Strict-Transport-Security: missing
🔴 Access-Control-Allow-Origin: * on /api/* (credentials / private data risk)
🟡 X-Frame-Options / frame-ancestors: missing
🟢 X-Content-Type-Options: nosniff present
```

**Fix now** — see Copy-Paste blocks below (nginx / Cloudflare / static host).

### 🟡 Improve — CSP present but `script-src 'unsafe-inline'`

```
Findings:
🟡 CSP script-src allows 'unsafe-inline' — move to nonce or hash; start with Content-Security-Policy-Report-Only
🟢 HSTS present (max-age ≥ 31536000)
🟢 frame-ancestors 'none' present
🟢 ACAO allowlisted (no wildcard)
```

### 🟢 OK — baseline locked

```
Findings:
🟢 CSP default-src 'self'; script-src with nonce
🟢 HSTS max-age=31536000; includeSubDomains
🟢 X-Frame-Options: DENY + frame-ancestors 'none'
🟢 ACAO explicit allowlist (or omitted for same-origin HTML)
🟢 nosniff + Referrer-Policy + Permissions-Policy present
```

---

## Copy-Paste fixes

### A) nginx

```nginx
# /etc/nginx/conf.d/security-headers.conf  (include from server {})
add_header Content-Security-Policy "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

# CORS — allowlist only (example). Do NOT use *.
map $http_origin $cors_origin {
    default "";
    "~^https://(www\.)?example\.com$" $http_origin;
    "~^https://app\.example\.com$" $http_origin;
}
# Inside location /api/ :
#   add_header Access-Control-Allow-Origin $cors_origin always;
#   add_header Vary "Origin" always;
```

Tighten `script-src` with a per-response nonce once your templates support it:

```nginx
# After you inject nonce="$csp_nonce" on <script> tags:
# add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$csp_nonce'; object-src 'none'; frame-ancestors 'none'" always;
```

### B) Cloudflare (Transform Rules / Response Header Transform)

Dashboard → **Rules** → **Transform Rules** → **Modify Response Header** → create rule matching your zone:

| Action | Header | Value |
|--------|--------|-------|
| Set | `Content-Security-Policy` | `default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'` |
| Set | `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| Set | `X-Frame-Options` | `DENY` |
| Set | `X-Content-Type-Options` | `nosniff` |
| Set | `Referrer-Policy` | `strict-origin-when-cross-origin` |
| Set | `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |

For CORS on Workers / API routes, set `Access-Control-Allow-Origin` to a single allowed origin (echo only if it matches your allowlist). Never `*`.

Optional Cloudflare one-liner via Wrangler / API is host-specific; prefer Transform Rules UI for static sites.

### C) Static host (Netlify `_headers` / Cloudflare Pages `_headers` / similar)

```txt
/*
  Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
```

Vercel `vercel.json` equivalent:

```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "Content-Security-Policy", "value": "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'" },
        { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains" },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" }
      ]
    }
  ]
}
```

---

## Rollout tips

1. Ship CSP as `Content-Security-Policy-Report-Only` first; collect violations; then enforce.
2. Add `preload` to HSTS only after every subdomain speaks HTTPS and you accept preload permanence.
3. Prefer CSP `frame-ancestors` for modern browsers; keep `X-Frame-Options: DENY` for defense in depth.
4. Same-origin HTML pages usually need **no** ACAO header at all.
5. Origin allowlists must be exact or label-bounded (see `HDR-CORS-SUFFIX`). Keep cookie values on `Set-Cookie` only — never a JS-readable twin header (`OAUTH-COOKIE-HDR` in playbook 05).

---

*Pre-launch Check · playbook 01 · defense-only*
