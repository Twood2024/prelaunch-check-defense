# Golden fixture — pb02-redirect-cred-headers

**id:** `pb02-redirect-cred-headers`  
**playbook:** 02-config-secrets (session cookies also 05-oauth-pkce-session)  
**class:** outbound HTTP client — do not forward credential headers across origins on redirect  
**Defense fixture only.** Not a live secret. Not an exploit PoC.

## Fixture (hardening-scan target)

```js
// BAD: same header bag reused on every hop, including Authorization / Cookie
// (array-form or duplicated header names must be stripped too)
export async function fetchFollow(url, headers) {
  const res = await rawRequest(url, { headers });
  const location = res.headers.location || res.headers.Location;
  if (res.status >= 300 && res.status < 400 && location) {
    return fetchFollow(new URL(location, url).toString(), headers);
  }
  return res;
}
```

## Expected finding shape

| field | value |
|-------|--------|
| id | `F-SEC-001` |
| rule_ref | `SEC-REDIRECT-CRED-HEADERS` (sample-local class name; pb02 secrets hygiene / pb05 cookie confidentiality) |
| severity | `medium` |
| blocking_release | `false` |
| queue_tier | `Warning` |
| target_file | path of the HTTP helper (e.g. `src/lib/http.js`) |
| line_hint | redirect-follow function range |
| evidence_snippet | Redirect follow reuses the original header bag (Authorization / Cookie, including array-form names) toward a new origin. Do not print live token values. |
| instruction_for_coder | On a cross-origin redirect, drop `Authorization`, `Cookie`, `Cookie2`, `Proxy-Authorization`, and any array-form / duplicate names of those headers before the next request. Keep credentials only when the next URL is same-origin (or an explicit allowlist). Prefer a maintained client that already strips these; still review array-form header handling. |
| verify_command | `rg -n 'Authorization|Cookie|follow|maxRedirects' src` and a same-origin vs cross-origin redirect review (headers on the second hop must not include credentials). |
| confidence | `high` |
| fix_constraints | Client-side redirect hygiene only. Do not log or fixture live credentials. No deploy. Do not weaken TLS or disable redirect limits to “make tests pass”. |

## Notes

Session cookies set by your own app remain playbook 05 (`HttpOnly` / no JS-readable twin headers). This fixture is about **outbound** clients leaking those headers to a different host after a 3xx.
