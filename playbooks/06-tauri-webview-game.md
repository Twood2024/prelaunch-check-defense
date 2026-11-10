# Playbook 06 — Tauri / Wails WebView

**Audience:** Tauri / Wails WebView apps (optional multiplayer or game-integrity checks)  
**Output:** finding-report JSON  
**Defense only.** File budget ＜~1500 tokens.  
**Local checks:** each rule lists an optional `rg_pattern` you may run with local `rg` on a tree you are authorized to review. This repository does not ship a scanner or an ignore-file.

---

## RULE_ID: TAURI-CSP-SET
- **Trigger:** `tauri.conf.json` → `app.security.csp` is `null` / missing while web host has CSP.
- **Risk_1L:** Desktop XSS / malicious dependency has full WebView blast radius.
- **rg_pattern:** `"csp"\s*:\s*null|security\.csp|opener:default`
- **scan_note:** Skip `src-tauri/target/` build output; scan `tauri.conf.json` / capabilities only.
- **Fix_Snippet:**
```json
{
  "app": {
    "security": {
      "csp": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; frame-ancestors 'none'; connect-src 'self' ipc: http://ipc.localhost https://YOUR_HOST wss://YOUR_HOST"
    }
  }
}
```
Also drop unused `opener:default` from capabilities.
- **Verify:** `rg '"csp"\\s*:\\s*null' src-tauri` empty; packaged conf shows non-null csp.

---

## RULE_ID: GAME-HOST-ONLY-START
- **Trigger:** Any joined peer can call `start*` / begin match.
- **Risk_1L:** Griefing / forced restarts; integrity abuse.
- **rg_pattern:** `assertHost|host only|hostId|handleStart`
- **Fix_Snippet:**
```ts
// First successful join sets hostId (or explicit transfer)
function assertHost(ws) {
  if (peerId(ws) !== hostId) { send(ws, { type: "error", message: "host only" }); return false; }
  return true;
}
// every handleStart* begins with assertHost
```
- **Verify:** Non-host start → `host only`; host start proceeds.

---

## RULE_ID: GAME-UNICAST-PRIVATE
- **Trigger:** Private role/word/dice/strokes broadcast on room channel.
- **Risk_1L:** Spectators or opponents learn hidden information.
- **rg_pattern:** `UNICAST|dealWordPrivate|toPublicState|SPECTATOR|send\(ws`
- **Fix_Snippet:**
```ts
// send private payload only to target WebSocket (UNICAST)
// public state scrubbed: no words/roles/dice arrays
// late join → SPECTATOR without private fields
```
- **Verify:** Code review: private events use per-ws send; public snapshot has no secret fields; mid-join spectator path exists.

---

## RULE_ID: GAME-RATE-LIMIT
- **Trigger:** No limits on join / chat / stroke (or equivalent) floods.
- **Risk_1L:** DoS of DO / UI jank / spam.
- **rg_pattern:** `RateLimiter|rateLimit\.allow|rateLimited|token-bucket|429`
- **Fix_Snippet:**
```ts
// Worker: IP token-bucket on /auth/* and /room/create
// DO: per-user join ~30/min, chat ~40/min, stroke ~120/min → 429 / error
```
- **Verify:** Burst chat/strokes → throttle; document the limits in your operations notes or this playbook.

---

## RULE_ID: GAME-STROKE-BOUNDS
- **Trigger:** Stroke color/points unbounded or stringy script sinks.
- **Risk_1L:** Payload bloat; future XSS if color rendered unsafely.
- **rg_pattern:** `stroke|points\.length|dangerouslySetInnerHTML|strokeStyle|color.*slice`
- **Fix_Snippet:**
```ts
// points.length ≤ 64 (or similar); color allowlist hex / palette only
// render via canvas APIs — no innerHTML of stroke fields
```
- **Verify:** Oversized batch rejected; React tree has no dangerouslySetInnerHTML on user fields.

---

## RULE_ID: TAURI-ORIGIN-BOUND
- **Trigger:** Desktop webview / bindings origin allowlist uses a trailing `*` or prefix/suffix match without a host label boundary (Wails `BindingsAllowedOrigins`, Tauri remote-domain / CSP host lists).
- **Risk_1L:** A look-alike host can invoke native bindings.
- **rg_pattern:** `BindingsAllowedOrigins|AllowedOrigins|dangerousRemoteDomainIpcAccess|startsWith\(.*origin|https?://[^\s"']+\*`
- **Fix_Snippet:**
```json
// Exact origins only (scheme + host + port). If a subdomain wildcard is required,
// allow host === "example.com" OR host.endsWith(".example.com") — never "https://example.com*".
```
Also see playbook 01 `HDR-CORS-SUFFIX`.
- **Verify:** `rg` on Wails/Tauri origin lists shows no trailing host `*`; allowlist is exact or label-bounded.

---

## RULE_ID: TAURI-IPC-FRAME
- **Trigger:** IPC / bindings origin checks use only the top-level WebView URI, not the calling frame (Wails Linux WebKitGTK OriginValidator).
- **Risk_1L:** A cross-origin or sandboxed iframe can call bound Go / Rust / runtime IPC.
- **rg_pattern:** `OriginValidator|ExpectedWebViewHost|BindingsAllowedOrigins|iframe|frame.?origin|ipc`
- **Fix_Snippet:**
```
// Validate the calling frame origin (not only the top-level WebView URI).
// Do not embed untrusted / sandboxed iframes that can reach the IPC bridge.
// Wails: upgrade to ≥ 2.17.1 (frame guard + ExpectedWebViewHost). Same-origin child
// frames may still share the bridge — keep those first-party only.
```
- **Verify:** Packaged WebView has no unexpected iframes; Wails ≥ 2.17.1 (or equivalent Tauri capability isolation); IPC allowlist is exact-origin.

---

## RULE_ID: TAURI-WS-ORIGIN
- **Trigger:** Desktop IPC WebSocket (Wails dev or v3 server) accepts upgrades without an exact Origin allowlist (any-origin, `*`, or a missing Origin check).
- **Risk_1L:** A foreign web origin can attach to the local IPC socket and call bound backend methods.
- **rg_pattern:** `BindingsAllowedOrigins|AllowedOrigins|CheckOrigin|Upgrade.*[Ww]eb[Ss]ocket|wails.*[Ii]pc|Origin.*["']\*["']`
- **Fix_Snippet:**
```go
// Exact Origin allowlist on the IPC WebSocket handshake (scheme + host + port).
// Reject a missing Origin and any host not in the list. Bind the IPC socket to loopback only.
// Wails: set BindingsAllowedOrigins / server origin list to the app origin(s) only — never "*".

func ipcOriginAllowed(origin string, allow []string) bool {
  if origin == "" {
    return false
  }
  for _, a := range allow {
    if origin == a {
      return true
    }
  }
  return false
}
// allow := []string{"http://wails.localhost", "https://wails.localhost"}
```
- **Verify:** A handshake from a non-allowlisted Origin is refused; the IPC socket is loopback-only; `rg` shows no `*` origin list. Wails: confirm a release that covers GHSA-qg59-r6hv-pvm6 / GHSA-cv6g-2vcq-wcvx as a **verify tip** — the allowlist and loopback bind are the controls, not “upgrade only”.
