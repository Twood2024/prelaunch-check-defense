# Golden fixture — pb07-vite-fs-deny

**id:** `pb07-vite-fs-deny`  
**playbook:** 07-vite-pwa-capacitor (env files also 02-config-secrets)  
**class:** Vite dev-server filesystem deny — denied paths must stay denied even when the request carries a module query suffix; do not network-expose the dev server (GHSA-8g5g-mxqh-grgj class)  
**Defense fixture only.** Not a live secret. Not an exploit PoC.

## Fixture (hardening-scan target)

```js
// BAD: dev server is network-exposed while .env / .git are only "protected"
// by server.fs.deny. A deny list that ignores module query suffixes
// (raw / import transforms) can still serve those paths.
import { defineConfig } from "vite";

export default defineConfig({
  server: {
    host: true, // 0.0.0.0 — LAN/WAN reachable dev server
    fs: {
      deny: [".env", ".env.*", "**/.git/**"],
    },
  },
});
```

## Expected finding shape

| field | value |
|-------|--------|
| id | `F-VITE-001` |
| rule_ref | `VITE-FS-DENY` (sample-local class name; pb07 dev-server fs.deny / partial pb02 env-file hygiene) |
| severity | `medium` |
| blocking_release | `false` |
| queue_tier | `Warning` |
| target_file | path of the Vite config (e.g. `vite.config.ts` / `vite.config.js`) |
| line_hint | `server.host` / `server.fs.deny` range |
| evidence_snippet | Dev server is bound beyond localhost while relying on `server.fs.deny` alone. Denied paths (`.env`, `.git`) may still be served when a request uses a module query suffix. Do not print env file contents. |
| instruction_for_coder | Bind the Vite dev server to localhost only (`server.host` unset, or explicit `localhost` / `127.0.0.1`). Keep `server.fs.deny` for `.env`, `.env.*`, and `.git`. Treat module query suffixes as in-scope for the deny list (do not strip the query and then serve the path). Do not commit `.env`. Do not expose the dev server on LAN/WAN. |
| verify_command | `rg -n 'host:\s*true|server\.host|fs:\s*\{?\s*deny' vite.config.*` plus confirm the dev server listens on localhost only; `.env` is gitignored and not committed. |
| confidence | `high` |
| fix_constraints | Defense-only bind-address / fs.deny / gitignore hygiene. Do not add exploit tests, do not deploy, do not log or fixture live env values. Upgrade Vite past GHSA-8g5g-mxqh-grgj as a verify tip — the localhost bind and deny coverage are the controls, not “upgrade only”. |

## Notes

Partial playbook 02: a served `.env` is an env-secret leak (`SEC-ENV-COMMITTED` / `SEC-VITE-PUBLIC-LEAK` class). This fixture does **not** add a playbook 07 RULE (golden_sample only).
