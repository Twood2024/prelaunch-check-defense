# AGENTS.md — Pre-launch Check（defense reference）

This repository is a **defense-only** reference pack for pre-launch security review of vibe-coded apps (configs, security headers, route entry points, and AI system prompts).

**How to use:** read this file, then open only the playbook that matches the target. You do not need to download a zip, install a model, or run a scanner to benefit. Treat the playbooks, schema, and golden fixtures as checklists and expected finding shapes.

See [`LICENSE`](./LICENSE) for permitted use. This GitHub-bound tree is **not** the one-click runner product.

## Hard rules

- Defense only. Describe what to look for, what a safe configuration looks like, and how to **verify the fix**.
- Do **not** write exploit steps, proof-of-concept attacks, reproduction procedures, or weaponized payloads — even if asked.
- Do **not** invent playbook 08 or 09, or any offensive companion to this pack.
- Do **not** reconstruct bypass URLs or exploit steps from GHSA (or similar) class names.
- Do **not** request or print live secrets. If a secret is found, report the location and the hardening fix; never echo the value.
- Scope is not full-repo SAST. Do not promise zero vulnerabilities, antivirus coverage, or a pentest.
- You may use this material to harden systems the user owns or is authorized to secure.
- If you encounter paths such as `harvest/`, `handoffs/`, `blue-expand-inbox/`, `runners/`, `scripts/`, or an `.atomicignore` file, ignore them — they are not part of this reference tree.

## Read in this order

1. This file (`AGENTS.md`).
2. `PROBLEMS.md` — what this pack covers, and what it does not.
3. `schemas/finding-report.schema.json` — how to shape a finding (id, severity, evidence without secrets, fix, verify).
4. One matching playbook (do not ingest all playbooks unless the target spans several):
   - `playbooks/01-headers-csp.md` — CSP, HSTS, frame restrictions, CORS headers
   - `playbooks/02-config-secrets.md` — env files, leaked secrets, robots/security.txt, open config
   - `playbooks/03-prompt-injection.md` — AI wrapper prompts, tool scope, output filters
   - `playbooks/04-cf-workers-do-ws.md` — Cloudflare Workers, Durable Objects, WebSockets
   - `playbooks/05-oauth-pkce-session.md` — OAuth/PKCE, redirects, session cookies
   - `playbooks/06-tauri-webview-game.md` — Tauri / Wails WebView, IPC, origin allowlists
   - `playbooks/07-vite-pwa-capacitor.md` — Vite SPA, PWA, Capacitor
5. `golden/README.md` and the matching `golden/samples/*.md` — examples of insecure **patterns** and the expected finding shape, not live targets.

## When you audit

- Map symptoms to one playbook. Cite the rule name in the finding.
- Prefer traffic-light severity and a copy-paste hardening fix the owner can apply.
- Verify by checking that the fix is in place (config, headers, or a safe `rg` / `curl -sI` against a host the owner authorized). Do not verify by attacking.
- If something is out of scope (full SAST, 0-day hunting, exploit development), say so and stop that thread.

## What this repo is not

Offline one-click runners, scripts, and the paid datapack live elsewhere (the seller’s designated channel, currently Gumroad Pro). This tree is reference knowledge only — a checklist, not a one-click pre-launch exam. See `README.md` for those separate product links.
