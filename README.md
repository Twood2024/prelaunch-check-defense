# Pre-launch Check — defense reference

**EN** · **繁體中文**

This repository is a **defense-only checklist and reference** for pre-launch review of vibe-coded apps (configs, security headers, route entry points, and AI system prompts).

It is **not** a one-click pre-launch exam, scanner, or installer. There is no zip, no runner, and no model to install here. Agents should start at [`AGENTS.md`](./AGENTS.md).

本倉庫係純防禦檢查清單／參考包，用嚟做出街前安全覆核。**唔係**一鍵體檢、掃描器或安裝包；呢度無 zip、無 runner、亦唔使裝模型。Agent 請先讀 [`AGENTS.md`](./AGENTS.md)。

## Teach your bot / 教你的 Bot

Paste this to your agent (replace nothing once the repo is public):

把下面幾句貼給你的 Bot 即可：

```
Read https://github.com/Twood2024/prelaunch-check-defense — start at AGENTS.md, then open only the matching playbook. Use it as a defense-only pre-launch checklist: report issues in the finding format and suggest hardening plus how to verify the fix. Do not write exploit steps, PoCs, bypass URLs, or attack payloads.

請閱讀 https://github.com/Twood2024/prelaunch-check-defense ，先讀 AGENTS.md，再按目標只打開對應 playbook。把它當成純防禦的上線前檢查清單：用 findings 格式寫出問題，只建議加固方法與如何驗證修復。不准寫攻擊步驟、PoC、繞過網址或利用鏈。
```

## For agents


Read `AGENTS.md` first, then `PROBLEMS.md`, the finding schema, and only the playbook that matches the target. Golden fixtures show insecure **patterns** and the expected finding shape — not live targets.

請先讀 `AGENTS.md`，再讀 `PROBLEMS.md`、finding schema，同對應嘅一份 playbook。golden 係不安全**模式**同 finding 格式示例，不是真實目標。

## Playbooks (01–07)

1. `playbooks/01-headers-csp.md` — CSP, HSTS, frame restrictions, CORS headers
2. `playbooks/02-config-secrets.md` — env files, leaked secrets, robots/security.txt, open config
3. `playbooks/03-prompt-injection.md` — AI wrapper prompts, tool scope, output filters
4. `playbooks/04-cf-workers-do-ws.md` — Cloudflare Workers, Durable Objects, WebSockets
5. `playbooks/05-oauth-pkce-session.md` — OAuth/PKCE, redirects, session cookies
6. `playbooks/06-tauri-webview-game.md` — Tauri / Wails WebView, IPC, origin allowlists
7. `playbooks/07-vite-pwa-capacitor.md` — Vite SPA / PWA / Capacitor

An older combined draft (formerly numbered 04) was split into playbooks 04, 05, and 06. That stub is not in this tree.

舊版合併稿（曾經叫 04）已拆成 playbook 04／05／06；本樹不含該過時檔。

## Optional runnable packs (separate product)

If you want a **local one-click / offline runner**, that is a different product, sold separately:

- Pro (US$9): https://ksworkshop.gumroad.com/l/liaexq
- Free trial ($0): https://ksworkshop.gumroad.com/l/bkdimo

Runners, scripts, and model files are **not** in this repository.

若需要本機一鍵／離線 runner，嗰份係分開嘅產品（唔喺呢個倉庫）：Pro（US$9）同上面 Free 試跑（$0）連結。runners、腳本同模型檔不在本倉庫。

## License

See [`LICENSE`](./LICENSE). Copyright © 2026 Kenneth Studio Workshop (KSWORKSHOP) and Twood.
