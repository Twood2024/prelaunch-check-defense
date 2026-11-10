# PROBLEMS — What Pre-launch Check covers

**EN** · **ZH** short list. Defense-only reference.

專為 Vibe-Coded App（Cursor / Windsurf / v0 等）出街前覆核關鍵設定、安全標頭、路由入口同 AI 系統提示。

---

## Problems this pack targets

| # | EN | ZH |
|---|----|----|
| 1 | **Missing security headers** (CSP / HSTS / X-Frame-Options / CSP `frame-ancestors`) | **缺安全標頭**（CSP / HSTS / XFO / `frame-ancestors`） |
| 2 | **Over-open CORS** — `Access-Control-Allow-Origin: *` on credentialed or private APIs | **CORS 過寬** — API 上 `ACAO: *` |
| 3 | **`.env` / secrets leak** on static host publish dir or in a public repo | **`.env`／密鑰外洩**（靜態站或公開 repo） |
| 4 | **`robots.txt` / `security.txt` return SPA HTML** instead of `text/plain` | **`robots.txt`／`security.txt` 回 SPA HTML**（非 text/plain） |
| 5 | **API open-by-default** — unknown routes/methods allowed; weak or missing authz | **API 預設全開** — 未知路由／方法無 authz |
| 6 | **Prompt injection on AI wrappers** — raw user text in system prompt, open tools, no output filter | **AI wrapper 提示注入** — 系統提示混用、工具過寬、無輸出過濾 |
| 7 | **Cloud scanners friction** — login walls, false refuse, data leaving the machine → need **copy-paste hardening fixes** | **雲端掃描摩擦** — 登入牆、誤拒、資料離機 → 需要**可貼上嘅硬化修補** |

---

## Non-goals（不做／不承諾）

| EN | ZH |
|----|----|
| Not an antivirus product | 不是防毒軟體 |
| Not 0-day hunting | 不做 0-day 獵捕 |
| Not a pentest / “zero vuln” guarantee | 不是滲透測試／「零漏洞」保證 |
| Not an always-on GUI monitor | 不是常駐 GUI 監控 |
| **Not a Full-Repo SAST Scanner** — only key configs, route entry points, and AI system prompts (Configs / Headers / System Prompts) | **唔做巨型 Repo 全庫源碼審計**；只睇關鍵設定檔、路由入口、AI 提示詞（Configs / Headers / System Prompts） |
| No attack recipes / red-team dual track | 不含攻擊劇本／紅隊雙軌 |
| This repository does not include model weights or runners, and does not promise weight updates | 本倉庫不含模型權重或 runners，亦不承諾權重更新 |
| This repository is not an installer or a vendor support desk | 本倉庫不是安裝程式，亦不是廠商客服 |

---

## How the pack answers them

1. Open the matching playbook (`01` headers · `02` config/secrets · `03` prompt-injection · and 04–07 as the target requires).
2. Shape findings with `schemas/finding-report.schema.json` (id, severity, evidence without secrets, fix, verify).
3. Prefer 🔴 / 🟡 / 🟢 findings plus a copy-paste hardening patch the owner can apply (nginx / Cloudflare / static / wrapper code).
4. Verify the fix on a system you are authorized to secure (config review, local `rg`, or `curl -sI`). Do not verify by attacking.

---

*Pre-launch Check · defense-only reference · Vibe-Coded Apps pre-launch check*
