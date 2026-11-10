# Playbook 07 — Vite SPA / PWA / Capacitor

**Audience:** Vite + React SPA, `vite-plugin-pwa`, optional Capacitor WebView, on-device MediaPipe  
**Output:** findings → `schemas/finding-report.schema.json`  
**Defense only.** File budget ＜~1500 tokens.  
**Local checks:** each rule lists an optional `rg_pattern` you may run with local `rg` on a tree you are authorized to review. This repository does not ship a scanner or an ignore-file.

---

## RULE_ID: VITE-STATIC-HEADERS
- **Trigger:** Ship path has no `public/_headers` (Pages/Netlify-style) and no equivalent nginx/CF Transform headers; HTML also lacks CSP meta.
- **Risk_1L:** XSS / clickjack / MIME sniff / over-broad Permissions-Policy defaults on first paint.
- **rg_pattern:** `_headers|Content-Security-Policy|X-Frame-Options|Permissions-Policy`
- **Fix_Snippet:**
```txt
# public/_headers  (Cloudflare Pages / Netlify)
/*
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  X-Frame-Options: DENY
  Permissions-Policy: camera=(self), microphone=(), geolocation=()
  Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; frame-ancestors 'none'; connect-src 'self' blob: data:; worker-src 'self' blob:; img-src 'self' data: blob:; media-src 'self' blob:; base-uri 'self'
```
Tighten `connect-src` / `script-src` only after local MediaPipe WASM works offline.
- **Verify:** `test -f public/_headers && rg -n 'Content-Security-Policy' public/_headers`; deployed response shows CSP.

---

## RULE_ID: VITE-MEDIAPIPE-CDN-FALLBACK
- **Trigger:** Pose/WASM loader falls back to `cdn.jsdelivr.net` / `storage.googleapis.com` (or any CDN) when local files missing.
- **Risk_1L:** Supply-chain / integrity drift; offline fail-open to third-party script/model hosts.
- **rg_pattern:** `jsdelivr|cdn\.jsdelivr|storage\.googleapis\.com.*pose_landmarker|CDN_WASM|CDN_MODEL`
- **scan_note:** Skip `**/mediapipe/` `*.wasm` `*.task` blobs; scan loader source only.
- **Fix_Snippet:**
```ts
// Prefer fail-closed in production builds:
if (import.meta.env.PROD) {
  // only LOCAL_WASM + LOCAL_MODEL; surface a UI error if local files are missing
  throw new Error("local_mediapipe_required");
}
// Dev may keep CDN fallback. Pin versions; never load unpinned @latest.
```
Ship `public/mediapipe/**` in the release artifact; document how local WASM/model files are fetched into that directory.
- **Verify:** `rg -n 'jsdelivr|storage.googleapis.com' src`; prod path refuses CDN; local model/WASM files (for example `pose_landmarker_lite.task`) are present in dist/public.

---

## RULE_ID: VITE-PWA-PRECACHE-SCOPE
- **Trigger:** Workbox `globPatterns` include large `.wasm`/`.task` with high `maximumFileSizeToCacheInBytes`, `registerSW({ immediate: true })` in prod.
- **Risk_1L:** Stale model/app shell after security fix; users keep poisoned cache; huge first install.
- **rg_pattern:** `maximumFileSizeToCacheInBytes|registerSW|globPatterns|VitePWA`
- **Fix_Snippet:**
```ts
// vite.config.ts — prefer versioned URLs + skipWaiting carefully
VitePWA({
  registerType: "prompt", // or show update UI; avoid silent immediate if model changes
  workbox: {
    globPatterns: ["**/*.{js,css,html,ico,png,svg}"], // keep .wasm/.task out of precache OR bump cache name on every model change
    navigateFallbackDenylist: [/^\/api/],
  },
})
```
- **Verify:** `rg -n 'maximumFileSizeToCacheInBytes|registerSW|globPatterns' vite.config.ts src/main.tsx`; after model bump, old SW does not serve previous `.task`.

---

## RULE_ID: VITE-LOCALSTORAGE-VALIDATE
- **Trigger:** `JSON.parse(localStorage.getItem(...))` into typed objects with only a shallow field check (or none).
- **Risk_1L:** Corrupt / injected storage shapes break app logic; future XSS if values ever render as HTML.
- **rg_pattern:** `localStorage\.getItem|JSON\.parse\(.*localStorage`
- **Fix_Snippet:**
```ts
function parseStoredState(raw: string): Record<string, StoredItem> | null {
  const data = JSON.parse(raw);
  if (!data || typeof data !== "object") return null;
  // validate each item: finite numbers only; reject unexpected keys / strings used in DOM
  return sanitized;
}
// Never innerHTML / dangerouslySetInnerHTML from storage fields.
```
- **Verify:** `rg -n 'localStorage|JSON.parse' src`; no DOM sink of storage strings; bad JSON returns null.

---

## RULE_ID: VITE-CAMERA-HARDENING
- **Trigger:** `getUserMedia({ video: … })` without matching Permissions-Policy / stop-on-unmount; or mic requested unused.
- **Risk_1L:** Over-broad device access; leaked tracks if navigation abandons page.
- **rg_pattern:** `getUserMedia|getTracks\(\)\.forEach|facingMode|Permissions-Policy.*camera`
- **Fix_Snippet:**
```ts
// audio: false; stop all tracks on unmount / route leave
useEffect(() => () => streamRef.current?.getTracks().forEach((t) => t.stop()), []);
// Headers: Permissions-Policy: camera=(self), microphone=()
```
- **Verify:** `rg -n 'getUserMedia|getTracks\\(\\)\\.forEach' src`; Permissions-Policy camera scoped; mic denied if unused.

---

## RULE_ID: CAP-CONFIG-REVIEW
- **Trigger:** `@capacitor/*` in package.json but missing `capacitor.config.*`, or config allows cleartext / wide `allowNavigation` / `android:usesCleartextTraffic=true`.
- **Risk_1L:** WebView loads unexpected origins; MITM on cleartext.
- **rg_pattern:** `@capacitor/|capacitor\.config|allowNavigation|usesCleartextTraffic|cleartext`
- **scan_note:** `android/` / `ios/` platform trees may be noisy; still require `capacitor.config.*` when Capacitor dependencies exist.
- **Fix_Snippet:**
```ts
// capacitor.config.ts
server: { androidScheme: "https" } // no cleartext
// allowNavigation: explicit https hosts only — never "*"
```
AndroidManifest: no `usesCleartextTraffic="true"` unless documented debug-only.
- **Verify:** `rg -n 'allowNavigation|cleartext|usesCleartextTraffic' capacitor.config.* android/;` package has Cap ⇒ config file exists.

---

## RULE_ID: VITE-THIRD-PARTY-ORIGIN
- **Trigger:** `index.html` pulls fonts/scripts from third parties (fonts.googleapis.com, analytics) while CSP/`_headers` absent or allowlist too wide.
- **Risk_1L:** Extra exfil / script surface; CSP bypass via style CDN.
- **rg_pattern:** `fonts\.googleapis|fonts\.gstatic|googletagmanager|analytics\.js|gtag\(`
- **Fix_Snippet:**
Self-host fonts under `public/fonts/` and drop Google Fonts `<link>`; or keep CDN only with matching CSP `style-src` / `font-src` allowlist.
- **Verify:** `rg -n 'fonts.googleapis|googletagmanager|analytics' index.html`; CSP matches or links removed.
