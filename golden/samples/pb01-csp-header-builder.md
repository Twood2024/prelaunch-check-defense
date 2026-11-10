# Golden fixture — pb01-csp-header-builder

**id:** `pb01-csp-header-builder`  
**playbook:** 01-headers-csp  
**class:** CSP quality / header builder — untrusted strings must not reach CSP  
**Defense fixture only.** Not a live secret. Not an exploit PoC.

## Fixture (hardening-scan target)

```js
// BAD: request input concatenated into Content-Security-Policy
export function buildCsp(req) {
  const cdn = String(req.query.cdn || "");
  return `default-src 'self'; img-src 'self' ${cdn}`;
}

res.setHeader("Content-Security-Policy", buildCsp(req));
```

## Expected finding shape

| field | value |
|-------|--------|
| id | `F-HDR-001` |
| rule_ref | `HDR-CSP-PRESENT` (CSP quality / header-builder class) |
| severity | `medium` |
| blocking_release | `false` |
| queue_tier | `Warning` |
| target_file | path of the CSP header builder (e.g. `src/security/csp.js`) |
| line_hint | builder function / `setHeader("Content-Security-Policy"` range |
| evidence_snippet | Header builder interpolates request/user strings into CSP. Redact any live values. |
| instruction_for_coder | Use a static CSP (or an allowlist of complete, pre-approved directive values). Reject any dynamic fragment that contains `;` or CR/LF. Never stitch query/body/header input into the CSP string. Prefer nonces/hashes over loosening `script-src`. |
| verify_command | `rg -n 'Content-Security-Policy|content-security-policy' src` plus review that no request field is interpolated into the header. |
| confidence | `high` |
| fix_constraints | Defense-only header change. Do not add exploit tests, do not deploy, do not relax `script-src` to `'unsafe-inline'` or `*` as a shortcut. |

## Notes

A clean fix is a constant policy string (see playbook 01 Copy-Paste CSP) or a vetted builder that only inserts values from a literal allowlist after rejecting `;`, `\r`, and `\n`.
