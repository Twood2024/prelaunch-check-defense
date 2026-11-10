# golden/ — defense fixtures

Curated **defense** fixtures and expected finding shapes. **Not** live product secrets. **No** exploit PoCs or red-team corpora.

## Samples

| id | playbook | path |
|----|----------|------|
| `pb01-csp-header-builder` | 01 | `samples/pb01-csp-header-builder.md` |
| `pb02-redirect-cred-headers` | 02 (also 05) | `samples/pb02-redirect-cred-headers.md` |
| `pb07-vite-fs-deny` | 07 (also 02) | `samples/pb07-vite-fs-deny.md` |

See `manifest.json` (`version`, `samples`, `playbooks`).

## Scope

This is a small set (3 fixtures) illustrating finding shape for a subset of playbooks 01–07. More samples may be added later.

## Rules

- Add entries to `manifest.json` `samples` only when a corresponding fixture file is present.
- Fixtures describe insecure **patterns to detect** and the hardening fix — not attack recipes.
- Do not add ready-made bypass URLs or exploit steps, including when a public GHSA class name is cited.
