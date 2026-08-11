# Development guide

## Repository layout

| Path | Purpose |
| --- | --- |
| `app/` | React/vinext console and API routes. |
| `lib/server/` | Authentication, audit, crypto, collectors, jobs, evidence, devices, timestamps, and packages. |
| `db/schema.ts` | Drizzle/D1 schema. |
| `drizzle/` | Ordered SQL migrations and snapshots. |
| `macos/ScopeproofCapture/` | Swift Package for the macOS menu-bar app and native tests. |
| `scripts/` and `Scripts/` | macOS build entry points retained for compatibility. |
| `tests/` | Rendered-product and security regression tests. |
| `.openai/hosting.json` | Logical Sites project, D1, and R2 declarations. |

## Local web development

Requirements: Node.js 22.13 or newer and npm.

```bash
npm install
npm run dev
```

Use `.env.example` as the variable inventory. Keep real values in the local/hosted secret mechanism and never commit `.env` files, provider responses, evidence, device tokens, or private keys.

## Validation

Run before every publication:

```bash
npm run lint
npx tsc --noEmit
npm test
git diff --check
```

`npm test` builds the production Worker bundle, verifies the rendered application/API surface, and runs security regression tests for redaction, audit immutability, native upload validation, assessor packaging, and Jira metadata.

Native tests:

```bash
cd macos/ScopeproofCapture
swift test
```

On machines with multiple developer toolchains, select the full Xcode toolchain through `DEVELOPER_DIR`.

## Change discipline

- Preserve server-side authorization; hiding a control in React is not an access-control decision.
- Treat provider content, capture metadata, filenames, Jira values, and package names as attacker-controlled.
- Use bound SQL parameters and strict size/type limits.
- Never log secrets, decrypted evidence, device tokens, or recognized OCR text.
- Keep original capture manifests immutable; record later decisions in lifecycle/audit records.
- Generate and inspect a forward migration for every D1 schema change.
- Update root, operator, assessor, security, deployment, native, in-app Help, and changelog documentation when behavior or trust boundaries change.

## Native release

Build from the repository root:

```bash
./Scripts/build_macos_capture.sh
```

The app is produced at `DerivedData/Scopeproof Capture.app`. Update `macos/ScopeproofCapture/Resources/Info.plist`, `.env.example`, the changelog, and operator documentation together for a new version. Production releases require Developer ID signing, hardened runtime, notarization, stapling, an HTTPS download, and a separately verified digest.

## Publishing checklist

1. Review the complete diff and confirm no evidence or secrets are present.
2. Run web lint, type checking, production build/tests, native tests, and whitespace validation.
3. Confirm migrations and `.openai/hosting.json` package correctly.
4. Commit the exact validated source.
5. Push to the intended GitHub repository and deploy the same commit to the private Sites project.
6. Verify the deployed application loads and record the release outcome.
