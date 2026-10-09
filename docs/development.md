# Development and releases

Use Node.js 24+ and npm. Runtime dependencies are limited to YAML and semantic-version parsers; the installed CLI does not require TypeScript or tsx.

```bash
npm ci
npm run check
npm run test:standalone
```

`check` runs ESLint, strict TypeScript checks across source/scripts/tests/config, offline unit and fixture integration tests, the compiled build, and npm package-content verification. `test:standalone` additionally accesses npm to scaffold a fresh app with the pinned official generator, installs a packed scanner into an isolated consumer, runs its real CLI bin, validates JSON against the published schema, checks deterministic findings, and verifies target metadata is unchanged. It never installs or executes application scripts.

| Command | Purpose |
|---|---|
| `npm run lint` | Lint all TypeScript |
| `npm run typecheck` | Type-check source, tests, helpers, and lint config |
| `npm run test:unit` | Rule, environment-parser, and safe-file unit tests |
| `npm run test:integration` | Fixture scans, CLI behavior, redaction, permission checks, and schema validation |
| `npm run build` | Compile runtime code and declarations; mark CLI executable |
| `npm run test:built` | Check compiled CLI policies and block repository fsmonitor execution |
| `npm run pack:check` | Check publish inventory and executable permissions |
| `npm run test:standalone` | Generate app, install packed CLI, save security reports |

GitHub [CI](../.github/workflows/ci.yml) runs separate lint, unit, build, and integration jobs on Node.js 24 and 26. Both standalone jobs use `create-mercato-app@0.8.0`. To test a different generator locally, set `MERCATO_APP_VERSION` to an npm version or tag. Generated reports remain under ignored `reports/standalone-<version>/security.{md,json}`. Do not upload target files or report artifacts.

Every rule must have a stable ID, unit coverage, and a matching `docs/rules/<id>.md` page. Preserve JSON schema version 1 for compatible changes, including additional rule results. Schema consumers must key on IDs rather than array positions. Never echo environment or credential values into evidence or diagnostics.

## Publish

Publishing requires explicit user authorization. Keep the version in `package.json` and `src/scan.ts` synchronized, run the checks, and review the package contents before publication:

```bash
npm run check
npm run test:standalone
npm publish --access public
```

`prepublishOnly` repeats validation and the real standalone-app test. `prepack` builds compiled assets, so a normal pack/publish contains the executable CLI and declarations. Consumers need neither TypeScript nor tsx. The published entry points are `mercato-readiness`, the package's ESM API, and `@open-mercato/readiness-scanner/report.schema.json`.
