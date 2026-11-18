# Testing Strategy

- **Runner:** Vitest. `npm test` (unit), `npm run test:cov` (coverage gate: 90% lines on `src/rules`, `src/parse`, `src/util`).
- **Fixtures:** `test/fixtures/<client>/{good,bad}/*.json`. Every rule needs good and bad fixtures. Use obviously fake secrets that still match patterns (generate in test, do not commit real keys; GitHub push protection may flag lookalikes, so build them at runtime via string concatenation).
- **Parser tests:** comments, trailing commas, BOM, CRLF, nested paths, error line/column, huge file (1 MB) under 100ms.
- **Rule tests:** table-driven `[input, expectedRuleIds]`; assert redaction of evidence.
- **Reporter tests:** snapshot text (strip ANSI), JSON schema validation, SARIF validated against the 2.1.0 schema (vendored in `test/schemas/`).
- **Security tests:** (1) run full scan over all bad fixtures and assert no output contains any runtime-built fixture secret; (2) assert default scan never calls `child_process` or `fetch` (mock and assert zero calls).
- **Introspection tests:** `test/fixtures/mock-mcp-server.mjs` implements minimal JSON-RPC; assert timeout, kill, no orphan PIDs.
- **Explain tests:** mock `fetch`; assert request body contains no secrets or file paths.
- **CLI e2e:** spawn built `dist/cli.js` with `--format json` against fixtures; assert exit codes 0/1/2.
- **Cross-platform:** CI matrix ubuntu, macos, windows; Node 18, 20, 22. Path handling must use `node:path`; avoid POSIX-only assumptions except MCPA-SEC-015.
- **Pre-release smoke:** `npm pack`, install the tarball in a temp dir, run `npx mcp-audit --version` and a sample scan.
