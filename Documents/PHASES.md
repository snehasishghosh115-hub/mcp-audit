# Delivery Phases

Each phase ends with: tests green, `npm run lint && npm run typecheck && npm test` passing, a conventional commit, and a CHANGELOG entry. Do not start a phase until the previous one meets its Definition of Done.

## Phase 0: Scaffolding (0.0.x)
**Tasks**
- [ ] Verify package name: `npm view mcp-audit` (404 means free). If taken, use scoped name and update all docs.
- [ ] `git init`, `package.json` (type: module, bin, exports, files, engines >=18), `tsconfig.json` (strict), `tsup.config.ts` (esm+cjs, shebang on cli), `vitest.config.ts`, ESLint + Prettier, `.gitignore`, `.editorconfig`, `LICENSE` (MIT), `.nvmrc`.
- [ ] CI workflow `.github/workflows/ci.yml` (matrix: ubuntu/macos/windows x node 18/20/22).
- [ ] Empty `src/cli.ts` prints version.
**DoD:** `npm run build && node dist/cli.js --version` works; CI green.

## Phase 1: Core engine (0.1.0-alpha)
**Tasks**
- [ ] `src/types.ts` (see ARCHITECTURE).
- [ ] JSONC parser with position tracking (`src/parse/jsonc.ts`) + tests (comments, trailing commas, BOM, errors with line/col).
- [ ] Client adapters + discovery (`src/discovery/*`) for Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, user and project scope; `--path` override.
- [ ] Normalization to `ServerEntry` (stdio/http/sse).
- [ ] Engine: run rules over entries, collect/sort findings, apply ignores.
**DoD:** `scan` on fixtures returns normalized entries and an empty-rule run without crashing; parser branch coverage >=95%.

## Phase 2: Rule catalog (0.1.0-beta)
**Tasks**
- [ ] Implement all P0 rules from docs/RULES.md (MCPA-SEC-001..009, 014, 015), one file each with a good fixture and a bad fixture.
- [ ] Secret detector with pattern list + entropy heuristic + env-reference allowance.
- [ ] Redaction util used by every `evidence` field.
**DoD:** every rule has >=3 positive and >=3 negative tests; no raw secret appears in any output (snapshot test greps for fixture secrets).

## Phase 3: Reporters (0.1.0-rc)
**Tasks**
- [ ] `text` reporter (grouped by file, then server; summary line; color only if TTY and `NO_COLOR` unset).
- [ ] `json` reporter (schema in CLI_SPEC).
- [ ] `sarif` reporter (2.1.0; rules metadata, regions from line/column). Validate against the official SARIF schema in a test.
**DoD:** snapshot tests; SARIF uploads successfully to GitHub code scanning (manual check documented).

## Phase 4: CLI polish (0.1.0)
**Tasks**
- [ ] Commands: `scan` (default), `rules`, `explain <id>`, `init` (creates `.mcp-audit.json`), `--version`, `--help`.
- [ ] Flags per CLI_SPEC; exit codes 0/1/2.
- [ ] `.mcp-audit.json` loading and validation (hand-written validator, no deps).
- [ ] Remaining P1 rules (MCPA-SEC-010, 016) and `--tools` mode with MCPA-TOOL-001..003.
**DoD:** README quickstart verified end to end on a clean machine. **Publish 0.1.0.**

## Phase 5: GitHub Action and pre-commit (0.2.0)
- [ ] `action.yml` (composite action running `npx mcp-audit@<version>`, uploads SARIF).
- [ ] `.pre-commit-hooks.yaml`.
- [ ] Example workflows in `docs/examples/`.
**DoD:** action tested in a throwaway repo; documented in README.

## Phase 6: Introspection (0.3.0)
- [ ] Minimal MCP client over stdio (JSON-RPC 2.0: `initialize`, `notifications/initialized`, `tools/list`) and over HTTP.
- [ ] Safety: confirmation prompt, `--yes`, 10s timeout, sanitized env, kill process tree, never pass user's full env.
- [ ] Rules MCPA-TOOL-001..004 run on live tool definitions.
**DoD:** tested against a bundled mock MCP server fixture; no orphan processes after run.

## Phase 7: AI explain (0.4.0)
- [ ] Provider interface; implementations for Anthropic and OpenAI-compatible endpoints via `fetch`.
- [ ] Prompt built from *redacted* findings only; user sees exactly what will be sent with `--explain --dry-run`.
- [ ] Graceful degradation: no key means a clear message and normal output.
**DoD:** unit tests with mocked fetch; no secrets in request body (test asserts).

## Phase 8: Docs, release, launch (1.0.0)
- [ ] Final README, demo GIF/asciinema, per-rule docs pages, SECURITY.md.
- [ ] Release workflow with npm provenance (docs/RELEASE.md).
- [ ] Launch checklist: Show HN, r/ClaudeAI, r/cursor, MCP Discord, awesome-mcp PRs, a post showing real findings from public repos' `.mcp.json` files (responsibly, no live secrets published).
**DoD:** 1.0.0 on npm with provenance; GitHub release notes; install guide verified via `npx`.

## Phase 9: Post-launch backlog
Codex TOML support, `--fix` (pin versions), baseline file, SBOM-style inventory export, typosquat list updates, Docker image, VS Code extension.
