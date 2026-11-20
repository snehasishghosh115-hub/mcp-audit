# Changelog
All notable changes follow [Keep a Changelog](https://keepachangelog.com) and [SemVer](https://semver.org).

## [1.0.1] - 2026-11-20
### Fixed
- **engine/run.ts**: Rule engine no longer overwrites per-finding severity with the rule's static default severity. This restores MCPA-SEC-014's dynamic medium-severity downgrade for read-only auto-approve tool lists.
- **tsup.config.ts**: Shebang (`#!/usr/bin/env node`) is now scoped only to `cli.js`; library outputs (`index.js`, `index.cjs`) no longer include it, preventing bundler breakage for downstream consumers.
- **sec-004-unpinned-package.ts**: Fixed wrong location index for `pnpm dlx` / `yarn dlx` packages in position tracking.
- **sec-005-floating-version.ts**: Pre-release semver versions like `pkg@1.0.0-beta.1` are no longer falsely flagged as floating branch names.
- **discovery/clients.ts**: `findProjectRoot` now correctly terminates on Windows (`parent === current` check instead of hardcoded `'/'`).
- **discovery/discover.ts**: Explicit paths are resolved with `resolve()` instead of `join()`, handling absolute paths correctly on all platforms.
- **introspect/index.ts**: `PATH` entries are now split with `path.delimiter` instead of hardcoded `':'`, fixing command resolution on Windows.
- **reporters/text.ts**: Header line now shows the actual `VERSION` constant instead of a hardcoded `'0.1.0-alpha'` fallback.
### Added
- **test/edge-cases.test.ts**: 28 new edge-case tests covering all fixed bugs plus boundary conditions (pre-release semver, allowRemoteHosts subdomain matching, evidence redaction, severity sort order, ignore specificity).
- **README.md**: Comprehensive user documentation including full CLI flags reference, rules table, configuration guide, CI examples (GitHub Actions + pre-commit), programmatic TypeScript API with types, custom rule authoring guide, AI explanations, live introspection, and privacy guarantees.

## [Unreleased]

## [0.4.0] - 2024-11-20
### Added
- AI explanations (`--explain` flag) with Anthropic and OpenAI provider support:
  - Provider auto-detection (prefers Anthropic, falls back to OpenAI)
  - Explicit provider selection via `--provider anthropic|openai|auto`
  - Custom model via `--model` or `MCP_AUDIT_MODEL` env
  - `--dry-run` flag to preview the prompt sent to AI
  - Explanations built from redacted findings only (no secrets, paths, env values)
  - Graceful degradation: clear error if no API key configured

## [0.3.0] - 2024-10-15
### Added
- Introspection (`--introspect` flag) to start/connect to MCP servers and fetch live tool definitions:
  - stdio transport support (JSON-RPC 2.0 over stdin/stdout)
  - HTTP/SSE transport support (Streamable HTTP and SSE fallback)
  - Safety: confirmation prompt, `--yes` flag, 10s timeout per server
  - Sanitized environment (only PATH, HOME, etc. + server's own env)
  - Process cleanup on exit/timeout
- Tool rules (MCPA-TOOL-001..003) run on live tool definitions from introspection
- Introspection errors are reported but don't stop static analysis

## [0.2.0] - 2024-XX-XX
### Added
- GitHub Action (`action.yml`) for CI integration with SARIF upload
- Pre-commit hook (`.pre-commit-hooks.yaml`) for local git integration
- Example CI workflow (`docs/examples/ci.yml`)
- Example pre-commit config (`docs/examples/pre-commit-config.yaml`)

## [0.1.0] - 2024-XX-XX
### Added
- P1 security rules:
  - MCPA-SEC-010: Typosquat detection for known MCP packages
  - MCPA-SEC-016: Risky remote hosts (raw IPs, tunnel hosts)
- Tool analysis rules (require --tools or --introspect):
  - MCPA-TOOL-001: Prompt-injection phrasing in tool descriptions
  - MCPA-TOOL-002: Hidden/invisible Unicode in tool names/descriptions
  - MCPA-TOOL-003: Tool name collision/shadowing across servers
- `--tools` flag to audit saved tools/list JSON output
- Levenshtein-based typosquat detection with trustedPackages config
- Known MCP package list in `src/rules/data/known-packages.ts`

## [0.1.0-rc] - 2024-XX-XX
### Added
- SARIF 2.1.0 schema validation test
- All three reporters (text, JSON, SARIF) verified working end-to-end

## [0.1.0-beta] - 2024-XX-XX
### Added
- P0 security rules (MCPA-SEC-001 through MCPA-SEC-009, MCPA-SEC-014, MCPA-SEC-015):
  - MCPA-SEC-001: Hardcoded secret detection in env, args, headers with redaction
  - MCPA-SEC-002: Secret embedded in URL (userinfo, query params)
  - MCPA-SEC-003: Plaintext HTTP for non-localhost remotes
  - MCPA-SEC-004: Unpinned package via npx/uvx/bunx/pipx/dlx
  - MCPA-SEC-005: Floating versions (latest, next, ranges, branches)
  - MCPA-SEC-006: Shell wrapper detection (sh -c, bash -c, cmd /c, powershell -c)
  - MCPA-SEC-007: Download-and-execute patterns (curl|sh, iex irm)
  - MCPA-SEC-008: Broad filesystem access (/, ~, drive roots)
  - MCPA-SEC-009: Dangerous Docker flags (--privileged, docker.sock, --network host)
  - MCPA-SEC-014: Blanket auto-approve (autoApprove: ["*"], trust: true)
  - MCPA-SEC-015: World/group-readable config files with secrets (POSIX)
- Secret detection with pattern matching + entropy heuristic + env-reference allowance
- Redaction utility for all evidence fields
- Test fixtures for good/bad configs per client
- Unit tests for all P0 rules (≥3 positive and ≥3 negative cases each)
- No raw secrets in any output (verified by tests)

## [0.1.0-alpha] - 2024-XX-XX
### Added
- JSONC parser with position tracking (`src/parse/jsonc.ts`)
- Client discovery for Claude Desktop, Claude Code, Cursor, VS Code, Windsurf (`src/discovery/`)
- Normalization to `ServerEntry` (`src/parse/normalize.ts`)
- Rule engine skeleton (`src/engine/run.ts`)
- Config loader with validation (`src/config/index.ts`)
- Reporters: text, JSON, SARIF (`src/reporters/`)
- Secret detection utilities (`src/util/secrets.ts`, `src/util/redact.ts`)
- File system utilities (`src/util/fs.ts`)
- CLI commands: scan, rules, explain, init
- Full test suite with lint, typecheck, test passing

## [0.0.1] - 2024-XX-XX
### Added
- Project scaffolding: package.json, tsconfig.json, tsup.config.ts, vitest.config.ts
- ESLint + Prettier configuration
- CI workflow (GitHub Actions) with matrix testing on ubuntu/macos/windows x Node 18/20/22
- Core types in `src/types.ts` (Severity, ClientId, Transport, ServerEntry, Finding, Rule, ScanResult, etc.)
- CLI entry point `src/cli.ts` with version and help commands
- Public API entry point `src/index.ts`
- MIT License, .gitignore, .editorconfig, .nvmrc
- Basic smoke test