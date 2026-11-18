# Changelog
All notable changes follow [Keep a Changelog](https://keepachangelog.com) and [SemVer](https://semver.org).

## [Unreleased]

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