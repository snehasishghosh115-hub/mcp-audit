# Changelog
All notable changes follow [Keep a Changelog](https://keepachangelog.com) and [SemVer](https://semver.org).

## [Unreleased]

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