# Changelog
All notable changes follow [Keep a Changelog](https://keepachangelog.com) and [SemVer](https://semver.org).

## [Unreleased]

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