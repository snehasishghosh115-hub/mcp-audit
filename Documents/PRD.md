# PRD: mcp-audit

**Status:** Draft v1 · **Owner:** TBD · **Package:** `mcp-audit` (verify name on npm; fallback `@<scope>/mcp-audit`)

## 1. Summary
`mcp-audit` is a zero-config CLI that scans MCP (Model Context Protocol) server configurations and, optionally, live tool definitions for security risks, then reports findings as text, JSON, or SARIF. The core is deterministic and rule-based and runs offline. AI explanations are an opt-in extra.

## 2. Problem
Developers add MCP servers to Claude Desktop, Claude Code, Cursor, VS Code, and Windsurf by copy-pasting JSON from READMEs. Nobody reviews what they are granting. Real risks:
- Secrets hardcoded in config files that get committed or synced.
- Unpinned `npx`/`uvx` packages (supply-chain and rug-pull risk).
- Shell-wrapper commands, `curl | sh`, privileged Docker.
- Filesystem servers rooted at `/` or `~`.
- Plain-HTTP or tunnel-hosted remote servers.
- Tool descriptions that carry prompt injection or hidden Unicode.
- Auto-approve settings that remove the human from the loop.

## 3. Goals
1. `npx mcp-audit` works with no setup and finishes in under 2 seconds on a typical machine (static mode).
2. Auto-discovers configs for the major MCP clients, user-level and project-level.
3. Findings are actionable: each has rule ID, severity, evidence (redacted), file and line, remediation.
4. Fits CI: exit codes, JSON, SARIF 2.1.0, GitHub Action, pre-commit hook.
5. Zero runtime dependencies. Node 18+.
6. Never leaks secrets: evidence is always redacted, and nothing is sent anywhere unless the user opts in.

## 4. Non-goals (v1)
- Not a runtime proxy or firewall.
- Not a vulnerability scanner for the *code* of MCP servers.
- No auto-fix that rewrites user configs (suggest only; `--fix` is a post-v1 idea).
- No hosted service or telemetry.

## 5. Users
| Persona | Need |
|---|---|
| Individual dev using AI IDEs | "Is my setup safe?" in one command |
| Team/security engineer | CI gate over repo `.mcp.json` / `.cursor/mcp.json` |
| MCP server author | Check how their server looks to an auditor, check tool descriptions |

## 6. Functional requirements
| ID | Requirement | Priority |
|---|---|---|
| FR-1 | Discover config files for supported clients (see ARCHITECTURE §Discovery) | P0 |
| FR-2 | Accept explicit paths: `mcp-audit scan <file\|dir>...` | P0 |
| FR-3 | Parse JSON and JSONC (comments, trailing commas) with line/column tracking | P0 |
| FR-4 | Normalize server entries across clients into `ServerEntry` | P0 |
| FR-5 | Run rule catalog (docs/RULES.md) and emit `Finding[]` | P0 |
| FR-6 | Reporters: `text` (default, colored when TTY), `json`, `sarif` | P0 |
| FR-7 | `--fail-on <severity>` sets exit code 1 on findings at or above threshold | P0 |
| FR-8 | Config file `.mcp-audit.json` for ignores, allowlists, thresholds | P1 |
| FR-9 | `scan --tools <file.json>` audits saved `tools/list` output | P1 |
| FR-10 | `scan --introspect` spawns/connects servers to fetch live tool defs (opt-in, loud warning) | P2 |
| FR-11 | `--explain` LLM explanations via BYO API key, with secrets redacted before sending | P2 |
| FR-12 | `rules` command lists rules; `explain <ruleId>` prints rule docs | P1 |
| FR-13 | GitHub Action and `.pre-commit-hooks.yaml` | P1 |
| FR-14 | Programmatic API (`import { scan } from 'mcp-audit'`) | P1 |

## 7. Non-functional requirements
- **Security:** never print raw secret values; never execute anything from configs unless `--introspect`; no network in default mode.
- **Performance:** <2s static scan; <50 MB memory.
- **Compatibility:** Node >=18, macOS, Linux, Windows. ESM + CJS builds, bundled types.
- **Determinism:** same input gives byte-identical JSON/SARIF output (sorted findings).
- **Quality:** >=90% line coverage on rules and parser; CI on 3 OSes and Node 18/20/22.

## 8. Success metrics
- Week 1: published, README with demo GIF, 100+ weekly downloads from launch posts.
- Month 3: listed in awesome-mcp lists, GitHub Action used by external repos, 5k weekly downloads.
- Downloads are an outcome of usefulness. We do not promise 100k. Track via npm and `npm-stat`.

## 9. Risks
| Risk | Mitigation |
|---|---|
| Name taken on npm | Check in Phase 0; scoped fallback |
| False positives annoy users | Severity tuning, `ignore` config, clear remediation, fixtures for good configs |
| MCP client config formats change | Isolate per-client adapters in one file; add fixtures per client |
| `--introspect` runs untrusted code | Opt-in, explicit warning, confirmation prompt unless `--yes`, timeouts, no inherited env except allowlist |

## 10. Open questions
- Support `~/.codex/config.toml` (TOML) in v1.1?
- Offer a `--fix` mode that pins package versions?
