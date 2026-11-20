# mcp-audit

<div align="center">

**Security audit for your MCP (Model Context Protocol) servers.**  
One command, zero config, zero runtime dependencies.

[![npm version](https://img.shields.io/npm/v/@snehasishghosh115-hub/mcp-audit.svg)](https://www.npmjs.com/package/@snehasishghosh115-hub/mcp-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

</div>

---

`mcp-audit` scans the MCP server configs used by **Claude Desktop, Claude Code, Cursor, VS Code, and Windsurf** and flags risky setups before they bite:

- 🔑 Hardcoded API keys and secrets
- 📌 Unpinned / floating package versions (`npx pkg` without a version)
- 🌐 Plaintext HTTP to remote servers
- 🐚 Shell wrappers (`bash -c`, `cmd /c`)
- ⬇️ Download-and-execute patterns (`curl | sh`)
- 📂 Overly broad filesystem access (`/`, `~`)
- 🐳 Dangerous Docker flags (`--privileged`, `docker.sock` mount)
- 🤖 Prompt-injection and hidden Unicode in tool descriptions
- 🎭 Typosquatted package names
- ✅ Blanket auto-approve configurations

**Runs fully offline** — no telemetry, no network calls, never executes your servers (unless you opt-in with `--introspect`).

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
  - [Commands](#commands)
  - [Flags Reference](#flags-reference)
  - [Output Formats](#output-formats)
- [Rules Reference](#rules-reference)
- [Configuration File](#configuration-file)
- [CI Integration](#ci-integration)
  - [GitHub Actions](#github-actions)
  - [Pre-commit Hook](#pre-commit-hook)
- [Programmatic API](#programmatic-api)
- [AI Explanations](#ai-explanations)
- [Live Introspection](#live-introspection)
- [Privacy & Safety](#privacy--safety)
- [Contributing](#contributing)
- [License](#license)

---

## Quick Start

```bash
# No install needed — just run:
npx @snehasishghosh115-hub/mcp-audit

# Or with the short alias after npm publish:
npx mcp-audit
```

That's it. `mcp-audit` auto-discovers all MCP config files for every supported client on your machine and prints a prioritised report.

---

## Installation

### No install (recommended for one-off scans)
```bash
npx @snehasishghosh115-hub/mcp-audit
```

### Global install
```bash
npm install -g @snehasishghosh115-hub/mcp-audit
mcp-audit
```

### Project dev-dependency (for CI)
```bash
npm install -D @snehasishghosh115-hub/mcp-audit
npx mcp-audit --no-user --format sarif
```

**Requires Node.js 18 or later.**

---

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `mcp-audit` | Auto-discover all configs and scan (same as `mcp-audit scan`) |
| `mcp-audit scan [files...]` | Scan specific files or auto-discover |
| `mcp-audit rules` | List all available rules with IDs and severities |
| `mcp-audit explain <RULE-ID>` | Show full documentation for one rule |
| `mcp-audit init` | Create a starter `.mcp-audit.json` config file |

### Common Examples

```bash
# Auto-scan every known MCP config on your machine
mcp-audit

# Scan specific files
mcp-audit scan .mcp.json .cursor/mcp.json

# Scan only Claude Desktop configs (skip cursor, vscode, etc.)
mcp-audit scan --client claude-desktop

# CI mode: only project-level configs, fail on medium+
mcp-audit scan --no-user --fail-on medium

# Output SARIF for GitHub code scanning
mcp-audit scan --format sarif --output results.sarif

# Output JSON for programmatic consumption
mcp-audit scan --format json

# Audit saved tool definitions (without running servers)
mcp-audit scan --tools tools.json

# Fetch live tools from running servers (see ⚠️ below)
mcp-audit scan --introspect

# Add AI explanations to findings
mcp-audit scan --explain

# See docs for a specific rule
mcp-audit explain MCPA-SEC-001

# List all rules
mcp-audit rules
```

### Flags Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--format`, `-f` | `text` | Output format: `text`, `json`, `sarif` |
| `--output`, `-o` | stdout | Write output to a file |
| `--fail-on` | `high` | Exit code 1 if any finding at this severity or above. Values: `critical`, `high`, `medium`, `low`, `info` |
| `--min-severity` | `info` | Only show/return findings at this severity or above |
| `--client` | all | Comma-separated client IDs: `claude-desktop`, `claude-code`, `cursor`, `vscode`, `windsurf` |
| `--no-user` | false | Skip user-level config files (only project-level) |
| `--no-project` | false | Skip project-level config files (only user-level) |
| `--rule` | all | Comma-separated rule IDs to run (e.g. `MCPA-SEC-001,MCPA-SEC-004`) |
| `--skip-rule` | — | Comma-separated rule IDs to skip |
| `--config` | auto-discover | Path to `.mcp-audit.json` config file |
| `--tools` | — | Path to a saved tools JSON file (from `mcp tools/list`) |
| `--introspect` | false | ⚠️ Start the configured MCP servers to fetch live tool definitions |
| `--yes` | false | Skip introspection confirmation prompt |
| `--strict` | false | Treat warnings as errors |
| `--explain` | false | Add AI-generated explanations (requires API key) |
| `--provider` | `auto` | AI provider: `anthropic`, `openai`, `auto` |
| `--model` | provider default | AI model to use for explanations |
| `--dry-run` | false | Preview what would be sent to the AI without calling it |
| `--version`, `-v` | — | Print version |
| `--help`, `-h` | — | Print help |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `--fail-on` severity |
| `1` | One or more findings at or above `--fail-on` severity |
| `2` | Fatal error (bad config, file not found, etc.) |

### Output Formats

#### Text (default)

```
~/.cursor/mcp.json
  github (claude-desktop)
    ✖ CRITICAL  MCPA-SEC-001  Hardcoded secret in env.GITHUB_TOKEN  (line 8)
        evidence: ghp_…[REDACTED len=40]
        fix: Use "${GITHUB_TOKEN}" and rotate the exposed secret.
    ◆ MEDIUM    MCPA-SEC-004  Unpinned package "mcp-server-github" via npx  (line 5)
        fix: Pin exact version: npx mcp-server-github@1.2.3

Summary: 1 critical · 0 high · 1 medium · 0 low · 0 info
```

#### JSON (`--format json`)

```json
{
  "tool": { "name": "mcp-audit", "version": "1.0.0" },
  "summary": {
    "files": 2,
    "servers": 3,
    "findings": 2,
    "bySeverity": { "critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0 }
  },
  "findings": [
    {
      "ruleId": "MCPA-SEC-001",
      "severity": "critical",
      "message": "Hardcoded secret in env.GITHUB_TOKEN",
      "remediation": "Use \"${GITHUB_TOKEN}\" and rotate the exposed secret.",
      "server": "github",
      "client": "claude-desktop",
      "file": "/Users/you/.cursor/mcp.json",
      "loc": { "line": 8, "column": 7 },
      "evidence": "ghp_…[REDACTED len=40]",
      "references": ["https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-001.md"]
    }
  ],
  "errors": []
}
```

#### SARIF (`--format sarif`)

Outputs [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) compatible with GitHub Code Scanning, VS Code SARIF Viewer, and any SAST platform.

---

## Rules Reference

All rules have stable IDs. Severity is the default and can be overridden per-rule in your config.

| ID | Title | Default Severity | Runs On |
|----|-------|-----------------|---------|
| **MCPA-SEC-001** | Hardcoded secret in env, args, or headers | 🔴 critical | Config |
| **MCPA-SEC-002** | Secret embedded in URL (query param or userinfo) | 🟠 high | Config |
| **MCPA-SEC-003** | Remote server over plaintext HTTP | 🟠 high | Config |
| **MCPA-SEC-004** | Unpinned package via npx/uvx/pipx/bunx/dlx | 🟡 medium | Config |
| **MCPA-SEC-005** | Floating version (latest, next, ranges, branches) | 🟡 medium | Config |
| **MCPA-SEC-006** | Shell interpreter as command (sh -c, bash -c, etc.) | 🟠 high | Config |
| **MCPA-SEC-007** | Download-and-execute (curl\|sh, iex irm) | 🔴 critical | Config |
| **MCPA-SEC-008** | Filesystem access too broad (/, ~, drive root) | 🟠 high | Config |
| **MCPA-SEC-009** | Dangerous Docker flags (--privileged, docker.sock) | 🟠 high | Config |
| **MCPA-SEC-010** | Possible typosquat of known MCP package | 🟠 high | Config |
| **MCPA-SEC-014** | Blanket auto-approve (autoApprove: ["*"], trust: true) | 🟠 high | Config |
| **MCPA-SEC-015** | Config file is group/world-readable with secrets (POSIX) | 🟡 medium | Config |
| **MCPA-SEC-016** | Risky remote (raw IP, ngrok, trycloudflare, etc.) | 🟡 medium | Config |
| **MCPA-TOOL-001** | Prompt-injection phrasing in tool description | 🟠 high | Tools |
| **MCPA-TOOL-002** | Invisible Unicode in tool name or description | 🟠 high | Tools |
| **MCPA-TOOL-003** | Tool name collision/shadowing across servers | 🟡 medium | Tools |

> **Note:** `MCPA-TOOL-*` rules only run when tool definitions are available via `--tools <file>` or `--introspect`.

For detailed documentation on any rule:
```bash
mcp-audit explain MCPA-SEC-001
```

---

## Configuration File

Create `.mcp-audit.json` in your project root (or run `mcp-audit init`):

```json
{
  "failOn": "high",
  "ignore": [
    {
      "rule": "MCPA-SEC-004",
      "server": "my-internal-tool",
      "reason": "Internal package — version pinned by lockfile"
    }
  ],
  "trustedPackages": [
    "@mycorp/mcp-tools"
  ],
  "allowRemoteHosts": [
    "internal.corp.example.com"
  ],
  "severityOverrides": {
    "MCPA-SEC-005": "low"
  }
}
```

### Configuration Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `failOn` | severity string | `"high"` | Exit code 1 if any finding at this level or above |
| `ignore` | array | `[]` | Suppress specific findings. Each entry needs `rule` and `reason`; optionally `server` and/or `file` for narrower targeting |
| `trustedPackages` | string array | `[]` | Package names or prefixes exempted from MCPA-SEC-004/005 (e.g. `"@mycorp/mcp-tools"`) |
| `allowRemoteHosts` | string array | `[]` | Hostnames (or domain suffixes) exempted from MCPA-SEC-003 plaintext HTTP check |
| `severityOverrides` | object | `{}` | Override the default severity for any rule ID |

### `ignore` Entry Fields

| Field | Required | Description |
|-------|----------|-------------|
| `rule` | ✅ | Rule ID to suppress (e.g. `"MCPA-SEC-004"`) |
| `reason` | ✅ | Human-readable justification (required — this is an audit trail) |
| `server` | optional | Only suppress for this server name |
| `file` | optional | Only suppress for this config file path |

### Config File Discovery

`mcp-audit` walks up from the current working directory to find `.mcp-audit.json`, like ESLint. You can also point to a specific file with `--config path/to/.mcp-audit.json`.

---

## CI Integration

### GitHub Actions

```yaml
name: MCP Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # required for SARIF upload
    steps:
      - uses: actions/checkout@v4
      
      - name: Run mcp-audit
        run: npx @snehasishghosh115-hub/mcp-audit scan --no-user --format sarif --output mcp-audit.sarif
        continue-on-error: true  # let SARIF upload even if findings exist
      
      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcp-audit.sarif
```

#### Using the GitHub Action directly (if published as an Action)

```yaml
- uses: snehasishghosh115-hub/mcp-audit@v1
  with:
    fail-on: high          # optional, default: high
    format: sarif          # optional, default: text
    output: results.sarif  # optional
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/snehasishghosh115-hub/mcp-audit
    rev: v1.0.0
    hooks:
      - id: mcp-audit
```

This runs `mcp-audit scan --no-user` on every commit, catching issues before they reach your repository.

### npm Script

Add to `package.json`:

```json
{
  "scripts": {
    "audit:mcp": "mcp-audit scan --no-user --fail-on medium"
  }
}
```

---

## Programmatic API

`mcp-audit` ships a full TypeScript API so you can integrate scanning into your own tools.

### Installation

```bash
npm install @snehasishghosh115-hub/mcp-audit
```

### Basic Usage

```typescript
import { scan } from '@snehasishghosh115-hub/mcp-audit';

const result = await scan({
  paths: ['.mcp.json', '.cursor/mcp.json'], // optional: auto-discover if omitted
  failOn: 'high',
  minSeverity: 'info',
});

console.log(`Found ${result.findings.length} findings across ${result.servers} servers`);

for (const finding of result.findings) {
  console.log(`[${finding.severity.toUpperCase()}] ${finding.ruleId}: ${finding.message}`);
  console.log(`  File: ${finding.file}${finding.loc ? ` (line ${finding.loc.line})` : ''}`);
  console.log(`  Fix:  ${finding.remediation}`);
}
```

### `scan()` Options

```typescript
const result = await scan({
  // Files to scan. If omitted, auto-discovers from all supported clients.
  paths?: string[];

  // Minimum severity to report ('critical'|'high'|'medium'|'low'|'info')
  failOn?: string;
  minSeverity?: string;

  // Filter to specific clients ('claude-desktop'|'claude-code'|'cursor'|'vscode'|'windsurf')
  clientIds?: string[];

  // Skip user-level / project-level configs
  noUser?: boolean;
  noProject?: boolean;

  // Path to .mcp-audit.json (auto-discovers if omitted)
  configPath?: string;

  // Run only / skip specific rule IDs
  ruleIds?: string[];
  skipRuleIds?: string[];

  // Path to a saved tools JSON file
  toolsPath?: string;

  // Start configured servers and fetch live tool definitions
  introspect?: boolean;
});
```

### `ScanResult` Shape

```typescript
interface ScanResult {
  findings: Finding[];     // All findings, sorted by severity then file then line
  scannedFiles: string[];  // All config files that were read
  servers: number;         // Total server entries parsed
  durationMs: number;      // Wall-clock time of the scan
  errors: ScanError[];     // Parse or I/O errors (non-fatal)
}

interface Finding {
  ruleId: string;        // e.g. "MCPA-SEC-001"
  severity: Severity;    // "critical"|"high"|"medium"|"low"|"info"
  message: string;       // Human-readable description
  remediation: string;   // How to fix it
  server: string;        // Server name from config
  client: ClientId;      // Which MCP client config file this came from
  file: string;          // Absolute path to the config file
  loc?: { line: number; column: number };
  evidence?: string;     // Redacted snippet (never raw secrets)
  references?: string[]; // Links to rule documentation
  explanation?: string;  // AI explanation if --explain was used
}
```

### Lower-level APIs

```typescript
import {
  parseJsonc,              // Parse JSONC (JSON with comments) → AST with position tracking
  normalizeServerEntries,  // Parse server config objects → ServerEntry[]
  runRules,               // Run rules against entries → { findings, errors }
  loadConfig,             // Load and merge .mcp-audit.json
  ALL_RULES,              // All built-in Rule objects
  discoverConfigFiles,     // Find config files for all clients
} from '@snehasishghosh115-hub/mcp-audit';
```

### Writing a Custom Rule

```typescript
import type { Rule, RuleContext, Finding } from '@snehasishghosh115-hub/mcp-audit';

const myRule: Rule = {
  id: 'CUSTOM-001',
  title: 'My custom check',
  severity: 'medium',
  description: 'Detects something specific to my org.',
  docs: '## CUSTOM-001\nFull documentation here.',
  check(ctx: RuleContext): Finding[] {
    const { entry } = ctx;
    const findings: Finding[] = [];

    // Example: flag any server whose name starts with "legacy-"
    if (entry.name.startsWith('legacy-')) {
      findings.push({
        ruleId: 'CUSTOM-001',
        severity: 'medium',
        message: `Legacy server: "${entry.name}"`,
        remediation: 'Migrate to the new server format.',
        server: entry.name,
        client: entry.client,
        file: entry.file,
        loc: entry.loc,
      });
    }

    return findings;
  },
};

// Use with runRules directly
import { runRules, normalizeServerEntries, parseJsonc, loadConfig } from '@snehasishghosh115-hub/mcp-audit';
import { readFileSync } from 'node:fs';

const content = readFileSync('.mcp.json', 'utf-8');
const ast = parseJsonc(content);
const entries = normalizeServerEntries(ast, 'claude-code', '.mcp.json', 'project', 'mcpServers', content);
const config = loadConfig();
const { findings } = runRules(entries, [myRule], config);
```

---

## AI Explanations

Add human-readable explanations to every finding using your own AI API key:

```bash
# Auto-detect: prefers Anthropic, falls back to OpenAI
ANTHROPIC_API_KEY=sk-ant-... mcp-audit scan --explain

# Or explicitly choose a provider
OPENAI_API_KEY=sk-... mcp-audit scan --explain --provider openai

# Preview the prompt without calling the API
mcp-audit scan --explain --dry-run
```

> **Privacy:** Only redacted finding metadata is sent to the AI — never the raw config file, never raw secrets, never file paths. Findings are sanitised before anything leaves your machine.

The AI adds an `explanation` field to each finding in JSON/SARIF output, and prints it inline in text mode:

```
✖ CRITICAL  MCPA-SEC-001  Hardcoded secret in env.GITHUB_TOKEN
    fix: Use "${GITHUB_TOKEN}" and rotate the exposed secret.
    💡 This GitHub token is committed in plaintext in your MCP config. Anyone
       with access to this file — including other processes on your machine,
       your git history, and cloud sync services like iCloud — can read it and
       authenticate as you. Rotate the token immediately in GitHub Settings →
       Developer Settings → Personal Access Tokens, then set it as an env var.
```

---

## Live Introspection

`--introspect` connects to your configured MCP servers, calls `tools/list`, and runs tool-level security rules (prompt injection, invisible Unicode, name shadowing) on the live definitions:

```bash
mcp-audit scan --introspect
# ⚠ WARNING: --introspect will START the configured MCP servers to fetch live
# tool definitions. This executes code from your configuration. Continue? [y/N]
```

> **Safety:** `--introspect` sanitises the environment (only `PATH`, `HOME`, and the server's own declared `env` are passed — no ambient credentials). Each server gets a 10-second timeout. All server processes are cleaned up on exit.

Skip the prompt with `--yes` in automated environments:
```bash
mcp-audit scan --introspect --yes
```

---

## Privacy & Safety

| Property | Guarantee |
|----------|-----------|
| **Telemetry** | None. Zero analytics, no crash reporting, no pings. |
| **Network** | Never used unless you pass `--explain` (AI API call) or `--introspect` (HTTP transport) |
| **Secret values** | Redacted in all output: `ghp_…[REDACTED len=40]` — the first 4 chars max are shown |
| **File execution** | Never. Static analysis only unless `--introspect` is explicitly passed |
| **Process isolation** | Introspected servers receive a sanitised environment (no `AWS_*`, no `ANTHROPIC_API_KEY`, etc.) |

---

## Supported Clients

| Client | Config Files Scanned |
|--------|---------------------|
| **Claude Desktop** | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) · `%APPDATA%\Claude\claude_desktop_config.json` (Windows) · `~/.config/Claude/claude_desktop_config.json` (Linux) |
| **Claude Code** | `~/.claude.json` (user) · `.mcp.json` (project) |
| **Cursor** | `~/.cursor/mcp.json` (user) · `.cursor/mcp.json` (project) |
| **VS Code** | `.vscode/mcp.json` (project) |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` (user) |

Pass `--client claude-desktop,cursor` to restrict to specific clients.

---

## Contributing

See [CONTRIBUTING.md](https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/Documents/CONTRIBUTING.md) for the full guide.

**Quick start:**
```bash
git clone https://github.com/snehasishghosh115-hub/mcp-audit.git
cd mcp-audit
npm install
npm test          # run all tests
npm run build     # build dist/
npm run typecheck # TypeScript check
npm run lint      # ESLint + Prettier
```

**Adding a rule:** See [RULES.md](https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/Documents/RULES.md) for the authoring checklist.

---

## License

[MIT](LICENSE) © snehasishghosh115-hub
