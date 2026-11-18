# mcp-audit

> Security audit for your MCP (Model Context Protocol) servers. One command, zero config, zero dependencies.

`mcp-audit` scans the MCP configs used by **Claude Desktop, Claude Code, Cursor, VS Code, and Windsurf** and flags risky setups before they bite: hardcoded secrets, unpinned packages, shell wrappers, overly broad filesystem access, plaintext remotes, and suspicious tool descriptions.

- Runs **offline** by default. It never executes your servers unless you pass `--introspect`.
- Output as **text, JSON, or SARIF** for CI and GitHub code scanning.
- Optional **AI explanations** (`--explain`) with your own API key. Secrets are redacted before anything is sent.

## Install and run

```bash
# no install needed
npx mcp-audit

# or install globally
npm install -g mcp-audit
mcp-audit

# or as a dev dependency
npm install -D mcp-audit
```
Requires Node.js 18+.

## Usage

```bash
mcp-audit                                   # auto-discover and scan all known configs
mcp-audit scan .mcp.json .cursor/mcp.json   # scan specific files
mcp-audit scan --no-user --fail-on medium   # repo-only scan, strict threshold (CI)
mcp-audit scan -f sarif -o results.sarif    # SARIF for GitHub code scanning
mcp-audit scan --tools tools.json           # audit saved tools/list output
mcp-audit scan --introspect                 # fetch live tool definitions (runs the servers!)
mcp-audit scan --explain                    # add AI explanations (needs ANTHROPIC_API_KEY or OPENAI_API_KEY)
mcp-audit rules                             # list all rules
mcp-audit explain MCPA-SEC-004              # docs for one rule
mcp-audit init                              # create .mcp-audit.json
```
Exit codes: `0` ok · `1` findings at/above `--fail-on` (default `high`) · `2` error.

## Example

```
~/.cursor/mcp.json
  github (stdio)
    ✖ CRITICAL  MCPA-SEC-001  Hardcoded secret in env.GITHUB_TOKEN  (line 8)
        fix: Use "${GITHUB_TOKEN}" and rotate the exposed token.
  filesystem (stdio)
    ▲ HIGH      MCPA-SEC-008  Filesystem server rooted at "/"  (line 14)
```

## What it checks
See [docs/RULES.md](docs/RULES.md). Highlights: hardcoded secrets · plaintext HTTP · unpinned `npx`/`uvx` · shell wrappers · `curl | sh` · broad filesystem roots · dangerous Docker flags · typosquats · blanket auto-approve · prompt-injection and invisible Unicode in tool descriptions.

## Configuration
Create `.mcp-audit.json` (or run `mcp-audit init`):
```json
{
  "failOn": "high",
  "ignore": [{ "rule": "MCPA-SEC-004", "server": "my-tool", "reason": "pinned via lockfile" }],
  "trustedPackages": ["@mycorp/mcp-tools"]
}
```

## CI

**GitHub Actions**
```yaml
- uses: actions/checkout@v4
- uses: <your-username>/mcp-audit@v1
  with: { fail-on: high }
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: mcp-audit.sarif }
```

**pre-commit**
```yaml
repos:
  - repo: https://github.com/<your-username>/mcp-audit
    rev: v1.0.0
    hooks: [{ id: mcp-audit }]
```

## Programmatic API
```ts
import { scan } from 'mcp-audit';
const result = await scan({ paths: ['.mcp.json'], failOn: 'high' });
console.log(result.findings);
```

## Privacy and safety
- No telemetry. No network calls unless you opt in with `--explain` or an HTTP `--introspect` target.
- Evidence is redacted (first 4 characters + length at most).
- `--introspect` starts the configured servers. Only use it on configs you trust.

## Development
See [AGENTS.md](AGENTS.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [docs/](docs/).

## License
MIT
