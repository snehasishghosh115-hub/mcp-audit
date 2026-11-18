# CLI Specification

```
mcp-audit [command] [options]

Commands
  scan [paths...]     Scan MCP configs (default command). No paths = auto-discover.
  rules               List all rules (id, severity, title).
  explain <ruleId>    Print rule documentation.
  init                Create a starter .mcp-audit.json in cwd.

Global options
  -h, --help          Show help
  -v, --version       Show version

scan options
  -f, --format <fmt>        text | json | sarif           (default: text)
  -o, --output <file>       Write report to file instead of stdout
      --fail-on <sev>       critical|high|medium|low|info|none   (default: high)
      --min-severity <sev>  Hide findings below this level       (default: info)
      --client <id,...>     Limit discovery: claude-desktop,claude-code,cursor,vscode,windsurf
      --no-user             Skip user-level configs (CI friendly)
      --no-project          Skip project-level configs
      --config <file>       Path to .mcp-audit.json
      --rule <id,...>       Only run these rules
      --skip-rule <id,...>  Skip these rules
      --tools <file>        Audit a saved tools/list JSON file (MCPA-TOOL-*)
      --introspect          Start/connect to servers to fetch live tool definitions (RUNS CODE)
  -y, --yes                 Skip --introspect confirmation
      --explain             Add LLM explanations (needs API key)
      --provider <name>     anthropic | openai          (default: auto by env key)
      --model <name>        Model id (or env MCP_AUDIT_MODEL)
      --dry-run             With --explain: print the payload that would be sent, then exit
      --strict              Treat parse/read errors as failures (exit 1)
      --no-color            Disable color (also respects NO_COLOR)
```

## Exit codes
| Code | Meaning |
|---|---|
| 0 | Scan completed; no findings at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` (or errors with `--strict`) |
| 2 | Usage error or fatal internal error |

## Examples
```bash
npx mcp-audit                                  # auto-discover and scan everything
npx mcp-audit scan .mcp.json .cursor/mcp.json  # explicit files
npx mcp-audit scan --no-user --fail-on medium  # CI mode for a repo
npx mcp-audit scan -f sarif -o results.sarif   # GitHub code scanning
npx mcp-audit scan --introspect                # also audit live tool descriptions
npx mcp-audit explain MCPA-SEC-004
```

## Text output (target)
```
mcp-audit 0.1.0 · scanned 3 files · 7 servers · 5 findings

~/.cursor/mcp.json
  github (stdio)
    ✖ CRITICAL  MCPA-SEC-001  Hardcoded secret in env.GITHUB_TOKEN  (line 8)
        evidence: ghp_…[REDACTED len=40]
        fix: Use "${GITHUB_TOKEN}" and rotate the exposed token.
  filesystem (stdio)
    ▲ HIGH      MCPA-SEC-008  Filesystem server rooted at "/"  (line 14)

Summary: 1 critical · 1 high · 2 medium · 1 low
```

## JSON output schema
```json
{
  "tool": { "name": "mcp-audit", "version": "0.1.0" },
  "summary": { "files": 3, "servers": 7, "findings": 5,
               "bySeverity": { "critical": 1, "high": 1, "medium": 2, "low": 1, "info": 0 } },
  "findings": [{
    "ruleId": "MCPA-SEC-001", "severity": "critical",
    "message": "...", "remediation": "...",
    "server": "github", "client": "cursor", "file": "/abs/path/mcp.json",
    "loc": { "line": 8, "column": 7 }, "evidence": "ghp_…[REDACTED len=40]"
  }],
  "errors": [{ "file": "...", "message": "..." }]
}
```

## Config file `.mcp-audit.json`
```json
{
  "failOn": "high",
  "ignore": [
    { "rule": "MCPA-SEC-004", "server": "my-local-tool", "reason": "internal package, pinned by lockfile" }
  ],
  "trustedPackages": ["@mycorp/mcp-tools"],
  "allowRemoteHosts": ["mcp.internal.example.com"],
  "severityOverrides": { "MCPA-SEC-005": "low" }
}
```
Discovery order: `--config`, then `./.mcp-audit.json`, then git root. Validate strictly; unknown keys produce a warning; every `ignore` needs a non-empty `reason`.
