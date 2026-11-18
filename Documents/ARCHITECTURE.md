# Architecture

## 1. Tech stack
- **Language:** TypeScript (strict), ESM source, built to ESM + CJS with `tsup`.
- **Runtime:** Node >=18. **Runtime dependencies: none.** Use `node:util` `parseArgs`, `node:fs`, `node:path`, `node:os`, global `fetch`.
- **Dev deps:** `typescript`, `tsup`, `vitest`, `eslint`, `typescript-eslint`, `prettier`, `@types/node`.

## 2. Data flow
```
CLI args ──► config load ──► discovery ──► parse (JSONC+positions) ──► normalize
                                                                           │
                                   (opt) introspect ──► ToolDef[] ─────────┤
                                                                           ▼
                                                                    rule engine
                                                                           │
                                          ignores/severity filter ◄────────┘
                                                                           ▼
                                      (opt) explain ──► reporter (text|json|sarif) ──► stdout, exit code
```

## 3. Repository layout
```
mcp-audit/
├─ src/
│  ├─ cli.ts                 # entry: parse args, dispatch, set exit code
│  ├─ index.ts               # public API: scan(), rules, types
│  ├─ types.ts
│  ├─ config.ts              # load/validate .mcp-audit.json
│  ├─ discovery/
│  │  ├─ clients.ts          # per-client path + key definitions
│  │  └─ discover.ts         # resolves existing files
│  ├─ parse/
│  │  ├─ jsonc.ts            # tokenizer + AST with offsets
│  │  └─ normalize.ts        # AST -> ServerEntry[]
│  ├─ rules/
│  │  ├─ index.ts            # registry
│  │  ├─ sec-001-hardcoded-secret.ts ...
│  │  └─ tool-001-prompt-injection.ts ...
│  ├─ engine/run.ts          # applies rules, sorts, filters
│  ├─ introspect/            # stdio + http MCP client (opt-in)
│  ├─ explain/               # provider interface + providers
│  ├─ reporters/ text.ts json.ts sarif.ts
│  └─ util/ redact.ts secrets.ts entropy.ts args.ts fs.ts
├─ test/ (unit) and test/fixtures/<client>/{good,bad}/*.json
├─ docs/  action.yml  .pre-commit-hooks.yaml  .mcp-audit.json (example)
└─ package.json tsconfig.json tsup.config.ts vitest.config.ts
```

## 4. Core types (`src/types.ts`)
```ts
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ClientId = 'claude-desktop' | 'claude-code' | 'cursor' | 'vscode' | 'windsurf' | 'generic';
export type Transport = 'stdio' | 'http' | 'sse';

export interface SourceLoc { line: number; column: number } // 1-based

export interface ServerEntry {
  id: string;                 // `${file}#${name}`
  name: string;
  client: ClientId;
  file: string;               // absolute path
  scope: 'user' | 'project';
  transport: Transport;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  url?: string;
  headers?: Record<string, string>;
  autoApprove?: string[] | boolean;   // alwaysAllow / autoApprove / trust variants
  loc: SourceLoc;                     // location of the server object key
  locOf(path: (string|number)[]): SourceLoc | undefined; // e.g. ['env','API_KEY']
}

export interface ToolDef { server: string; name: string; description?: string; inputSchema?: unknown }

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  remediation: string;
  server: string; client: ClientId; file: string;
  loc?: SourceLoc;
  evidence?: string;          // ALWAYS redacted
  references?: string[];
  explanation?: string;       // filled by --explain
}

export interface RuleContext { entry: ServerEntry; config: ResolvedConfig; tools?: ToolDef[] }
export interface Rule {
  id: string; title: string; severity: Severity; description: string;
  docs: string;               // markdown for `explain <id>`
  check(ctx: RuleContext): Finding[];
}

export interface ScanResult { findings: Finding[]; scannedFiles: string[]; servers: number; durationMs: number; errors: ScanError[] }
```

## 5. Discovery
Paths (expand `~`, `%APPDATA%`); key is the JSON property holding the server map.

| Client | Scope | Path | Key |
|---|---|---|---|
| Claude Desktop | user | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`; Windows `%APPDATA%/Claude/claude_desktop_config.json`; Linux `~/.config/Claude/claude_desktop_config.json` | `mcpServers` |
| Claude Code | project | `<cwd>/.mcp.json` | `mcpServers` |
| Claude Code | user | `~/.claude.json` (also per-project entries under `projects.*.mcpServers`) | `mcpServers` |
| Cursor | user / project | `~/.cursor/mcp.json`, `<cwd>/.cursor/mcp.json` | `mcpServers` |
| VS Code | project | `<cwd>/.vscode/mcp.json` | `servers` |
| Windsurf | user | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` |

Verify these against current client docs in Phase 1 and encode them only in `clients.ts` so changes are one-file edits. For project scope, also walk up from cwd to the git root. Missing files are skipped silently. Unreadable or invalid files produce a `ScanError`, not a crash.

Transport inference: has `url` means `http` (or `sse` if `type: "sse"`); has `command` means `stdio`.

## 6. Parser
Write a small JSONC tokenizer/parser (~150 lines) producing an AST where every node keeps `offset` so line/column can be computed. Support `//` and `/* */` comments, trailing commas, BOM. Do not use `eval` or `new Function`. On syntax error, throw `ParseError{line,column,message}`.

## 7. Rule engine
- Registry exports `ALL_RULES: Rule[]`. Engine iterates entries x rules, catches rule exceptions (record as `ScanError`, continue).
- Ignore matching: `{rule, server?, file?, reason}`. Reasons are mandatory in config (validator rejects missing reason).
- Sorting: severity desc, file, line, ruleId. Output must be deterministic.
- Severity threshold: `--min-severity` hides, `--fail-on` controls exit code.

## 8. Secret detection (`util/secrets.ts`)
Ordered checks per string value:
1. If value is an env reference (`${VAR}`, `$VAR`, `${env:VAR}`, `${input:id}`, `%VAR%`) then it is safe, skip.
2. Known-prefix regexes: AWS `AKIA[0-9A-Z]{16}`, GitHub `gh[pousr]_[A-Za-z0-9]{36,}` and `github_pat_`, Slack `xox[baprs]-`, Anthropic `sk-ant-`, OpenAI `sk-[A-Za-z0-9_-]{20,}`, Stripe `sk_live_`, Google `AIza[0-9A-Za-z_-]{35}`, PEM private key header, JWT `eyJ...\..*\..*`, `Bearer <long>` in headers.
3. Key-name heuristic: key matches `/(secret|token|password|passwd|api[_-]?key|auth|credential)/i` AND value length >=12 AND Shannon entropy >=3.0 AND not a placeholder (`your-...`, `<...>`, `xxx`, `changeme`, `example`).
Redaction: `firstFour + '…' + '[REDACTED len=N]'`; never log more than 4 chars.

## 9. Introspection (opt-in)
- Implement JSON-RPC 2.0 over stdio (newline-delimited) and Streamable HTTP/SSE minimal client. Sequence: `initialize` then `notifications/initialized` then `tools/list` (follow `nextCursor`).
- Spawn with `child_process.spawn`, `shell: false`, sanitized env (`PATH`, `HOME`, plus the entry's own `env`), 10s timeout, kill on exit/SIGINT, cap stdout at 5 MB.
- Requires `--introspect` AND interactive confirmation or `--yes`. Print the exact command line before running.

## 10. Explain (opt-in)
```ts
interface ExplainProvider { name: string; explain(batch: RedactedFinding[], signal: AbortSignal): Promise<Record<string,string>> }
```
Providers: `anthropic` (env `ANTHROPIC_API_KEY`), `openai` (env `OPENAI_API_KEY`, optional `OPENAI_BASE_URL`). Model via `MCP_AUDIT_MODEL` or `--model`. Send only: ruleId, severity, message, remediation, redacted evidence, transport, command basename. Never file contents, paths beyond basename, or env values. `--dry-run` prints the payload and exits.

## 11. Reporters
- **text:** human-readable, grouped by file then server.
- **json:** `{ tool:{name,version}, summary:{...}, findings:[...], errors:[...] }`.
- **sarif:** 2.1.0, one `run`, `tool.driver.rules` from registry, `results[].locations[].physicalLocation.region{startLine,startColumn}`, `level` mapping critical/high=error, medium=warning, low/info=note.

## 12. Error handling and exit codes
`0` clean (or below threshold), `1` findings at/above `--fail-on`, `2` usage or fatal error. Per-file errors are reported in output and do not change exit code unless `--strict`.

## 13. Security design principles
1. Default mode is read-only, offline, no process spawn.
2. Redact at the source (rule level), not only at the reporter.
3. A test greps all outputs for known fixture secrets and fails if found.
4. No telemetry.
5. Publish with npm provenance; pin Action versions by SHA in workflows.
