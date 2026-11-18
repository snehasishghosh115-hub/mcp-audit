import type { Rule, RuleContext, Finding, Severity } from '../types.js';
import { homedir } from 'node:os';

const SEVERITY: Severity = 'high';

const BROAD_PATHS = new Set(['/', '~', '$HOME', '${HOME}', 'C:\\', 'C:/']);

function isBroadPath(path: string): boolean {
  const normalized = path.trim();
  if (BROAD_PATHS.has(normalized)) return true;
  const home = homedir();
  if (normalized === home) return true;
  // Check for paths with <= 1 segment (e.g., /Users, /home, /tmp, C:\\Users)
  const segments = normalized.split(/[/\\]/).filter(s => s.length > 0);
  if (segments.length <= 1 && normalized.startsWith('/')) return true;
  if (segments.length <= 1 && /^[A-Za-z]:\\?$/.test(normalized)) return true;
  return false;
}

function isFilesystemServer(entry: { command?: string; args?: string[] }): boolean {
  if (!entry.command) return false;
  const cmd = entry.command.toLowerCase();
  if (cmd.includes('server-filesystem') || cmd.includes('filesystem')) return true;
  const args = entry.args ?? [];
  const fullCmd = [cmd, ...args].join(' ').toLowerCase();
  return fullCmd.includes('server-filesystem') || fullCmd.includes('mcp-server-filesystem');
}

export const rule: Rule = {
  id: 'MCPA-SEC-008',
  title: 'Filesystem access too broad (/, ~, drive root, $HOME, C:\\)',
  severity: SEVERITY,
  description:
    'Detects filesystem servers or arguments pointing to overly broad paths like root, home directory, or drive roots.',
  docs: `## MCPA-SEC-008: Broad filesystem access

### Why it matters
Filesystem servers rooted at \`/\`, \`~\`, or drive roots (\`C:\\\`) grant access to the entire filesystem. This includes:
- SSH keys (\`~/.ssh\`)
- AWS credentials (\`~/.aws\`)
- Environment files (\`.env\`)
- Source code and secrets
- System configuration

### How it works
This rule flags:
1. Filesystem servers (identified by package/command name containing "filesystem") with broad root paths
2. Any server argument that is a broad path: \`/\`, \`~\`, \`$HOME\`, \`$\{HOME}\`, \`C:\\\`, \`C:/\`, or any path with <= 1 segment (e.g., \`/Users\`, \`/home\`)

### Remediation
Scope filesystem servers to a specific project directory:
- Instead of \`/\`, use \`/home/user/projects/myproject\`
- Instead of \`~\`, use \`~/projects/myproject\`

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-SEC-008", "server": "readonly-fs", "reason": "Read-only filesystem server for documentation lookup" }
  ]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { entry } = ctx;

    // Check if it's a filesystem server
    const isFsServer = isFilesystemServer(entry);

    // Check args for broad paths
    if (entry.args) {
      for (let i = 0; i < entry.args.length; i++) {
        const arg = entry.args[i];
        if (arg === undefined) continue;
        if (isBroadPath(arg)) {
          if (
            !isFsServer &&
            !arg.startsWith('/') &&
            !arg.startsWith('~') &&
            !/^[A-Za-z]:/.test(arg)
          ) {
            continue; // Not an absolute path, might be a relative path or flag
          }
          const loc = entry.locOf(['args', i]);
          findings.push({
            ruleId: 'MCPA-SEC-008',
            severity: SEVERITY,
            message: 'Filesystem path too broad: "' + arg + '"',
            remediation:
              'Scope to a specific project directory (e.g., /home/user/projects/myproject).',
            server: entry.name,
            client: entry.client,
            file: entry.file,
            loc,
            evidence: arg,
            references: [
              'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-008.md',
            ],
          });
        }
      }
    }

    // Check cwd if it's a broad path
    if (entry.cwd && isBroadPath(entry.cwd)) {
      const loc = entry.locOf(['cwd']);
      findings.push({
        ruleId: 'MCPA-SEC-008',
        severity: SEVERITY,
        message: 'Working directory too broad: "' + entry.cwd + '"',
        remediation: 'Set cwd to a specific project directory.',
        server: entry.name,
        client: entry.client,
        file: entry.file,
        loc,
        evidence: entry.cwd,
        references: [
          'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-008.md',
        ],
      });
    }

    return findings;
  },
};

export default rule;
