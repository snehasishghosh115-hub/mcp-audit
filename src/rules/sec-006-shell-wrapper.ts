import type { Rule, RuleContext, Finding, Severity } from '../types.js';

const SEVERITY: Severity = 'high';

const SHELLS = new Set(['sh', 'bash', 'zsh', 'fish', 'cmd', 'cmd.exe', 'powershell', 'pwsh']);

const SHELL_FLAGS = new Set(['-c', '/c', '-Command']);

export const rule: Rule = {
  id: 'MCPA-SEC-006',
  title: 'Shell interpreter used as command (sh -c, bash -c, cmd /c, powershell -c)',
  severity: SEVERITY,
  description:
    'Detects when a shell is used as the command with -c/-Command flags, indicating string-based command composition.',
  docs: `## MCPA-SEC-006: Shell wrapper

### Why it matters
Using a shell as the command (e.g., \`bash -c "command"\`) indicates string-based command composition. This is risky because:
1. It requires proper escaping of arguments
2. It can hide the actual command being run
3. It enables injection attacks if any part of the command comes from untrusted input

### How it works
This rule detects when the command basename is a known shell (sh, bash, zsh, fish, cmd, cmd.exe, powershell, pwsh) and the args include -c, /c, or -Command.

### Remediation
Invoke the binary directly with args array instead of composing a shell string:
- Instead of: \`bash -c "node server.js --port 3000"\`
- Use: \`command: "node", args: ["server.js", "--port", "3000"]\`

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-SEC-006", "server": "legacy-wrapper", "reason": "Legacy wrapper script, planned for rewrite" }
  ]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { entry } = ctx;

    if (!entry.command) return findings;

    const cmd = entry.command.split('/').pop() ?? entry.command;
    const baseCmd = (cmd.split('.')[0] ?? cmd).toLowerCase();

    if (!SHELLS.has(baseCmd)) return findings;

    const args = entry.args ?? [];
    const hasShellFlag = args.some(arg => SHELL_FLAGS.has(arg));

    if (!hasShellFlag) return findings;

    const flagArg = args.find(arg => SHELL_FLAGS.has(arg));
    const flagIndex = args.indexOf(flagArg ?? '');
    const commandArgIndex = flagIndex + 1;
    const commandString = commandArgIndex < args.length ? args[commandArgIndex] : '';

    const loc = entry.locOf(['args', flagIndex]);
    findings.push({
      ruleId: 'MCPA-SEC-006',
      severity: SEVERITY,
      message: 'Shell wrapper detected: ' + baseCmd + ' ' + flagArg,
      remediation: 'Invoke the binary directly with args array; avoid shell string composition.',
      server: entry.name,
      client: entry.client,
      file: entry.file,
      loc,
      evidence: commandString ? commandString.slice(0, 100) : '(empty)',
      references: [
        'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-006.md',
      ],
    });

    return findings;
  },
};

export default rule;
