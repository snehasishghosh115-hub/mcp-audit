import type { Rule, RuleContext, Finding, Severity } from '../types.js';

const SEVERITY: Severity = 'high';

const DANGEROUS_DOCKER_FLAGS = [
  '--privileged',
  '--network=host',
  '--net=host',
  '-v/var/run/docker.sock',
  '--volume=/var/run/docker.sock',
  '-v /var/run/docker.sock',
  '--volume /var/run/docker.sock',
  '-v /:',
  '--volume /:',
  '-v ~:',
  '--volume ~:',
  '-v $HOME:',
  '--volume $HOME:',
  '-v ${HOME}:',
  '--volume ${HOME}:',
  '--cap-add=ALL',
  '--pid=host',
];

function isDockerRunCommand(command: string, args: string[]): boolean {
  const cmd = command.toLowerCase();
  const baseCmd = cmd.split('/').pop()?.split('.')[0] ?? '';
  if (baseCmd !== 'docker' && baseCmd !== 'podman') return false;
  return args[0] === 'run' || args[0] === 'create';
}

export const rule: Rule = {
  id: 'MCPA-SEC-009',
  title: 'Dangerous Docker flags (--privileged, docker.sock mount, --network host, -v /:/)',
  severity: SEVERITY,
  description:
    'Detects dangerous Docker flags that break container isolation or grant excessive host access.',
  docs: `## MCPA-SEC-009: Dangerous Docker flags

### Why it matters
Certain Docker flags completely break container isolation:
- \`--privileged\`: Grants ALL capabilities to the container
- \`--network=host\`: Shares host network stack (no network isolation)
- \`-v /var/run/docker.sock\`: Allows container to control Docker daemon (full host compromise)
- \`-v /:/\` or \`-v ~:/\`: Mounts host root or home directory
- \`--cap-add=ALL\`: Adds all Linux capabilities
- \`--pid=host\`: Shares host PID namespace

### How it works
This rule checks \`docker run\` / \`podman run\` commands for dangerous flags.

### Remediation
1. Avoid \`--privileged\` - grant only specific capabilities with \`--cap-add\`
2. Use bridge networks instead of \`--network=host\`
3. Never mount \`/var/run/docker.sock\` - use Docker API over TCP with TLS instead
4. Mount only specific directories needed, not root or home

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-SEC-009", "server": "docker-manager", "reason": "Manages Docker containers, requires docker.sock access" }
  ]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { entry } = ctx;

    if (!entry.command || !entry.args) return findings;

    if (!isDockerRunCommand(entry.command, entry.args)) return findings;

    const fullArgs = entry.args.join(' ');

    for (const flag of DANGEROUS_DOCKER_FLAGS) {
      if (fullArgs.includes(flag)) {
        // Find the arg index containing this flag
        let argIndex = -1;
        for (let i = 0; i < entry.args.length; i++) {
          const arg = entry.args[i];
          if (arg === undefined) continue;
          const nextArg = entry.args[i + 1];
          if (
            arg.includes(flag) ||
            (nextArg !== undefined && (arg + ' ' + nextArg).includes(flag))
          ) {
            argIndex = i;
            break;
          }
        }

        const loc = argIndex >= 0 ? entry.locOf(['args', argIndex]) : entry.loc;
        findings.push({
          ruleId: 'MCPA-SEC-009',
          severity: SEVERITY,
          message: 'Dangerous Docker flag: ' + flag,
          remediation: 'Remove dangerous flag. Use least-privilege alternatives.',
          server: entry.name,
          client: entry.client,
          file: entry.file,
          loc,
          evidence: flag,
          references: [
            'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-009.md',
          ],
        });
        break; // Report once per server
      }
    }

    return findings;
  },
};

export default rule;
