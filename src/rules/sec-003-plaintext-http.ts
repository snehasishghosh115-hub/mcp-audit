import type { Rule, RuleContext, Finding, Severity } from '../types.js';

const SEVERITY: Severity = 'high';

const LOCALHOST_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

export const rule: Rule = {
  id: 'MCPA-SEC-003',
  title: 'Remote server over plaintext HTTP',
  severity: SEVERITY,
  description:
    'Detects MCP servers configured with plaintext HTTP (not HTTPS) for non-localhost destinations.',
  docs: `## MCPA-SEC-003: Plaintext HTTP

### Why it matters
Plaintext HTTP exposes all traffic to network sniffing. Credentials, tool calls, and responses can be intercepted and modified by any party on the network path.

### How it works
This rule flags any server with a \`url\` starting with \`http://\` where the host is not \`localhost\`, \`127.0.0.1\`, or \`::1\`.

### Remediation
1. Use HTTPS for all remote servers
2. For local development, use \`localhost\` or \`127.0.0.1\`
3. Consider using SSH tunnels or VPNs for secure local access

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-SEC-003", "server": "local-dev", "reason": "Development server on isolated network" }
  ],
  "allowRemoteHosts": ["internal.example.com"]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { entry, config } = ctx;

    if (!entry.url) return findings;

    try {
      const url = new URL(entry.url);
      if (url.protocol !== 'http:') return findings;

      const hostname = url.hostname.replace(/^\[|\]$/g, ''); // Remove IPv6 brackets
      if (LOCALHOST_HOSTS.has(hostname)) return findings;

      // Check allowRemoteHosts config
      if (config.allowRemoteHosts.some(h => hostname === h || hostname.endsWith('.' + h))) {
        return findings;
      }

      const loc = entry.locOf(['url']);
      findings.push({
        ruleId: 'MCPA-SEC-003',
        severity: SEVERITY,
        message: 'Plaintext HTTP to remote host "' + hostname + '"',
        remediation:
          'Use HTTPS. If this is an internal host, add it to allowRemoteHosts in config.',
        server: entry.name,
        client: entry.client,
        file: entry.file,
        loc,
        evidence: hostname,
        references: [
          'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-003.md',
        ],
      });
    } catch {
      // Invalid URL, skip
    }

    return findings;
  },
};

export default rule;
