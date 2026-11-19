import type { Rule, RuleContext, Finding, Severity } from '../types.js';

const SEVERITY: Severity = 'medium';

const TUNNEL_HOSTS = ['ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'loca.lt', 'serveo.net'];

const IP_REGEX = /^(\d{1,3}\.){3}\d{1,3}$|^\[?([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]?$/;

export const rule: Rule = {
  id: 'MCPA-SEC-016',
  title: 'Remote URL is raw IP, tunnel host (ngrok, trycloudflare, localtunnel), or non-local http',
  severity: SEVERITY,
  description:
    'Detects MCP server URLs pointing to raw IPs, known tunnel hosts, or other risky remote endpoints.',
  docs: `## MCPA-SEC-016: Risky remote host

### Why it matters
Connections to raw IP addresses or tunnel hosts (ngrok, Cloudflare tunnels, localtunnel, etc.) can indicate:
- Temporary development tunnels exposed to the internet
- Potential man-in-the-middle attacks
- Unverified or ephemeral endpoints
- Bypass of network security controls

### How it works
This rule flags server URLs where the host is:
- An IPv4 or IPv6 literal (non-loopback)
- A known tunnel host: ngrok.io, ngrok-free.app, trycloudflare.com, loca.lt, serveo.net
- A non-localhost HTTP endpoint (already caught by MCPA-SEC-003, but this adds tunnel detection)

Allowed hosts can be configured via allowRemoteHosts.

### Remediation
1. Use proper domain names with HTTPS for production
2. For development tunnels, ensure they're temporary and access-controlled
3. Add legitimate internal hosts to allowRemoteHosts in config

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-SEC-016", "server": "dev-tunnel", "reason": "Temporary development tunnel" }
  ],
  "allowRemoteHosts": ["mcp.internal.example.com"]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { entry, config } = ctx;

    if (!entry.url) return findings;

    try {
      const url = new URL(entry.url);
      const hostname = url.hostname.replace(/^\[|\]$/g, '');

      // Check allowRemoteHosts
      if (config.allowRemoteHosts.some(h => hostname === h || hostname.endsWith('.' + h))) {
        return findings;
      }

      // Check for raw IP (non-loopback)
      if (IP_REGEX.test(hostname)) {
        // Check if loopback
        if (
          hostname === '127.0.0.1' ||
          hostname === '::1' ||
          hostname === '0.0.0.0' ||
          hostname === '[::1]'
        ) {
          return findings;
        }
        const loc = entry.locOf(['url']);
        findings.push({
          ruleId: 'MCPA-SEC-016',
          severity: SEVERITY,
          message: 'Remote URL uses raw IP address: ' + hostname,
          remediation: 'Use a proper domain name with HTTPS. Add to allowRemoteHosts if internal.',
          server: entry.name,
          client: entry.client,
          file: entry.file,
          loc,
          evidence: hostname,
          references: [
            'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-016.md',
          ],
        });
        return findings;
      }

      // Check for tunnel hosts
      for (const tunnelHost of TUNNEL_HOSTS) {
        if (hostname === tunnelHost || hostname.endsWith('.' + tunnelHost)) {
          const loc = entry.locOf(['url']);
          findings.push({
            ruleId: 'MCPA-SEC-016',
            severity: SEVERITY,
            message: 'Remote URL uses tunnel host: ' + hostname,
            remediation:
              'Use a proper domain name with HTTPS. Tunnel hosts are ephemeral and risky.',
            server: entry.name,
            client: entry.client,
            file: entry.file,
            loc,
            evidence: hostname,
            references: [
              'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-016.md',
            ],
          });
          return findings;
        }
      }
    } catch {
      // Invalid URL, skip
    }

    return findings;
  },
};

export default rule;
