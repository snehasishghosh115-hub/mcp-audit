import type { Rule, RuleContext, Finding, Severity } from '../types.js';
import { redactSecret } from '../util/secrets.js';

const SEVERITY: Severity = 'high';

export const rule: Rule = {
  id: 'MCPA-SEC-002',
  title: 'Secret embedded in URL (query or userinfo)',
  severity: SEVERITY,
  description:
    'Detects secrets embedded in HTTP/SSE server URLs, either in userinfo or query parameters.',
  docs: `## MCPA-SEC-002: Secret embedded in URL

### Why it matters
URLs with embedded credentials or API keys in query parameters are logged in server access logs, browser history, and proxy logs. They should never contain secrets.

### How it works
This rule checks \`url\` fields for:
- Userinfo credentials: \`https://user:password@host\`
- Query parameters with secret-like names: \`api_key\`, \`token\`, \`secret\`, \`password\`, \`auth_key\`, \`access_token\`

### Remediation
1. Use HTTP headers for authentication instead of URL parameters
2. Use the client's secret input mechanism
3. If the server requires URL-based auth, use environment variable references

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-SEC-002", "server": "my-server", "reason": "Legacy server requires URL-based auth, migrating soon" }
  ]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { entry } = ctx;

    if (!entry.url) return findings;

    const url = entry.url;

    // Check userinfo
    const userinfoMatch = url.match(/^https?:\/\/([^:]+):([^@]+)@/);
    if (userinfoMatch) {
      const [, user, pass] = userinfoMatch;
      const loc = entry.locOf(['url']);
      findings.push({
        ruleId: 'MCPA-SEC-002',
        severity: SEVERITY,
        message: 'Secret in URL userinfo',
        remediation: 'Move credentials to headers or use environment variables.',
        server: entry.name,
        client: entry.client,
        file: entry.file,
        loc,
        evidence: redactSecret(`${user}:${pass}`),
        references: [
          'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-002.md',
        ],
      });
    }

    // Check query parameters
    const paramPatterns: Array<[string, RegExp]> = [
      ['api_key', /[?&]api[_-]?key=([^&]+)/i],
      ['token', /[?&]token=([^&]+)/i],
      ['secret', /[?&]secret=([^&]+)/i],
      ['password', /[?&]password=([^&]+)/i],
      ['auth_key', /[?&]auth[_-]?key=([^&]+)/i],
      ['access_token', /[?&]access[_-]?token=([^&]+)/i],
    ];
    for (const [paramName, pattern] of paramPatterns) {
      const match = url.match(pattern);
      if (match && match[1]) {
        const loc = entry.locOf(['url']);
        findings.push({
          ruleId: 'MCPA-SEC-002',
          severity: SEVERITY,
          message: 'Secret in URL query parameter "' + paramName + '"',
          remediation: 'Move secrets to headers or use environment variables.',
          server: entry.name,
          client: entry.client,
          file: entry.file,
          loc,
          evidence: redactSecret(match[1]),
          references: [
            'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-002.md',
          ],
        });
      }
    }

    return findings;
  },
};

export default rule;
