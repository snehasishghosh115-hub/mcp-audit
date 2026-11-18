import type { Rule, RuleContext, Finding, Severity } from '../types.js';
import { scanForSecrets, redactSecret } from '../util/secrets.js';

const SEVERITY: Severity = 'critical';

export const rule: Rule = {
  id: 'MCPA-SEC-001',
  title: 'Hardcoded secret in env, args, or headers',
  severity: SEVERITY,
  description:
    'Detects hardcoded secrets (API keys, tokens, passwords) in environment variables, command arguments, or HTTP headers.',
  docs: `## MCPA-SEC-001: Hardcoded secret in env, args, or headers

### Why it matters
Hardcoded secrets in MCP config files are a critical security risk. These files are often committed to version control, shared across teams, or synced via cloud services. Any secret exposed this way must be considered compromised and rotated immediately.

### How it works
This rule scans all \`env\` values, \`args\` elements, and \`headers\` values for known secret patterns (AWS keys, GitHub tokens, Anthropic keys, etc.) and high-entropy strings with secret-like key names.

### Safe patterns (allowed)
- Environment variable references: \`${'${'}GITHUB_TOKEN}\`, \`$GITHUB_TOKEN\`, \`${'${'}env:GITHUB_TOKEN}\`
- Input references: \`${'${'}input:token}\`
- Windows-style: \`%GITHUB_TOKEN%\`
- Placeholders: \`your-token-here\`, \`<YOUR_TOKEN>\`, \`xxx\`, \`changeme\`

### Remediation
1. Move secrets to environment variables or the client's secret input mechanism
2. Rotate any exposed secrets immediately
3. Use \`\${ENV_VAR}\` syntax in configs instead of hardcoding values

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-SEC-001", "server": "my-server", "reason": "Secret is a test token in development environment" }
  ]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { entry } = ctx;

    const checkValue = (value: string, path: (string | number)[], fieldName: string): void => {
      const detected = scanForSecrets({ [fieldName]: value }, fieldName);
      if (detected.length > 0) {
        for (const d of detected) {
          const loc = entry.locOf(path);
          findings.push({
            ruleId: 'MCPA-SEC-001',
            severity: SEVERITY,
            message: 'Hardcoded secret in ' + fieldName + '.' + d.key,
            remediation: 'Use "${' + d.key.toUpperCase() + '}" and rotate the exposed secret.',
            server: entry.name,
            client: entry.client,
            file: entry.file,
            loc,
            evidence: redactSecret(d.value),
            references: [
              'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-001.md',
            ],
          });
        }
      }
    };

    // Check env
    if (entry.env) {
      for (const [key, value] of Object.entries(entry.env)) {
        checkValue(value, ['env', key], key);
      }
    }

    // Check args
    if (entry.args) {
      for (let i = 0; i < entry.args.length; i++) {
        const arg = entry.args[i];
        if (arg !== undefined) {
          checkValue(arg, ['args', i], 'args[' + i + ']');
        }
      }
    }

    // Check headers
    if (entry.headers) {
      for (const [key, value] of Object.entries(entry.headers)) {
        checkValue(value, ['headers', key], key);
      }
    }

    return findings;
  },
};

export default rule;
