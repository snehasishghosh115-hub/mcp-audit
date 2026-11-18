import type { Rule, RuleContext, Finding, Severity } from '../types.js';
import { isWorldOrGroupReadable } from '../util/fs.js';
import { scanForSecrets, isEnvReference } from '../util/secrets.js';

const SEVERITY: Severity = 'medium';

export const rule: Rule = {
  id: 'MCPA-SEC-015',
  title: 'Config containing secrets is group/world-readable (POSIX)',
  severity: SEVERITY,
  description:
    'Detects MCP config files with overly permissive file permissions that contain non-reference secrets.',
  docs: `## MCPA-SEC-015: File permissions

### Why it matters
Config files with group/world read permissions (mode 0644, 0664, etc.) that contain hardcoded secrets expose those secrets to other users on the system. This is especially risky on shared servers or CI runners.

### How it works
This rule (POSIX only) checks:
1. File mode has group or other read bit set (mode & 0o044)
2. File contains at least one non-reference secret (via secret detection)

Environment variable references like \`\${VAR}\` are not considered secrets for this rule.

### Remediation
1. Restrict file permissions: \`chmod 600 config.json\`
2. Move secrets to environment variables or secret managers
3. Use the client's secret input mechanism

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-SEC-015", "server": "shared-config", "reason": "Config is in shared location, secrets are env refs" }
  ]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { entry } = ctx;

    // Skip on Windows
    if (process.platform === 'win32') return findings;

    if (!isWorldOrGroupReadable(entry.file)) return findings;

    // Check if file contains non-reference secrets
    let hasSecrets = false;
    let secretEvidence = '';

    // Check env
    if (entry.env) {
      for (const [key, value] of Object.entries(entry.env)) {
        if (!isEnvReference(value)) {
          const detected = scanForSecrets({ [key]: value }, key);
          if (detected.length > 0 && detected[0]) {
            hasSecrets = true;
            secretEvidence = detected[0].value;
            break;
          }
        }
      }
    }

    // Check args
    if (!hasSecrets && entry.args) {
      for (let i = 0; i < entry.args.length; i++) {
        const arg = entry.args[i];
        if (arg === undefined) continue;
        const detected = scanForSecrets({ [`args[${i}]`]: arg }, `args[${i}]`);
        if (detected.length > 0 && detected[0]) {
          hasSecrets = true;
          secretEvidence = detected[0].value;
          break;
        }
      }
    }

    // Check headers
    if (!hasSecrets && entry.headers) {
      for (const [key, value] of Object.entries(entry.headers)) {
        const detected = scanForSecrets({ [key]: value }, key);
        if (detected.length > 0 && detected[0]) {
          hasSecrets = true;
          secretEvidence = detected[0].value;
          break;
        }
      }
    }

    if (!hasSecrets) return findings;

    const loc = entry.loc;
    findings.push({
      ruleId: 'MCPA-SEC-015',
      severity: SEVERITY,
      message: 'Config file is group/world-readable and contains secrets',
      remediation: 'Run "chmod 600" on the config file and move secrets to environment variables.',
      server: entry.name,
      client: entry.client,
      file: entry.file,
      loc,
      evidence: secretEvidence,
      references: [
        'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-015.md',
      ],
    });

    return findings;
  },
};

export default rule;
