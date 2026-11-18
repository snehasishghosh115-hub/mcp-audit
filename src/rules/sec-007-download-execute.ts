import type { Rule, RuleContext, Finding, Severity } from '../types.js';

const SEVERITY: Severity = 'critical';

const DOWNLOAD_EXECUTE_PATTERNS = [
  // curl | sh, curl | bash, wget | sh, wget | bash
  /(curl|wget)[^|]*\|\s*(sudo\s+)?(sh|bash|zsh)/i,
  // PowerShell: iex (irm ...), iex (iwr ...), Invoke-Expression ... DownloadString
  /iex\s*\(?\s*(irm|iwr|Invoke-WebRequest|Invoke-RestMethod)\s/,
  /Invoke-Expression\s.*DownloadString/i,
];

export const rule: Rule = {
  id: 'MCPA-SEC-007',
  title: 'Download-and-execute pattern (curl|sh, wget|bash, iex (irm ...))',
  severity: SEVERITY,
  description: 'Detects dangerous download-and-execute patterns in command lines.',
  docs: `## MCPA-SEC-007: Download and execute

### Why it matters
Download-and-execute patterns (\`curl ... | sh\`, \`wget ... | bash\`, \`iex (irm ...)\`) are extremely dangerous because:
1. They execute arbitrary code from a remote source without verification
2. The remote content can change at any time (supply chain attack)
3. No integrity checking is performed
4. Often used in malware installation

### How it works
This rule checks the full command line (command + args joined) for patterns matching:
- \`curl ... | sh\`, \`curl ... | bash\`, \`wget ... | sh\`
- PowerShell \`iex (irm ...)\`, \`iex (iwr ...)\`, \`Invoke-Expression ... DownloadString\`

### Remediation
1. Download the script first, verify its integrity (checksum/signature), then execute
2. Use package managers (npm, pip, cargo) which provide integrity guarantees
3. If you must use this pattern, pin to a specific commit/hash and verify checksum

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-SEC-007", "server": "bootstrap", "reason": "One-time bootstrap script, verified manually" }
  ]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { entry } = ctx;

    if (!entry.command) return findings;

    const fullCommand = [entry.command, ...(entry.args ?? [])].join(' ');

    for (const pattern of DOWNLOAD_EXECUTE_PATTERNS) {
      const match = fullCommand.match(pattern);
      if (match) {
        const loc = entry.loc;
        findings.push({
          ruleId: 'MCPA-SEC-007',
          severity: SEVERITY,
          message: 'Download-and-execute pattern detected',
          remediation:
            'Download and verify script integrity before execution. Use package managers instead.',
          server: entry.name,
          client: entry.client,
          file: entry.file,
          loc,
          evidence: match[0].slice(0, 200),
          references: [
            'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-007.md',
          ],
        });
        break; // Only report once per server
      }
    }

    return findings;
  },
};

export default rule;
