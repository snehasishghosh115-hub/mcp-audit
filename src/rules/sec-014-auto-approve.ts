import type { Rule, RuleContext, Finding, Severity } from '../types.js';

const AUTO_APPROVE_KEYS = ['autoApprove', 'alwaysAllow', 'autoapprove', 'trust'];

export const rule: Rule = {
  id: 'MCPA-SEC-014',
  title: 'Blanket auto-approve (autoApprove: ["*"], alwaysAllow: true, trust: true)',
  severity: 'high',
  description: 'Detects configurations that auto-approve all tool calls without user confirmation.',
  docs: `## MCPA-SEC-014: Blanket auto-approve

### Why it matters
Auto-approve settings remove the human from the loop, allowing MCP servers to execute arbitrary tools without user consent. This defeats the primary security model of MCP where users must approve each tool call.

### How it works
This rule checks for auto-approve settings:
- \`autoApprove: ["*"]\` or \`alwaysAllow: ["*"]\`
- \`autoApprove: true\` or \`alwaysAllow: true\`
- \`trust: true\`
- Arrays containing \`"*"\`

If the array lists specific tools that appear read-only (e.g., \`read_*\`, \`list_*\`, \`get_*\`), severity is lowered to medium.

### Remediation
1. Remove blanket auto-approve
2. If needed, explicitly list only safe, read-only tools
3. Consider if auto-approve is truly necessary

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-SEC-014", "server": "read-only-server", "reason": "Only exposes read-only tools" }
  ]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { entry } = ctx;

    for (const key of AUTO_APPROVE_KEYS) {
      const value = entry[key as keyof typeof entry] as unknown;
      if (value === undefined) continue;

      let isBlanket = false;
      let severity: Severity = 'high';
      let message = '';

      if (value === true) {
        isBlanket = true;
        message = key + ': true';
      } else if (Array.isArray(value)) {
        if (value.includes('*')) {
          isBlanket = true;
          message = key + ': ["*"]';
        } else if (value.length > 0) {
          // Check if all tools appear read-only
          const allReadOnly = value.every(
            tool =>
              typeof tool === 'string' &&
              /^(read_|list_|get_|search_|find_|query_|describe_|fetch_)/i.test(tool)
          );
          if (!allReadOnly) {
            isBlanket = true;
            message = key + ': [' + value.join(', ') + ']';
          } else {
            isBlanket = true;
            severity = 'medium';
            message = key + ': [' + value.join(', ') + '] (read-only tools)';
          }
        }
      }

      if (isBlanket) {
        const loc = entry.locOf([key]);
        findings.push({
          ruleId: 'MCPA-SEC-014',
          severity,
          message: 'Blanket auto-approve: ' + message,
          remediation:
            'Remove blanket auto-approve. If needed, explicitly list only safe read-only tools.',
          server: entry.name,
          client: entry.client,
          file: entry.file,
          loc,
          evidence: JSON.stringify(value),
          references: [
            'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-014.md',
          ],
        });
        break; // Only report once per server
      }
    }

    return findings;
  },
};

export default rule;
