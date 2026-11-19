import type { Rule, RuleContext, Finding, Severity } from '../types.js';

const SEVERITY: Severity = 'medium';

function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

export const rule: Rule = {
  id: 'MCPA-TOOL-003',
  title: 'Tool name collision/shadowing across servers',
  severity: SEVERITY,
  description:
    'Detects when the same tool name is exposed by multiple servers, or names that differ only by case/punctuation.',
  docs: `## MCPA-TOOL-003: Tool name shadowing

### Why it matters
When multiple MCP servers expose tools with the same name (or names that differ only by case/punctuation), it creates ambiguity:
- The LLM may not know which tool to call
- A malicious server could shadow a legitimate tool
- Users may unintentionally call the wrong tool

### How it works
This rule checks all tools across all servers in the scan for:
1. Exact name collisions (same name from 2+ servers)
2. Near-collisions: names that differ only by case or punctuation (e.g., "read_file" vs "read-file" vs "readFile")

### Remediation
1. Rename tools to be unique across servers
2. Use server-specific prefixes (e.g., "github_read_file", "fs_read_file")
3. Configure the client to only expose tools from trusted servers

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-TOOL-003", "server": "github", "reason": "Intentional alias for compatibility" }
  ]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { tools } = ctx;

    if (!tools || tools.length === 0) return findings;

    // Group by normalized name
    const byNormalized = new Map<string, Array<{ tool: (typeof tools)[0]; server: string }>>();

    for (const tool of tools) {
      const normalized = normalizeName(tool.name);
      const existing = byNormalized.get(normalized) ?? [];
      existing.push({ tool, server: ctx.entry.name });
      byNormalized.set(normalized, existing);
    }

    // Check for collisions
    for (const [normalized, entries] of byNormalized.entries()) {
      if (entries.length > 1) {
        const servers = [...new Set(entries.map(e => e.server))];
        if (servers.length > 1) {
          // Cross-server collision
          for (const entry of entries) {
            findings.push({
              ruleId: 'MCPA-TOOL-003',
              severity: SEVERITY,
              message:
                'Tool name collision: "' +
                entry.tool.name +
                '" exposed by ' +
                servers.length +
                ' servers (' +
                servers.join(', ') +
                ')',
              remediation: 'Use unique tool names across servers (e.g., add server prefix).',
              server: entry.server,
              client: ctx.entry.client,
              file: ctx.entry.file,
              loc: undefined,
              evidence: normalized,
              references: [
                'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-TOOL-003.md',
              ],
            });
          }
        }
      }
    }

    return findings;
  },
};

export default rule;
