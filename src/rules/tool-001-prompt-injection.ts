import type { Rule, RuleContext, Finding, Severity } from '../types.js';

const SEVERITY: Severity = 'high';

const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior)\s+instructions/i,
  /do\s+not\s+(tell|inform|mention).*user/i,
  /<important>/i,
  /before\s+(using|calling)\s+this\s+tool.*(read|send|include)/i,
  /system\s+prompt/i,
  /you\s+must\s+(also\s+)?(call|use)/i,
  /instruction.*(call|use)\s+other\s+tools?/i,
  /base64\s*[A-Za-z0-9+/]{200,}={0,2}/i,
];

export const rule: Rule = {
  id: 'MCPA-TOOL-001',
  title: 'Prompt-injection phrasing in tool description',
  severity: SEVERITY,
  description:
    'Detects suspicious phrases in tool descriptions that may indicate prompt injection attempts.',
  docs: `## MCPA-TOOL-001: Prompt-injection phrasing

### Why it matters
Tool descriptions are shown to the LLM and can contain instructions that manipulate the model's behavior. Attackers can embed prompt injection phrases to:
- Make the model ignore previous instructions
- Hide information from the user
- Force the model to call other tools
- Exfiltrate data

### How it works
This rule scans tool descriptions for suspicious patterns (case-insensitive):
- "ignore (all )?(previous|prior) instructions"
- "do not (tell|inform|mention).*user"
- "<important>"
- "before (using|calling) this tool.*(read|send|include)"
- "system prompt"
- "you must (also )?(call|use)"
- Instructions to call other tools
- Base64 blobs >200 chars

Also flags descriptions longer than 2000 chars as a low-severity note.

### Remediation
1. Review the tool description for suspicious content
2. Report to the MCP server maintainer
3. Consider if this tool should be exposed at all

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-TOOL-001", "server": "legacy-server", "reason": "Known false positive in description" }
  ]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { tools } = ctx;

    if (!tools || tools.length === 0) return findings;

    for (const tool of tools) {
      if (!tool.description) continue;

      const desc = tool.description;

      for (const pattern of PROMPT_INJECTION_PATTERNS) {
        if (pattern.test(desc)) {
          findings.push({
            ruleId: 'MCPA-TOOL-001',
            severity: SEVERITY,
            message: 'Prompt-injection phrasing in tool "' + tool.name + '"',
            remediation:
              'Review tool description for prompt injection attempts. Report to server maintainer.',
            server: ctx.entry.name,
            client: ctx.entry.client,
            file: ctx.entry.file,
            loc: undefined,
            evidence: desc.slice(0, 200),
            references: [
              'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-TOOL-001.md',
            ],
          });
          break; // Only report once per tool
        }
      }

      // Long description note
      if (desc.length > 2000) {
        findings.push({
          ruleId: 'MCPA-TOOL-001',
          severity: 'low',
          message:
            'Tool "' + tool.name + '" has unusually long description (' + desc.length + ' chars)',
          remediation: 'Verify description is not hiding malicious content.',
          server: ctx.entry.name,
          client: ctx.entry.client,
          file: ctx.entry.file,
          loc: undefined,
          evidence: 'Length: ' + desc.length,
          references: [
            'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-TOOL-001.md',
          ],
        });
      }
    }

    return findings;
  },
};

export default rule;
