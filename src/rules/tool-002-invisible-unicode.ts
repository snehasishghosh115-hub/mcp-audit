import type { Rule, RuleContext, Finding, Severity } from '../types.js';

const SEVERITY: Severity = 'high';

const INVISIBLE_RANGES = [
  { start: 0x200b, end: 0x200f, name: 'Zero-width' },
  { start: 0x202a, end: 0x202e, name: 'Bidi controls' },
  { start: 0x2066, end: 0x2069, name: 'Bidi isolates' },
  { start: 0xe0000, end: 0xe007f, name: 'Tag characters' },
];

function hasInvisibleChars(str: string): { char: string; code: number; name: string } | null {
  for (let i = 0; i < str.length; i++) {
    const code = str.codePointAt(i);
    if (code === undefined) continue;
    const ch = str[i];
    if (ch === undefined) continue;

    // Check BOM mid-string (not at position 0)
    if (code === 0xfeff && i > 0) {
      return { char: ch, code, name: 'BOM' };
    }

    for (const range of INVISIBLE_RANGES) {
      if (code >= range.start && code <= range.end) {
        return { char: ch, code, name: range.name };
      }
    }
  }
  return null;
}

export const rule: Rule = {
  id: 'MCPA-TOOL-002',
  title: 'Hidden/invisible Unicode in tool name or description',
  severity: SEVERITY,
  description:
    'Detects invisible Unicode characters (zero-width, bidi controls, tag chars, BOM) in tool names or descriptions.',
  docs: `## MCPA-TOOL-002: Invisible Unicode

### Why it matters
Invisible Unicode characters can be used to:
- Hide malicious instructions from human reviewers while still being processed by LLMs
- Create visually identical but semantically different tool names (homograph attacks)
- Manipulate text rendering and processing

### How it works
This rule scans tool names and descriptions for:
- Zero-width characters (U+200B-U+200F)
- Bidirectional controls (U+202A-U+202E, U+2066-U+2069)
- Tag characters (U+E0000-U+E007F)
- BOM (U+FEFF) appearing mid-string

### Remediation
1. Remove invisible characters from tool definitions
2. Report to the MCP server maintainer
3. Consider if this tool should be exposed at all

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-TOOL-002", "server": "legacy-server", "reason": "Known false positive" }
  ]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { tools } = ctx;

    if (!tools || tools.length === 0) return findings;

    for (const tool of tools) {
      // Check tool name
      if (tool.name) {
        const invisible = hasInvisibleChars(tool.name);
        if (invisible) {
          const codeStr = 'U+' + invisible.code.toString(16).toUpperCase().padStart(4, '0');
          findings.push({
            ruleId: 'MCPA-TOOL-002',
            severity: SEVERITY,
            message:
              'Invisible Unicode in tool name "' +
              tool.name +
              '" (' +
              invisible.name +
              ': ' +
              codeStr +
              ')',
            remediation: 'Remove invisible characters from tool name.',
            server: ctx.entry.name,
            client: ctx.entry.client,
            file: ctx.entry.file,
            loc: undefined,
            evidence: codeStr,
            references: [
              'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-TOOL-002.md',
            ],
          });
        }
      }

      // Check tool description
      if (tool.description) {
        const invisible = hasInvisibleChars(tool.description);
        if (invisible) {
          const codeStr = 'U+' + invisible.code.toString(16).toUpperCase().padStart(4, '0');
          findings.push({
            ruleId: 'MCPA-TOOL-002',
            severity: SEVERITY,
            message:
              'Invisible Unicode in tool "' +
              tool.name +
              '" description (' +
              invisible.name +
              ': ' +
              codeStr +
              ')',
            remediation: 'Remove invisible characters from tool description.',
            server: ctx.entry.name,
            client: ctx.entry.client,
            file: ctx.entry.file,
            loc: undefined,
            evidence: codeStr,
            references: [
              'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-TOOL-002.md',
            ],
          });
        }
      }
    }

    return findings;
  },
};

export default rule;
