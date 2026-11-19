import type { Rule, RuleContext, Finding, Severity } from '../types.js';
import { findTyposquat } from '../rules/data/known-packages.js';

const SEVERITY: Severity = 'high';

const PACKAGE_RUNNERS = new Set(['npx', 'bunx', 'pnpm', 'yarn', 'uvx', 'pipx', 'dlx']);

function getPackageSpec(args: string[]): string | null {
  if (args.length === 0) return null;
  for (const arg of args) {
    if (!arg.startsWith('-')) return arg;
  }
  return null;
}

export const rule: Rule = {
  id: 'MCPA-SEC-010',
  title: 'Possible typosquat of known MCP/npm package',
  severity: SEVERITY,
  description:
    'Detects package names that are similar to well-known MCP packages (Levenshtein distance 1-2).',
  docs: `## MCPA-SEC-010: Possible typosquat

### Why it matters
Typosquatting is a supply-chain attack where attackers publish packages with names similar to popular packages (e.g., "mcp-server-githb" instead of "mcp-server-github"). Developers who mistype the name install the malicious package.

### How it works
This rule checks package names in npx/uvx/bunx/etc. commands against a list of well-known MCP packages. It flags names with Levenshtein distance 1-2 (or common character swaps like -/_, doubled letters, scope removal) from known packages, unless the name is in the trustedPackages config.

### Remediation
1. Verify the exact package name spelling
2. Check the package publisher and repository
3. Add legitimate internal packages to trustedPackages in config

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-SEC-010", "server": "my-internal-tool", "reason": "Internal package with similar name" }
  ],
  "trustedPackages": ["@mycorp/mcp-tools"]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { entry, config } = ctx;

    if (!entry.command) return findings;

    const cmd = entry.command.split('/').pop() ?? entry.command;
    const baseCmd = cmd.split('.')[0] ?? cmd;

    if (!PACKAGE_RUNNERS.has(baseCmd)) return findings;

    const args = entry.args ?? [];
    let effectiveArgs = args;
    if ((baseCmd === 'pnpm' || baseCmd === 'yarn') && args[0] === 'dlx') {
      effectiveArgs = args.slice(1);
    }

    const spec = getPackageSpec(effectiveArgs);
    if (!spec) return findings;

    // Extract package name (before @version)
    const pkgName = spec.split('@')[0];
    if (!pkgName) return findings;

    const match = findTyposquat(pkgName, config.trustedPackages);
    if (!match) return findings;

    const specIndex = effectiveArgs.indexOf(spec);
    const argIndex =
      (baseCmd === 'pnpm' || baseCmd === 'yarn') && args[0] === 'dlx'
        ? args.indexOf('dlx') + 1 + specIndex
        : args.indexOf(spec);

    const loc = entry.locOf(['args', argIndex]);
    findings.push({
      ruleId: 'MCPA-SEC-010',
      severity: SEVERITY,
      message: 'Possible typosquat: "' + pkgName + '" is similar to known package "' + match + '"',
      remediation:
        'Verify the exact package name. If legitimate, add to trustedPackages in config.',
      server: entry.name,
      client: entry.client,
      file: entry.file,
      loc,
      evidence: pkgName,
      references: [
        'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-010.md',
      ],
    });

    return findings;
  },
};

export default rule;
