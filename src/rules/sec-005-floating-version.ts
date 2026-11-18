import type { Rule, RuleContext, Finding, Severity } from '../types.js';

const SEVERITY: Severity = 'medium';

const PACKAGE_RUNNERS = new Set(['npx', 'bunx', 'pnpm', 'yarn', 'uvx', 'pipx', 'dlx']);

function getPackageSpec(args: string[]): string | null {
  if (args.length === 0) return null;
  for (const arg of args) {
    if (!arg.startsWith('-')) return arg;
  }
  return null;
}

function isFloatingVersion(spec: string): boolean {
  // Check for version part after @
  const atIndex = spec.lastIndexOf('@');
  if (atIndex === -1) return false; // No version specified - handled by SEC-004
  const version = spec.slice(atIndex + 1);

  // latest, next, *, branch names, semver ranges
  if (version === 'latest' || version === 'next' || version === '*') return true;
  if (/^[0-9]+\.[0-9]+\.[0-9]+$/.test(version)) return false; // Exact semver
  if (/^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/.test(version)) return false; // Exact with v prefix
  if (/^[a-f0-9]{7,40}$/i.test(version)) return false; // Git SHA
  if (/^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$/.test(version)) return false; // Semver
  // Ranges: ^1.2.3, ~1.2.3, >1.2.3, >=1.2.3, <1.2.3, etc.
  if (/^[\^~><=]/.test(version)) return true;
  // Git branch refs (heuristic: contains slash or dash, not semver)
  if (version.includes('/') || (version.includes('-') && !/^\d+\.\d+\.\d+-/.test(version))) {
    // Could be a branch name like "main", "develop", "feature/xyz"
    return true;
  }
  return false;
}

export const rule: Rule = {
  id: 'MCPA-SEC-005',
  title: 'Package pinned to latest/next/branch/floating range',
  severity: SEVERITY,
  description:
    'Detects package runners with version specifiers that are not exact (latest, next, ranges, branches).',
  docs: `## MCPA-SEC-005: Floating version

### Why it matters
Even when a version is specified, using \`latest\`, \`next\`, semver ranges (\`^1.2.3\`, \`~1.2.3\`), or branch names means the resolved version can change over time. This introduces supply-chain risk similar to unpinned packages.

### How it works
This rule detects when the package spec includes a version that is:
- \`latest\`, \`next\`, \`*\`
- Semver ranges: \`^1.2.3\`, \`~1.2.3\`, \`>1.2.3\`, \`>=1.2.3\`
- Git branch names: \`main\`, \`develop\`, \`feature/xyz\`

### Safe patterns
- \`pkg@1.2.3\` (exact semver)
- \`pkg@v1.2.3\` (exact tag)
- \`pkg@abc123def\` (git SHA)

### Unsafe patterns
- \`pkg@latest\`
- \`pkg@next\`
- \`pkg@^1.2.3\`
- \`pkg@main\`

### Remediation
Use exact versions: \`pkg@1.2.3\` or git SHA \`pkg@abc123def\`

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-SEC-005", "server": "dev-tool", "reason": "Development tool, always want latest" }
  ]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { entry } = ctx;

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

    if (!isFloatingVersion(spec)) return findings;

    const specIndex = effectiveArgs.indexOf(spec);
    const argIndex =
      (baseCmd === 'pnpm' || baseCmd === 'yarn') && args[0] === 'dlx'
        ? args.indexOf('dlx') + 1 + specIndex
        : args.indexOf(spec);

    const loc = entry.locOf(['args', argIndex]);
    findings.push({
      ruleId: 'MCPA-SEC-005',
      severity: SEVERITY,
      message: 'Floating version in package "' + spec + '"',
      remediation: 'Pin exact version (e.g., pkg@1.2.3) or git SHA (pkg@abc123def).',
      server: entry.name,
      client: entry.client,
      file: entry.file,
      loc,
      evidence: spec,
      references: [
        'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-005.md',
      ],
    });

    return findings;
  },
};

export default rule;
