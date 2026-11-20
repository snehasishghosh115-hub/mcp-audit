import type { Rule, RuleContext, Finding, Severity } from '../types.js';

const SEVERITY: Severity = 'medium';

const PACKAGE_RUNNERS = new Set(['npx', 'bunx', 'pnpm', 'yarn', 'uvx', 'pipx', 'dlx']);

function getPackageSpec(args: string[]): string | null {
  if (args.length === 0) return null;
  // Skip flags like -y, --yes
  for (const arg of args) {
    if (!arg.startsWith('-')) return arg;
  }
  return null;
}

function isPinned(spec: string): boolean {
  // Exact semver: pkg@1.2.3 or @scope/pkg@1.2.3
  if (/^(@[^/]+\/)?[^@]+@\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/.test(spec)) {
    return true;
  }
  // Git SHA or tag: pkg@sha123, pkg@v1.2.3
  if (/^(@[^/]+\/)?[^@]+@[a-f0-9]{7,40}$/i.test(spec)) return true;
  if (/^(@[^/]+\/)?[^@]+@v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(spec)) return true;
  return false;
}

export const rule: Rule = {
  id: 'MCPA-SEC-004',
  title: 'Unpinned package run via npx/uvx/pipx/bunx/dlx',
  severity: SEVERITY,
  description: 'Detects package runners (npx, uvx, etc.) invoked without a pinned version.',
  docs: `## MCPA-SEC-004: Unpinned package

### Why it matters
Running \`npx pkg\` or \`uvx pkg\` without a version specifier means you'll get whatever is the latest publish at runtime. This is a supply-chain risk: a malicious publish or compromised registry could inject malicious code.

### How it works
This rule detects when the command is a known package runner (npx, bunx, pnpm dlx, yarn dlx, uvx, pipx) and the first non-flag argument (the package spec) does not contain a pinned version.

### Safe patterns
- \`npx pkg@1.2.3\`
- \`uvx pkg@v1.2.3\`
- \`pnpm dlx @scope/pkg@1.2.3\`

### Unsafe patterns
- \`npx pkg\`
- \`uvx pkg\`
- \`npx @scope/pkg\`

### Remediation
Pin exact versions: \`npx pkg@1.2.3\` or \`uvx pkg@v1.2.3\`

### How to ignore
Add to \`.mcp-audit.json\`:
\`\`\`json
{
  "ignore": [
    { "rule": "MCPA-SEC-004", "server": "my-local-tool", "reason": "Internal package, pinned by lockfile" }
  ],
  "trustedPackages": ["@mycorp/mcp-tools"]
}
\`\`\``,
  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { entry, config } = ctx;

    if (!entry.command) return findings;

    const cmd = entry.command.split('/').pop() ?? entry.command;
    const baseCmd = cmd.split('.')[0] ?? cmd; // Handle npx.cmd on Windows

    if (!PACKAGE_RUNNERS.has(baseCmd)) return findings;

    const args = entry.args ?? [];
    const spec = getPackageSpec(args);
    if (!spec) return findings;

    // Check trusted packages
    if (config.trustedPackages.some(tp => spec.startsWith(tp))) return findings;

    // Check if it's a pnpm/yarn with dlx subcommand
    let effectiveArgs = args;
    if ((baseCmd === 'pnpm' || baseCmd === 'yarn') && args[0] === 'dlx') {
      effectiveArgs = args.slice(1);
      const dlxSpec = getPackageSpec(effectiveArgs);
      if (!dlxSpec) return findings;
      if (config.trustedPackages.some(tp => dlxSpec.startsWith(tp))) return findings;
      if (isPinned(dlxSpec)) return findings;

      const loc = entry.locOf(['args', args.indexOf('dlx') + 1 + effectiveArgs.indexOf(dlxSpec)]);
      findings.push({
        ruleId: 'MCPA-SEC-004',
        severity: SEVERITY,
        message: 'Unpinned package "' + dlxSpec + '" via ' + baseCmd + ' dlx',
        remediation: 'Pin exact version: ' + baseCmd + ' dlx ' + dlxSpec + '@1.2.3',
        server: entry.name,
        client: entry.client,
        file: entry.file,
        loc,
        evidence: dlxSpec,
        references: [
          'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-004.md',
        ],
      });
      return findings;
    }

    if (isPinned(spec)) return findings;

    const loc2 = entry.locOf(['args', args.indexOf(spec)]);
    findings.push({
      ruleId: 'MCPA-SEC-004',
      severity: SEVERITY,
      message: 'Unpinned package "' + spec + '" via ' + baseCmd,
      remediation: 'Pin exact version: ' + baseCmd + ' ' + spec + '@1.2.3',
      server: entry.name,
      client: entry.client,
      file: entry.file,
      loc: loc2,
      evidence: spec,
      references: [
        'https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/MCPA-SEC-004.md',
      ],
    });

    return findings;
  },
};

export default rule;
