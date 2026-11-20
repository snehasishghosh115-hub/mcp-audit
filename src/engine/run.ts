import type {
  Rule,
  RuleContext,
  Finding,
  ServerEntry,
  ResolvedConfig,
  ScanError,
  ToolDef,
} from '../types.js';

export function runRules(
  entries: ServerEntry[],
  rules: Rule[],
  config: ResolvedConfig,
  tools?: Map<string, { server: string; tools: ToolDef[] }>
): { findings: Finding[]; errors: ScanError[] } {
  const findings: Finding[] = [];
  const errors: ScanError[] = [];

  for (const entry of entries) {
    const toolDefs = tools?.get(entry.id);
    const context: RuleContext = {
      entry,
      config,
      tools: toolDefs?.tools,
    };

    for (const rule of rules) {
      if (config.ruleIds && !config.ruleIds.includes(rule.id)) continue;
      if (config.skipRuleIds?.includes(rule.id)) continue;

      const severityOverride = config.severityOverrides[rule.id];
      // Only override severity if the user has explicitly configured it in severityOverrides.
      // Otherwise, use the per-finding severity returned by the rule (which may differ from
      // rule.severity for rules that dynamically downgrade e.g. read-only auto-approve).

      if (shouldIgnore(rule.id, entry, config)) continue;

      try {
        const ruleFindings = rule.check(context);
        for (const finding of ruleFindings) {
          const effectiveSeverity = severityOverride ?? finding.severity;
          const finalFinding = { ...finding, severity: effectiveSeverity };
          if (meetsMinSeverity(finalFinding.severity, config.minSeverity)) {
            findings.push(finalFinding);
          }
        }
      } catch (e) {
        errors.push({
          file: entry.file,
          message: `Rule ${rule.id} threw: ${e instanceof Error ? e.message : String(e)}`,
          code: 'RULE_ERROR',
        });
      }
    }
  }

  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  findings.sort((a, b) => {
    const sevDiff = (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4);
    if (sevDiff !== 0) return sevDiff;
    const fileDiff = a.file.localeCompare(b.file);
    if (fileDiff !== 0) return fileDiff;
    const lineDiff = (a.loc?.line ?? 0) - (b.loc?.line ?? 0);
    if (lineDiff !== 0) return lineDiff;
    return a.ruleId.localeCompare(b.ruleId);
  });

  return { findings, errors };
}

function shouldIgnore(ruleId: string, entry: ServerEntry, config: ResolvedConfig): boolean {
  for (const ignore of config.ignore) {
    if (ignore.rule !== ruleId) continue;
    if (ignore.server && ignore.server !== entry.name) continue;
    if (ignore.file && ignore.file !== entry.file) continue;
    return true;
  }
  return false;
}

function meetsMinSeverity(severity: string, minSeverity: string): boolean {
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return (order[severity] ?? 4) <= (order[minSeverity] ?? 4);
}
