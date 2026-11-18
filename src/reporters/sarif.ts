import type { ScanResult, Severity } from '../types.js';
import { VERSION } from '../version.js';
import { ALL_RULES } from '../rules/index.js';

const SEVERITY_TO_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

export function printSarifReport(result: ScanResult): string {
  const rules = ALL_RULES.map(r => ({
    id: r.id,
    name: r.title,
    shortDescription: { text: r.description },
    fullDescription: { text: r.docs },
    defaultConfiguration: { level: SEVERITY_TO_LEVEL[r.severity] },
    helpUri: `https://github.com/snehasishghosh115-hub/mcp-audit/blob/main/docs/rules/${r.id.toLowerCase()}.md`,
  }));

  const results = result.findings.map(f => ({
    ruleId: f.ruleId,
    level: SEVERITY_TO_LEVEL[f.severity],
    message: { text: `${f.message}. ${f.remediation}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file, uriBaseId: '%SRCROOT%' },
          region: f.loc ? { startLine: f.loc.line, startColumn: f.loc.column } : undefined,
        },
      },
    ],
    properties: {
      server: f.server,
      client: f.client,
      evidence: f.evidence,
      references: f.references,
    },
  }));

  const sarif = {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-audit',
            version: VERSION,
            informationUri: 'https://github.com/snehasishghosh115-hub/mcp-audit',
            rules,
          },
        },
        results,
        columnKind: 'utf16CodeUnits',
      },
    ],
  };

  return JSON.stringify(sarif, null, 2) + '\n';
}
