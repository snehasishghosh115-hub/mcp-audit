import type { ScanResult, Severity } from '../types.js';
import { VERSION } from '../version.js';

export function printJsonReport(result: ScanResult): string {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of result.findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  }

  const output = {
    tool: { name: 'mcp-audit', version: VERSION },
    summary: {
      files: result.scannedFiles.length,
      servers: result.servers,
      findings: result.findings.length,
      bySeverity,
    },
    findings: result.findings.map(f => ({
      ruleId: f.ruleId,
      severity: f.severity,
      message: f.message,
      remediation: f.remediation,
      server: f.server,
      client: f.client,
      file: f.file,
      loc: f.loc,
      evidence: f.evidence,
      references: f.references,
      explanation: f.explanation,
    })),
    errors: result.errors.map(e => ({
      file: e.file,
      message: e.message,
      code: e.code,
    })),
  };

  return JSON.stringify(output, null, 2) + '\n';
}
