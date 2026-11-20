import type { ScanResult, Finding, Severity } from '../types.js';
import { VERSION } from '../version.js';

const SEVERITY_SYMBOLS: Record<Severity, string> = {
  critical: '✖',
  high: '▲',
  medium: '◆',
  low: '●',
  info: 'ℹ',
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '\x1b[31m', // red
  high: '\x1b[33m', // yellow
  medium: '\x1b[34m', // blue
  low: '\x1b[36m', // cyan
  info: '\x1b[37m', // white
};

const RESET = '\x1b[0m';

function isTTY(): boolean {
  return process.stdout.isTTY && !process.env['NO_COLOR'];
}

function colorize(text: string, severity: Severity): string {
  if (!isTTY()) return text;
  return `${SEVERITY_COLORS[severity]}${text}${RESET}`;
}

export function printTextReport(result: ScanResult): string {
  const lines: string[] = [];

  lines.push(
    `mcp-audit v${VERSION} · scanned ${result.scannedFiles.length} files · ${result.servers} servers · ${result.findings.length} findings`
  );
  lines.push('');

  const byFile = new Map<string, Finding[]>();
  for (const finding of result.findings) {
    const list = byFile.get(finding.file) ?? [];
    list.push(finding);
    byFile.set(finding.file, list);
  }

  for (const [file, findings] of byFile.entries()) {
    lines.push(file);
    const byServer = new Map<string, Finding[]>();
    for (const f of findings) {
      const list = byServer.get(f.server) ?? [];
      list.push(f);
      byServer.set(f.server, list);
    }

    for (const [server, serverFindings] of byServer.entries()) {
      const first = serverFindings[0];
      if (!first) continue;
      lines.push(`  ${server}`);
      for (const f of serverFindings) {
        const symbol = SEVERITY_SYMBOLS[f.severity];
        const severityStr = f.severity.toUpperCase().padEnd(8);
        const locStr = f.loc ? ` (line ${f.loc.line})` : '';
        const coloredSeverity = colorize(`${symbol} ${severityStr}`, f.severity);
        lines.push(`    ${coloredSeverity} ${f.ruleId}  ${f.message}${locStr}`);
        if (f.evidence) {
          lines.push(`        evidence: ${f.evidence}`);
        }
        lines.push(`        fix: ${f.remediation}`);
      }
    }
    lines.push('');
  }

  if (result.errors.length > 0) {
    lines.push('Errors:');
    for (const err of result.errors) {
      lines.push(`  ${err.file}: ${err.message}`);
    }
    lines.push('');
  }

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of result.findings) {
    counts[f.severity]++;
  }
  lines.push(
    `Summary: ${counts.critical} critical · ${counts.high} high · ${counts.medium} medium · ${counts.low} low · ${counts.info} info`
  );

  return lines.join('\n') + '\n';
}
