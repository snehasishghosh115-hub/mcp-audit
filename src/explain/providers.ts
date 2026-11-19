import type { Finding, Severity } from '../types.js';

export interface ExplainProvider {
  name: string;
  explain(findings: ExplainInput[], signal: AbortSignal): Promise<Record<string, string>>;
}

export interface ExplainInput {
  ruleId: string;
  severity: Severity;
  message: string;
  remediation: string;
  evidence?: string;
  transport: string;
  command?: string;
}

export async function buildExplainPrompt(findings: ExplainInput[]): Promise<string> {
  const lines: string[] = [
    'You are a security expert analyzing MCP (Model Context Protocol) server configuration audit findings.',
    'For each finding below, provide a clear, concise explanation (2-3 sentences) of:',
    '1. What the vulnerability means in practice',
    '2. Why it is dangerous',
    '3. How to fix it (specific steps)',
    '',
    'Findings:',
    '',
  ];

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i]!;
    lines.push(`--- Finding ${i + 1} ---`);
    lines.push(`Rule: ${f.ruleId} (${f.severity.toUpperCase()})`);
    lines.push(`Message: ${f.message}`);
    lines.push(`Remediation: ${f.remediation}`);
    if (f.evidence) lines.push(`Evidence (redacted): ${f.evidence}`);
    lines.push(`Transport: ${f.transport}`);
    if (f.command) lines.push(`Command: ${f.command.split('/').pop()}`);
    lines.push('');
  }

  lines.push('Return a JSON object mapping ruleId to explanation string.');
  return lines.join('\n');
}

export function redactForExplain(findings: Finding[]): ExplainInput[] {
  return findings.map(f => ({
    ruleId: f.ruleId,
    severity: f.severity,
    message: f.message,
    remediation: f.remediation,
    evidence: f.evidence,
    transport: f.client, // Using client as transport proxy
    command: undefined, // Not available in Finding
  }));
}
