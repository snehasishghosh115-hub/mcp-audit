import { redactSecret } from './secrets.js';

export function redact(value: string): string {
  return redactSecret(value);
}

export function redactFindings(findings: Array<{ evidence?: string }>): void {
  for (const finding of findings) {
    if (finding.evidence) {
      finding.evidence = redact(finding.evidence);
    }
  }
}
