import type { ExplainProvider, ExplainInput } from './providers.js';

export class AnthropicProvider implements ExplainProvider {
  name = 'anthropic';
  private apiKey: string;
  private baseUrl: string;
  private model: string;

  constructor() {
    this.apiKey = process.env['ANTHROPIC_API_KEY'] ?? '';
    this.baseUrl = process.env['ANTHROPIC_BASE_URL'] ?? 'https://api.anthropic.com';
    this.model = process.env['MCP_AUDIT_MODEL'] ?? 'claude-3-haiku-20240307';
  }

  isAvailable(): boolean {
    return this.apiKey.length > 0;
  }

  async explain(findings: ExplainInput[], signal: AbortSignal): Promise<Record<string, string>> {
    if (!this.isAvailable()) {
      throw new Error('ANTHROPIC_API_KEY not set');
    }

    const prompt = await this.buildPrompt(findings);
    const response = await this.callApi(prompt, signal);
    return this.parseResponse(response, findings);
  }

  private async buildPrompt(findings: ExplainInput[]): Promise<string> {
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
      if (f.command) lines.push(`Command: ${f.command}`);
      lines.push('');
    }

    lines.push('Return a JSON object mapping ruleId to explanation string.');
    return lines.join('\n');
  }

  private async callApi(prompt: string, signal: AbortSignal): Promise<string> {
    const response = await fetch(`${this.baseUrl}/v1/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: 2000,
        temperature: 0.1,
        messages: [{ role: 'user', content: prompt }],
      }),
      signal,
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Anthropic API error: ${response.status} ${error}`);
    }

    const data = (await response.json()) as { content: Array<{ type: string; text: string }> };
    return data.content?.[0]?.text ?? '{}';
  }

  private parseResponse(response: string, findings: ExplainInput[]): Record<string, string> {
    try {
      const json = JSON.parse(response);
      const result: Record<string, string> = {};
      for (const f of findings) {
        result[f.ruleId] = json[f.ruleId] ?? 'No explanation provided.';
      }
      return result;
    } catch {
      // Fallback: try to extract explanations from text
      const result: Record<string, string> = {};
      for (const f of findings) {
        result[f.ruleId] = 'Could not parse AI response.';
      }
      return result;
    }
  }
}
