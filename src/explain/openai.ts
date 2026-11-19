import type { ExplainProvider, ExplainInput } from './providers.js';

export class OpenAIProvider implements ExplainProvider {
  name = 'openai';
  private apiKey: string;
  private baseUrl: string;
  private model: string;

  constructor() {
    this.apiKey = process.env['OPENAI_API_KEY'] ?? '';
    this.baseUrl = process.env['OPENAI_BASE_URL'] ?? 'https://api.openai.com/v1';
    this.model = process.env['MCP_AUDIT_MODEL'] ?? 'gpt-4o-mini';
  }

  isAvailable(): boolean {
    return this.apiKey.length > 0;
  }

  async explain(findings: ExplainInput[], signal: AbortSignal): Promise<Record<string, string>> {
    if (!this.isAvailable()) {
      throw new Error('OPENAI_API_KEY not set');
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
    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: 2000,
        temperature: 0.1,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: 'You are a security expert. Return valid JSON only.' },
          { role: 'user', content: prompt },
        ],
      }),
      signal,
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`OpenAI API error: ${response.status} ${error}`);
    }

    const data = (await response.json()) as { choices: Array<{ message: { content: string } }> };
    return data.choices?.[0]?.message?.content ?? '{}';
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
      const result: Record<string, string> = {};
      for (const f of findings) {
        result[f.ruleId] = 'Could not parse AI response.';
      }
      return result;
    }
  }
}
