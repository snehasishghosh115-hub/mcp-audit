import type { Finding, Severity } from '../types.js';
import { AnthropicProvider } from './anthropic.js';
import { OpenAIProvider } from './openai.js';
import { redactForExplain, type ExplainInput } from './providers.js';

export interface ExplainOptions {
  provider?: 'anthropic' | 'openai' | 'auto';
  model?: string;
  dryRun?: boolean;
}

export async function explainFindings(
  findings: Finding[],
  options: ExplainOptions = {}
): Promise<Record<string, string>> {
  const explainInputs = redactForExplain(findings);

  if (options.dryRun) {
    const prompt = await buildPromptForDryRun(explainInputs);
    console.error('--- DRY RUN: Prompt that would be sent to AI ---');
    console.error(prompt);
    console.error('--- END DRY RUN ---');
    return {};
  }

  const provider = createProvider(options.provider, options.model);
  if (!provider) {
    throw new Error('No AI provider available. Set ANTHROPIC_API_KEY or OPENAI_API_KEY.');
  }

  if (!provider.isAvailable()) {
    throw new Error(
      `Provider ${provider.name} not configured. Set ${provider.name === 'anthropic' ? 'ANTHROPIC_API_KEY' : 'OPENAI_API_KEY'}.`
    );
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);

  try {
    return await provider.explain(redactForExplain(findings), controller.signal);
  } finally {
    clearTimeout(timeout);
  }
}

interface ProviderInstance {
  name: string;
  isAvailable: () => boolean;
  explain: (findings: ExplainInput[], signal: AbortSignal) => Promise<Record<string, string>>;
}

function createProvider(
  providerName?: 'anthropic' | 'openai' | 'auto',
  _model?: string
): ProviderInstance | null {
  if (providerName === 'anthropic') {
    return new AnthropicProvider() as ProviderInstance;
  }
  if (providerName === 'openai') {
    return new OpenAIProvider() as ProviderInstance;
  }

  // Auto-detect: prefer Anthropic, then OpenAI
  const anthropic = new AnthropicProvider();
  if (anthropic.isAvailable()) return anthropic as ProviderInstance;

  const openai = new OpenAIProvider();
  if (openai.isAvailable()) return openai as ProviderInstance;

  return null;
}

async function buildPromptForDryRun(
  findings: Array<{
    ruleId: string;
    severity: Severity;
    message: string;
    remediation: string;
    evidence?: string;
    transport: string;
    command?: string;
  }>
): Promise<string> {
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
