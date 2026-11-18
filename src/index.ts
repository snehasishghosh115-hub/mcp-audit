export * from './types.js';

import type { ScanResult, Rule } from './types.js';

export async function scan(_options: { paths?: string[]; failOn?: string }): Promise<ScanResult> {
  throw new Error('Not yet implemented');
}

export const ALL_RULES: Rule[] = [];
