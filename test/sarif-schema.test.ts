import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { scan } from '../src/index.js';

describe('SARIF schema validation', () => {
  it('should produce valid SARIF 2.1.0 output', async () => {
    const result = await scan({
      paths: [join(__dirname, 'fixtures/claude-desktop/bad/secrets.json')],
    });

    // Generate SARIF
    const { printSarifReport } = await import('../src/reporters/sarif.js');
    const sarifOutput = printSarifReport(result);

    const sarif = JSON.parse(sarifOutput);

    // Basic structure validation
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
    expect(sarif.runs).toBeDefined();
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs.length).toBeGreaterThan(0);

    const run = sarif.runs[0];
    expect(run.tool).toBeDefined();
    expect(run.tool.driver).toBeDefined();
    expect(run.tool.driver.name).toBe('mcp-audit');
    expect(run.tool.driver.version).toBeDefined();
    expect(run.tool.driver.rules).toBeDefined();
    expect(Array.isArray(run.tool.driver.rules)).toBe(true);

    expect(run.results).toBeDefined();
    expect(Array.isArray(run.results)).toBe(true);

    // Validate each result has required fields
    for (const resultItem of run.results) {
      expect(resultItem.ruleId).toBeDefined();
      expect(resultItem.level).toBeDefined();
      expect(['error', 'warning', 'note']).toContain(resultItem.level);
      expect(resultItem.message).toBeDefined();
      expect(resultItem.message.text).toBeDefined();
      expect(resultItem.locations).toBeDefined();
      expect(Array.isArray(resultItem.locations)).toBe(true);
    }

    // Validate rules have required fields
    for (const rule of run.tool.driver.rules) {
      expect(rule.id).toBeDefined();
      expect(rule.name).toBeDefined();
      expect(rule.shortDescription).toBeDefined();
      expect(rule.shortDescription.text).toBeDefined();
      expect(rule.defaultConfiguration).toBeDefined();
      expect(rule.defaultConfiguration.level).toBeDefined();
    }
  });
});
