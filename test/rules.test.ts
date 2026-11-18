import { describe, it, expect } from 'vitest';
import { parseJsonc } from '../src/parse/jsonc.js';
import { normalizeServerEntries } from '../src/parse/normalize.js';
import { runRules } from '../src/engine/run.js';
import { loadConfig } from '../src/config/index.js';
import { ALL_RULES } from '../src/rules/index.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding, ServerEntry } from '../src/types.js';

function scanFile(
  filePath: string,
  clientId: string,
  scope: 'user' | 'project' = 'user'
): {
  findings: Finding[];
  entries: ServerEntry[];
} {
  const content = readFileSync(filePath, 'utf-8');
  const ast = parseJsonc(content);
  const key = 'mcpServers';
  const entries = normalizeServerEntries(
    ast,
    clientId as 'claude-desktop',
    filePath,
    scope,
    key,
    content
  );
  const config = loadConfig();
  const { findings } = runRules(entries, ALL_RULES, config);
  return { findings, entries };
}

describe('Rules', () => {
  describe('MCPA-SEC-001: Hardcoded secret', () => {
    it('should detect hardcoded secret in env', () => {
      const { findings } = scanFile(
        join(__dirname, 'fixtures/claude-desktop/bad/secrets.json'),
        'claude-desktop'
      );
      const secretFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-001');
      expect(secretFindings.length).toBeGreaterThan(0);
      expect(secretFindings[0].severity).toBe('critical');
      expect(secretFindings[0].evidence).toMatch(/REDACTED/);
    });

    it('should not flag env references', () => {
      const { findings } = scanFile(
        join(__dirname, 'fixtures/claude-desktop/good/basic.json'),
        'claude-desktop'
      );
      const secretFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-001');
      expect(secretFindings.length).toBe(0);
    });
  });

  describe('MCPA-SEC-002: Secret in URL', () => {
    it('should detect secret in URL userinfo', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { url: 'https://user:pass@example.com' },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const urlFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-002');
      expect(urlFindings.length).toBeGreaterThan(0);
    });

    it('should detect secret in URL query param', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { url: 'https://example.com?api_key=secret123' },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const urlFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-002');
      expect(urlFindings.length).toBeGreaterThan(0);
    });
  });

  describe('MCPA-SEC-003: Plaintext HTTP', () => {
    it('should detect plaintext HTTP to remote host', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { url: 'http://example.com' },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const httpFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-003');
      expect(httpFindings.length).toBeGreaterThan(0);
    });

    it('should not flag localhost', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { url: 'http://localhost:3000' },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const httpFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-003');
      expect(httpFindings.length).toBe(0);
    });

    it('should not flag HTTPS', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { url: 'https://example.com' },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const httpFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-003');
      expect(httpFindings.length).toBe(0);
    });
  });

  describe('MCPA-SEC-004: Unpinned package', () => {
    it('should detect unpinned npx package', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { command: 'npx', args: ['pkg'] },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const unpinnedFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-004');
      expect(unpinnedFindings.length).toBeGreaterThan(0);
    });

    it('should not flag pinned package', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { command: 'npx', args: ['pkg@1.2.3'] },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const unpinnedFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-004');
      expect(unpinnedFindings.length).toBe(0);
    });
  });

  describe('MCPA-SEC-005: Floating version', () => {
    it('should detect latest version', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { command: 'npx', args: ['pkg@latest'] },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const floatFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-005');
      expect(floatFindings.length).toBeGreaterThan(0);
    });

    it('should detect semver range', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { command: 'npx', args: ['pkg@^1.2.3'] },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const floatFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-005');
      expect(floatFindings.length).toBeGreaterThan(0);
    });
  });

  describe('MCPA-SEC-006: Shell wrapper', () => {
    it('should detect bash -c', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { command: 'bash', args: ['-c', 'node server.js'] },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const shellFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-006');
      expect(shellFindings.length).toBeGreaterThan(0);
    });

    it('should detect sh -c', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { command: 'sh', args: ['-c', 'echo hello'] },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const shellFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-006');
      expect(shellFindings.length).toBeGreaterThan(0);
    });
  });

  describe('MCPA-SEC-007: Download and execute', () => {
    it('should detect curl | sh', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { command: 'bash', args: ['-c', 'curl https://example.com/script.sh | sh'] },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const dlFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-007');
      expect(dlFindings.length).toBeGreaterThan(0);
    });
  });

  describe('MCPA-SEC-008: Broad filesystem', () => {
    it('should detect root path', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { command: 'npx', args: ['server-filesystem', '/'] },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const fsFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-008');
      expect(fsFindings.length).toBeGreaterThan(0);
    });
  });

  describe('MCPA-SEC-009: Docker flags', () => {
    it('should detect --privileged', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { command: 'docker', args: ['run', '--privileged', 'alpine'] },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const dockerFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-009');
      expect(dockerFindings.length).toBeGreaterThan(0);
    });

    it('should detect docker.sock mount', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: {
            command: 'docker',
            args: ['run', '-v', '/var/run/docker.sock:/var/run/docker.sock', 'alpine'],
          },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const dockerFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-009');
      expect(dockerFindings.length).toBeGreaterThan(0);
    });
  });

  describe('MCPA-SEC-014: Auto-approve', () => {
    it('should detect autoApprove: ["*"]', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { command: 'npx', args: ['pkg@1.2.3'], autoApprove: ['*'] },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const aaFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-014');
      expect(aaFindings.length).toBeGreaterThan(0);
    });

    it('should detect trust: true', () => {
      const content = JSON.stringify({
        mcpServers: {
          test: { command: 'npx', args: ['pkg@1.2.3'], trust: true },
        },
      });
      const ast = parseJsonc(content);
      const entries = normalizeServerEntries(
        ast,
        'claude-desktop',
        '/test.json',
        'user',
        'mcpServers',
        content
      );
      const config = loadConfig();
      const { findings } = runRules(entries, ALL_RULES, config);
      const aaFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-014');
      expect(aaFindings.length).toBeGreaterThan(0);
    });
  });
});
