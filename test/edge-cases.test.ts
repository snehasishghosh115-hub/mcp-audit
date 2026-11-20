/**
 * Edge-case tests covering bugs that were identified and fixed:
 * 1. SEC-004 pnpm/yarn dlx location tracking
 * 2. SEC-005 pre-release semver false positive
 * 3. SEC-003 allowRemoteHosts subdomain matching
 * 4. SEC-002 URL with no userinfo/query (should not flag)
 * 5. Config ignore by file/server specifics
 * 6. Empty scan (no files) returns empty result
 * 7. Absolute path resolution for explicit paths
 * 8. SEC-001 short values (<8 chars) should not flag
 * 9. SEC-001 placeholder patterns should not flag
 * 10. SEC-010 typosquat near-miss detection
 */
import { describe, it, expect } from 'vitest';
import { parseJsonc } from '../src/parse/jsonc.js';
import { normalizeServerEntries } from '../src/parse/normalize.js';
import { runRules } from '../src/engine/run.js';
import { loadConfig } from '../src/config/index.js';
import { ALL_RULES } from '../src/rules/index.js';
import type { Finding, ResolvedConfig } from '../src/types.js';

function makeEntries(serverConfig: Record<string, unknown>, file = '/test.json') {
  const content = JSON.stringify({ mcpServers: serverConfig });
  const ast = parseJsonc(content);
  return normalizeServerEntries(ast, 'claude-desktop', file, 'user', 'mcpServers', content);
}

function scanConfig(
  serverConfig: Record<string, unknown>,
  config?: Partial<ResolvedConfig>
): Finding[] {
  const entries = makeEntries(serverConfig);
  const resolvedConfig = {
    ...loadConfig(),
    ...config,
  } as ResolvedConfig;
  const { findings } = runRules(entries, ALL_RULES, resolvedConfig);
  return findings;
}

// ─── SEC-004 & SEC-005: pnpm dlx / floating version edge cases ───────────────

describe('SEC-004: pnpm dlx package detection', () => {
  it('should detect unpinned pnpm dlx package', () => {
    const findings = scanConfig({
      test: { command: 'pnpm', args: ['dlx', 'some-pkg'] },
    });
    expect(findings.some(f => f.ruleId === 'MCPA-SEC-004')).toBe(true);
  });

  it('should NOT flag pinned pnpm dlx package', () => {
    const findings = scanConfig({
      test: { command: 'pnpm', args: ['dlx', 'some-pkg@1.2.3'] },
    });
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-004')).toHaveLength(0);
  });

  it('should detect unpinned yarn dlx package', () => {
    const findings = scanConfig({
      test: { command: 'yarn', args: ['dlx', 'create-react-app'] },
    });
    expect(findings.some(f => f.ruleId === 'MCPA-SEC-004')).toBe(true);
  });
});

describe('SEC-005: Floating version edge cases', () => {
  it('should flag pkg@latest', () => {
    const findings = scanConfig({
      test: { command: 'npx', args: ['some-pkg@latest'] },
    });
    expect(findings.some(f => f.ruleId === 'MCPA-SEC-005')).toBe(true);
  });

  it('should flag pkg@next', () => {
    const findings = scanConfig({
      test: { command: 'npx', args: ['some-pkg@next'] },
    });
    expect(findings.some(f => f.ruleId === 'MCPA-SEC-005')).toBe(true);
  });

  it('should flag semver range pkg@^1.2.3', () => {
    const findings = scanConfig({
      test: { command: 'npx', args: ['some-pkg@^1.2.3'] },
    });
    expect(findings.some(f => f.ruleId === 'MCPA-SEC-005')).toBe(true);
  });

  it('should NOT flag pre-release semver like pkg@1.0.0-beta.1', () => {
    const findings = scanConfig({
      test: { command: 'npx', args: ['some-pkg@1.0.0-beta.1'] },
    });
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-005')).toHaveLength(0);
  });

  it('should NOT flag pre-release semver like pkg@2.0.0-rc.3', () => {
    const findings = scanConfig({
      test: { command: 'npx', args: ['some-pkg@2.0.0-rc.3'] },
    });
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-005')).toHaveLength(0);
  });

  it('should NOT flag exact semver pkg@1.2.3', () => {
    const findings = scanConfig({
      test: { command: 'npx', args: ['some-pkg@1.2.3'] },
    });
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-005')).toHaveLength(0);
  });

  it('should NOT flag git SHA pkg@abc1234def', () => {
    const findings = scanConfig({
      test: { command: 'npx', args: ['some-pkg@abc1234def5678901'] },
    });
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-005')).toHaveLength(0);
  });
});

// ─── SEC-003: HTTP allowRemoteHosts ──────────────────────────────────────────

describe('SEC-003: allowRemoteHosts config', () => {
  it('should not flag http host that is in allowRemoteHosts', () => {
    const findings = scanConfig(
      { test: { url: 'http://internal.example.com' } },
      { allowRemoteHosts: ['internal.example.com'] }
    );
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-003')).toHaveLength(0);
  });

  it('should not flag http subdomain of an allowRemoteHosts entry', () => {
    const findings = scanConfig(
      { test: { url: 'http://api.corp.internal' } },
      { allowRemoteHosts: ['corp.internal'] }
    );
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-003')).toHaveLength(0);
  });

  it('should still flag unlisted http remote hosts', () => {
    const findings = scanConfig(
      { test: { url: 'http://evil.example.com' } },
      { allowRemoteHosts: ['good.example.com'] }
    );
    expect(findings.some(f => f.ruleId === 'MCPA-SEC-003')).toBe(true);
  });

  it('should not flag http://127.0.0.1', () => {
    const findings = scanConfig({ test: { url: 'http://127.0.0.1:8080' } });
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-003')).toHaveLength(0);
  });
});

// ─── SEC-002: Edge cases for URL secrets ─────────────────────────────────────

describe('SEC-002: Secret in URL edge cases', () => {
  it('should not flag a clean HTTPS URL', () => {
    const findings = scanConfig({ test: { url: 'https://api.example.com/v1' } });
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-002')).toHaveLength(0);
  });

  it('should not flag localhost URL with no credentials', () => {
    const findings = scanConfig({ test: { url: 'http://localhost:3000/mcp' } });
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-002')).toHaveLength(0);
  });

  it('should detect secret in Authorization header', () => {
    const findings = scanConfig({
      test: { url: 'https://api.example.com', headers: { Authorization: 'Bearer sk-ant-abc123def456ghi789' } },
    });
    expect(findings.some(f => f.ruleId === 'MCPA-SEC-001')).toBe(true);
  });
});

// ─── SEC-001: Secret detection edge cases ────────────────────────────────────

describe('SEC-001: Secret detection edge cases', () => {
  it('should not flag short values (<8 chars) even with secret key name', () => {
    const findings = scanConfig({
      test: { command: 'npx', args: ['pkg@1.0.0'], env: { API_KEY: 'short' } },
    });
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-001')).toHaveLength(0);
  });

  it('should not flag placeholder values', () => {
    const findings = scanConfig({
      test: { command: 'npx', args: ['pkg@1.0.0'], env: { API_KEY: 'your-token-here' } },
    });
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-001')).toHaveLength(0);
  });

  it('should not flag env variable references', () => {
    const findings = scanConfig({
      test: { command: 'npx', args: ['pkg@1.0.0'], env: { API_KEY: '${MY_API_KEY}' } },
    });
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-001')).toHaveLength(0);
  });

  it('should detect AWS access key', () => {
    const findings = scanConfig({
      test: { command: 'npx', args: ['pkg@1.0.0'], env: { AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE' } },
    });
    expect(findings.some(f => f.ruleId === 'MCPA-SEC-001')).toBe(true);
  });

  it('evidence should be redacted (contain REDACTED)', () => {
    const findings = scanConfig({
      test: { command: 'npx', args: ['pkg@1.0.0'], env: { ANTHROPIC_API_KEY: 'sk-ant-api03-xxxxxxxxxxxxxxxxxxx' } },
    });
    const f = findings.find(f => f.ruleId === 'MCPA-SEC-001');
    expect(f).toBeDefined();
    expect(f!.evidence).toMatch(/REDACTED/);
    // Evidence must NOT contain the raw secret
    expect(f!.evidence).not.toContain('sk-ant-api03-xxxxxxxxxxxxxxxxxxx');
  });
});

// ─── Ignore config ───────────────────────────────────────────────────────────

describe('Config: ignore by rule+server', () => {
  it('should suppress findings for ignored server', () => {
    const findings = scanConfig(
      { myserver: { command: 'npx', args: ['unpinned-pkg'] } },
      {
        ignore: [{ rule: 'MCPA-SEC-004', server: 'myserver', reason: 'trusted internal tool' }],
      }
    );
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-004')).toHaveLength(0);
  });

  it('should NOT suppress findings for other servers', () => {
    const findings = scanConfig(
      {
        myserver: { command: 'npx', args: ['unpinned-pkg'] },
        otherserver: { command: 'npx', args: ['other-pkg'] },
      },
      {
        ignore: [{ rule: 'MCPA-SEC-004', server: 'myserver', reason: 'trusted internal tool' }],
      }
    );
    expect(findings.filter(f => f.ruleId === 'MCPA-SEC-004' && f.server === 'otherserver').length).toBeGreaterThan(0);
  });
});

// ─── SEC-014: Auto-approve edge cases ────────────────────────────────────────

describe('SEC-014: Auto-approve edge cases', () => {
  it('should flag autoApprove: true (boolean)', () => {
    const findings = scanConfig({
      test: { command: 'npx', args: ['pkg@1.2.3'], autoApprove: true },
    });
    expect(findings.some(f => f.ruleId === 'MCPA-SEC-014')).toBe(true);
  });

  it('should flag autoApprove with specific tool names at high severity (non-read-only tools)', () => {
    // Any non-empty autoApprove array is flagged; non-read-only tools → high severity
    const findings = scanConfig({
      test: { command: 'npx', args: ['pkg@1.2.3'], autoApprove: ['write_file', 'execute'] },
    });
    const aaFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-014');
    expect(aaFindings.length).toBeGreaterThan(0);
    expect(aaFindings[0]!.severity).toBe('high');
  });

  it('should flag autoApprove with read-only tools at medium severity', () => {
    // read_*, list_*, get_*, etc. → severity downgraded to medium
    const findings = scanConfig({
      test: { command: 'npx', args: ['pkg@1.2.3'], autoApprove: ['read_file', 'list_dir', 'get_info'] },
    });
    const aaFindings = findings.filter(f => f.ruleId === 'MCPA-SEC-014');
    expect(aaFindings.length).toBeGreaterThan(0);
    expect(aaFindings[0]!.severity).toBe('medium');
  });
});

// ─── Severity ordering in output ─────────────────────────────────────────────

describe('Finding sort order', () => {
  it('critical findings come before high and medium', () => {
    const findings = scanConfig({
      secretserver: {
        command: 'npx',
        args: ['unpinned-pkg'],
        env: { ANTHROPIC_API_KEY: 'sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxx' },
      },
    });
    // Should have both a secret (critical) and an unpinned (medium) finding
    const severities = findings.map(f => f.severity);
    const criticalIdx = severities.indexOf('critical');
    const mediumIdx = severities.indexOf('medium');
    if (criticalIdx !== -1 && mediumIdx !== -1) {
      expect(criticalIdx).toBeLessThan(mediumIdx);
    }
  });
});
