import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import type { ConfigFile, ResolvedConfig, IgnoreEntry, Severity } from '../types.js';

const DEFAULT_CONFIG: ResolvedConfig = {
  failOn: 'high',
  minSeverity: 'info',
  ignore: [],
  trustedPackages: [],
  allowRemoteHosts: [],
  severityOverrides: {},
};

function isValidSeverity(s: string): s is Severity {
  return ['critical', 'high', 'medium', 'low', 'info'].includes(s);
}

interface RawIgnoreEntry {
  rule?: unknown;
  server?: unknown;
  file?: unknown;
  reason?: unknown;
}

function validateIgnoreEntry(entry: unknown, file: string): IgnoreEntry {
  if (!entry || typeof entry !== 'object') {
    throw new Error(`${file}: ignore entry must be an object`);
  }
  const e = entry as RawIgnoreEntry;
  if (!e.rule || typeof e.rule !== 'string') {
    throw new Error(`${file}: ignore entry must have a "rule" string`);
  }
  if (!e.reason || typeof e.reason !== 'string' || e.reason.trim() === '') {
    throw new Error(`${file}: ignore entry must have a non-empty "reason" string`);
  }
  return {
    rule: e.rule,
    server: typeof e.server === 'string' ? e.server : undefined,
    file: typeof e.file === 'string' ? e.file : undefined,
    reason: e.reason.trim(),
  };
}

export function loadConfig(explicitPath?: string, cwd: string = process.cwd()): ResolvedConfig {
  let configPath: string | undefined;

  if (explicitPath) {
    configPath = resolve(cwd, explicitPath);
  } else {
    let current = cwd;
    while (true) {
      const candidate = join(current, '.mcp-audit.json');
      if (existsSync(candidate)) {
        configPath = candidate;
        break;
      }
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }

  if (!configPath || !existsSync(configPath)) {
    return DEFAULT_CONFIG;
  }

  let fileConfig: ConfigFile;
  try {
    const content = readFileSync(configPath, 'utf-8');
    fileConfig = JSON.parse(content);
  } catch (e) {
    throw new Error(
      `Failed to parse config ${configPath}: ${e instanceof Error ? e.message : String(e)}`
    );
  }

  const merged: ResolvedConfig = { ...DEFAULT_CONFIG };

  if (fileConfig.failOn && isValidSeverity(fileConfig.failOn)) {
    merged.failOn = fileConfig.failOn;
  }

  if (fileConfig.ignore && Array.isArray(fileConfig.ignore)) {
    merged.ignore = fileConfig.ignore.map(e => validateIgnoreEntry(e, configPath));
  }

  if (fileConfig.trustedPackages && Array.isArray(fileConfig.trustedPackages)) {
    merged.trustedPackages = fileConfig.trustedPackages.filter(
      (p): p is string => typeof p === 'string'
    );
  }

  if (fileConfig.allowRemoteHosts && Array.isArray(fileConfig.allowRemoteHosts)) {
    merged.allowRemoteHosts = fileConfig.allowRemoteHosts.filter(
      (h): h is string => typeof h === 'string'
    );
  }

  if (fileConfig.severityOverrides && typeof fileConfig.severityOverrides === 'object') {
    for (const [ruleId, severity] of Object.entries(fileConfig.severityOverrides)) {
      if (isValidSeverity(severity)) {
        merged.severityOverrides[ruleId] = severity;
      }
    }
  }

  return merged;
}

export function createDefaultConfig(): string {
  return JSON.stringify(
    {
      failOn: 'high',
      ignore: [
        {
          rule: 'MCPA-SEC-004',
          server: 'my-local-tool',
          reason: 'internal package, pinned by lockfile',
        },
      ],
      trustedPackages: ['@mycorp/mcp-tools'],
    },
    null,
    2
  );
}
