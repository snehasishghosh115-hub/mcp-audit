export * from './types.js';
export * from './parse/jsonc.js';
export * from './parse/normalize.js';
export * from './discovery/clients.js';
export * from './discovery/discover.js';
export * from './engine/run.js';
export * from './config/index.js';
export * from './rules/index.js';

import type {
  ScanResult,
  ResolvedConfig,
  Severity,
  ClientId,
  ServerEntry,
  ScanError,
} from './types.js';
import { discoverConfigFiles } from './discovery/discover.js';
import { parseJsonc } from './parse/jsonc.js';
import { normalizeServerEntries } from './parse/normalize.js';
import { runRules } from './engine/run.js';
import { loadConfig } from './config/index.js';
import { ALL_RULES } from './rules/index.js';
import { getClientById } from './discovery/clients.js';

export async function scan(
  options: {
    paths?: string[];
    failOn?: string;
    minSeverity?: string;
    clientIds?: string[];
    noUser?: boolean;
    noProject?: boolean;
    configPath?: string;
    ruleIds?: string[];
    skipRuleIds?: string[];
    strict?: boolean;
  } = {}
): Promise<ScanResult> {
  const startTime = Date.now();
  const config = loadConfig(options.configPath);

  const resolvedConfig: ResolvedConfig = {
    ...config,
    failOn: (options.failOn as Severity) ?? config.failOn,
    minSeverity: (options.minSeverity as Severity) ?? config.minSeverity,
    ruleIds: options.ruleIds,
    skipRuleIds: options.skipRuleIds,
    clientIds: options.clientIds as ClientId[] | undefined,
    noUser: options.noUser,
    noProject: options.noProject,
    strict: options.strict,
  };

  const { files: discoveredFiles, errors: discoverErrors } = discoverConfigFiles({
    cwd: process.cwd(),
    clientIds: resolvedConfig.clientIds,
    noUser: resolvedConfig.noUser,
    noProject: resolvedConfig.noProject,
    explicitPaths: options.paths,
  });

  const allEntries: ServerEntry[] = [];
  const scannedFiles: string[] = [];
  const parseErrors: ScanError[] = [];

  for (const df of discoveredFiles) {
    scannedFiles.push(df.path);
    try {
      const ast = parseJsonc(df.content);
      const clientConfig = getClientById(df.client);
      const key = clientConfig?.key ?? 'mcpServers';
      const entries = normalizeServerEntries(ast, df.client, df.path, df.scope, key, df.content);
      allEntries.push(...entries);
    } catch (e) {
      parseErrors.push({
        file: df.path,
        message: `Parse error: ${e instanceof Error ? e.message : String(e)}`,
        code: 'PARSE_ERROR',
      });
      if (options.strict) {
        throw e;
      }
    }
  }

  const { findings, errors: ruleErrors } = runRules(allEntries, ALL_RULES, resolvedConfig);

  const durationMs = Date.now() - startTime;

  return {
    findings,
    scannedFiles,
    servers: allEntries.length,
    durationMs,
    errors: [...discoverErrors, ...parseErrors, ...ruleErrors],
  };
}

export { ALL_RULES } from './rules/index.js';
