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
  ToolDef,
} from './types.js';
import { discoverConfigFiles } from './discovery/discover.js';
import { parseJsonc } from './parse/jsonc.js';
import { normalizeServerEntries } from './parse/normalize.js';
import { runRules } from './engine/run.js';
import { loadConfig } from './config/index.js';
import { ALL_RULES } from './rules/index.js';
import { getClientById } from './discovery/clients.js';
import { readFileSync } from 'node:fs';
import { introspectServers } from './introspect/index.js';

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
    toolsPath?: string;
    introspect?: boolean;
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

  // Load tools from file if provided
  let toolsMap: Map<string, { server: string; tools: ToolDef[] }> | undefined;
  if (options.toolsPath) {
    try {
      const content = readFileSync(options.toolsPath, 'utf-8');
      const toolsData = JSON.parse(content);
      if (toolsData.tools && Array.isArray(toolsData.tools)) {
        // For --tools mode, we create a pseudo-server entry for the tools
        toolsMap = new Map();
        toolsMap.set('tools-file', {
          server: 'tools-file',
          tools: toolsData.tools.map((t: ToolDef) => ({
            server: 'tools-file',
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          })),
        });
      }
    } catch (e) {
      console.error(`Failed to load tools file: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

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

  // If toolsPath was provided but no config files found, create a dummy entry for the tools
  if (toolsMap && allEntries.length === 0) {
    // Create a minimal entry to run tool rules against
    const dummyEntry: ServerEntry = {
      id: 'tools-file',
      name: 'tools-file',
      client: 'generic',
      file: options.toolsPath!,
      scope: 'project',
      transport: 'stdio',
      loc: { line: 1, column: 1 },
      locOf: () => undefined,
    };
    allEntries.push(dummyEntry);
  }

  // Introspection: connect to servers and fetch live tool definitions
  let introspectToolsMap: Map<string, { server: string; tools: ToolDef[] }> | undefined;
  if (options.introspect && allEntries.length > 0) {
    try {
      const introspectResults = await introspectServers(allEntries);
      introspectToolsMap = new Map();
      for (const result of introspectResults) {
        if (result.tools.length > 0) {
          introspectToolsMap.set(result.serverId, {
            server: result.serverName,
            tools: result.tools.map(t => ({
              server: result.serverName,
              name: t.name,
              description: t.description,
              inputSchema: t.inputSchema,
            })),
          });
        }
      }
    } catch (e) {
      console.error(`Introspection failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // Merge tools maps: introspection results take precedence over --tools file
  const finalToolsMap = new Map([...(toolsMap ?? []), ...(introspectToolsMap ?? [])]);

  // If toolsPath was provided but no config files found, create a dummy entry for the tools
  if (finalToolsMap.size > 0 && allEntries.length === 0) {
    // Create a minimal entry to run tool rules against
    const dummyEntry: ServerEntry = {
      id: 'tools-file',
      name: 'tools-file',
      client: 'generic',
      file: options.toolsPath ?? 'introspect',
      scope: 'project',
      transport: 'stdio',
      loc: { line: 1, column: 1 },
      locOf: () => undefined,
    };
    allEntries.push(dummyEntry);
  }

  const { findings, errors: ruleErrors } = runRules(
    allEntries,
    ALL_RULES,
    resolvedConfig,
    finalToolsMap
  );

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
