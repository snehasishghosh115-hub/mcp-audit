import type { JsoncNode } from './jsonc.js';
import type { ServerEntry, ClientId, Transport } from '../types.js';
import { getLoc, getValueAtPath } from './jsonc.js';

interface ServerConfig {
  command?: unknown;
  args?: unknown;
  env?: unknown;
  cwd?: unknown;
  url?: unknown;
  headers?: unknown;
  autoApprove?: unknown;
  alwaysAllow?: unknown;
  autoapprove?: unknown;
  trust?: unknown;
  type?: unknown;
}

export function normalizeServerEntries(
  ast: JsoncNode,
  client: ClientId,
  file: string,
  scope: 'user' | 'project',
  key: string,
  source: string
): ServerEntry[] {
  const serversObj = getValueAtPath(ast, [key]);
  if (!serversObj || typeof serversObj !== 'object' || Array.isArray(serversObj)) {
    return [];
  }

  const entries: ServerEntry[] = [];
  const servers = serversObj as Record<string, unknown>;

  for (const [name, config] of Object.entries(servers)) {
    if (!config || typeof config !== 'object') continue;
    const cfg = config as ServerConfig;

    const transport = inferTransport(cfg);
    const loc = getLoc(ast, [key, name], source) ?? { line: 1, column: 1 };

    const entry: ServerEntry = {
      id: `${file}#${name}`,
      name,
      client,
      file,
      scope,
      transport,
      command: typeof cfg.command === 'string' ? cfg.command : undefined,
      args: Array.isArray(cfg.args)
        ? cfg.args.filter((a): a is string => typeof a === 'string')
        : undefined,
      env: cfg.env && typeof cfg.env === 'object' ? (cfg.env as Record<string, string>) : undefined,
      cwd: typeof cfg.cwd === 'string' ? cfg.cwd : undefined,
      url: typeof cfg.url === 'string' ? cfg.url : undefined,
      headers:
        cfg.headers && typeof cfg.headers === 'object'
          ? (cfg.headers as Record<string, string>)
          : undefined,
      autoApprove: (() => {
        const v = cfg.autoApprove ?? cfg.alwaysAllow ?? cfg.autoapprove ?? cfg.trust;
        if (typeof v === 'boolean') return v;
        if (Array.isArray(v) && v.every((x): x is string => typeof x === 'string')) return v;
        return undefined;
      })(),
      loc,
      locOf: (path: (string | number)[]) => getLoc(ast, [key, name, ...path], source),
    };
    entries.push(entry);
  }

  return entries.sort((a, b) => a.name.localeCompare(b.name));
}

function inferTransport(config: ServerConfig): Transport {
  if (typeof config.url === 'string') {
    if (config.type === 'sse') return 'sse';
    return 'http';
  }
  if (typeof config.command === 'string') {
    return 'stdio';
  }
  return 'stdio';
}
