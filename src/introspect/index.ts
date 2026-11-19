import { StdioMcpClient } from './stdio-client.js';
import { HttpMcpClient } from './http-client.js';
import type { ServerEntry } from '../types.js';
import { homedir } from 'node:os';
import { join } from 'node:path';

export interface IntrospectResult {
  serverId: string;
  serverName: string;
  tools: Array<{ name: string; description?: string; inputSchema?: unknown }>;
  transport: 'stdio' | 'http' | 'sse';
  error?: string;
}

export async function introspectServers(
  entries: ServerEntry[],
  options: { yes?: boolean; timeout?: number } = {}
): Promise<IntrospectResult[]> {
  const results: IntrospectResult[] = [];
  const abortController = new AbortController();
  const timeout = options.timeout ?? 10000;

  // Set global timeout
  const globalTimeout = setTimeout(() => {
    abortController.abort();
  }, timeout * entries.length);

  for (const entry of entries) {
    if (abortController.signal.aborted) break;

    console.error(`[introspect] Connecting to ${entry.name} (${entry.transport})...`);

    try {
      let tools: Array<{ name: string; description?: string; inputSchema?: unknown }> = [];

      if (entry.transport === 'stdio') {
        tools = await introspectStdio(entry, abortController.signal, timeout);
      } else if (entry.transport === 'http' || entry.transport === 'sse') {
        tools = await introspectHttp(entry, abortController.signal, timeout);
      } else {
        throw new Error(`Unsupported transport: ${entry.transport}`);
      }

      results.push({
        serverId: entry.id,
        serverName: entry.name,
        tools,
        transport: entry.transport,
      });
      console.error(`[introspect] ${entry.name}: found ${tools.length} tools`);
    } catch (e) {
      const errorMsg = e instanceof Error ? e.message : String(e);
      console.error(`[introspect] ${entry.name}: failed - ${errorMsg}`);
      results.push({
        serverId: entry.id,
        serverName: entry.name,
        tools: [],
        transport: entry.transport,
        error: errorMsg,
      });
    }
  }

  clearTimeout(globalTimeout);
  return results;
}

async function introspectStdio(
  entry: ServerEntry,
  signal: AbortSignal,
  timeout: number
): Promise<Array<{ name: string; description?: string; inputSchema?: unknown }>> {
  if (!entry.command) throw new Error('No command for stdio server');

  // Resolve command path
  const command = await resolveCommand(entry.command);
  const args = entry.args ?? [];
  const cwd = entry.cwd
    ? entry.cwd.startsWith('~')
      ? join(homedir(), entry.cwd.slice(2))
      : entry.cwd
    : undefined;
  const env = entry.env ?? {};

  const client = new StdioMcpClient(command, args, env, cwd);

  const connectPromise = client.connect(signal);
  const timeoutPromise = new Promise<never>((_, reject) => {
    const t = setTimeout(() => reject(new Error('Connection timeout')), timeout);
    signal.addEventListener('abort', () => clearTimeout(t));
  });

  await Promise.race([connectPromise, timeoutPromise]);

  try {
    const tools = await client.listTools(signal);
    return tools;
  } finally {
    client.kill();
  }
}

async function introspectHttp(
  entry: ServerEntry,
  signal: AbortSignal,
  timeout: number
): Promise<Array<{ name: string; description?: string; inputSchema?: unknown }>> {
  if (!entry.url) throw new Error('No URL for HTTP server');

  const headers = entry.headers ?? {};
  const client = new HttpMcpClient(entry.url, headers);

  const connectPromise = client.connect(signal);
  const timeoutPromise = new Promise<never>((_, reject) => {
    const t = setTimeout(() => reject(new Error('Connection timeout')), timeout);
    signal.addEventListener('abort', () => clearTimeout(t));
  });

  await Promise.race([connectPromise, timeoutPromise]);

  return client.listTools(signal);
}

async function resolveCommand(cmd: string): Promise<string> {
  if (cmd.includes('/') || cmd.includes('\\')) return cmd;

  const pathDirs = (process.env['PATH'] ?? '').split(':');
  for (const dir of pathDirs) {
    const fullPath = join(dir, cmd);
    try {
      const fs = await import('node:fs/promises');
      const stat = await fs.stat(fullPath);
      if (stat.isFile() && stat.mode & 0o111) return fullPath;
    } catch {
      // Not found, continue
    }
  }
  return cmd; // Let spawn handle it
}
