import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { CLIENTS, findProjectRoot } from './clients.js';
import type { ClientConfig, ClientId, ScanError } from '../types.js';

export interface DiscoveredFile {
  client: ClientId;
  scope: 'user' | 'project';
  path: string;
  content: string;
}

export interface DiscoverOptions {
  cwd?: string;
  clientIds?: ClientId[];
  noUser?: boolean;
  noProject?: boolean;
  explicitPaths?: string[];
}

export function discoverConfigFiles(options: DiscoverOptions = {}): {
  files: DiscoveredFile[];
  errors: ScanError[];
} {
  const cwd = options.cwd ?? process.cwd();
  const projectRoot = findProjectRoot(cwd);
  const files: DiscoveredFile[] = [];
  const errors: ScanError[] = [];

  if (options.explicitPaths && options.explicitPaths.length > 0) {
    for (const explicitPath of options.explicitPaths) {
      // resolve() handles both absolute and relative paths correctly
      const fullPath = resolve(cwd, explicitPath);
      if (existsSync(fullPath)) {
        try {
          const content = readFileSync(fullPath, 'utf-8');
          const client = detectClientFromPath(fullPath);
          const scope = client?.userPaths.some((p: string) =>
            fullPath.startsWith(p.replace('~', process.env['HOME'] ?? ''))
          )
            ? 'user'
            : 'project';
          files.push({
            client: client?.id ?? 'generic',
            scope: scope ?? 'project',
            path: fullPath,
            content,
          });
        } catch (e) {
          errors.push({
            file: fullPath,
            message: `Failed to read: ${e instanceof Error ? e.message : String(e)}`,
          });
        }
      } else {
        errors.push({ file: fullPath, message: 'File not found' });
      }
    }
    return { files, errors };
  }

  const targetClients = options.clientIds
    ? CLIENTS.filter(c => options.clientIds!.includes(c.id))
    : CLIENTS;

  for (const client of targetClients) {
    if (!options.noUser) {
      for (const userPath of client.userPaths) {
        const fullPath =
          userPath.startsWith('~/') || userPath.startsWith('%APPDATA%')
            ? userPath
            : join(cwd, userPath);
        const expandedPath = fullPath
          .replace('~', process.env['HOME'] ?? '')
          .replace('%APPDATA%', process.env['APPDATA'] ?? '');
        if (existsSync(expandedPath)) {
          try {
            const content = readFileSync(expandedPath, 'utf-8');
            files.push({ client: client.id, scope: 'user', path: expandedPath, content });
          } catch (e) {
            errors.push({
              file: expandedPath,
              message: `Failed to read: ${e instanceof Error ? e.message : String(e)}`,
            });
          }
        }
      }
    }

    if (!options.noProject) {
      for (const projectPath of client.projectPaths) {
        let searchPath = projectRoot;
        while (true) {
          const fullPath = join(searchPath, projectPath);
          if (existsSync(fullPath)) {
            try {
              const content = readFileSync(fullPath, 'utf-8');
              files.push({ client: client.id, scope: 'project', path: fullPath, content });
            } catch (e) {
              errors.push({
                file: fullPath,
                message: `Failed to read: ${e instanceof Error ? e.message : String(e)}`,
              });
            }
            break;
          }
          const parent = join(searchPath, '..');
          if (parent === searchPath) break;
          searchPath = parent;
        }
      }
    }
  }

  return { files, errors };
}

function detectClientFromPath(path: string): ClientConfig | undefined {
  const lowerPath = path.toLowerCase();
  if (
    lowerPath.includes('claude_desktop_config') ||
    lowerPath.includes('claude/claude_desktop_config')
  ) {
    return CLIENTS.find(c => c.id === 'claude-desktop');
  }
  if (lowerPath.includes('.mcp.json') && !lowerPath.includes('.cursor')) {
    return CLIENTS.find(c => c.id === 'claude-code');
  }
  if (lowerPath.includes('.cursor/mcp.json')) {
    return CLIENTS.find(c => c.id === 'cursor');
  }
  if (lowerPath.includes('.vscode/mcp.json')) {
    return CLIENTS.find(c => c.id === 'vscode');
  }
  if (lowerPath.includes('windsurf') || lowerPath.includes('mcp_config.json')) {
    return CLIENTS.find(c => c.id === 'windsurf');
  }
  return undefined;
}
