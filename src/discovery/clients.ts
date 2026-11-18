import { homedir } from 'node:os';
import { join } from 'node:path';
import { existsSync } from 'node:fs';
import type { ClientId, ClientConfig } from '../types.js';

function expandPath(path: string): string {
  if (path.startsWith('~/')) {
    return join(homedir(), path.slice(2));
  }
  if (path.startsWith('%APPDATA%')) {
    const appData = process.env['APPDATA'] ?? join(homedir(), 'AppData', 'Roaming');
    return path.replace('%APPDATA%', appData);
  }
  return path;
}

export const CLIENTS: ClientConfig[] = [
  {
    id: 'claude-desktop',
    name: 'Claude Desktop',
    userPaths: [
      '~/Library/Application Support/Claude/claude_desktop_config.json',
      '%APPDATA%/Claude/claude_desktop_config.json',
      '~/.config/Claude/claude_desktop_config.json',
    ],
    projectPaths: [],
    key: 'mcpServers',
  },
  {
    id: 'claude-code',
    name: 'Claude Code',
    userPaths: ['~/.claude.json'],
    projectPaths: ['.mcp.json'],
    key: 'mcpServers',
  },
  {
    id: 'cursor',
    name: 'Cursor',
    userPaths: ['~/.cursor/mcp.json'],
    projectPaths: ['.cursor/mcp.json'],
    key: 'mcpServers',
  },
  {
    id: 'vscode',
    name: 'VS Code',
    userPaths: [],
    projectPaths: ['.vscode/mcp.json'],
    key: 'servers',
  },
  {
    id: 'windsurf',
    name: 'Windsurf',
    userPaths: ['~/.codeium/windsurf/mcp_config.json'],
    projectPaths: [],
    key: 'mcpServers',
  },
];

export function getClientById(id: ClientId): ClientConfig | undefined {
  return CLIENTS.find(c => c.id === id);
}

export function getClientPaths(
  client: ClientConfig,
  cwd: string,
  scope: 'user' | 'project'
): string[] {
  const paths = scope === 'user' ? client.userPaths : client.projectPaths;
  if (scope === 'project') {
    return paths.map(p => join(cwd, p));
  }
  return paths.map(expandPath);
}

export function findProjectRoot(start: string): string {
  let current = start;
  while (current !== '/') {
    try {
      if (existsSync(join(current, '.git'))) {
        return current;
      }
    } catch {
      // ignore
    }
    const parent = join(current, '..');
    if (parent === current) break;
    current = parent;
  }
  return start;
}
