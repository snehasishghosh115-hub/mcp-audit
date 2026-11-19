import { spawn } from 'node:child_process';

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: number | string;
  method: string;
  params?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: number | string;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export interface InitializeParams {
  protocolVersion: string;
  capabilities: Record<string, unknown>;
  clientInfo: { name: string; version: string };
}

export interface InitializeResult {
  protocolVersion: string;
  capabilities: Record<string, unknown>;
  serverInfo: { name: string; version: string };
}

export interface Tool {
  name: string;
  description?: string;
  inputSchema: unknown;
}

export interface ToolsListResult {
  tools: Tool[];
  nextCursor?: string;
}

export class StdioMcpClient {
  private process: ReturnType<typeof spawn> | null = null;
  private requestId = 0;
  private pending = new Map<
    number,
    { resolve: (value: JsonRpcResponse) => void; reject: (error: Error) => void }
  >();
  private buffer = '';
  private toolsCache: Tool[] | null = null;
  private command: string;
  private args: string[];
  private env: Record<string, string>;
  private cwd?: string;

  constructor(command: string, args: string[], env: Record<string, string>, cwd?: string) {
    this.command = command;
    this.args = args;
    this.env = env;
    this.cwd = cwd;
  }

  async connect(signal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      const safeEnv = this.sanitizeEnv();
      this.process = spawn(this.command, this.args, {
        env: safeEnv,
        cwd: this.cwd,
        stdio: ['pipe', 'pipe', 'pipe'],
        shell: false,
      });

      let stderrOutput = '';
      this.process.stderr?.on('data', data => {
        stderrOutput += data.toString();
      });

      this.process.on('error', err => {
        reject(new Error(`Failed to spawn process: ${err.message}`));
      });

      this.process.on('exit', (code, sig) => {
        if (code !== 0 && code !== null) {
          reject(new Error(`Process exited with code ${code}, signal ${sig}: ${stderrOutput}`));
        }
      });

      this.process.stdout?.on('data', data => {
        this.buffer += data.toString();
        this.processBuffer();
      });

      // Send initialize
      this.sendRequest('initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'mcp-audit', version: '0.2.0' },
      })
        .then(resp => {
          if (resp.error) {
            reject(new Error(`Initialize failed: ${resp.error.message}`));
            return;
          }
          // Send notifications/initialized
          this.sendNotification('notifications/initialized', {});
          resolve();
        })
        .catch(reject);

      // Handle abort
      signal.addEventListener('abort', () => {
        this.kill();
        reject(new Error('Aborted'));
      });
    });
  }

  private sanitizeEnv(): Record<string, string> {
    const allowed = new Set([
      'PATH',
      'HOME',
      'USER',
      'SHELL',
      'TERM',
      'LANG',
      'LC_ALL',
      'TMPDIR',
      'TMP',
      'TEMP',
    ]);
    const safeEnv: Record<string, string> = {};
    for (const [key, value] of Object.entries(process.env)) {
      if (allowed.has(key) && value !== undefined) {
        safeEnv[key] = value;
      }
    }
    // Add the server's own env
    for (const [key, value] of Object.entries(this.env)) {
      safeEnv[key] = value;
    }
    return safeEnv;
  }

  private processBuffer(): void {
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() ?? '';
    for (const line of lines) {
      if (line.trim() === '') continue;
      try {
        const msg = JSON.parse(line) as JsonRpcResponse;
        const pending = this.pending.get(msg.id as number);
        if (pending) {
          this.pending.delete(msg.id as number);
          pending.resolve(msg);
        }
      } catch {
        // Ignore parse errors
      }
    }
  }

  private sendRequest(method: string, params?: unknown): Promise<JsonRpcResponse> {
    const id = ++this.requestId;
    const request: JsonRpcRequest = { jsonrpc: '2.0', id, method, params };
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.process?.stdin?.write(JSON.stringify(request) + '\n');
      // Timeout
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`Request timeout: ${method}`));
        }
      }, 10000);
    });
  }

  private sendNotification(method: string, params?: unknown): void {
    const request: JsonRpcRequest = { jsonrpc: '2.0', id: 0, method, params };
    this.process?.stdin?.write(JSON.stringify(request) + '\n');
  }

  async listTools(_signal: AbortSignal): Promise<Tool[]> {
    if (this.toolsCache) return this.toolsCache;

    const allTools: Tool[] = [];
    let cursor: string | undefined;

    do {
      const resp = await this.sendRequest('tools/list', { cursor });
      if (resp.error) {
        throw new Error(`tools/list failed: ${resp.error.message}`);
      }
      const result = resp.result as ToolsListResult;
      allTools.push(...result.tools);
      cursor = result.nextCursor;
    } while (cursor);

    this.toolsCache = allTools;
    return allTools;
  }

  kill(): void {
    if (this.process) {
      this.process.kill('SIGTERM');
      setTimeout(() => {
        if (this.process && !this.process.killed) {
          this.process.kill('SIGKILL');
        }
      }, 1000);
    }
  }
}
