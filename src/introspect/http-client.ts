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

export interface Tool {
  name: string;
  description?: string;
  inputSchema: unknown;
}

export interface ToolsListResult {
  tools: Tool[];
  nextCursor?: string;
}

export class HttpMcpClient {
  private url: string;
  private headers: Record<string, string>;
  private requestId = 0;
  private sseController: ReadableStreamDefaultController<Uint8Array> | null = null;
  private pending = new Map<
    number,
    { resolve: (value: JsonRpcResponse) => void; reject: (error: Error) => void }
  >();

  constructor(url: string, headers: Record<string, string> = {}) {
    this.url = url;
    this.headers = { ...headers, 'Content-Type': 'application/json' };
  }

  async connect(signal: AbortSignal): Promise<void> {
    try {
      await this.sendHttpRequest('initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'mcp-audit', version: '0.2.0' },
      });
      return;
    } catch {
      // Fall back to SSE if Streamable HTTP fails
    }

    // SSE fallback
    const sseUrl = this.url.endsWith('/sse') ? this.url : `${this.url.replace(/\/$/, '')}/sse`;
    await this.connectSSE(sseUrl, signal);
  }

  private async sendHttpRequest(method: string, params?: unknown): Promise<JsonRpcResponse> {
    const id = ++this.requestId;
    const request: JsonRpcRequest = { jsonrpc: '2.0', id, method, params };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    try {
      const response = await fetch(this.url, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = (await response.json()) as JsonRpcResponse;
      return data;
    } catch (e) {
      clearTimeout(timeout);
      throw e;
    }
  }

  private async connectSSE(sseUrl: string, signal: AbortSignal): Promise<void> {
    const response = await fetch(sseUrl, {
      headers: { ...this.headers, Accept: 'text/event-stream' },
      signal,
    });

    if (!response.ok) {
      throw new Error(`SSE connection failed: ${response.status}`);
    }

    const reader = response.body?.getReader();
    if (!reader) throw new Error('No response body');

    const decoder = new TextDecoder();
    let buffer = '';

    const readLoop = async (): Promise<void> => {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() ?? '';
          for (const line of lines) {
            this.processSSELine(line);
          }
        }
      } catch {
        // Ignore stream errors
      }
    };

    readLoop();

    // Send initialize via POST to the base URL
    await this.sendHttpRequest('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'mcp-audit', version: '0.2.0' },
    });
  }

  private processSSELine(line: string): void {
    if (line.startsWith('data: ')) {
      const data = line.slice(6);
      try {
        const msg = JSON.parse(data) as JsonRpcResponse;
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

  async listTools(_signal: AbortSignal): Promise<Tool[]> {
    const allTools: Tool[] = [];
    let cursor: string | undefined;

    do {
      const resp = await this.sendHttpRequest('tools/list', { cursor });
      if (resp.error) {
        throw new Error(`tools/list failed: ${resp.error.message}`);
      }
      const result = resp.result as ToolsListResult;
      allTools.push(...result.tools);
      cursor = result.nextCursor;
    } while (cursor);

    return allTools;
  }
}
