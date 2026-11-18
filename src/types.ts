export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ClientId =
  'claude-desktop' | 'claude-code' | 'cursor' | 'vscode' | 'windsurf' | 'generic';
export type Transport = 'stdio' | 'http' | 'sse';

export interface ClientConfig {
  id: ClientId;
  name: string;
  userPaths: string[];
  projectPaths: string[];
  key: string;
}

export interface SourceLoc {
  line: number;
  column: number;
}

export interface ServerEntry {
  id: string;
  name: string;
  client: ClientId;
  file: string;
  scope: 'user' | 'project';
  transport: Transport;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  url?: string;
  headers?: Record<string, string>;
  autoApprove?: string[] | boolean;
  loc: SourceLoc;
  locOf(path: (string | number)[]): SourceLoc | undefined;
}

export interface ToolDef {
  server: string;
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  remediation: string;
  server: string;
  client: ClientId;
  file: string;
  loc?: SourceLoc;
  evidence?: string;
  references?: string[];
  explanation?: string;
}

export interface ScanError {
  file: string;
  message: string;
  code?: string;
}

export interface RuleContext {
  entry: ServerEntry;
  config: ResolvedConfig;
  tools?: ToolDef[];
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  docs: string;
  check(ctx: RuleContext): Finding[];
}

export interface ScanResult {
  findings: Finding[];
  scannedFiles: string[];
  servers: number;
  durationMs: number;
  errors: ScanError[];
}

export interface IgnoreEntry {
  rule: string;
  server?: string;
  file?: string;
  reason: string;
}

export interface ResolvedConfig {
  failOn: Severity;
  minSeverity: Severity;
  ignore: IgnoreEntry[];
  trustedPackages: string[];
  allowRemoteHosts: string[];
  severityOverrides: Record<string, Severity>;
  ruleIds?: string[];
  skipRuleIds?: string[];
  clientIds?: ClientId[];
  noUser?: boolean;
  noProject?: boolean;
  strict?: boolean;
}

export interface ConfigFile {
  failOn?: Severity;
  ignore?: IgnoreEntry[];
  trustedPackages?: string[];
  allowRemoteHosts?: string[];
  severityOverrides?: Record<string, Severity>;
}

export interface ParseError extends Error {
  line: number;
  column: number;
}
